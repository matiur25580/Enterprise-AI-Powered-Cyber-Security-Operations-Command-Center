import { Router } from "express";
import { rateLimit } from "express-rate-limit";
import { Types } from "mongoose";
import { z } from "zod";

import { AuditService } from "./audit-service.js";
import { AuditLog } from "./models/AuditLog.js";
import { authenticate } from "../identity/middleware/authenticate.js";
import {
  requirePermission,
  requireTenantContext,
  requireTenantMembership,
} from "../identity/middleware/authorize.js";
import { withTenantScope } from "../identity/tenant-scope.js";
import { sanitizeSensitiveData } from "../security-data.js";

const router: import("express").Router = Router();
const severityValues = ["info", "low", "medium", "high", "critical"] as const;
const outcomeValues = ["success", "failure", "denied", "partial"] as const;
const objectIdSchema = z.string().regex(/^[a-f\d]{24}$/i);

const listQueryFieldsSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  cursor: z.coerce.number().int().min(1).optional(),
  action: z.string().trim().min(1).max(120).optional(),
  resourceType: z.string().trim().min(1).max(100).optional(),
  outcome: z.enum(outcomeValues).optional(),
  severity: z.enum(severityValues).optional(),
  actorUserId: objectIdSchema.optional(),
  startDate: z.iso.datetime().optional(),
  endDate: z.iso.datetime().optional(),
}).strict();

const listQuerySchema = listQueryFieldsSchema.refine(
  (query) => Boolean(query.startDate) === Boolean(query.endDate),
  { message: "startDate and endDate must be provided together." },
).refine(
  (query) => !query.startDate || !query.endDate
    || new Date(query.startDate).getTime() <= new Date(query.endDate).getTime(),
  { message: "startDate must not be after endDate." },
);

const exportQuerySchema = listQueryFieldsSchema.omit({ limit: true, cursor: true }).extend({
  startDate: z.iso.datetime(),
  endDate: z.iso.datetime(),
}).strict().refine(
  (query) => {
    const range = new Date(query.endDate).getTime() - new Date(query.startDate).getTime();
    return range >= 0 && range <= 31 * 24 * 60 * 60 * 1000;
  },
  { message: "Export date range must be no more than 31 days." },
);

const verifyLimiter = rateLimit({
  windowMs: 60_000,
  limit: 5,
  standardHeaders: "draft-8",
  legacyHeaders: false,
});

const readLimiter = rateLimit({
  windowMs: 60_000,
  limit: 300,
  standardHeaders: "draft-8",
  legacyHeaders: false,
});

function requestId(request: import("express").Request): string {
  return request.requestId ?? "request-id-unavailable";
}

function publicRecord(record: Record<string, unknown>) {
  return {
    id: String(record._id),
    organizationId: String(record.organizationId),
    actorUserId: record.actorUserId ? String(record.actorUserId) : null,
    actorRole: record.actorRole ?? null,
    action: record.action,
    resourceType: record.resourceType,
    resourceId: record.resourceId ?? null,
    timestamp: record.occurredAt,
    sourceIp: record.sourceIp ?? null,
    userAgent: record.userAgent ?? null,
    requestId: record.requestId,
    outcome: record.outcome,
    severity: record.severity,
    metadata: sanitizeSensitiveData(record.metadata ?? {}),
    previousHash: record.previousHash ?? null,
    entryHash: record.entryHash,
    chainIndex: record.chainIndex,
  };
}

function buildFilter(query: Pick<
  z.infer<typeof listQueryFieldsSchema>,
  "action" | "resourceType" | "outcome" | "severity" | "actorUserId" | "startDate" | "endDate"
>) {
  const filter: Record<string, unknown> = {};
  if (query.action) filter.action = query.action;
  if (query.resourceType) filter.resourceType = query.resourceType;
  if (query.outcome) filter.outcome = query.outcome;
  if (query.severity) filter.severity = query.severity;
  if (query.actorUserId) filter.actorUserId = new Types.ObjectId(query.actorUserId);
  if (query.startDate || query.endDate) {
    filter.occurredAt = {
      ...(query.startDate ? { $gte: new Date(query.startDate) } : {}),
      ...(query.endDate ? { $lte: new Date(query.endDate) } : {}),
    };
  }
  return filter;
}

router.use(authenticate, requireTenantContext(), requireTenantMembership(), requirePermission("audit:read"));

router.get("/verify", verifyLimiter, async (request, response) => {
  const result = await AuditService.verify(request.principal!.tenantId);
  response.status(result.valid ? 200 : 409).json({
    data: result,
    meta: { requestId: requestId(request) },
  });
});

router.get("/export", verifyLimiter, async (request, response) => {
  const parsed = exportQuerySchema.safeParse(request.query);
  if (!parsed.success) {
    response.status(400).json({
      error: { code: "VALIDATION_ERROR", message: "Invalid audit export filters.", requestId: requestId(request) },
    });
    return;
  }

  const filters = parsed.data;
  const criteria = buildFilter(filters);
  const records = await AuditLog.find(withTenantScope(request.principal!.tenantId, criteria, "organizationId"))
    .sort({ chainIndex: -1 })
    .limit(501)
    .lean();

  if (records.length > 500) {
    response.status(413).json({
      error: { code: "EXPORT_TOO_LARGE", message: "Narrow the date range or filters to export no more than 500 records.", requestId: requestId(request) },
    });
    return;
  }

  await AuditService.append({
    organizationId: request.principal!.tenantId,
    actorUserId: request.principal!.userId,
    actorRole: request.principal!.roles[0],
    action: "audit.export",
    resourceType: "audit",
    requestId: requestId(request),
    sourceIp: request.ip,
    userAgent: request.get("user-agent")?.slice(0, 500),
    outcome: "success",
    severity: "medium",
    metadata: { exportedCount: records.length, filters },
  });

  response.status(200).json({
    data: records.map((record) => publicRecord(record as unknown as Record<string, unknown>)),
    meta: { requestId: requestId(request), exportedCount: records.length },
  });
});

router.get("/", readLimiter, async (request, response) => {
  const parsed = listQuerySchema.safeParse(request.query);
  if (!parsed.success) {
    response.status(400).json({
      error: { code: "VALIDATION_ERROR", message: "Invalid audit filters.", requestId: requestId(request) },
    });
    return;
  }

  const query = parsed.data;
  const filter = buildFilter(query);
  if (query.cursor !== undefined) filter.chainIndex = { $lt: query.cursor };
  const records = await AuditLog.find(withTenantScope(request.principal!.tenantId, filter, "organizationId"))
    .sort({ chainIndex: -1 })
    .limit(query.limit + 1)
    .lean();
  const hasMore = records.length > query.limit;
  const page = hasMore ? records.slice(0, query.limit) : records;
  response.status(200).json({
    data: page.map((record) => publicRecord(record as unknown as Record<string, unknown>)),
    meta: {
      requestId: requestId(request),
      nextCursor: hasMore ? page[page.length - 1]?.chainIndex ?? null : null,
    },
  });
});

router.get("/:id", readLimiter, async (request, response) => {
  const parsedId = objectIdSchema.safeParse(request.params.id);
  if (!parsedId.success) {
    response.status(400).json({
      error: { code: "VALIDATION_ERROR", message: "Invalid audit record ID.", requestId: requestId(request) },
    });
    return;
  }

  const record = await AuditLog.findOne(withTenantScope(request.principal!.tenantId, {
    _id: new Types.ObjectId(parsedId.data),
  }, "organizationId")).lean();
  if (!record) {
    response.status(404).json({
      error: { code: "AUDIT_RECORD_NOT_FOUND", message: "The audit record was not found.", requestId: requestId(request) },
    });
    return;
  }

  response.status(200).json({
    data: publicRecord(record as unknown as Record<string, unknown>),
    meta: { requestId: requestId(request) },
  });
});

export { router as auditRouter };
