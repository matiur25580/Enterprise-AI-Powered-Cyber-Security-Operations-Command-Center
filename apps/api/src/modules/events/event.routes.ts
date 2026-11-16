import { Router } from "express";
import { rateLimit } from "express-rate-limit";
import { Types } from "mongoose";
import { z } from "zod";

import { AuditService } from "../audit/audit-service.js";
import { authenticate } from "../identity/middleware/authenticate.js";
import {
  requirePermission,
  requireTenantContext,
  requireTenantMembership,
} from "../identity/middleware/authorize.js";
import { withTenantScope } from "../identity/tenant-scope.js";
import { sanitizeSensitiveData } from "../security-data.js";
import { EventIngestionService } from "./ingestion-service.js";
import { SecurityEvent } from "./models/SecurityEvent.js";
import { bulkSecurityEventInputSchema, securityEventInputSchema } from "./event-schema.js";
import { normalizeSecurityEvent } from "./event-normalization.js";

const router: import("express").Router = Router();
const severityValues = ["info", "low", "medium", "high", "critical"] as const;
const objectIdSchema = z.string().regex(/^[a-f\d]{24}$/i);
const idempotencyKeySchema = z.string().min(8).max(128).regex(/^[A-Za-z0-9._:-]+$/);

const listQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  cursor: z.string().max(128).regex(/^[A-Za-z0-9_-]+$/).optional(),
  startDate: z.iso.datetime(),
  endDate: z.iso.datetime(),
  severity: z.enum(severityValues).optional(),
  eventType: z.string().trim().min(1).max(120).optional(),
  source: z.string().trim().min(1).max(120).optional(),
  hostname: z.string().trim().min(1).max(255).optional(),
  username: z.string().trim().min(1).max(256).optional(),
}).strict().refine(
  (query) => {
    const start = new Date(query.startDate).getTime();
    const end = new Date(query.endDate).getTime();
    return start <= end && end - start <= 31 * 24 * 60 * 60 * 1000;
  },
  { message: "A valid date range of no more than 31 days is required." },
);

function requestId(request: import("express").Request): string {
  return request.requestId ?? "request-id-unavailable";
}

function eventResponse(event: Record<string, unknown>) {
  return {
    id: String(event._id),
    organizationId: String(event.organizationId),
    eventId: event.eventId,
    timestamp: event.occurredAt,
    source: event.source,
    sourceType: event.sourceType,
    sourceIp: event.sourceIp ?? null,
    destinationIp: event.destinationIp ?? null,
    username: event.username ?? null,
    hostname: event.hostname ?? null,
    eventType: event.eventType,
    category: event.category,
    severity: event.severity,
    action: event.action ?? null,
    outcome: event.outcome ?? null,
    rawEvent: sanitizeSensitiveData(event.rawEvent),
    normalizedData: sanitizeSensitiveData(event.normalizedData),
    tags: event.tags,
    processingStatus: event.processingStatus,
    createdAt: event.createdAt,
  };
}

function parseCursor(cursor: string | undefined): { timestamp: Date; id: Types.ObjectId } | undefined {
  if (!cursor) return undefined;
  try {
    const decoded = Buffer.from(cursor, "base64url").toString("utf8");
    const match = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z)\|([a-f\d]{24})$/i.exec(decoded);
    if (!match || !match[1] || !match[2] || new Date(match[1]).toISOString() !== match[1]) return undefined;
    return { timestamp: new Date(match[1]), id: new Types.ObjectId(match[2]) };
  } catch {
    return undefined;
  }
}

function encodeCursor(timestamp: Date, id: Types.ObjectId): string {
  return Buffer.from(`${timestamp.toISOString()}|${id.toHexString()}`).toString("base64url");
}

const ingestLimiter = rateLimit({
  windowMs: 60_000,
  limit: 120,
  standardHeaders: "draft-8",
  legacyHeaders: false,
});
const readLimiter = rateLimit({
  windowMs: 60_000,
  limit: 300,
  standardHeaders: "draft-8",
  legacyHeaders: false,
});

router.post(
  "/ingest",
  authenticate,
  requireTenantContext(),
  requireTenantMembership(),
  requirePermission("events:ingest"),
  ingestLimiter,
  async (request, response) => {
    const parsed = securityEventInputSchema.safeParse(request.body);
    if (!parsed.success) {
      response.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "Invalid security event.", requestId: requestId(request) },
      });
      return;
    }

    const idempotencyKey = request.header("idempotency-key");
    if (idempotencyKey !== undefined && !idempotencyKeySchema.safeParse(idempotencyKey).success) {
      response.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "Invalid idempotency key.", requestId: requestId(request) },
      });
      return;
    }

    try {
      normalizeSecurityEvent(parsed.data);
    } catch {
      response.status(400).json({
        error: { code: "INVALID_EVENT_DATA", message: "The event contains invalid or oversized structured data.", requestId: requestId(request) },
      });
      return;
    }

    const result = await EventIngestionService.ingest(
      request.principal!.tenantId,
      parsed.data,
      idempotencyKey,
    );
    await AuditService.append({
      organizationId: request.principal!.tenantId,
      actorUserId: request.principal!.userId,
      actorRole: request.principal!.roles[0],
      action: "security_event.ingest",
      resourceType: "security_event",
      resourceId: String(result.event._id),
      requestId: requestId(request),
      sourceIp: request.ip,
      userAgent: request.get("user-agent")?.slice(0, 500),
      outcome: "success",
      severity: "low",
      metadata: { duplicate: result.duplicate, eventType: parsed.data.eventType },
    });

    response.status(result.duplicate ? 200 : 201).json({
      data: eventResponse(result.event),
      meta: { requestId: requestId(request), duplicate: result.duplicate },
    });
  },
);

router.post(
  "/bulk-ingest",
  authenticate,
  requireTenantContext(),
  requireTenantMembership(),
  requirePermission("events:ingest"),
  ingestLimiter,
  async (request, response) => {
    const parsedBatch = bulkSecurityEventInputSchema.safeParse(request.body);
    if (!parsedBatch.success) {
      response.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "Invalid or oversized event batch.", requestId: requestId(request) },
      });
      return;
    }

    const idempotencyKey = request.header("idempotency-key");
    if (idempotencyKey !== undefined && !idempotencyKeySchema.safeParse(idempotencyKey).success) {
      response.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "Invalid idempotency key.", requestId: requestId(request) },
      });
      return;
    }

    const results: Array<Record<string, unknown>> = [];
    const failures: Array<{ index: number; code: string }> = [];
    let createdCount = 0;
    let duplicateCount = 0;

    for (const [index, rawEvent] of parsedBatch.data.events.entries()) {
      const parsed = securityEventInputSchema.safeParse(rawEvent);
      if (!parsed.success) {
        failures.push({ index, code: "VALIDATION_ERROR" });
        continue;
      }

      try {
        normalizeSecurityEvent(parsed.data);
      } catch {
        failures.push({ index, code: "INVALID_EVENT_DATA" });
        continue;
      }

      const perEventIdempotencyKey = idempotencyKey ? `${idempotencyKey}:${index}` : undefined;
      const result = await EventIngestionService.ingest(
        request.principal!.tenantId,
        parsed.data,
        perEventIdempotencyKey,
      );
      results.push({ index, duplicate: result.duplicate, event: eventResponse(result.event) });
      if (result.duplicate) duplicateCount += 1;
      else createdCount += 1;
    }

    await AuditService.append({
      organizationId: request.principal!.tenantId,
      actorUserId: request.principal!.userId,
      actorRole: request.principal!.roles[0],
      action: "security_event.bulk_ingest",
      resourceType: "security_event_batch",
      requestId: requestId(request),
      sourceIp: request.ip,
      userAgent: request.get("user-agent")?.slice(0, 500),
      outcome: failures.length > 0 ? "partial" : "success",
      severity: "low",
      metadata: {
        submittedCount: parsedBatch.data.events.length,
        createdCount,
        duplicateCount,
        rejectedCount: failures.length,
      },
    });

    response.status(failures.length > 0 ? 207 : 200).json({
      data: { results, failures },
      meta: {
        requestId: requestId(request),
        submittedCount: parsedBatch.data.events.length,
        createdCount,
        duplicateCount,
        rejectedCount: failures.length,
      },
    });
  },
);

router.get(
  "/",
  authenticate,
  requireTenantContext(),
  requireTenantMembership(),
  requirePermission("events:read"),
  readLimiter,
  async (request, response) => {
    const parsed = listQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      response.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "Invalid event filters or date range.", requestId: requestId(request) },
      });
      return;
    }

    const query = parsed.data;
    const cursor = parseCursor(query.cursor);
    if (query.cursor && !cursor) {
      response.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "Invalid event cursor.", requestId: requestId(request) },
      });
      return;
    }

    const filter: Record<string, unknown> = {
      occurredAt: { $gte: new Date(query.startDate), $lte: new Date(query.endDate) },
    };
    if (query.severity) filter.severity = query.severity;
    if (query.eventType) filter.eventType = query.eventType;
    if (query.source) filter.source = query.source;
    if (query.hostname) filter.hostname = query.hostname;
    if (query.username) filter.username = query.username;
    if (cursor) {
      filter.$or = [
        { occurredAt: { $lt: cursor.timestamp } },
        { occurredAt: cursor.timestamp, _id: { $lt: cursor.id } },
      ];
    }

    const events = await SecurityEvent.find(withTenantScope(request.principal!.tenantId, filter, "organizationId"))
      .sort({ occurredAt: -1, _id: -1 })
      .limit(query.limit + 1)
      .lean();
    const hasMore = events.length > query.limit;
    const page = hasMore ? events.slice(0, query.limit) : events;
    const last = page[page.length - 1];

    response.status(200).json({
      data: page.map((event) => eventResponse(event as unknown as Record<string, unknown>)),
      meta: {
        requestId: requestId(request),
        nextCursor: hasMore && last ? encodeCursor(last.occurredAt, last._id) : null,
      },
    });
  },
);

router.get(
  "/:id",
  authenticate,
  requireTenantContext(),
  requireTenantMembership(),
  requirePermission("events:read"),
  readLimiter,
  async (request, response) => {
    const parsedId = objectIdSchema.safeParse(request.params.id);
    if (!parsedId.success) {
      response.status(400).json({
        error: { code: "VALIDATION_ERROR", message: "Invalid event ID.", requestId: requestId(request) },
      });
      return;
    }

    const event = await SecurityEvent.findOne(withTenantScope(request.principal!.tenantId, {
      _id: new Types.ObjectId(parsedId.data),
    }, "organizationId")).lean();
    if (!event) {
      response.status(404).json({
        error: { code: "EVENT_NOT_FOUND", message: "The event was not found.", requestId: requestId(request) },
      });
      return;
    }

    response.status(200).json({
      data: eventResponse(event as unknown as Record<string, unknown>),
      meta: { requestId: requestId(request) },
    });
  },
);

export { router as eventRouter };
