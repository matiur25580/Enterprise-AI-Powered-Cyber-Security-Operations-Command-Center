import { Router } from "express";
import { z } from "zod";

import { authenticate } from "../identity/middleware/authenticate.js";
import { requirePermission, requireTenantContext, requireTenantMembership } from "../identity/middleware/authorize.js";
import { withTenantScope } from "../identity/tenant-scope.js";
import { DetectionFinding } from "./models/DetectionFinding.js";

const router: import("express").Router = Router();
const querySchema = z.object({
  status: z.enum(["open", "acknowledged", "resolved"]).optional(),
  severity: z.enum(["low", "medium", "high", "critical"]).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
}).strict();

router.get(
  "/findings",
  authenticate,
  requireTenantContext(),
  requireTenantMembership(),
  requirePermission("events:read"),
  async (request, response) => {
    const parsed = querySchema.safeParse(request.query);
    if (!parsed.success) {
      response.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Invalid finding filters." } });
      return;
    }

    const filter: Record<string, unknown> = {};
    if (parsed.data.status) filter.status = parsed.data.status;
    if (parsed.data.severity) filter.severity = parsed.data.severity;
    const findings = await DetectionFinding.find(
      withTenantScope(request.principal!.tenantId, filter, "organizationId"),
    ).sort({ lastSeenAt: -1, _id: -1 }).limit(parsed.data.limit).lean();

    response.status(200).json({
      data: findings.map((finding) => ({
        id: String(finding._id),
        title: finding.title,
        description: finding.description,
        severity: finding.severity,
        riskScore: finding.riskScore,
        confidence: finding.confidence,
        ruleKeys: finding.ruleKeys,
        evidenceEventIds: finding.evidenceEventIds.map(String),
        status: finding.status,
        firstSeenAt: finding.firstSeenAt,
        lastSeenAt: finding.lastSeenAt,
      })),
      meta: { requestId: request.requestId ?? "request-id-unavailable" },
    });
  },
);

export { router as detectionRouter };
