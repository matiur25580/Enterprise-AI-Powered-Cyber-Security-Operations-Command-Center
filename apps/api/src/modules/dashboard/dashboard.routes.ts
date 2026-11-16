import { Router } from "express";

import { authenticate } from "../identity/middleware/authenticate.js";
import { requirePermission, requireTenantContext, requireTenantMembership } from "../identity/middleware/authorize.js";
import { SecurityEvent } from "../events/models/SecurityEvent.js";
import { withTenantScope } from "../identity/tenant-scope.js";

const router: import("express").Router = Router();
const severities = ["info", "low", "medium", "high", "critical"] as const;

router.get(
  "/overview",
  authenticate,
  requireTenantContext(),
  requireTenantMembership(),
  requirePermission("dashboard:read"),
  async (request, response) => {
    const tenantId = request.principal!.tenantId;
    const now = new Date();
    const currentStart = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const previousStart = new Date(now.getTime() - 48 * 60 * 60 * 1000);
    const tenantScope = (filter: Record<string, unknown>) =>
      withTenantScope(tenantId, filter, "organizationId");

    const [totalEvents, previousEvents, severityRows, recentEvents, highSeverityEvents] = await Promise.all([
      SecurityEvent.countDocuments(tenantScope({ occurredAt: { $gte: currentStart, $lte: now } })),
      SecurityEvent.countDocuments(tenantScope({ occurredAt: { $gte: previousStart, $lt: currentStart } })),
      SecurityEvent.aggregate([
        { $match: tenantScope({ occurredAt: { $gte: currentStart, $lte: now } }) },
        { $group: { _id: "$severity", count: { $sum: 1 } } },
      ]),
      SecurityEvent.find(tenantScope({}))
        .sort({ occurredAt: -1, _id: -1 })
        .limit(10)
        .select("eventId occurredAt source eventType severity outcome hostname username")
        .lean(),
      SecurityEvent.countDocuments(tenantScope({
        occurredAt: { $gte: currentStart, $lte: now },
        severity: { $in: ["high", "critical"] },
      })),
    ]);

    const bySeverity = Object.fromEntries(severities.map((severity) => [severity, 0])) as Record<typeof severities[number], number>;
    for (const row of severityRows as Array<{ _id: string; count: number }>) {
      if (severities.includes(row._id as typeof severities[number])) {
        bySeverity[row._id as typeof severities[number]] = row.count;
      }
    }

    response.status(200).json({
      data: {
        window: { start: currentStart.toISOString(), end: now.toISOString() },
        metrics: {
          eventsLast24Hours: totalEvents,
          eventsPrevious24Hours: previousEvents,
          eventVolumeChange: previousEvents === 0
            ? (totalEvents === 0 ? 0 : null)
            : Math.round(((totalEvents - previousEvents) / previousEvents) * 100),
          highSeverityLast24Hours: highSeverityEvents,
        },
        bySeverity,
        recentEvents: recentEvents.map((event) => ({
          id: String(event._id),
          eventId: event.eventId,
          occurredAt: event.occurredAt,
          source: event.source,
          eventType: event.eventType,
          severity: event.severity,
          outcome: event.outcome ?? null,
          hostname: event.hostname ?? null,
          username: event.username ?? null,
        })),
      },
      meta: { requestId: request.requestId ?? "request-id-unavailable" },
    });
  },
);

export { router as dashboardRouter };
