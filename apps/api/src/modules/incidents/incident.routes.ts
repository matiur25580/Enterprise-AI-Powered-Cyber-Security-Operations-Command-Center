import { Router } from "express";
import { Types } from "mongoose";
import { z } from "zod";

import { AuditService } from "../audit/audit-service.js";
import { authenticate } from "../identity/middleware/authenticate.js";
import { requirePermission, requireTenantContext, requireTenantMembership } from "../identity/middleware/authorize.js";
import { withTenantScope } from "../identity/tenant-scope.js";
import { Membership } from "../identity/models/Membership.js";
import { Incident } from "./models/Incident.js";
import { canTransitionIncident } from "./incident-workflow.js";

const router: import("express").Router = Router();
const idSchema = z.string().regex(/^[a-f\d]{24}$/i);
const createSchema = z.object({
  title: z.string().trim().min(4).max(180),
  description: z.string().trim().min(8).max(4000),
  severity: z.enum(["low", "medium", "high", "critical"]),
}).strict();
const statusSchema = z.object({ status: z.enum(["open", "acknowledged", "investigating", "contained", "resolved", "reopened"]), detail: z.string().trim().max(500).optional() }).strict();
const assignSchema = z.object({ assigneeUserId: z.string().regex(/^[a-f\d]{24}$/i).nullable() }).strict();
const noteSchema = z.object({ body: z.string().trim().min(1).max(4000) }).strict();

function requestId(request: import("express").Request): string {
  return request.requestId ?? "request-id-unavailable";
}

router.get("/", authenticate, requireTenantContext(), requireTenantMembership(), requirePermission("incidents:read"), async (request, response) => {
  const limit = z.coerce.number().int().min(1).max(100).safeParse(request.query.limit ?? 50);
  if (!limit.success) {
    response.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Invalid incident limit." } });
    return;
  }
  const filter: Record<string, unknown> = {};
  if (typeof request.query.status === "string") filter.status = request.query.status;
  if (typeof request.query.severity === "string") filter.severity = request.query.severity;
  const incidents = await Incident.find(withTenantScope(request.principal!.tenantId, filter, "organizationId"))
    .sort({ updatedAt: -1, _id: -1 }).limit(limit.data).lean();
  response.status(200).json({
    data: incidents.map((incident) => ({
      id: String(incident._id), title: incident.title, description: incident.description,
      severity: incident.severity, status: incident.status, createdBy: String(incident.createdBy),
      assigneeUserId: incident.assigneeUserId ? String(incident.assigneeUserId) : null,
      notes: incident.notes, timeline: incident.timeline, createdAt: incident.createdAt, updatedAt: incident.updatedAt,
    })),
    meta: { requestId: requestId(request) },
  });
});

router.post("/", authenticate, requireTenantContext(), requireTenantMembership(), requirePermission("incidents:create"), async (request, response) => {
  const parsed = createSchema.safeParse(request.body);
  if (!parsed.success) {
    response.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Invalid incident payload.", requestId: requestId(request) } });
    return;
  }
  const incident = await Incident.create({
    organizationId: new Types.ObjectId(request.principal!.tenantId),
    ...parsed.data,
    createdBy: new Types.ObjectId(request.principal!.userId),
    timeline: [{ actorUserId: new Types.ObjectId(request.principal!.userId), action: "incident.created", toStatus: "open" }],
  });
  await AuditService.append({
    organizationId: request.principal!.tenantId, actorUserId: request.principal!.userId,
    actorRole: request.principal!.roles[0], action: "incident.created", resourceType: "incident",
    resourceId: incident.id, requestId: requestId(request), outcome: "success", severity: parsed.data.severity,
    metadata: { incidentSeverity: parsed.data.severity },
  });
  response.status(201).json({ data: { id: incident.id, title: incident.title, severity: incident.severity, status: incident.status }, meta: { requestId: requestId(request) } });
});

router.patch("/:id/status", authenticate, requireTenantContext(), requireTenantMembership(), requirePermission("incidents:investigate"), async (request, response) => {
  const id = idSchema.safeParse(request.params.id);
  const parsed = statusSchema.safeParse(request.body);
  if (!id.success || !parsed.success) {
    response.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Invalid incident status update.", requestId: requestId(request) } });
    return;
  }
  const filter = withTenantScope(request.principal!.tenantId, { _id: new Types.ObjectId(id.data) }, "organizationId");
  const incident = await Incident.findOne(filter);
  if (!incident) {
    response.status(404).json({ error: { code: "INCIDENT_NOT_FOUND", message: "Incident was not found.", requestId: requestId(request) } });
    return;
  }
  if (!canTransitionIncident(incident.status as import("@soc/contracts").IncidentStatus, parsed.data.status)) {
    response.status(409).json({ error: { code: "INVALID_STATUS_TRANSITION", message: "The requested incident status transition is not allowed.", requestId: requestId(request) } });
    return;
  }
  const previousStatus = incident.status;
  incident.status = parsed.data.status;
  if (parsed.data.status === "resolved") incident.resolvedAt = new Date();
  if (parsed.data.status === "reopened") incident.resolvedAt = null;
  incident.timeline.push({
    actorUserId: new Types.ObjectId(request.principal!.userId),
    action: "incident.status_changed",
    fromStatus: previousStatus,
    toStatus: parsed.data.status,
    detail: parsed.data.detail,
    createdAt: new Date(),
  });
  await incident.save();
  await AuditService.append({
    organizationId: request.principal!.tenantId, actorUserId: request.principal!.userId,
    actorRole: request.principal!.roles[0], action: "incident.status_changed", resourceType: "incident",
    resourceId: incident.id, requestId: requestId(request), outcome: "success", severity: "medium",
    metadata: { fromStatus: previousStatus, toStatus: parsed.data.status },
  });
  response.status(200).json({ data: { id: incident.id, status: incident.status, resolvedAt: incident.resolvedAt ?? null }, meta: { requestId: requestId(request) } });
});

router.patch("/:id/assignee", authenticate, requireTenantContext(), requireTenantMembership(), requirePermission("incidents:assign"), async (request, response) => {
  const id = idSchema.safeParse(request.params.id);
  const parsed = assignSchema.safeParse(request.body);
  if (!id.success || !parsed.success) {
    response.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Invalid incident assignment.", requestId: requestId(request) } });
    return;
  }
  const assignee = parsed.data.assigneeUserId;
  if (assignee) {
    const active = await Membership.exists({
      tenantId: new Types.ObjectId(request.principal!.tenantId),
      userId: new Types.ObjectId(assignee),
      status: "active",
    });
    if (!active) {
      response.status(400).json({ error: { code: "INVALID_ASSIGNEE", message: "Assignee must be an active member of this organization.", requestId: requestId(request) } });
      return;
    }
  }
  const incident = await Incident.findOneAndUpdate(
    withTenantScope(request.principal!.tenantId, { _id: new Types.ObjectId(id.data) }, "organizationId"),
    { $set: { assigneeUserId: assignee ? new Types.ObjectId(assignee) : null }, $push: { timeline: {
      actorUserId: new Types.ObjectId(request.principal!.userId), action: "incident.assigned",
      detail: assignee ?? "unassigned", createdAt: new Date(),
    } } },
    { new: true },
  );
  if (!incident) {
    response.status(404).json({ error: { code: "INCIDENT_NOT_FOUND", message: "Incident was not found.", requestId: requestId(request) } });
    return;
  }
  await AuditService.append({
    organizationId: request.principal!.tenantId, actorUserId: request.principal!.userId,
    actorRole: request.principal!.roles[0], action: "incident.assigned", resourceType: "incident",
    resourceId: incident.id, requestId: requestId(request), outcome: "success", severity: "medium",
    metadata: { assigneeUserId: assignee },
  });
  response.status(200).json({ data: { id: incident.id, assigneeUserId: incident.assigneeUserId?.toString() ?? null }, meta: { requestId: requestId(request) } });
});

router.post("/:id/notes", authenticate, requireTenantContext(), requireTenantMembership(), requirePermission("incidents:investigate"), async (request, response) => {
  const id = idSchema.safeParse(request.params.id);
  const parsed = noteSchema.safeParse(request.body);
  if (!id.success || !parsed.success) {
    response.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Invalid investigation note.", requestId: requestId(request) } });
    return;
  }
  const incident = await Incident.findOneAndUpdate(
    withTenantScope(request.principal!.tenantId, { _id: new Types.ObjectId(id.data) }, "organizationId"),
    { $push: { notes: { authorUserId: new Types.ObjectId(request.principal!.userId), body: parsed.data.body, createdAt: new Date() }, timeline: {
      actorUserId: new Types.ObjectId(request.principal!.userId), action: "incident.note_added", detail: "Investigation note added", createdAt: new Date(),
    } } },
    { new: true },
  );
  if (!incident) {
    response.status(404).json({ error: { code: "INCIDENT_NOT_FOUND", message: "Incident was not found.", requestId: requestId(request) } });
    return;
  }
  await AuditService.append({
    organizationId: request.principal!.tenantId, actorUserId: request.principal!.userId,
    actorRole: request.principal!.roles[0], action: "incident.note_added", resourceType: "incident",
    resourceId: incident.id, requestId: requestId(request), outcome: "success", severity: "low",
    metadata: { noteLength: parsed.data.body.length },
  });
  response.status(201).json({ data: { id: incident.id, notesCount: incident.notes.length }, meta: { requestId: requestId(request) } });
});

export { router as incidentRouter };
