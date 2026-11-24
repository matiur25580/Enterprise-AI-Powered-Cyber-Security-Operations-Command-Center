import type { NextFunction, Request, Response } from "express";
import { Types } from "mongoose";

import { AuditService } from "../../audit/audit-service.js";
import { Membership } from "../models/Membership.js";
import { hasPermission, type Permission, type SystemRole } from "../roles.js";
import { rejectTenantOverride } from "../tenant-scope.js";

export interface AuthenticatedPrincipal {
  userId: string;
  tenantId: string;
  roles: SystemRole[];
}

declare global {
  namespace Express {
    interface Request {
      principal?: AuthenticatedPrincipal;
      membership?: { tenantId: string; userId: string; roles: SystemRole[]; status: "active" | "suspended" };
    }
  }
}

export async function validateActiveMembership(principal: AuthenticatedPrincipal): Promise<void> {
  if (!Types.ObjectId.isValid(principal.userId) || !Types.ObjectId.isValid(principal.tenantId)) {
    throw new Error("INVALID_TENANT_CONTEXT");
  }

  const membership = await Membership.findOne({
    userId: new Types.ObjectId(principal.userId),
    tenantId: new Types.ObjectId(principal.tenantId),
    status: "active",
  }).lean();

  if (!membership) {
    throw new Error("TENANT_ACCESS_DENIED");
  }
}

// Reject client-supplied tenant identifiers that differ from the tenant established by authentication.
export function requireTenantContext() {
  return (request: Request, response: Response, next: NextFunction): void => {
    const principal = request.principal;
    if (!principal) {
      response.status(401).json({
        error: { code: "UNAUTHENTICATED", message: "Authentication is required." },
      });
      return;
    }

    try {
      rejectTenantOverride(principal.tenantId, request.params?.tenantId, "params.tenantId");
      rejectTenantOverride(principal.tenantId, request.query?.tenantId, "query.tenantId");
      rejectTenantOverride(principal.tenantId, request.body?.tenantId, "body.tenantId");
      rejectTenantOverride(principal.tenantId, request.params?.organizationId, "params.organizationId");
      rejectTenantOverride(principal.tenantId, request.query?.organizationId, "query.organizationId");
      rejectTenantOverride(principal.tenantId, request.body?.organizationId, "body.organizationId");
      next();
    } catch {
      response.status(403).json({
        error: { code: "TENANT_CONTEXT_MISMATCH", message: "The requested tenant does not match the authenticated context." },
      });
    }
  };
}

export function requireTenantMembership() {
  return async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    const principal = request.principal;
    if (!principal) {
      response.status(401).json({
        error: { code: "UNAUTHENTICATED", message: "Authentication is required." },
      });
      return;
    }

    try {
      await validateActiveMembership(principal);
      next();
    } catch {
      response.status(403).json({
        error: { code: "TENANT_ACCESS_DENIED", message: "This user is not authorized for the current tenant." },
      });
    }
  };
}

export function requirePermission(permission: Permission) {
  return async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    const principal = request.principal;

    if (!principal) {
      response.status(401).json({
        error: { code: "UNAUTHENTICATED", message: "Authentication is required." },
      });
      return;
    }

    const allowed = principal.roles.some((role) => hasPermission(role, permission));
    if (!allowed) {
      await AuditService.append({
        organizationId: principal.tenantId,
        actorUserId: principal.userId,
        actorRole: principal.roles[0],
        action: "authorization.permission_denied",
        resourceType: "api_route",
        resourceId: request.route?.path?.toString().slice(0, 160),
        requestId: request.requestId ?? "request-id-unavailable",
        sourceIp: request.ip,
        userAgent: request.get("user-agent")?.slice(0, 500),
        outcome: "denied",
        severity: "medium",
        metadata: { permission, method: request.method },
      });
      response.status(403).json({
        error: { code: "FORBIDDEN", message: "You do not have permission to perform this action." },
      });
      return;
    }

    next();
  };
}
