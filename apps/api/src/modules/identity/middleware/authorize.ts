import type { NextFunction, Request, Response } from "express";

import { hasPermission, type Permission, type SystemRole } from "../roles.js";

export interface AuthenticatedPrincipal {
  userId: string;
  tenantId: string;
  roles: SystemRole[];
}

declare global {
  namespace Express {
    interface Request {
      principal?: AuthenticatedPrincipal;
    }
  }
}

export function requirePermission(permission: Permission) {
  return (request: Request, response: Response, next: NextFunction): void => {
    const principal = request.principal;

    if (!principal) {
      response.status(401).json({
        error: { code: "UNAUTHENTICATED", message: "Authentication is required." },
      });
      return;
    }

    const allowed = principal.roles.some((role) => hasPermission(role, permission));
    if (!allowed) {
      response.status(403).json({
        error: { code: "FORBIDDEN", message: "You do not have permission to perform this action." },
      });
      return;
    }

    next();
  };
}
