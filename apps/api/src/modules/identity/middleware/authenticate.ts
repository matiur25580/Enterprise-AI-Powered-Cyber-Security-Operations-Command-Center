import type { NextFunction, Request, Response } from "express";

import { Membership } from "../models/Membership.js";
import { verifyAccessToken } from "../token.js";
import { principalFromActiveMembership } from "../current-principal.js";

export async function authenticate(
  request: Request,
  response: Response,
  next: NextFunction,
): Promise<void> {
  const authorization = request.header("authorization");
  const [scheme, token] = authorization?.split(" ") ?? [];

  if (scheme !== "Bearer" || !token) {
    response.status(401).json({
      error: { code: "UNAUTHENTICATED", message: "A valid access token is required." },
    });
    return;
  }

  let claims;
  try {
    claims = await verifyAccessToken(token);
  } catch {
    response.status(401).json({
      error: { code: "INVALID_TOKEN", message: "The access token is invalid or expired." },
    });
    return;
  }

  const membership = await Membership.findOne({
    userId: claims.userId,
    tenantId: claims.tenantId,
    status: "active",
  }).lean();
  const principal = principalFromActiveMembership(claims, membership);

  if (!principal) {
    response.status(403).json({
      error: { code: "TENANT_ACCESS_DENIED", message: "This user no longer has an active membership in the current tenant." },
    });
    return;
  }

  request.principal = principal;
  next();
}
