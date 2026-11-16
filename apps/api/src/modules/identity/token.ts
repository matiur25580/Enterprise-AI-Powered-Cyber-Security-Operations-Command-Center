import { createHash, randomBytes } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";

import { env } from "../../config/env.js";
import type { SystemRole } from "./roles.js";

const ISSUER = "enterprise-soc-command-center";
const AUDIENCE = "soc-web";

function secretBytes(value: string | undefined, name: string): Uint8Array {
  if (!value || value.length < 32) {
    throw new Error(`${name} must be configured with at least 32 characters.`);
  }
  return new TextEncoder().encode(value);
}

export interface AccessClaims {
  userId: string;
  tenantId: string;
  roles: SystemRole[];
}

export async function createAccessToken(claims: AccessClaims): Promise<string> {
  return new SignJWT({
    tenantId: claims.tenantId,
    roles: claims.roles,
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setSubject(claims.userId)
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("10m")
    .sign(secretBytes(env.JWT_ACCESS_SECRET, "JWT_ACCESS_SECRET"));
}

export async function verifyAccessToken(token: string): Promise<AccessClaims> {
  const { payload } = await jwtVerify(
    token,
    secretBytes(env.JWT_ACCESS_SECRET, "JWT_ACCESS_SECRET"),
    { issuer: ISSUER, audience: AUDIENCE, algorithms: ["HS256"] },
  );

  if (
    typeof payload.sub !== "string" ||
    typeof payload.tenantId !== "string" ||
    !Array.isArray(payload.roles) ||
    !payload.roles.every((role) =>
      ["super_admin", "soc_manager", "soc_analyst_l1", "soc_analyst_l2", "auditor", "viewer"].includes(String(role))
    )
  ) {
    throw new Error("Invalid access token claims.");
  }

  return {
    userId: payload.sub,
    tenantId: payload.tenantId,
    roles: payload.roles as SystemRole[],
  };
}

export function createRefreshToken(): string {
  return randomBytes(48).toString("base64url");
}

export function hashRefreshToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}
