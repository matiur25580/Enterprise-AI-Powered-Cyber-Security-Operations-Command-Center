import type { Response } from "express";

import { env } from "../../config/env.js";
import { Session } from "./models/Session.js";

export const refreshCookieName = "soc_refresh";
export const refreshLifetimeMs = 7 * 24 * 60 * 60 * 1000;
export const refreshCookiePath = "/api/v1/auth";

export function getRefreshCookieOptions() {
  return {
    httpOnly: true,
    secure: env.NODE_ENV === "production",
    sameSite: "strict" as const,
    path: refreshCookiePath,
    maxAge: refreshLifetimeMs,
  };
}

export function clearRefreshCookie(response: Response): void {
  response.clearCookie(refreshCookieName, {
    ...getRefreshCookieOptions(),
    maxAge: undefined,
  });
}

export function isSessionUsable(
  session: { revokedAt?: Date | null; expiresAt: Date | string },
  now = new Date(),
): boolean {
  const expiration = new Date(session.expiresAt).getTime();
  const current = now.getTime();

  if (session.revokedAt) {
    return false;
  }

  return expiration > current;
}

export async function revokeSessionFamily(
  tokenFamilyId: string,
  now = new Date(),
): Promise<void> {
  await Session.updateMany(
    { tokenFamilyId, revokedAt: null },
    { $set: { revokedAt: now, lastUsedAt: now } },
  );
}

export async function revokeUserSessions(
  userId: string,
  tenantId: string,
  now = new Date(),
): Promise<void> {
  await Session.updateMany(
    { userId, tenantId, revokedAt: null },
    { $set: { revokedAt: now, lastUsedAt: now } },
  );
}

export async function listActiveSessionsForPrincipal(
  userId: string,
  tenantId: string,
): Promise<Array<{
  id: string;
  tokenFamilyId: string;
  createdAt: Date | null;
  expiresAt: Date;
  lastUsedAt?: Date | null;
  revokedAt?: Date | null;
  rotatedFrom?: string | null;
}>> {
  const sessions = await Session.find({
    userId,
    tenantId,
    revokedAt: null,
  })
    .sort({ lastUsedAt: -1, createdAt: -1 })
    .lean();

  return sessions.map((session) => ({
    id: session._id.toString(),
    tokenFamilyId: session.tokenFamilyId,
    createdAt: session.createdAt ?? null,
    expiresAt: session.expiresAt,
    lastUsedAt: session.lastUsedAt ?? null,
    revokedAt: session.revokedAt ?? null,
    rotatedFrom: session.rotatedFrom ? session.rotatedFrom.toString() : null,
  }));
}
