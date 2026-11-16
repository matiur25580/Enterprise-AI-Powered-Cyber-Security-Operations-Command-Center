import { randomUUID } from "node:crypto";
import { Router } from "express";
import argon2 from "argon2";
import { rateLimit } from "express-rate-limit";
import { z } from "zod";

import { env } from "../../config/env.js";
import { AuditService } from "../audit/audit-service.js";
import { Membership } from "./models/Membership.js";
import { Organization } from "./models/Organization.js";
import { Session } from "./models/Session.js";
import { User } from "./models/User.js";
import { createAccessToken, createRefreshToken, hashRefreshToken } from "./token.js";
import { authenticate } from "./middleware/authenticate.js";
import {
  clearRefreshCookie,
  getRefreshCookieOptions,
  listActiveSessionsForPrincipal,
  refreshCookieName,
  refreshLifetimeMs,
  revokeSessionFamily,
  revokeUserSessions,
  isSessionUsable,
} from "./session-security.js";

const router: import("express").Router = Router();

const loginSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(1).max(256),
  tenantSlug: z.string().trim().min(2).max(80).regex(/^[a-z0-9-]+$/),
}).strict();

const refreshCookieOptions = getRefreshCookieOptions();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    error: { code: "LOGIN_RATE_LIMITED", message: "Too many login attempts. Try again later." },
  },
});

function auditRequestFields(request: import("express").Request) {
  return {
    requestId: request.requestId ?? randomUUID(),
    sourceIp: request.ip,
    userAgent: request.get("user-agent")?.slice(0, 500),
  };
}

async function auditLoginFailure(
  request: import("express").Request,
  organizationId: string,
  actorUserId: string | undefined,
  reason: string,
): Promise<void> {
  await AuditService.append({
    organizationId,
    actorUserId,
    action: "auth.login",
    resourceType: "session",
    ...auditRequestFields(request),
    outcome: "failure",
    severity: "medium",
    metadata: { reason },
  });
}

function requireTrustedOrigin(request: import("express").Request, response: import("express").Response, next: import("express").NextFunction) {
  const origin = request.header("origin");
  if (origin !== env.WEB_ORIGIN) {
    response.status(403).json({
      error: { code: "UNTRUSTED_ORIGIN", message: "Request origin is not allowed." },
    });
    return;
  }
  next();
}

router.post("/login", loginLimiter, async (request, response) => {
  const parsed = loginSchema.safeParse(request.body);
  if (!parsed.success) {
    response.status(400).json({
      error: { code: "VALIDATION_ERROR", message: "Invalid login request." },
    });
    return;
  }

  const emailNormalized = parsed.data.email.toLowerCase();
  const organization = await Organization.findOne({
    slug: parsed.data.tenantSlug,
    status: "active",
  }).lean();

  if (!organization) {
    response.status(401).json({
      error: { code: "INVALID_CREDENTIALS", message: "Email, password or organization is incorrect." },
    });
    return;
  }

  const user = await User.findOne({
    emailNormalized,
    status: "active",
  }).select("+passwordHash");

  if (!user || !(await argon2.verify(user.passwordHash, parsed.data.password))) {
    await auditLoginFailure(request, organization._id.toString(), user?._id.toString(), "invalid_credentials");
    response.status(401).json({
      error: { code: "INVALID_CREDENTIALS", message: "Email, password or organization is incorrect." },
    });
    return;
  }

  const membership = await Membership.findOne({
    tenantId: organization._id,
    userId: user._id,
    status: "active",
  }).lean();

  if (!membership || membership.roles.length === 0) {
    await auditLoginFailure(request, organization._id.toString(), user.id, "membership_unavailable");
    response.status(401).json({
      error: { code: "INVALID_CREDENTIALS", message: "Email, password or organization is incorrect." },
    });
    return;
  }

  const refreshToken = createRefreshToken();
  const expiresAt = new Date(Date.now() + refreshLifetimeMs);
  const session = await Session.create({
    userId: user._id,
    tenantId: organization._id,
    refreshTokenHash: hashRefreshToken(refreshToken),
    tokenFamilyId: randomUUID(),
    expiresAt,
    lastUsedAt: new Date(),
  });

  user.lastLoginAt = new Date();
  await user.save();

  const accessToken = await createAccessToken({
    userId: user.id,
    tenantId: organization._id.toString(),
    roles: membership.roles as import("./roles.js").SystemRole[],
  });

  await AuditService.append({
    organizationId: organization._id.toString(),
    actorUserId: user.id,
    actorRole: membership.roles[0],
    action: "auth.login",
    resourceType: "session",
    resourceId: session.id,
    ...auditRequestFields(request),
    outcome: "success",
    severity: "info",
    metadata: { sessionId: session.id },
  });

  response.cookie(refreshCookieName, refreshToken, refreshCookieOptions);
  response.status(200).json({
    data: {
      accessToken,
      tokenType: "Bearer",
      expiresIn: 600,
      sessionId: session.id,
      user: {
        id: user.id,
        email: user.emailNormalized,
        displayName: user.displayName,
      },
      organization: {
        id: organization._id.toString(),
        name: organization.name,
        slug: organization.slug,
      },
      roles: membership.roles,
    },
  });
});

router.post("/refresh", requireTrustedOrigin, async (request, response) => {
  const currentToken = request.cookies?.[refreshCookieName] as string | undefined;
  if (!currentToken) {
    response.status(401).json({
      error: { code: "REFRESH_REQUIRED", message: "A refresh session is required." },
    });
    return;
  }

  const tokenHash = hashRefreshToken(currentToken);
  const existing = await Session.findOne({ refreshTokenHash: tokenHash }).select("+refreshTokenHash");

  if (!existing) {
    clearRefreshCookie(response);
    response.status(401).json({
      error: { code: "INVALID_REFRESH", message: "The refresh session is invalid." },
    });
    return;
  }

  const now = new Date();
  if (!isSessionUsable(existing, now)) {
    await revokeSessionFamily(existing.tokenFamilyId, now);
    await AuditService.append({
      organizationId: existing.tenantId.toString(),
      actorUserId: existing.userId.toString(),
      action: "auth.refresh.replay_detected",
      resourceType: "session",
      resourceId: existing.id,
      ...auditRequestFields(request),
      outcome: "failure",
      severity: "high",
      metadata: { reason: "session_not_usable" },
    });
    clearRefreshCookie(response);
    response.status(401).json({
      error: { code: "REFRESH_REUSE_DETECTED", message: "The refresh session is no longer valid. Sign in again." },
    });
    return;
  }

  const replacementToken = createRefreshToken();
  const rotated = await Session.findOneAndUpdate(
    { _id: existing._id, refreshTokenHash: tokenHash, revokedAt: null, expiresAt: { $gt: now } },
    { $set: { revokedAt: now, lastUsedAt: now } },
    { new: false },
  );

  if (!rotated) {
    await revokeSessionFamily(existing.tokenFamilyId, now);
    await AuditService.append({
      organizationId: existing.tenantId.toString(),
      actorUserId: existing.userId.toString(),
      action: "auth.refresh.replay_detected",
      resourceType: "session",
      resourceId: existing.id,
      ...auditRequestFields(request),
      outcome: "failure",
      severity: "high",
      metadata: { reason: "concurrent_rotation" },
    });
    clearRefreshCookie(response);
    response.status(401).json({
      error: { code: "REFRESH_REUSE_DETECTED", message: "The refresh session could not be rotated. Sign in again." },
    });
    return;
  }

  const membership = await Membership.findOne({
    tenantId: existing.tenantId,
    userId: existing.userId,
    status: "active",
  }).lean();
  const user = await User.findOne({ _id: existing.userId, status: "active" }).lean();

  if (!membership || !user || membership.roles.length === 0) {
    await revokeSessionFamily(existing.tokenFamilyId, now);
    await AuditService.append({
      organizationId: existing.tenantId.toString(),
      actorUserId: existing.userId.toString(),
      action: "auth.refresh.denied",
      resourceType: "session",
      resourceId: existing.id,
      ...auditRequestFields(request),
      outcome: "failure",
      severity: "medium",
      metadata: { reason: "membership_unavailable" },
    });
    clearRefreshCookie(response);
    response.status(401).json({
      error: { code: "SESSION_ACCESS_REVOKED", message: "This account no longer has access." },
    });
    return;
  }

  await Session.create({
    userId: existing.userId,
    tenantId: existing.tenantId,
    refreshTokenHash: hashRefreshToken(replacementToken),
    tokenFamilyId: existing.tokenFamilyId,
    rotatedFrom: existing._id,
    expiresAt: new Date(Date.now() + refreshLifetimeMs),
    lastUsedAt: now,
  });

  const accessToken = await createAccessToken({
    userId: user._id.toString(),
    tenantId: existing.tenantId.toString(),
    roles: membership.roles as import("./roles.js").SystemRole[],
  });

  await AuditService.append({
    organizationId: existing.tenantId.toString(),
    actorUserId: existing.userId.toString(),
    actorRole: membership.roles[0],
    action: "auth.refresh.rotate",
    resourceType: "session",
    resourceId: existing.id,
    ...auditRequestFields(request),
    outcome: "success",
    severity: "info",
  });

  response.cookie(refreshCookieName, replacementToken, refreshCookieOptions);
  response.status(200).json({
    data: { accessToken, tokenType: "Bearer", expiresIn: 600 },
  });
});

router.post("/logout", requireTrustedOrigin, async (request, response) => {
  const refreshToken = request.cookies?.[refreshCookieName] as string | undefined;
  if (refreshToken) {
    const session = await Session.findOne({ refreshTokenHash: hashRefreshToken(refreshToken) });
    await Session.updateOne(
      { refreshTokenHash: hashRefreshToken(refreshToken), revokedAt: null },
      { $set: { revokedAt: new Date() } },
    );
    if (session) {
      const membership = await Membership.findOne({
        tenantId: session.tenantId,
        userId: session.userId,
        status: "active",
      }).lean();
      await AuditService.append({
        organizationId: session.tenantId.toString(),
        actorUserId: session.userId.toString(),
        actorRole: membership?.roles[0],
        action: "auth.logout",
        resourceType: "session",
        resourceId: session.id,
        ...auditRequestFields(request),
        outcome: "success",
        severity: "info",
      });
    }
  }

  clearRefreshCookie(response);
  response.status(204).send();
});

router.get("/sessions", authenticate, async (request, response) => {
  const sessions = await listActiveSessionsForPrincipal(
    request.principal!.userId,
    request.principal!.tenantId,
  );

  response.status(200).json({
    data: sessions,
  });
});

router.delete("/sessions/:sessionId", authenticate, async (request, response) => {
  const { sessionId } = request.params;
  const principal = request.principal!;
  const target = await Session.findOne({ _id: sessionId, userId: principal.userId, tenantId: principal.tenantId })
    .select("+refreshTokenHash");

  if (!target) {
    response.status(404).json({
      error: { code: "SESSION_NOT_FOUND", message: "The session was not found." },
    });
    return;
  }

  if (target.revokedAt) {
    response.status(204).send();
    return;
  }

  const currentToken = request.cookies?.[refreshCookieName] as string | undefined;
  if (currentToken && hashRefreshToken(currentToken) === target.refreshTokenHash) {
    clearRefreshCookie(response);
  }

  await Session.updateOne({ _id: sessionId, revokedAt: null }, { $set: { revokedAt: new Date() } });
  await AuditService.append({
    organizationId: principal.tenantId,
    actorUserId: principal.userId,
    actorRole: principal.roles[0],
    action: "session.revoke",
    resourceType: "session",
    resourceId: target.id,
    ...auditRequestFields(request),
    outcome: "success",
    severity: "medium",
  });
  response.status(204).send();
});

router.post("/logout-all", authenticate, async (request, response) => {
  await revokeUserSessions(request.principal!.userId, request.principal!.tenantId, new Date());

  await AuditService.append({
    organizationId: request.principal!.tenantId,
    actorUserId: request.principal!.userId,
    actorRole: request.principal!.roles[0],
    action: "auth.logout_all",
    resourceType: "session_family",
    ...auditRequestFields(request),
    outcome: "success",
    severity: "medium",
  });

  clearRefreshCookie(response);
  response.status(204).send();
});

router.get("/me", authenticate, async (request, response) => {
  const principal = request.principal!;
  const user = await User.findOne({ _id: principal.userId, status: "active" }).lean();

  if (!user) {
    response.status(401).json({
      error: { code: "ACCOUNT_UNAVAILABLE", message: "The account is not available." },
    });
    return;
  }

  response.status(200).json({
    data: {
      user: { id: user._id.toString(), email: user.emailNormalized, displayName: user.displayName },
      tenantId: principal.tenantId,
      roles: principal.roles,
    },
  });
});

export { router as authRouter };
