import { Router } from "express";
import argon2 from "argon2";
import cookieParser from "cookie-parser";
import { rateLimit } from "express-rate-limit";
import { z } from "zod";

import { env } from "../../config/env.js";
import { Membership } from "./models/Membership.js";
import { Organization } from "./models/Organization.js";
import { Session } from "./models/Session.js";
import { User } from "./models/User.js";
import { createAccessToken, createRefreshToken, hashRefreshToken } from "./token.js";
import { authenticate } from "./middleware/authenticate.js";

const router = Router();

const loginSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(1).max(256),
  tenantSlug: z.string().trim().min(2).max(80).regex(/^[a-z0-9-]+$/),
}).strict();

const refreshCookieName = "soc_refresh";
const refreshLifetimeMs = 7 * 24 * 60 * 60 * 1000;

const refreshCookieOptions = {
  httpOnly: true,
  secure: env.NODE_ENV === "production",
  sameSite: "strict" as const,
  path: "/api/v1/auth",
  maxAge: refreshLifetimeMs,
};

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    error: { code: "LOGIN_RATE_LIMITED", message: "Too many login attempts. Try again later." },
  },
});

function requireTrustedOrigin(request: import("express").Request, response: import("express").Response, next: import("express").NextFunction) {
  const origin = request.header("origin");
  if (origin && origin !== env.WEB_ORIGIN) {
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
    tokenFamilyId: crypto.randomUUID(),
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
    response.clearCookie(refreshCookieName, { ...refreshCookieOptions, maxAge: undefined });
    response.status(401).json({
      error: { code: "INVALID_REFRESH", message: "The refresh session is invalid." },
    });
    return;
  }

  if (existing.revokedAt || existing.expiresAt <= new Date()) {
    await Session.updateMany(
      { tokenFamilyId: existing.tokenFamilyId, revokedAt: null },
      { $set: { revokedAt: new Date() } },
    );
    response.clearCookie(refreshCookieName, { ...refreshCookieOptions, maxAge: undefined });
    response.status(401).json({
      error: { code: "REFRESH_REUSE_DETECTED", message: "The refresh session is no longer valid. Sign in again." },
    });
    return;
  }

  const replacementToken = createRefreshToken();
  const now = new Date();
  const rotated = await Session.findOneAndUpdate(
    { _id: existing._id, refreshTokenHash: tokenHash, revokedAt: null, expiresAt: { $gt: now } },
    { $set: { revokedAt: now, lastUsedAt: now } },
    { new: false },
  );

  if (!rotated) {
    await Session.updateMany(
      { tokenFamilyId: existing.tokenFamilyId, revokedAt: null },
      { $set: { revokedAt: now } },
    );
    response.clearCookie(refreshCookieName, { ...refreshCookieOptions, maxAge: undefined });
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
    await Session.updateMany(
      { tokenFamilyId: existing.tokenFamilyId, revokedAt: null },
      { $set: { revokedAt: now } },
    );
    response.clearCookie(refreshCookieName, { ...refreshCookieOptions, maxAge: undefined });
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

  response.cookie(refreshCookieName, replacementToken, refreshCookieOptions);
  response.status(200).json({
    data: { accessToken, tokenType: "Bearer", expiresIn: 600 },
  });
});

router.post("/logout", requireTrustedOrigin, async (request, response) => {
  const refreshToken = request.cookies?.[refreshCookieName] as string | undefined;
  if (refreshToken) {
    await Session.updateOne(
      { refreshTokenHash: hashRefreshToken(refreshToken), revokedAt: null },
      { $set: { revokedAt: new Date() } },
    );
  }

  response.clearCookie(refreshCookieName, { ...refreshCookieOptions, maxAge: undefined });
  response.status(204).send();
});

router.post("/logout-all", authenticate, async (request, response) => {
  await Session.updateMany(
    { userId: request.principal!.userId, tenantId: request.principal!.tenantId, revokedAt: null },
    { $set: { revokedAt: new Date() } },
  );

  response.clearCookie(refreshCookieName, { ...refreshCookieOptions, maxAge: undefined });
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

export { router as authRouter, cookieParser };
