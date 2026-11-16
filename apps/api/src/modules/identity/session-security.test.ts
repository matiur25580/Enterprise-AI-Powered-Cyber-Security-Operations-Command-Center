import assert from "node:assert/strict";
import test from "node:test";

import { getRefreshCookieOptions, isSessionUsable } from "./session-security.js";

test("active sessions remain usable until expiration", () => {
  const now = new Date("2026-01-01T00:00:00.000Z");
  const session = {
    revokedAt: null,
    expiresAt: new Date("2026-01-01T01:00:00.000Z"),
  };

  assert.equal(isSessionUsable(session, now), true);
});

test("revoked and expired sessions are rejected", () => {
  const now = new Date("2026-01-01T00:00:00.000Z");

  assert.equal(
    isSessionUsable({ revokedAt: new Date("2025-12-31T23:59:00.000Z"), expiresAt: new Date("2026-01-01T01:00:00.000Z") }, now),
    false,
  );

  assert.equal(
    isSessionUsable({ revokedAt: null, expiresAt: new Date("2025-12-31T23:59:00.000Z") }, now),
    false,
  );
});

test("cookie policy enforces the expected session security defaults", () => {
  const options = getRefreshCookieOptions();

  assert.equal(options.httpOnly, true);
  assert.equal(options.sameSite, "strict");
  assert.equal(options.path, "/api/v1/auth");
  assert.equal(options.maxAge, 7 * 24 * 60 * 60 * 1000);
});
