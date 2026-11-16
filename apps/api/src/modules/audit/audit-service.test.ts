import assert from "node:assert/strict";
import test from "node:test";
import { Types } from "mongoose";

import {
  calculateAuditEntryHash,
  verifyAuditEntries,
  type AuditHashEntry,
} from "./audit-service.js";
import { sanitizeSensitiveData } from "../security-data.js";

function createEntry(
  chainIndex: number,
  previousHash: string | null,
  changes: Partial<AuditHashEntry> = {},
): AuditHashEntry {
  return {
    organizationId: new Types.ObjectId().toHexString(),
    actorUserId: new Types.ObjectId().toHexString(),
    actorRole: "soc_manager",
    action: "auth.login",
    resourceType: "session",
    resourceId: "session-1",
    timestamp: new Date("2026-01-01T00:00:00.000Z"),
    sourceIp: "192.0.2.1",
    userAgent: "test-agent",
    requestId: "request-1",
    outcome: "success",
    severity: "info",
    metadata: { safe: true },
    previousHash,
    chainIndex,
    ...changes,
  };
}

test("audit hashes verify ordered entries and detect metadata tampering", () => {
  const first = createEntry(1, null);
  const firstHash = calculateAuditEntryHash(first);
  const second = createEntry(2, firstHash, { requestId: "request-2" });
  const records = [
    { ...first, entryHash: firstHash },
    { ...second, entryHash: calculateAuditEntryHash(second) },
  ];

  assert.deepEqual(verifyAuditEntries(records), { valid: true, checkedEntries: 2 });
  assert.deepEqual(
    verifyAuditEntries([{ ...records[0]!, metadata: { safe: false } }, records[1]!]),
    { valid: false, checkedEntries: 0, failedAt: 1 },
  );
});

test("audit hashing includes chain sequence and previous hash", () => {
  const entry = createEntry(1, null);
  assert.notEqual(calculateAuditEntryHash(entry), calculateAuditEntryHash({ ...entry, chainIndex: 2 }));
  assert.notEqual(calculateAuditEntryHash(entry), calculateAuditEntryHash({ ...entry, previousHash: "a".repeat(64) }));
});

test("sensitive values are redacted recursively before persistence or response", () => {
  assert.deepEqual(
    sanitizeSensitiveData({
      message: "login",
      password: "must-not-appear",
      sessionId: "session-secret",
      csrfToken: "csrf-secret",
      nested: { refreshToken: "also-secret", status: "failed" },
    }),
    {
      message: "login",
      password: "[REDACTED]",
      sessionId: "[REDACTED]",
      csrfToken: "[REDACTED]",
      nested: { refreshToken: "[REDACTED]", status: "failed" },
    },
  );
  const embeddedSecret = sanitizeSensitiveData({
    message: "Authorization: Bearer abc.def.token token=second-secret",
  }) as { message: string };
  assert.equal(embeddedSecret.message.includes("abc.def.token"), false);
  assert.equal(embeddedSecret.message.includes("second-secret"), false);
  assert.throws(() => sanitizeSensitiveData(JSON.parse('{"__proto__":{"polluted":true}}')), /prohibited field/);
});
