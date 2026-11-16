import assert from "node:assert/strict";
import test from "node:test";

import { securityEventInputSchema } from "./event-schema.js";
import { normalizeSecurityEvent } from "./event-normalization.js";

const validInput = {
  eventId: "evt-001",
  timestamp: "2026-01-01T00:00:00.000Z",
  source: "endpoint-agent",
  sourceType: "endpoint",
  sourceIp: "192.0.2.10",
  destinationIp: "198.51.100.20",
  username: "analyst",
  hostname: "workstation-01",
  eventType: "authentication",
  category: "identity",
  severity: "high",
  action: "login",
  outcome: "failure",
  rawEvent: { message: "login rejected", password: "do-not-store" },
  normalizedData: { result: "denied", accessToken: "do-not-store" },
  tags: ["identity", "identity"],
};

test("event schema rejects tenant overrides and malformed event fields", () => {
  assert.equal(securityEventInputSchema.safeParse(validInput).success, true);
  assert.equal(securityEventInputSchema.safeParse({ ...validInput, organizationId: "tenant-b" }).success, false);
  assert.equal(securityEventInputSchema.safeParse({ ...validInput, severity: "urgent" }).success, false);
  assert.equal(securityEventInputSchema.safeParse({ ...validInput, sourceIp: "not-an-ip" }).success, false);
});

test("event normalization redacts auth material and deduplicates tags", () => {
  const parsed = securityEventInputSchema.parse(validInput);
  const normalized = normalizeSecurityEvent(parsed);

  assert.equal(normalized.rawEvent.password, "[REDACTED]");
  assert.equal(normalized.normalizedData.accessToken, "[REDACTED]");
  assert.deepEqual(normalized.tags, ["identity"]);
  assert.equal(normalized.processingStatus, "pending");
  assert.equal(normalized.occurredAt.toISOString(), validInput.timestamp);
});

test("event normalization rejects oversized or structurally unsafe raw content", () => {
  const tooLarge = securityEventInputSchema.parse({
    ...validInput,
    rawEvent: { message: "x".repeat(129 * 1024) },
  });
  assert.throws(() => normalizeSecurityEvent(tooLarge), /maximum allowed size/);

  const prohibited = securityEventInputSchema.parse({
    ...validInput,
    rawEvent: JSON.parse('{"constructor":{"prototype":{"unsafe":true}}}'),
  });
  assert.throws(() => normalizeSecurityEvent(prohibited), /prohibited field/);
});
