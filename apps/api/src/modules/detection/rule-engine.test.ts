import assert from "node:assert/strict";
import test from "node:test";

import { evaluateSecurityEvent } from "./rule-engine.js";

const baseEvent = {
  eventId: "detection-test",
  timestamp: "2026-01-01T00:00:00.000Z",
  source: "test-agent",
  sourceType: "endpoint",
  eventType: "authentication",
  category: "identity",
  severity: "medium" as const,
  outcome: "failure",
  rawEvent: {},
  normalizedData: {},
  tags: [],
};

test("low-signal event produces bounded explainable risk", () => {
  const result = evaluateSecurityEvent(baseEvent);
  assert.equal(result.score, 12);
  assert.equal(result.severity, "low");
  assert.equal(result.reasons.length, 1);
  assert.ok(result.confidence > 0 && result.confidence <= 1);
});

test("repeated failed authentication attempts increase risk", () => {
  const result = evaluateSecurityEvent(baseEvent, { failedAttemptsInWindow: 6 });
  assert.equal(result.score, 57);
  assert.equal(result.severity, "medium");
  assert.ok(result.reasons.some((reason) => reason.ruleKey === "identity.repeated-authentication-failures"));
});

test("malware and critical event signals saturate at 100", () => {
  const result = evaluateSecurityEvent({
    ...baseEvent,
    eventType: "malware.detected",
    severity: "critical",
  });
  assert.equal(result.score, 90);
  assert.equal(result.severity, "critical");
  assert.ok(result.reasons.some((reason) => reason.ruleKey === "endpoint.malware-detected"));
});

test("network activity contributes an explicit rule reason", () => {
  const result = evaluateSecurityEvent({
    ...baseEvent,
    eventType: "network.connection.suspicious",
    category: "network",
  });
  assert.equal(result.score, 32);
  assert.equal(result.severity, "medium");
  assert.equal(result.reasons.filter((reason) => reason.ruleKey === "network.suspicious-activity").length, 1);
});
