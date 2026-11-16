import { assertJsonSize, sanitizeSensitiveData } from "../security-data.js";
import type { SecurityEventInput } from "./event-schema.js";

export function normalizeSecurityEvent(input: SecurityEventInput) {
  const rawEvent = sanitizeSensitiveData(input.rawEvent) as Record<string, unknown>;
  const normalizedData = sanitizeSensitiveData(input.normalizedData) as Record<string, unknown>;
  assertJsonSize({ rawEvent, normalizedData }, 128 * 1024);

  return {
    eventId: input.eventId,
    occurredAt: new Date(input.timestamp),
    source: input.source,
    sourceType: input.sourceType,
    sourceIp: input.sourceIp,
    destinationIp: input.destinationIp,
    username: input.username,
    hostname: input.hostname,
    eventType: input.eventType,
    category: input.category,
    severity: input.severity,
    action: input.action,
    outcome: input.outcome,
    rawEvent,
    normalizedData,
    tags: [...new Set(input.tags)],
    processingStatus: "pending" as const,
  };
}
