import { createHash } from "node:crypto";
import { Types } from "mongoose";

import { SecurityEvent } from "./models/SecurityEvent.js";
import { normalizeSecurityEvent } from "./event-normalization.js";
import type { SecurityEventInput } from "./event-schema.js";

function isDuplicateKeyError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === 11000;
}

export class EventIngestionService {
  static async ingest(
    organizationId: string,
    input: SecurityEventInput,
    idempotencyKey?: string,
  ): Promise<{ event: Record<string, unknown>; duplicate: boolean }> {
    if (!Types.ObjectId.isValid(organizationId)) {
      throw new Error("A valid organization context is required for event ingestion.");
    }

    const organization = new Types.ObjectId(organizationId);
    const normalized = normalizeSecurityEvent(input);
    const idempotencyKeyHash = idempotencyKey
      ? createHash("sha256").update(idempotencyKey).digest("hex")
      : undefined;

    try {
      const event = await SecurityEvent.create({
        organizationId: organization,
        ...normalized,
        idempotencyKeyHash,
      });
      return { event: event.toObject() as unknown as Record<string, unknown>, duplicate: false };
    } catch (error) {
      if (!isDuplicateKeyError(error)) throw error;

      const existing = idempotencyKeyHash
        ? (await SecurityEvent.findOne({ organizationId: organization, idempotencyKeyHash }).lean())
          ?? (await SecurityEvent.findOne({ organizationId: organization, source: input.source, eventId: input.eventId }).lean())
        : await SecurityEvent.findOne({ organizationId: organization, source: input.source, eventId: input.eventId }).lean();
      if (!existing) throw error;
      return { event: existing as unknown as Record<string, unknown>, duplicate: true };
    }
  }
}
