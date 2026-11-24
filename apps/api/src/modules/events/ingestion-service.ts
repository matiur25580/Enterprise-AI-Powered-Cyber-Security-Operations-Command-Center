import { createHash } from "node:crypto";
import { Types } from "mongoose";

import { SecurityEvent } from "./models/SecurityEvent.js";
import { normalizeSecurityEvent } from "./event-normalization.js";
import type { SecurityEventInput } from "./event-schema.js";
import { hashEventPayload } from "./event-idempotency.js";

function isDuplicateKeyError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === 11000;
}

// Idempotent ingestion distinguishes safe retries from reuse of the same key with different event data.
export class EventIngestionService {
  static async ingest(
    organizationId: string,
    input: SecurityEventInput,
    idempotencyKey?: string,
  ): Promise<{ event: Record<string, unknown>; duplicate: boolean; conflict: boolean }> {
    if (!Types.ObjectId.isValid(organizationId)) {
      throw new Error("A valid organization context is required for event ingestion.");
    }

    const organization = new Types.ObjectId(organizationId);
    const normalized = normalizeSecurityEvent(input);
    const idempotencyPayloadHash = hashEventPayload(normalized);
    const idempotencyKeyHash = idempotencyKey
      ? createHash("sha256").update(idempotencyKey).digest("hex")
      : undefined;

    try {
      const event = await SecurityEvent.create({
        organizationId: organization,
        ...normalized,
        idempotencyKeyHash,
        idempotencyPayloadHash,
      });
      return { event: event.toObject() as unknown as Record<string, unknown>, duplicate: false, conflict: false };
    } catch (error) {
      if (!isDuplicateKeyError(error)) throw error;

      const existingByKey = idempotencyKeyHash
        ? await SecurityEvent.findOne({ organizationId: organization, idempotencyKeyHash }).lean()
        : null;
      if (existingByKey) {
        const matchesPayload = existingByKey.idempotencyPayloadHash === idempotencyPayloadHash;
        return {
          event: existingByKey as unknown as Record<string, unknown>,
          duplicate: matchesPayload,
          conflict: !matchesPayload,
        };
      }

      const existingByEvent = await SecurityEvent.findOne({
        organizationId: organization, source: input.source, eventId: input.eventId,
      }).lean();
      if (!existingByEvent) throw error;
      return { event: existingByEvent as unknown as Record<string, unknown>, duplicate: true, conflict: false };
    }
  }
}
