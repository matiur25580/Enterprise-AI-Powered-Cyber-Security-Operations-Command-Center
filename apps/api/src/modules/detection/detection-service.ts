import { createHash } from "node:crypto";
import { Types } from "mongoose";

import { SecurityEvent } from "../events/models/SecurityEvent.js";
import { DetectionFinding } from "./models/DetectionFinding.js";
import { evaluateSecurityEvent } from "./rule-engine.js";

const correlationWindowMs = 10 * 60 * 1000;

export class DetectionService {
  static async evaluateEvent(eventId: string): Promise<{ findingId: string | null; score: number; severity: string }> {
    if (!Types.ObjectId.isValid(eventId)) throw new Error("INVALID_EVENT_ID");
    const event = await SecurityEvent.findById(new Types.ObjectId(eventId)).lean();
    if (!event) throw new Error("SECURITY_EVENT_NOT_FOUND");

    let failedAttemptsInWindow = 0;
    if (event.category === "identity" && event.outcome === "failure") {
      const filter: Record<string, unknown> = {
        organizationId: event.organizationId,
        category: "identity",
        outcome: "failure",
        occurredAt: { $gte: new Date(event.occurredAt.getTime() - correlationWindowMs), $lte: event.occurredAt },
      };
      if (event.username) filter.username = event.username;
      else if (event.sourceIp) filter.sourceIp = event.sourceIp;
      else filter.eventId = event.eventId;
      failedAttemptsInWindow = await SecurityEvent.countDocuments(filter);
    }

    const evaluation = evaluateSecurityEvent({
      eventId: event.eventId,
      timestamp: event.occurredAt.toISOString(),
      source: event.source,
      sourceType: event.sourceType,
      sourceIp: event.sourceIp ?? undefined,
      destinationIp: event.destinationIp ?? undefined,
      username: event.username ?? undefined,
      hostname: event.hostname ?? undefined,
      eventType: event.eventType,
      category: event.category,
      severity: event.severity as "info" | "low" | "medium" | "high" | "critical",
      action: event.action ?? undefined,
      outcome: event.outcome ?? undefined,
      rawEvent: (event.rawEvent ?? {}) as Record<string, unknown>,
      normalizedData: (event.normalizedData ?? {}) as Record<string, unknown>,
      tags: event.tags ?? [],
    }, { failedAttemptsInWindow });

    if (evaluation.score < 30 || evaluation.reasons.length === 0) {
      return { findingId: null, score: evaluation.score, severity: evaluation.severity };
    }

    const windowBucket = Math.floor(event.occurredAt.getTime() / correlationWindowMs);
    const ruleKeys = evaluation.reasons.map((reason) => reason.ruleKey).sort();
    const dedupeKey = createHash("sha256").update([
      event.organizationId.toString(),
      ruleKeys.join(","),
      event.username ?? event.sourceIp ?? event.eventId,
      String(windowBucket),
    ].join("|")).digest("hex");
    const title = ruleKeys.includes("identity.repeated-authentication-failures")
      ? "Repeated authentication failures"
      : ruleKeys.includes("endpoint.malware-detected")
        ? "Malware detection"
        : ruleKeys.includes("network.suspicious-activity")
          ? "Suspicious network activity"
          : "Elevated security event";
    const description = evaluation.reasons.map((reason) => reason.explanation).join(" ");

    const finding = await DetectionFinding.findOneAndUpdate(
      { organizationId: event.organizationId, dedupeKey },
      {
        $set: {
          title,
          description,
          severity: evaluation.severity === "info" ? "low" : evaluation.severity,
          riskScore: evaluation.score,
          confidence: evaluation.confidence,
          ruleKeys,
          lastSeenAt: event.occurredAt,
        },
        $setOnInsert: {
          organizationId: event.organizationId,
          dedupeKey,
          status: "open",
          firstSeenAt: event.occurredAt,
        },
        $addToSet: { evidenceEventIds: event._id },
      },
      { upsert: true, new: true, setDefaultsOnInsert: true },
    ).lean();

    return { findingId: finding ? String(finding._id) : null, score: evaluation.score, severity: evaluation.severity };
  }
}
