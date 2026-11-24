import type { SecurityEventInput } from "../events/event-schema.js";

export interface DetectionEvidence {
  ruleKey: string;
  ruleVersion: number;
  contribution: number;
  explanation: string;
}

export interface DetectionContext {
  failedAttemptsInWindow?: number;
}

export interface DetectionEvaluation {
  score: number;
  severity: "low" | "medium" | "high" | "critical";
  confidence: number;
  reasons: DetectionEvidence[];
}

const severityWeight: Record<SecurityEventInput["severity"], number> = {
  info: 0,
  low: 5,
  medium: 12,
  high: 22,
  critical: 35,
};

// Combine deterministic rule contributions into a bounded risk score with explainable evidence.
export function evaluateSecurityEvent(
  event: SecurityEventInput,
  context: DetectionContext = {},
): DetectionEvaluation {
  const reasons: DetectionEvidence[] = [];
  const base = severityWeight[event.severity];

  if (base > 0) {
    reasons.push({
      ruleKey: "event.severity-baseline",
      ruleVersion: 1,
      contribution: base,
      explanation: `Source event was classified as ${event.severity} severity.`,
    });
  }

  if (event.eventType === "malware.detected") {
    reasons.push({
      ruleKey: "endpoint.malware-detected",
      ruleVersion: 1,
      contribution: 55,
      explanation: "A malware detection event was reported by the source.",
    });
  }

  if (
    event.category === "identity" &&
    event.outcome === "failure" &&
    (context.failedAttemptsInWindow ?? 0) >= 5
  ) {
    reasons.push({
      ruleKey: "identity.repeated-authentication-failures",
      ruleVersion: 1,
      contribution: 45,
      explanation: `${context.failedAttemptsInWindow} failed authentication events were observed in the correlation window.`,
    });
  }

  if (
    event.eventType === "network.connection.suspicious" ||
    event.category === "network"
  ) {
    reasons.push({
      ruleKey: "network.suspicious-activity",
      ruleVersion: 1,
      contribution: 20,
      explanation: "The event is categorized as suspicious network activity.",
    });
  }

  const score = Math.min(100, reasons.reduce((total, reason) => total + reason.contribution, 0));
  const severity = score >= 85 ? "critical" : score >= 60 ? "high" : score >= 30 ? "medium" : "low";
  const confidence = Math.min(0.99, 0.5 + reasons.length * 0.12);

  return { score, severity, confidence, reasons };
}
