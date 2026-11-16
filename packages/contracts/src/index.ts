import { z } from "zod";

export const securitySeveritySchema = z.enum([
  "low",
  "medium",
  "high",
  "critical",
]);

export type SecuritySeverity = z.infer<typeof securitySeveritySchema>;

export const securityEventTypeSchema = z.enum([
  "authentication.failed",
  "authentication.succeeded",
  "network.connection.suspicious",
  "malware.detected",
  "file.access.unusual",
  "endpoint.health.changed",
  "vulnerability.detected",
]);

export const securityEventInputSchema = z.object({
  eventKey: z.string().trim().min(1).max(160).optional(),
  eventType: securityEventTypeSchema,
  occurredAt: z.string().datetime({ offset: true }),
  severity: securitySeveritySchema,
  outcome: z.enum(["success", "failure", "unknown"]).default("unknown"),
  actor: z.object({
    id: z.string().trim().max(160).optional(),
    username: z.string().trim().max(160).optional(),
    ipAddress: z.string().trim().max(64).optional(),
  }).optional(),
  source: z.object({
    ipAddress: z.string().trim().max(64).optional(),
    hostname: z.string().trim().max(255).optional(),
    service: z.string().trim().max(120).optional(),
  }).optional(),
  target: z.object({
    id: z.string().trim().max(160).optional(),
    hostname: z.string().trim().max(255).optional(),
    resource: z.string().trim().max(500).optional(),
  }).optional(),
  message: z.string().trim().max(2_000).optional(),
  labels: z.array(z.string().trim().min(1).max(64)).max(30).default([]),
}).strict();

export type SecurityEventInput = z.infer<typeof securityEventInputSchema>;

export const riskAssessmentSchema = z.object({
  score: z.number().int().min(0).max(100),
  severity: securitySeveritySchema,
  confidence: z.number().min(0).max(1),
  reasons: z.array(z.object({
    ruleKey: z.string().min(1),
    ruleVersion: z.number().int().positive(),
    contribution: z.number().int(),
    explanation: z.string().min(1).max(500),
    evidenceEventIds: z.array(z.string()).default([]),
  })).min(1),
  assessedAt: z.string().datetime({ offset: true }),
});

export type RiskAssessment = z.infer<typeof riskAssessmentSchema>;

export const incidentStatusSchema = z.enum([
  "open",
  "acknowledged",
  "investigating",
  "contained",
  "resolved",
  "reopened",
]);

export type IncidentStatus = z.infer<typeof incidentStatusSchema>;
