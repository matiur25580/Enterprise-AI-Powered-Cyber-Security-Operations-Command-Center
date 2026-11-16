import { isIP } from "node:net";
import { z } from "zod";

export const severitySchema = z.enum(["info", "low", "medium", "high", "critical"]);
const ipAddressSchema = z.string().trim().refine((value) => isIP(value) !== 0, "Invalid IP address.");

export const securityEventInputSchema = z.object({
  eventId: z.string().trim().min(1).max(160),
  timestamp: z.iso.datetime(),
  source: z.string().trim().min(1).max(120),
  sourceType: z.string().trim().min(1).max(80),
  sourceIp: ipAddressSchema.optional(),
  destinationIp: ipAddressSchema.optional(),
  username: z.string().trim().min(1).max(256).optional(),
  hostname: z.string().trim().min(1).max(255).optional(),
  eventType: z.string().trim().min(1).max(120),
  category: z.string().trim().min(1).max(80),
  severity: severitySchema,
  action: z.string().trim().min(1).max(120).optional(),
  outcome: z.string().trim().min(1).max(80).optional(),
  rawEvent: z.record(z.string(), z.unknown()),
  normalizedData: z.record(z.string(), z.unknown()).default({}),
  tags: z.array(z.string().trim().min(1).max(64)).max(50).default([]),
}).strict();

export const bulkSecurityEventInputSchema = z.object({
  events: z.array(z.unknown()).min(1).max(100),
}).strict();

export type SecurityEventInput = z.infer<typeof securityEventInputSchema>;
