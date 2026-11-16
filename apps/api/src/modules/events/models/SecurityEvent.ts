import { Schema, model, type InferSchemaType } from "mongoose";

const securityEventSchema = new Schema({
  organizationId: { type: Schema.Types.ObjectId, ref: "Organization", required: true },
  eventId: { type: String, required: true, maxlength: 160 },
  occurredAt: { type: Date, required: true },
  source: { type: String, required: true, maxlength: 120 },
  sourceType: { type: String, required: true, maxlength: 80 },
  sourceIp: { type: String, maxlength: 64 },
  destinationIp: { type: String, maxlength: 64 },
  username: { type: String, maxlength: 256 },
  hostname: { type: String, maxlength: 255 },
  eventType: { type: String, required: true, maxlength: 120 },
  category: { type: String, required: true, maxlength: 80 },
  severity: { type: String, enum: ["info", "low", "medium", "high", "critical"], required: true },
  action: { type: String, maxlength: 120 },
  outcome: { type: String, maxlength: 80 },
  rawEvent: { type: Schema.Types.Mixed, required: true },
  normalizedData: { type: Schema.Types.Mixed, required: true },
  tags: { type: [String], default: [] },
  processingStatus: { type: String, enum: ["pending", "processed", "failed"], required: true, default: "pending" },
  idempotencyKeyHash: { type: String, maxlength: 64 },
}, { versionKey: false, timestamps: { createdAt: true, updatedAt: true } });

securityEventSchema.index({ organizationId: 1, occurredAt: -1, _id: -1 });
securityEventSchema.index({ organizationId: 1, eventType: 1, occurredAt: -1 });
securityEventSchema.index({ organizationId: 1, severity: 1, occurredAt: -1 });
securityEventSchema.index({ organizationId: 1, source: 1, eventId: 1 }, { unique: true });
securityEventSchema.index(
  { organizationId: 1, idempotencyKeyHash: 1 },
  { unique: true, partialFilterExpression: { idempotencyKeyHash: { $type: "string" } } },
);

export type SecurityEventDocument = InferSchemaType<typeof securityEventSchema>;
export const SecurityEvent = model("SecurityEvent", securityEventSchema);
