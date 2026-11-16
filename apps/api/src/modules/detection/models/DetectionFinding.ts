import { Schema, model, type InferSchemaType } from "mongoose";

const detectionFindingSchema = new Schema({
  organizationId: { type: Schema.Types.ObjectId, ref: "Organization", required: true },
  dedupeKey: { type: String, required: true, maxlength: 64 },
  title: { type: String, required: true, maxlength: 180 },
  description: { type: String, required: true, maxlength: 1000 },
  severity: { type: String, enum: ["low", "medium", "high", "critical"], required: true },
  riskScore: { type: Number, min: 0, max: 100, required: true },
  confidence: { type: Number, min: 0, max: 1, required: true },
  ruleKeys: { type: [String], required: true },
  evidenceEventIds: [{ type: Schema.Types.ObjectId, ref: "SecurityEvent" }],
  status: { type: String, enum: ["open", "acknowledged", "resolved"], default: "open", required: true },
  firstSeenAt: { type: Date, required: true },
  lastSeenAt: { type: Date, required: true },
}, { timestamps: true, versionKey: false });

detectionFindingSchema.index({ organizationId: 1, status: 1, lastSeenAt: -1 });
detectionFindingSchema.index({ organizationId: 1, severity: 1, lastSeenAt: -1 });
detectionFindingSchema.index({ organizationId: 1, dedupeKey: 1 }, { unique: true });

export type DetectionFindingDocument = InferSchemaType<typeof detectionFindingSchema>;
export const DetectionFinding = model("DetectionFinding", detectionFindingSchema);
