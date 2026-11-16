import { Schema, model, type InferSchemaType } from "mongoose";

const auditLogSchema = new Schema({
  organizationId: { type: Schema.Types.ObjectId, ref: "Organization", required: true },
  actorUserId: { type: Schema.Types.ObjectId, ref: "User" },
  actorRole: { type: String, maxlength: 80 },
  action: { type: String, required: true, maxlength: 120 },
  resourceType: { type: String, required: true, maxlength: 100 },
  resourceId: { type: String, maxlength: 160 },
  occurredAt: { type: Date, required: true },
  sourceIp: { type: String, maxlength: 64 },
  userAgent: { type: String, maxlength: 500 },
  requestId: { type: String, required: true, maxlength: 120 },
  outcome: { type: String, enum: ["success", "failure", "denied", "partial"], required: true },
  severity: { type: String, enum: ["info", "low", "medium", "high", "critical"], required: true },
  metadata: { type: Schema.Types.Mixed, default: {} },
  previousHash: { type: String, maxlength: 128, default: null },
  entryHash: { type: String, required: true, maxlength: 128 },
  chainIndex: { type: Number, required: true, min: 1 },
}, { versionKey: false, timestamps: { createdAt: true, updatedAt: false } });

auditLogSchema.index({ organizationId: 1, chainIndex: -1 }, { unique: true });
auditLogSchema.index({ organizationId: 1, occurredAt: -1 });
auditLogSchema.index({ organizationId: 1, action: 1, occurredAt: -1 });
auditLogSchema.index({ organizationId: 1, severity: 1, occurredAt: -1 });

export type AuditLogDocument = InferSchemaType<typeof auditLogSchema>;
export const AuditLog = model("AuditLog", auditLogSchema);
