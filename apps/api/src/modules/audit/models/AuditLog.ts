import { Schema, model, type InferSchemaType } from "mongoose";

const auditLogSchema = new Schema({
  tenantId: { type: Schema.Types.ObjectId, required: true, index: true },
  actorId: { type: Schema.Types.ObjectId, ref: "User" },
  action: { type: String, required: true, maxlength: 120 },
  resourceType: { type: String, required: true, maxlength: 100 },
  resourceId: { type: String, maxlength: 160 },
  requestId: { type: String, required: true, maxlength: 120 },
  ipAddress: { type: String, maxlength: 64 },
  userAgent: { type: String, maxlength: 500 },
  occurredAt: { type: Date, required: true, default: Date.now },
  previousRecordHash: { type: String, maxlength: 128 },
  recordHash: { type: String, required: true, maxlength: 128 },
  metadata: { type: Schema.Types.Mixed, default: {} },
}, { versionKey: false, timestamps: { createdAt: true, updatedAt: false } });

auditLogSchema.index({ tenantId: 1, occurredAt: -1 });
auditLogSchema.index({ tenantId: 1, requestId: 1 });

export type AuditLogDocument = InferSchemaType<typeof auditLogSchema>;
export const AuditLog = model("AuditLog", auditLogSchema);
