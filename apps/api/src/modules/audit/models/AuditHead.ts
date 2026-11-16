import { Schema, model } from "mongoose";

const auditHeadSchema = new Schema({
  organizationId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, unique: true },
  headSequence: { type: Number, required: true, default: 0 },
  headHash: { type: String, default: null },
  lockOwner: { type: String, default: null },
  lockExpiresAt: { type: Date, required: true, default: new Date(0) },
}, { versionKey: false, timestamps: false });

export const AuditHead = model("AuditHead", auditHeadSchema);
