import { Schema, model, type InferSchemaType } from "mongoose";

const sessionSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
  tenantId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, index: true },
  refreshTokenHash: { type: String, required: true, select: false },
  tokenFamilyId: { type: String, required: true, index: true },
  expiresAt: { type: Date, required: true },
  revokedAt: { type: Date },
  rotatedFrom: { type: Schema.Types.ObjectId, ref: "Session" },
  lastUsedAt: { type: Date },
}, { timestamps: true, versionKey: true });

sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
sessionSchema.index({ tokenFamilyId: 1, revokedAt: 1 });

export type SessionDocument = InferSchemaType<typeof sessionSchema>;
export const Session = model("Session", sessionSchema);
