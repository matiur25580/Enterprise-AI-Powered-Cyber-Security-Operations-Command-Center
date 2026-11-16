import { Schema, model, type InferSchemaType } from "mongoose";

const userSchema = new Schema({
  emailNormalized: {
    type: String, required: true, trim: true, lowercase: true,
    maxlength: 254,
  },
  displayName: { type: String, required: true, trim: true, maxlength: 120 },
  passwordHash: { type: String, required: true, select: false },
  status: { type: String, enum: ["invited", "active", "disabled"], default: "invited", required: true },
  mfaEnabled: { type: Boolean, default: false },
  lastLoginAt: { type: Date },
}, { timestamps: true, versionKey: true });

userSchema.index({ emailNormalized: 1 }, { unique: true });

export type UserDocument = InferSchemaType<typeof userSchema>;
export const User = model("User", userSchema);
