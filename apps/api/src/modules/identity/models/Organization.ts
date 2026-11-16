import { Schema, model, type InferSchemaType } from "mongoose";

const organizationSchema = new Schema({
  name: { type: String, required: true, trim: true, maxlength: 160 },
  slug: { type: String, required: true, trim: true, lowercase: true, maxlength: 80 },
  status: { type: String, enum: ["active", "suspended"], default: "active", required: true },
  settings: {
    timezone: { type: String, default: "UTC" },
    dataRetentionDays: { type: Number, min: 1, max: 3650, default: 90 },
  },
}, { timestamps: true });

organizationSchema.index({ slug: 1 }, { unique: true });

export type OrganizationDocument = InferSchemaType<typeof organizationSchema>;
export const Organization = model("Organization", organizationSchema);
