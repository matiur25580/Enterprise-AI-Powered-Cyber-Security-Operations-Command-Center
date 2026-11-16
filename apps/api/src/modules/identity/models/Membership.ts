import { Schema, model, type InferSchemaType } from "mongoose";

const membershipSchema = new Schema({
  tenantId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, index: true },
  userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
  roles: {
    type: [String],
    enum: ["super_admin", "soc_manager", "soc_analyst_l1", "soc_analyst_l2", "auditor", "viewer"],
    default: ["viewer"],
    required: true,
  },
  status: { type: String, enum: ["active", "suspended"], default: "active", required: true },
}, { timestamps: true, versionKey: true });

membershipSchema.index({ tenantId: 1, userId: 1 }, { unique: true });

export type MembershipDocument = InferSchemaType<typeof membershipSchema>;
export const Membership = model("Membership", membershipSchema);
