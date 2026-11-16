import { Schema, model, type InferSchemaType } from "mongoose";

const incidentNoteSchema = new Schema({
  authorUserId: { type: Schema.Types.ObjectId, required: true },
  body: { type: String, required: true, maxlength: 4000 },
  createdAt: { type: Date, required: true, default: Date.now },
}, { _id: true });

const incidentTimelineSchema = new Schema({
  actorUserId: { type: Schema.Types.ObjectId, required: true },
  action: { type: String, required: true, maxlength: 80 },
  fromStatus: { type: String, maxlength: 32 },
  toStatus: { type: String, maxlength: 32 },
  detail: { type: String, maxlength: 500 },
  createdAt: { type: Date, required: true, default: Date.now },
}, { _id: false });

const incidentSchema = new Schema({
  organizationId: { type: Schema.Types.ObjectId, ref: "Organization", required: true },
  title: { type: String, required: true, maxlength: 180 },
  description: { type: String, required: true, maxlength: 4000 },
  severity: { type: String, enum: ["low", "medium", "high", "critical"], required: true },
  status: { type: String, enum: ["open", "acknowledged", "investigating", "contained", "resolved", "reopened"], default: "open", required: true },
  createdBy: { type: Schema.Types.ObjectId, required: true },
  assigneeUserId: { type: Schema.Types.ObjectId },
  notes: { type: [incidentNoteSchema], default: [] },
  timeline: { type: [incidentTimelineSchema], default: [] },
  resolvedAt: { type: Date },
}, { timestamps: true, versionKey: false });

incidentSchema.index({ organizationId: 1, status: 1, severity: 1, updatedAt: -1 });
incidentSchema.index({ organizationId: 1, assigneeUserId: 1, status: 1 });
incidentSchema.index({ organizationId: 1, createdAt: -1 });

export type IncidentDocument = InferSchemaType<typeof incidentSchema>;
export const Incident = model("Incident", incidentSchema);
