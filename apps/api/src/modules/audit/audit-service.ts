import { createHash, randomUUID } from "node:crypto";
import { Types } from "mongoose";

import { AuditHead } from "./models/AuditHead.js";
import { AuditLog } from "./models/AuditLog.js";
import { assertJsonSize, sanitizeSensitiveData } from "../security-data.js";

export type AuditOutcome = "success" | "failure" | "denied" | "partial";
export type AuditSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface AppendAuditInput {
  organizationId: string;
  actorUserId?: string | undefined;
  actorRole?: string | undefined;
  action: string;
  resourceType: string;
  resourceId?: string | undefined;
  timestamp?: Date;
  sourceIp?: string | undefined;
  userAgent?: string | undefined;
  requestId: string;
  outcome: AuditOutcome;
  severity: AuditSeverity;
  metadata?: Record<string, unknown>;
}

export interface AuditHashEntry {
  organizationId: string;
  actorUserId?: string | undefined;
  actorRole?: string | undefined;
  action: string;
  resourceType: string;
  resourceId?: string | undefined;
  timestamp: Date | string;
  sourceIp?: string | undefined;
  userAgent?: string | undefined;
  requestId: string;
  outcome: AuditOutcome;
  severity: AuditSeverity;
  metadata: Record<string, unknown>;
  previousHash: string | null;
  chainIndex: number;
}

const lockLeaseMs = 30_000;
const lockWaitLimitMs = 20_000;

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value instanceof Date) return value.toISOString();
  if (value instanceof Types.ObjectId) return value.toHexString();
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, nested]) => nested !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, canonicalize(nested)]),
    );
  }
  return value;
}

export function calculateAuditEntryHash(entry: AuditHashEntry): string {
  return createHash("sha256")
    .update(JSON.stringify(canonicalize(entry)))
    .digest("hex");
}

export function verifyAuditEntries(entries: Array<AuditHashEntry & { entryHash: string }>): {
  valid: boolean;
  checkedEntries: number;
  failedAt?: number;
} {
  let expectedPreviousHash: string | null = null;
  let expectedSequence = 1;

  for (const entry of entries) {
    if (entry.chainIndex !== expectedSequence || entry.previousHash !== expectedPreviousHash) {
      return { valid: false, checkedEntries: expectedSequence - 1, failedAt: entry.chainIndex };
    }

    const { entryHash, ...hashFields } = entry;
    if (calculateAuditEntryHash(hashFields) !== entryHash) {
      return { valid: false, checkedEntries: expectedSequence - 1, failedAt: entry.chainIndex };
    }

    expectedPreviousHash = entryHash;
    expectedSequence += 1;
  }

  return { valid: true, checkedEntries: entries.length };
}

function isDuplicateKeyError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === 11000;
}

async function acquireOrganizationLock(organizationId: Types.ObjectId, owner: string): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < lockWaitLimitMs) {
    const now = new Date();
    const acquired = await AuditHead.findOneAndUpdate(
      { organizationId, lockExpiresAt: { $lte: now } },
      { $set: { lockOwner: owner, lockExpiresAt: new Date(now.getTime() + lockLeaseMs) } },
      { new: true },
    );

    if (acquired) return;

    const headExists = await AuditHead.exists({ organizationId });
    if (!headExists) {
      try {
        await AuditHead.create({
          organizationId,
          lockOwner: owner,
          lockExpiresAt: new Date(now.getTime() + lockLeaseMs),
        });
        return;
      } catch (error) {
        if (!isDuplicateKeyError(error)) throw error;
      }
    }

    await new Promise((resolve) => setTimeout(resolve, 50));
  }

  throw new Error("AUDIT_WRITE_LOCK_TIMEOUT");
}

function toHashEntry(input: {
  organizationId: Types.ObjectId;
  actorUserId?: Types.ObjectId | undefined;
  actorRole?: string | undefined;
  action: string;
  resourceType: string;
  resourceId?: string | undefined;
  occurredAt: Date;
  sourceIp?: string | undefined;
  userAgent?: string | undefined;
  requestId: string;
  outcome: AuditOutcome;
  severity: AuditSeverity;
  metadata: Record<string, unknown>;
  previousHash: string | null;
  chainIndex: number;
}): AuditHashEntry {
  return {
    organizationId: input.organizationId.toHexString(),
    actorUserId: input.actorUserId?.toHexString(),
    actorRole: input.actorRole,
    action: input.action,
    resourceType: input.resourceType,
    resourceId: input.resourceId,
    timestamp: input.occurredAt,
    sourceIp: input.sourceIp,
    userAgent: input.userAgent,
    requestId: input.requestId,
    outcome: input.outcome,
    severity: input.severity,
    metadata: input.metadata,
    previousHash: input.previousHash,
    chainIndex: input.chainIndex,
  };
}

export class AuditService {
  static async append(input: AppendAuditInput) {
    if (!Types.ObjectId.isValid(input.organizationId)) {
      throw new Error("A valid organization context is required for audit writes.");
    }
    if (input.actorUserId && !Types.ObjectId.isValid(input.actorUserId)) {
      throw new Error("A valid actor user ID is required for audit writes.");
    }

    const metadata = sanitizeSensitiveData(input.metadata ?? {}) as Record<string, unknown>;
    assertJsonSize(metadata, 16 * 1024);
    const organizationId = new Types.ObjectId(input.organizationId);
    const owner = randomUUID();
    await acquireOrganizationLock(organizationId, owner);

    try {
      const previous = await AuditLog.findOne({ organizationId }).sort({ chainIndex: -1 }).lean();
      const chainIndex = (previous?.chainIndex ?? 0) + 1;
      const hashFields = toHashEntry({
        organizationId,
        actorUserId: input.actorUserId ? new Types.ObjectId(input.actorUserId) : undefined,
        actorRole: input.actorRole,
        action: input.action,
        resourceType: input.resourceType,
        resourceId: input.resourceId,
        occurredAt: input.timestamp ?? new Date(),
        sourceIp: input.sourceIp,
        userAgent: input.userAgent,
        requestId: input.requestId,
        outcome: input.outcome,
        severity: input.severity,
        metadata,
        previousHash: previous?.entryHash ?? null,
        chainIndex,
      });
      const entryHash = calculateAuditEntryHash(hashFields);

      const [created] = await AuditLog.create([{
        organizationId,
        actorUserId: hashFields.actorUserId ? new Types.ObjectId(hashFields.actorUserId) : undefined,
        actorRole: hashFields.actorRole,
        action: hashFields.action,
        resourceType: hashFields.resourceType,
        resourceId: hashFields.resourceId,
        occurredAt: new Date(hashFields.timestamp),
        sourceIp: hashFields.sourceIp,
        userAgent: hashFields.userAgent,
        requestId: hashFields.requestId,
        outcome: hashFields.outcome,
        severity: hashFields.severity,
        metadata,
        previousHash: hashFields.previousHash,
        entryHash,
        chainIndex,
      }]);

      await AuditHead.updateOne(
        { organizationId, lockOwner: owner },
        { $set: { headSequence: chainIndex, headHash: entryHash } },
      );
      return created;
    } finally {
      await AuditHead.updateOne(
        { organizationId, lockOwner: owner },
        { $set: { lockOwner: null, lockExpiresAt: new Date(0) } },
      );
    }
  }

  static async verify(organizationId: string) {
    if (!Types.ObjectId.isValid(organizationId)) {
      throw new Error("A valid organization context is required for audit verification.");
    }

    const records = await AuditLog.find({ organizationId: new Types.ObjectId(organizationId) })
      .sort({ chainIndex: 1 })
      .lean();
    const entries = records.map((record) => ({
      ...toHashEntry({
        organizationId: record.organizationId,
        actorUserId: record.actorUserId ?? undefined,
        actorRole: record.actorRole ?? undefined,
        action: record.action,
        resourceType: record.resourceType,
        resourceId: record.resourceId ?? undefined,
        occurredAt: record.occurredAt,
        sourceIp: record.sourceIp ?? undefined,
        userAgent: record.userAgent ?? undefined,
        requestId: record.requestId,
        outcome: record.outcome,
        severity: record.severity,
        metadata: (record.metadata ?? {}) as Record<string, unknown>,
        previousHash: record.previousHash ?? null,
        chainIndex: record.chainIndex,
      }),
      entryHash: record.entryHash,
    }));

    return verifyAuditEntries(entries);
  }
}
