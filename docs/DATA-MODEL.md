# Domain and Data Model

This document defines the initial logical model. Physical Mongoose schemas will be implemented in the API workspace and refined through migrations and tests.

## 1. Modeling conventions

- Every tenant-owned document includes `tenantId`.
- IDs are opaque MongoDB ObjectIds at the persistence layer and serialized as strings in API contracts.
- Store timestamps in UTC; preserve the original event timestamp and ingestion timestamp separately.
- Use explicit enums and schema validation for lifecycle fields.
- Store references rather than unbounded embedded arrays for high-cardinality relationships.
- Add `createdAt` and `updatedAt` where applicable.
- Audit records are append-only through application permissions and integrity chaining.
- Never store plaintext passwords, raw refresh tokens, API secrets or unnecessary sensitive personal data.

## 2. Core collections

### organizations
- `_id`, `name`, `slug`, `status`, `plan`, `settings`
- `createdAt`, `updatedAt`

### users
- `_id`, `emailNormalized`, `displayName`, `passwordHash`, `status`
- `mfa`: enrollment state and encrypted secret reference (never return secret material)
- `lastLoginAt`, `createdAt`, `updatedAt`

### memberships
- `_id`, `tenantId`, `userId`, `roleIds[]`, `status`
- Unique index: `tenantId + userId`

### roles and permissions
- `roles`: `tenantId`, `name`, `systemRole`, `permissionKeys[]`
- `permissions`: stable permission key, description and resource scope
- System roles are seeded and changes to privileged roles are audited.

### sessions
- `_id`, `userId`, `tenantId`, `refreshTokenHash`, `tokenFamilyId`
- `expiresAt`, `revokedAt`, `rotatedFrom`, `createdAt`, `lastUsedAt`
- TTL index on expiry; rotation reuse revokes the token family.

### eventSources
- `_id`, `tenantId`, `name`, `sourceType`, `credentialHash`, `status`
- `lastSeenAt`, `configuration`, `createdAt`

### securityEvents
- `_id`, `tenantId`, `sourceId`, `eventKey`, `eventType`
- `occurredAt`, `ingestedAt`, `severity`, `outcome`
- `actor`, `source`, `destination`, `assetId`, `rawReference`
- `normalized`, `labels[]`, `correlationKeys[]`
- Unique/deduplication strategy is source-aware; do not assume all identical payloads are duplicates.

### detectionRules
- `_id`, `tenantId` (null for platform-managed rules), `ruleKey`, `version`
- `name`, `description`, `enabled`, `logic`, `severity`, `scoreContribution`
- `createdBy`, `approvedBy`, `effectiveAt`
- Unique index: `tenantId + ruleKey + version`

### findings
- `_id`, `tenantId`, `ruleKey`, `ruleVersion`, `eventIds[]`
- `riskScore` (0–100), `severity`, `confidence`, `explanation[]`
- `status`, `firstSeenAt`, `lastSeenAt`, `incidentId`

### incidents
- `_id`, `tenantId`, `incidentNumber`, `title`, `description`
- `severity`, `status`, `category`, `priority`
- `findingIds[]`, `assetIds[]`, `assigneeId`, `teamId`
- `openedAt`, `acknowledgedAt`, `containedAt`, `resolvedAt`
- `slaDueAt`, `resolutionSummary`, `createdAt`, `updatedAt`
- Unique index: `tenantId + incidentNumber`

### incidentActivities
- `_id`, `tenantId`, `incidentId`, `actorId`, `activityType`
- `body`, `metadata`, `createdAt`
- Append-only activity timeline.

### assets and vulnerabilities
- `assets`: `tenantId`, `assetTag`, `hostname`, `assetType`, `ownerId`, `criticality`, `environment`, `status`, `lastSeenAt`
- `vulnerabilityFindings`: `tenantId`, `assetId`, `cve`, `title`, `severity`, `cvss`, `detectedAt`, `remediationState`, `dueAt`

### indicators
- `indicators`: `tenantId`, `indicatorType`, `valueNormalized`, `sourceName`, `confidence`, `firstSeenAt`, `lastSeenAt`, `expiresAt`, `tags[]`
- Sensitive or potentially malicious indicator values are treated as untrusted data and safely rendered.

### playbooks and executions
- `playbooks`: `tenantId`, `name`, `version`, `trigger`, `steps[]`, `enabled`, `requiresApproval`
- `playbookExecutions`: `tenantId`, `playbookId`, `incidentId`, `requestedBy`, `approvedBy`, `mode`, `status`, `stepResults[]`, `startedAt`, `completedAt`
- `mode` defaults to `simulation`; production adapters require explicit allowlisting and authorization.

### GRC collections
- `frameworks`: framework key, version, publisher and release metadata.
- `controls`: framework reference, control key, title, description and mapping metadata.
- `controlAssessments`: `tenantId`, `controlId`, `status`, `ownerId`, `assessedAt`, `notes`.
- `evidence`: `tenantId`, `controlAssessmentId`, `evidenceType`, `storageRef`, `checksum`, `collectedAt`, `collectedBy`.
- Framework mappings are guidance, not a certification or legal-compliance guarantee.

### auditLogs
- `_id`, `tenantId`, `actorId`, `action`, `resourceType`, `resourceId`
- `requestId`, `ipAddress`, `userAgent`, `beforeHash`, `afterHash`
- `occurredAt`, `previousRecordHash`, `recordHash`
- Append-only writes; integrity chain is periodically verifiable. Hash chaining is tamper-evident, not a substitute for independently protected backups or WORM storage.

## 3. Initial indexes

| Collection | Index |
|---|---|
| memberships | unique `tenantId, userId` |
| securityEvents | `tenantId, occurredAt desc` |
| securityEvents | `tenantId, eventType, occurredAt desc` |
| securityEvents | `tenantId, severity, occurredAt desc` |
| findings | `tenantId, status, lastSeenAt desc` |
| incidents | unique `tenantId, incidentNumber` |
| incidents | `tenantId, status, severity, updatedAt desc` |
| incidentActivities | `tenantId, incidentId, createdAt` |
| assets | unique `tenantId, assetTag` |
| indicators | `tenantId, indicatorType, valueNormalized` |
| auditLogs | `tenantId, occurredAt desc` |
| sessions | TTL on `expiresAt` |

Index design will be validated against real query plans and representative seeded data. Avoid unbounded arrays and unbounded event retention.

## 4. Risk scoring contract

A score is a prioritization signal, not proof of compromise:
- 0–24: Low
- 25–49: Medium
- 50–74: High
- 75–100: Critical

Each score must include contributing rule IDs, rule versions, evidence references, weights, timestamps and human-readable reasons. Missing evidence must not silently increase confidence. Thresholds are configuration and will be tested.

## 5. Incident lifecycle

`Open → Acknowledged → Investigating → Contained → Resolved`

A controlled `Reopened` transition is permitted with reason and audit entry. Every transition is validated server-side and recorded in the activity timeline. Terminal states cannot be changed silently.
