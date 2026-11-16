# Implementation Roadmap

The roadmap is capability-driven. A phase is complete only when its acceptance criteria and tests pass; a dashboard screen alone does not count as a finished feature.

## Phase 0 — Product and engineering foundation

- [x] Confirm independent repository and default branch.
- [x] Document architecture and module boundaries.
- [x] Define initial tenant-aware domain model.
- [x] Define API and realtime conventions.
- [x] Define security boundaries and safe response policy.
- [ ] Create runnable TypeScript monorepo.
- [ ] Add formatting, linting, type-checking and test commands.
- [ ] Add environment validation and safe local development configuration.
- [ ] Add Docker Compose for local dependencies.

**Exit criteria:** clean install, typecheck, lint and test commands work from a documented setup.

## Phase 1 — Identity, tenancy and platform shell

- [x] Organization and membership model.
- [x] Tenant-aware login (account provisioning is invitation/bootstrap only; public registration is intentionally disabled).
- [x] Argon2id password verification, signed short-lived access tokens and rotating opaque refresh sessions.
- [x] RBAC permission registry and server-side authorization middleware.
- [ ] Tenant isolation tests.
- [ ] Audit write service, request correlation IDs and cross-tenant authorization test suite.
- [ ] React application shell, navigation and protected routes.

**Exit criteria:** users can sign in, operate only within authorized tenant scope, and privileged actions are audited.

## Phase 2 — Telemetry and detection

- [ ] Event source management and collector credentials.
- [ ] Validated ingestion endpoint.
- [ ] Event normalization and searchable event store.
- [ ] Seed-data generator for realistic synthetic events.
- [ ] Versioned detection rule registry.
- [ ] Brute-force and suspicious-access detection.
- [ ] Explainable 0–100 risk score.
- [ ] Finding deduplication and incident correlation.
- [ ] Event search, filters and cursor pagination.

**Exit criteria:** deterministic fixtures produce expected findings and scores; ingestion is authenticated, bounded and idempotent.

## Phase 3 — SOC dashboard and incident operations

- [ ] Live dashboard KPIs and trend endpoints.
- [ ] Event feed and realtime updates.
- [ ] Incident creation, assignment and lifecycle.
- [ ] Investigation notes, evidence and activity timeline.
- [ ] SLA tracking and escalation rules.
- [ ] Analyst workflow and role-specific views.

**Exit criteria:** an event can be traced to a finding and incident, investigated, transitioned and audited end to end.

## Phase 4 — SOAR and asset security

- [ ] Playbook definitions and versioning.
- [ ] Approval workflow and simulation adapter.
- [ ] Execution history, idempotency and cancellation.
- [ ] Asset inventory and endpoint posture.
- [ ] Vulnerability findings and remediation workflow.
- [ ] Threat indicator enrichment with source provenance.

**Exit criteria:** playbooks safely simulate approved actions and produce verifiable execution records; asset/vulnerability workflows are tenant-isolated.

## Phase 5 — GRC, reporting and evidence

- [ ] Framework/control catalog with version metadata.
- [ ] ISO/IEC 27001, GDPR and SOC 2 control mappings.
- [ ] Control owners, assessments and evidence records.
- [ ] Audit integrity verification.
- [ ] Operational and compliance PDF reports.
- [ ] Export permissions and export audit records.

**Exit criteria:** reports are reproducible, traceable to stored evidence and clearly state assessment scope and limitations.

## Phase 6 — Production readiness

- [ ] Unit, integration, API and browser E2E coverage.
- [ ] Load testing and documented benchmark methodology.
- [ ] Structured logs, metrics, health and readiness endpoints.
- [ ] Docker images and non-root runtime.
- [ ] GitHub Actions CI with tests and security scans.
- [ ] Backup/restore and retention runbooks.
- [ ] Deployment and rollback documentation.
- [ ] Production configuration review and threat-model update.

**Exit criteria:** repeatable deployment, tested recovery procedures, security checks passing and no unverified performance claims.

## Definition of done

A feature is done only when it has:
1. Validated API contract and server-side authorization.
2. Tenant-scoped persistence and indexes where needed.
3. Loading, empty, error and success UI states (when UI applies).
4. Unit/integration tests for business rules and negative cases.
5. Audit coverage for sensitive actions.
6. Documentation and operational notes.
7. No secrets or unsafe defaults committed.
