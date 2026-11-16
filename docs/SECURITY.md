# Security Model and Threat Considerations

## 1. Security objectives

Protect tenant confidentiality, integrity of security evidence, availability of the SOC console, and accountability of privileged actions.

## 2. Trust boundaries

- Browser to API: untrusted client; validate all inputs and authorize every request.
- Collector to ingestion API: authenticate source identity, rotate credentials and rate-limit.
- API to database/cache: private network and least-privilege credentials.
- Worker to response adapter: constrained service identity and explicit action allowlist.
- External threat-intelligence providers: treat returned data as untrusted and preserve provenance.
- Tenant to tenant: strict tenant-scoped access at service and persistence layers.

## 3. Identity and access

- Passwords hashed with Argon2id or an appropriately configured modern password hash.
- MFA support planned for privileged roles.
- Short-lived access tokens and rotating refresh tokens.
- Refresh token reuse detection and family revocation.
- Secure, HttpOnly, SameSite cookies in browser production deployments.
- CSRF protection for cookie-authenticated mutations.
- Session revocation and administrative session visibility.
- Role and permission checks enforced server-side.
- Default-deny authorization.

Initial role templates:
- Super Admin
- SOC Manager
- SOC Analyst L1
- SOC Analyst L2
- Auditor (read-only)
- Viewer (read-only, restricted)

Role names are templates; permission keys and tenant scope define actual access.

## 4. Application and API controls

- Helmet and restrictive Content Security Policy.
- CORS allowlist; no wildcard credentialed origins.
- Rate limiting by identity, tenant and source where appropriate.
- Request body and upload size limits.
- Schema validation and safe query construction.
- Output encoding and safe rendering of untrusted event content.
- Parameterized operations; no arbitrary command execution.
- Secrets only in environment/secret manager, never committed.
- Dependency and container vulnerability scanning in CI.
- Redaction of credentials, tokens and sensitive fields from logs.
- Security headers, TLS and secure cookie settings in production.

## 5. Tenant isolation

- Tenant context is derived from authenticated membership, not trusted from a request body.
- Every tenant-owned read, update and delete includes tenant scope.
- Background jobs carry an explicit tenant context and validate it.
- Cross-tenant tests are required for every resource module.
- Platform-level resources are clearly distinguished from tenant-owned records.

## 6. Safe SOAR response

Default mode is `simulation`.
- Simulated actions create realistic execution records without affecting external systems.
- Production adapters are disabled unless explicitly configured.
- Each adapter has a narrow action allowlist and least-privilege credentials.
- Destructive or disruptive actions require approval, policy checks and a recorded justification.
- Every execution records requester, approver, target, parameters (redacted), result and timestamps.
- Support dry-run, timeout, retry policy, cancellation and idempotency.
- Never execute shell commands or arbitrary scripts supplied by an event, user or model.

## 7. AI safety and explainability

- AI-generated summaries are advisory and cite the event/finding IDs they use.
- Detection rules and deterministic scoring remain independently inspectable.
- Model output is untrusted input and cannot grant permissions or directly invoke response actions.
- Prompt injection in logs, email content, URLs and threat-intelligence data must be treated as hostile content.
- Human approval is required for consequential response actions.
- Record model/provider, prompt template version, evidence references and output provenance where AI is used.
- Do not send sensitive tenant data to external models without explicit configuration and appropriate data controls.

## 8. Audit integrity

- Audit records are append-only at the application layer.
- Hash chaining supports tamper-evidence and integrity verification.
- Protect audit storage and backups independently from the primary application credentials.
- Log authentication events, permission changes, exports, response approvals and incident transitions.
- Avoid logging passwords, access tokens, refresh tokens, secrets or unnecessary personal data.

## 9. Privacy and compliance

- Define data classification, retention and deletion policies before production.
- Minimize personal data in event payloads and reports.
- Restrict exports and record export activity.
- Framework mappings are implementation aids, not legal advice or a certification.
- GDPR workflows must account for lawful basis, purpose limitation, retention and data-subject obligations where applicable.

## 10. Required security tests

- Unauthenticated and unauthorized access tests.
- Cross-tenant IDOR tests for all tenant-owned resources.
- Refresh token rotation and replay/reuse tests.
- CSRF, CORS and rate-limit tests.
- Input validation and NoSQL injection tests.
- WebSocket authentication and room isolation tests.
- Approval bypass and response idempotency tests.
- Audit integrity verification tests.
- Secret scanning and dependency vulnerability checks.
