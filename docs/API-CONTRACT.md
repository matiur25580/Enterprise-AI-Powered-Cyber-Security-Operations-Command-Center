# API and Realtime Contract

## 1. API conventions

- Base path: `/api/v1`
- JSON request and response bodies.
- UTC ISO-8601 timestamps.
- Opaque string IDs.
- Validate every request body, query and path parameter at the API boundary.
- Reject unknown fields on sensitive write endpoints unless explicitly documented.
- Use cursor pagination for event and audit collections.
- Never expose persistence documents directly.

## 2. Authentication

- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `POST /api/v1/auth/logout-all`
- `GET /api/v1/auth/me`
- MFA enrollment and verification endpoints will be added with the identity module.

Access tokens are short-lived. Refresh tokens are rotated, stored as hashes server-side and bound to a session/token family. Browser refresh credentials should use Secure, HttpOnly, SameSite cookies in production. CSRF protection is required for cookie-authenticated state-changing requests.

## 3. Initial resource groups

| Resource | Endpoints |
|---|---|
| Dashboard | `GET /dashboard/summary`, `GET /dashboard/trends` |
| Events | `GET /events`, `GET /events/:id`, `POST /events/ingest`, `POST /events/bulk-ingest` |
| Findings | `GET /findings`, `GET /findings/:findingId` |
| Detection rules | `GET /detection-rules`, privileged create/update/enable endpoints |
| Incidents | `GET /incidents`, `POST /incidents`, `GET /incidents/:id`, `PATCH /incidents/:id` |
| Incident activity | `GET /incidents/:id/activities`, `POST /incidents/:id/activities` |
| Response | `GET /playbooks`, `POST /incidents/:id/respond`, `GET /playbook-executions/:id` |
| Assets | `GET /assets`, `POST /assets`, `GET /assets/:id`, `PATCH /assets/:id` |
| Vulnerabilities | `GET /vulnerabilities`, `PATCH /vulnerabilities/:id` |
| Threat intelligence | `GET /indicators`, privileged indicator management |
| GRC | `GET /grc/frameworks`, `GET /grc/controls`, `GET /grc/assessments` |
| Audit | `GET /audit`, `GET /audit/:id`, `GET /audit/verify`, `GET /audit/export` |
| Users and roles | `GET /users`, `GET /roles`, privileged membership/role endpoints |

Exact payload schemas and permission requirements will live in shared contracts and OpenAPI documentation as endpoints are implemented.

## 4. Response envelope

Success:
```json
{
  "data": {},
  "meta": {
    "requestId": "req_example"
  }
}
```

Paginated success:
```json
{
  "data": [],
  "meta": {
    "requestId": "req_example",
    "nextCursor": null
  }
}
```

Error:
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "The request is invalid.",
    "details": [],
    "requestId": "req_example"
  }
}
```

Do not return stack traces, secrets, raw database errors or sensitive authorization details to clients.

## 5. Filtering and pagination

- Allowlist filter and sort fields per endpoint.
- Enforce maximum page size.
- Use opaque, signed or integrity-checked cursors where query state requires it.
- Require a bounded time range for expensive event searches.
- Escape user input and use safe database query construction; never accept arbitrary MongoDB operators from clients.

## 6. Authorization

Authorization is evaluated on every request:
1. Authenticate principal.
2. Resolve active organization membership.
3. Check permission key and resource scope.
4. Enforce tenant ownership in the database query itself.
5. Validate requested state transition.
6. Write audit record for sensitive actions.

UI visibility is not authorization. A user cannot access another tenant by changing an ID or request parameter.

## 7. Realtime events

Socket.IO event names are namespaced and versioned, for example:
- `soc.v1.event.created`
- `soc.v1.finding.created`
- `soc.v1.incident.updated`
- `soc.v1.playbook.execution.updated`

Payloads contain only identifiers, tenant-scoped routing metadata and minimal display-safe fields. The client retrieves full authorized details through REST. Socket connections are authenticated and rooms are assigned by the server after authorization.

## 8. Idempotency and concurrency

- Ingestion accepts an idempotency key or source event identity.
- Response execution requires an idempotency key.
- State transitions use optimistic concurrency/version checks.
- Retried worker jobs must be safe to execute more than once.
- Side effects occur only after authorization and required approval checks.

## 9. Implemented audit and event endpoints

Every endpoint below requires a bearer access token, an active membership in the token's organization, and the listed permission. The API derives organization scope from the authenticated principal; clients cannot select another organization. The persisted audit/event records use `organizationId`; the principal's existing Phase 2 `tenantId` is the authoritative organization ID and is applied using the shared tenant-scope helper.

### Audit

| Method and path | Permission | Behavior |
|---|---|---|
| `GET /api/v1/audit` | `audit:read` | Tenant-only audit records, newest chain index first. |
| `GET /api/v1/audit/:id` | `audit:read` | Tenant-only record lookup; an ID from another organization returns 404. |
| `GET /api/v1/audit/verify` | `audit:read` | Re-hashes the complete tenant chain; returns 409 if verification fails. Rate limited. |
| `GET /api/v1/audit/export` | `audit:read` | Sanitized JSON export, required date range up to 31 days and at most 500 records. Export is itself audited. Rate limited. |

Audit list filters are allowlisted: `action`, `resourceType`, `outcome`, `severity`, `actorUserId`, `startDate`, and `endDate`. Date filters must be supplied together. `limit` is 1–100 (default 50); `cursor` is a chain index from the prior response. Export supports the same filters except pagination. Audit entries expose `organizationId`, actor, action/resource, timestamp, request/source context, outcome, severity, sanitized metadata, `previousHash`, `entryHash`, and `chainIndex`.

### Security event ingestion and search

| Method and path | Permission | Behavior |
|---|---|---|
| `POST /api/v1/events/ingest` | `events:ingest` | Validate, normalize, redact, and store one event. |
| `POST /api/v1/events/bulk-ingest` | `events:ingest` | Ingest up to 100 event objects; returns per-index validation failures with 207 for partial success. |
| `GET /api/v1/events` | `events:read` | Tenant-only filtered event search with cursor pagination. |
| `GET /api/v1/events/:id` | `events:read` | Tenant-only event lookup; an ID from another organization returns 404. |

Event input is strict and does not accept `organizationId` or `tenantId`; event ownership always comes from the authenticated principal. The normalized input fields are `eventId`, ISO `timestamp`, `source`, `sourceType`, optional source/destination IP, username, hostname, event type/category/severity, optional action/outcome, object-valued `rawEvent` and `normalizedData`, and up to 50 tags. `processingStatus` is assigned by the server (`pending`). Common password, token, secret, credential, cookie, session/CSRF, API/private-key, and signature fields are replaced with `[REDACTED]` before storage and response. Raw event data is stored as data only and is never executed.

An optional `Idempotency-Key` header is accepted on ingestion and stored only as a SHA-256 digest. Duplicate `(organization, source, eventId)` values and repeated idempotency keys return the existing event. Bulk requests accept 1–100 items and are additionally bounded by the API's 256 KiB JSON body limit. Search requires `startDate` and `endDate` within a maximum 31-day range; `limit` is 1–100 and cursors are opaque base64url timestamp/ID pairs. Filters are allowlisted (`severity`, `eventType`, `source`, `hostname`, `username`). Ingestion endpoints are limited to 120 requests/minute per IP; event and audit list/detail reads are limited to 300 requests/minute, and audit verify/export share a 5 requests/minute limit.

Security-event collector credentials are not yet a separate identity type: ingestion currently requires a normal authenticated membership with `events:ingest`.

The MongoDB integration suite uses only a loopback URI with a `soc_api_test*` database name and overrides it with a unique disposable database; it never uses the application's `MONGODB_URI`.
