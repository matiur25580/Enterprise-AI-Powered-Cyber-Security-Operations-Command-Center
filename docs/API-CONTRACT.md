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
| Events | `GET /events`, `GET /events/:eventId`, `POST /ingest/events` |
| Findings | `GET /findings`, `GET /findings/:findingId` |
| Detection rules | `GET /detection-rules`, privileged create/update/enable endpoints |
| Incidents | `GET /incidents`, `POST /incidents`, `GET /incidents/:id`, `PATCH /incidents/:id` |
| Incident activity | `GET /incidents/:id/activities`, `POST /incidents/:id/activities` |
| Response | `GET /playbooks`, `POST /incidents/:id/respond`, `GET /playbook-executions/:id` |
| Assets | `GET /assets`, `POST /assets`, `GET /assets/:id`, `PATCH /assets/:id` |
| Vulnerabilities | `GET /vulnerabilities`, `PATCH /vulnerabilities/:id` |
| Threat intelligence | `GET /indicators`, privileged indicator management |
| GRC | `GET /grc/frameworks`, `GET /grc/controls`, `GET /grc/assessments` |
| Audit | `GET /audit-logs`, integrity verification endpoint for auditors/admins |
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
