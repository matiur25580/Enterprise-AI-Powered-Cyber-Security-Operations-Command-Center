# Local Development

## Prerequisites

- Node.js 22+
- pnpm 9.15+
- Docker Engine with Docker Compose

## Start local infrastructure

From the repository root:

```bash
docker compose up -d mongodb redis
```

## Configure the API

```bash
cp apps/api/.env.example apps/api/.env
```

Use unique random values for the access and refresh secrets. Never commit a real `.env` file or share production credentials.

## Install and run

```bash
pnpm install
pnpm dev
```

- Web application: http://localhost:5173
- API liveness: http://localhost:4000/api/v1/health/live
- API readiness: http://localhost:4000/api/v1/health/ready

The readiness endpoint intentionally returns HTTP 503 until database readiness checks are implemented and a database connection is established. The current API scaffold does not yet persist application data.

## Quality checks

```bash
pnpm typecheck
pnpm build
pnpm test
```

## Current limitations

This is an early scaffold, not a production deployment:
- MongoDB connection lifecycle and basic identity models are implemented; migration/versioning workflow is not implemented yet.
- Tenant-aware login, access-token authentication and permission middleware are implemented; tenant-isolation tests and full authorization coverage are still pending.
- Socket.IO connections are deliberately disconnected until handshake authentication and tenant-room authorization exist.
- No real response action is enabled.
- CI currently validates typechecking and builds; automated test suites and CI test execution are still pending.
