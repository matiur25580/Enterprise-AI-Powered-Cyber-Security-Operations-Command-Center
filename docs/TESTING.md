# Testing

## API unit tests

Run API unit tests and any configured MongoDB integration tests:

```powershell
cd apps/api
corepack pnpm test
```

The audit hash tests cover valid chains, sequence/link integrity, metadata tampering, and recursive secret redaction. Event unit tests cover strict schema validation (including tenant override rejection and IP syntax), normalized timestamps, tag deduplication, sensitive-field redaction, and unsafe/oversized payload rejection. These are unit tests and do not claim database behavior.

## MongoDB integration tests

`src/modules/security-phase3.integration.test.ts` exercises real Mongoose persistence, concurrent audit writes, audit chain verification/tamper detection, tenant-scoped audit/event HTTP endpoints, authentication and authorization on every route, event deduplication/idempotency, malformed events, and bulk limits.

The integration test accepts only a loopback `mongodb://` URI whose database name begins with `soc_api_test`. It overrides that URI's database name with a unique `soc_api_test_phase3_<pid>_<uuid>` database, then drops only that generated database during teardown. Remote URIs, `mongodb+srv`, and ordinary application database names are rejected before connecting. The suite does not use `MONGODB_URI`.

Recommended isolated local setup (Docker required):

```powershell
docker compose -p soc-phase3-test -f docker-compose.test.yml up -d --wait mongodb-test
$env:API_TEST_MONGODB_URI = "mongodb://127.0.0.1:27018/soc_api_test"
corepack pnpm -r test
docker compose -p soc-phase3-test -f docker-compose.test.yml down --remove-orphans
Remove-Item Env:API_TEST_MONGODB_URI
```

`docker-compose.test.yml` binds MongoDB to loopback port 27018 and has no named volume; remove the test container with the matching `down` command. Run the tests only against this dedicated test service. Without `API_TEST_MONGODB_URI`, the integration test is reported as skipped; no database integration result should be claimed.

## Workspace checks

Run from the repository root:

```powershell
corepack pnpm -r test
corepack pnpm -r typecheck
corepack pnpm -r build
```

API authentication uses a test-signed access token and real isolated MongoDB membership records in the integration test. It does not mock production audit or event storage.

## Latest verification in this workspace

- `corepack pnpm -r test`: API 19 passed, 0 failed, 1 skipped; web 0 tests. The skipped test is the real MongoDB integration suite because `API_TEST_MONGODB_URI` is unset and localhost port 27017 is unreachable.
- `corepack pnpm -r typecheck`: passed for API and web.
- `corepack pnpm -r build`: passed for API and web.
- `git diff --check`: passed.

These results do not verify MongoDB persistence, lock behavior, or the database-backed HTTP assertions. Follow the isolated Docker procedure above to run those checks.
