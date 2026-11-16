import assert from "node:assert/strict";
import test from "node:test";

import { withTenantScope } from "../identity/tenant-scope.js";

test("dashboard tenant scope always constrains organizationId to the authenticated tenant", () => {
  const tenantId = "507f1f77bcf86cd799439011";
  const scoped = withTenantScope(tenantId, { severity: { $in: ["high", "critical"] } }, "organizationId") as {
    organizationId: { toString(): string };
    severity: { $in: string[] };
  };

  assert.equal(scoped.organizationId.toString(), tenantId);
  assert.deepEqual(scoped.severity.$in, ["high", "critical"]);
});
