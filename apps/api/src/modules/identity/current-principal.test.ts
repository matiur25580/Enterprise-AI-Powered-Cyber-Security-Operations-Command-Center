import assert from "node:assert/strict";
import test from "node:test";

import { principalFromActiveMembership } from "./current-principal.js";
import type { AccessClaims } from "./token.js";

const claims: AccessClaims = {
  userId: "user-1",
  tenantId: "tenant-1",
  roles: ["soc_manager"],
};

test("authorization roles are refreshed from the current active tenant membership", () => {
  const principal = principalFromActiveMembership(claims, {
    userId: "user-1",
    tenantId: "tenant-1",
    roles: ["viewer"],
    status: "active",
  });

  assert.deepEqual(principal?.roles, ["viewer"]);
});

test("a suspended or missing membership invalidates the principal", () => {
  assert.equal(principalFromActiveMembership(claims, {
    userId: "user-1",
    tenantId: "tenant-1",
    roles: ["soc_manager"],
    status: "suspended",
  }), null);
  assert.equal(principalFromActiveMembership(claims, null), null);
});

test("a membership from another user or tenant cannot authorize the token", () => {
  assert.equal(principalFromActiveMembership(claims, {
    userId: "user-2",
    tenantId: "tenant-1",
    roles: ["super_admin"],
    status: "active",
  }), null);
  assert.equal(principalFromActiveMembership(claims, {
    userId: "user-1",
    tenantId: "tenant-2",
    roles: ["super_admin"],
    status: "active",
  }), null);
});
