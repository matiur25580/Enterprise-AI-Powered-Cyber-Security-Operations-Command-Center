import assert from "node:assert/strict";
import test from "node:test";

import { Types } from "mongoose";

import { Membership } from "./models/Membership.js";
import { requirePermission } from "./middleware/authorize.js";
import { AuditService } from "../audit/audit-service.js";
import { hasPermission, type SystemRole } from "./roles.js";
import { authorizeSocketTenantSubscription } from "./socket-tenant.js";
import { assertTenantContextMatches, rejectTenantOverride, withTenantScope } from "./tenant-scope.js";

test("tenant A cannot read tenant B resources", () => {
  const tenantA = new Types.ObjectId().toHexString();
  const tenantB = new Types.ObjectId().toHexString();

  const scope = withTenantScope(tenantA, { status: "active" });
  assert.equal(scope.tenantId?.toString(), tenantA);
  assert.throws(() => assertTenantContextMatches(tenantA, tenantB), /TENANT_CONTEXT_MISMATCH/);
});

test("tenant ids supplied in request bodies cannot override authenticated tenant context", () => {
  const tenantA = new Types.ObjectId().toHexString();
  const tenantB = new Types.ObjectId().toHexString();

  const request = { principal: { tenantId: tenantA }, body: { tenantId: tenantB } };
  assert.throws(() => rejectTenantOverride(request.principal.tenantId, request.body.tenantId), /TENANT_CONTEXT_MISMATCH/);
});

test("aggregation and search scopes remain tenant-scoped", () => {
  const tenantA = new Types.ObjectId().toHexString();
  const tenantB = new Types.ObjectId().toHexString();

  const scope = withTenantScope(tenantA, { $or: [{ severity: "high" }, { severity: "critical" }] });
  assert.equal(scope.tenantId.toString(), tenantA);
  assert.notEqual(scope.tenantId.toString(), tenantB);
  const organizationScope = withTenantScope(tenantA, { severity: "high" }, "organizationId");
  assert.equal(organizationScope.organizationId?.toString(), tenantA);
  assert.equal(organizationScope.tenantId, undefined);
});

test("viewer cannot execute privileged operations", async () => {
  const originalAppend = AuditService.append;
  AuditService.append = async () => ({} as never);
  const request = {
    principal: {
      userId: new Types.ObjectId().toHexString(),
      tenantId: new Types.ObjectId().toHexString(),
      roles: ["viewer" as SystemRole],
    },
    ip: "127.0.0.1",
    requestId: "unit-test-request",
    get: () => undefined,
    route: { path: "/admin" },
    method: "POST",
  } as any;
  const response = {
    statusCode: 200,
    status(code: number) { this.statusCode = code; return this; },
    json() { return this; },
  };

  try {
    await requirePermission("users:manage")(request, response as any, () => {
      throw new Error("permission middleware should have denied access");
    });
    assert.equal(response.statusCode, 403);
  } finally {
    AuditService.append = originalAppend;
  }
});

test("auditor cannot modify protected records", () => {
  assert.equal(hasPermission("auditor", "users:manage"), false);
  assert.equal(hasPermission("auditor", "incidents:assign"), false);
});

test("l1 analyst cannot execute manager-only operations", () => {
  assert.equal(hasPermission("soc_analyst_l1", "incidents:assign"), false);
  assert.equal(hasPermission("soc_analyst_l1", "response:approve"), false);
});

test("unauthorized socket subscriptions are rejected", () => {
  const tenantA = new Types.ObjectId().toHexString();
  const tenantB = new Types.ObjectId().toHexString();
  const principal = { userId: new Types.ObjectId().toHexString(), tenantId: tenantA, roles: ["viewer" as SystemRole] };

  assert.deepEqual(authorizeSocketTenantSubscription(principal, tenantB), { ok: false, code: "UNAUTHORIZED_TENANT" });
});

test("super admin access is restricted to explicitly authorized tenant contexts", () => {
  const tenantA = new Types.ObjectId().toHexString();
  const tenantB = new Types.ObjectId().toHexString();
  const principal = { userId: new Types.ObjectId().toHexString(), tenantId: tenantA, roles: ["super_admin" as SystemRole] };

  assert.deepEqual(authorizeSocketTenantSubscription(principal, tenantB), { ok: false, code: "UNAUTHORIZED_TENANT" });
});

test("tenant membership validation blocks cross-tenant access", async () => {
  const tenantA = new Types.ObjectId();
  const principal = { userId: new Types.ObjectId().toHexString(), tenantId: tenantA.toHexString(), roles: ["viewer" as SystemRole] };
  const originalFindOne = Membership.findOne;

  Membership.findOne = () => ({ lean: async () => null }) as any;

  try {
    await assert.rejects(async () => {
      const { validateActiveMembership } = await import("./middleware/authorize.js");
      return validateActiveMembership(principal);
    }, /TENANT_ACCESS_DENIED/);
  } finally {
    Membership.findOne = originalFindOne;
  }
});
