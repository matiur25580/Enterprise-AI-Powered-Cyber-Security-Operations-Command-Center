import { Types, type FilterQuery } from "mongoose";

export interface TenantOwned {
  tenantId: Types.ObjectId;
}

export interface OrganizationOwned {
  organizationId: Types.ObjectId;
}

export function normalizeTenantId(tenantId: string | undefined): string {
  if (typeof tenantId !== "string" || !Types.ObjectId.isValid(tenantId)) {
    throw new Error("A valid authenticated tenant context is required.");
  }

  return tenantId;
}

export function assertTenantContextMatches(
  principalTenantId: string | undefined,
  suppliedTenantId: string | undefined,
): void {
  const currentTenantId = normalizeTenantId(principalTenantId);
  if (suppliedTenantId !== undefined && suppliedTenantId !== null && suppliedTenantId !== "") {
    const requestedTenantId = normalizeTenantId(suppliedTenantId);
    if (requestedTenantId !== currentTenantId) {
      throw new Error("TENANT_CONTEXT_MISMATCH");
    }
  }
}

export function rejectTenantOverride(
  principalTenantId: string | undefined,
  candidateTenantId: unknown,
  fieldName = "tenantId",
): void {
  if (candidateTenantId === undefined || candidateTenantId === null || candidateTenantId === "") {
    return;
  }

  const currentTenantId = normalizeTenantId(principalTenantId);
  const tenantId = String(candidateTenantId);

  if (tenantId !== currentTenantId) {
    throw new Error(`TENANT_CONTEXT_MISMATCH:${fieldName}`);
  }
}

/**
 * Always compose tenant scope into database filters for tenant-owned records.
 * The tenant ID must come from the authenticated server-side principal, never
 * directly from an untrusted request body or query string.
 */
export function withTenantScope<T extends TenantOwned | OrganizationOwned>(
  tenantId: string,
  filter: FilterQuery<T> = {},
  scopeField: "tenantId" | "organizationId" = "tenantId",
): FilterQuery<T> {
  const validTenantId = normalizeTenantId(tenantId);

  return {
    ...filter,
    [scopeField]: new Types.ObjectId(validTenantId),
  } as FilterQuery<T>;
}
