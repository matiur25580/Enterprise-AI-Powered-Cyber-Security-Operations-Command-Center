import { Types, type FilterQuery } from "mongoose";

export interface TenantOwned {
  tenantId: Types.ObjectId;
}

/**
 * Always compose tenant scope into database filters for tenant-owned records.
 * The tenant ID must come from the authenticated server-side principal, never
 * directly from an untrusted request body or query string.
 */
export function withTenantScope<T extends TenantOwned>(
  tenantId: string,
  filter: FilterQuery<T> = {},
): FilterQuery<T> {
  if (!Types.ObjectId.isValid(tenantId)) {
    throw new Error("A valid authenticated tenant context is required.");
  }

  return {
    ...filter,
    tenantId: new Types.ObjectId(tenantId),
  } as FilterQuery<T>;
}
