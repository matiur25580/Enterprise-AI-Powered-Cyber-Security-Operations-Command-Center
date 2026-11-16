import { Types } from "mongoose";

import type { AuthenticatedPrincipal } from "./middleware/authorize.js";

export interface SocketTenantAuthorizationResult {
  ok: boolean;
  code?: string;
  tenantId?: string;
}

export function authorizeSocketTenantSubscription(
  principal: AuthenticatedPrincipal | undefined,
  requestedTenantId: unknown,
): SocketTenantAuthorizationResult {
  if (!principal) {
    return { ok: false, code: "UNAUTHENTICATED" };
  }

  if (typeof requestedTenantId !== "string" || !Types.ObjectId.isValid(requestedTenantId)) {
    return { ok: false, code: "INVALID_TENANT_CONTEXT" };
  }

  if (requestedTenantId !== principal.tenantId) {
    return { ok: false, code: "UNAUTHORIZED_TENANT" };
  }

  return { ok: true, tenantId: requestedTenantId };
}
