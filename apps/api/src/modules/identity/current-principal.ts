import type { AccessClaims } from "./token.js";

interface ActiveMembership {
  userId: { toString(): string } | string;
  tenantId: { toString(): string } | string;
  roles: AccessClaims["roles"];
  status: "active" | "suspended";
}

export function principalFromActiveMembership(
  claims: AccessClaims,
  membership: ActiveMembership | null | undefined,
): AccessClaims | null {
  if (!membership || membership.status !== "active") return null;
  if (membership.userId.toString() !== claims.userId || membership.tenantId.toString() !== claims.tenantId) return null;
  if (!Array.isArray(membership.roles) || membership.roles.length === 0) return null;

  return { ...claims, roles: membership.roles };
}
