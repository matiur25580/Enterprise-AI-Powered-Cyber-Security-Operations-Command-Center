export const PERMISSIONS = {
  dashboardRead: "dashboard:read",
  eventsRead: "events:read",
  eventsIngest: "events:ingest",
  incidentsRead: "incidents:read",
  incidentsCreate: "incidents:create",
  incidentsInvestigate: "incidents:investigate",
  incidentsAssign: "incidents:assign",
  responseSimulate: "response:simulate",
  responseApprove: "response:approve",
  assetsRead: "assets:read",
  assetsManage: "assets:manage",
  grcRead: "grc:read",
  grcManage: "grc:manage",
  auditRead: "audit:read",
  usersManage: "users:manage",
  rolesManage: "roles:manage",
  organizationManage: "organization:manage",
} as const;

export type Permission = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

export const SYSTEM_ROLES = {
  superAdmin: "super_admin",
  socManager: "soc_manager",
  analystL1: "soc_analyst_l1",
  analystL2: "soc_analyst_l2",
  auditor: "auditor",
  viewer: "viewer",
} as const;

export type SystemRole = (typeof SYSTEM_ROLES)[keyof typeof SYSTEM_ROLES];

const allPermissions = Object.values(PERMISSIONS);

export const ROLE_PERMISSIONS: Record<SystemRole, readonly Permission[]> = {
  [SYSTEM_ROLES.superAdmin]: allPermissions,
  [SYSTEM_ROLES.socManager]: [
    PERMISSIONS.dashboardRead, PERMISSIONS.eventsRead, PERMISSIONS.eventsIngest,
    PERMISSIONS.incidentsRead, PERMISSIONS.incidentsCreate, PERMISSIONS.incidentsInvestigate,
    PERMISSIONS.incidentsAssign, PERMISSIONS.responseSimulate, PERMISSIONS.responseApprove,
    PERMISSIONS.assetsRead, PERMISSIONS.assetsManage, PERMISSIONS.grcRead,
    PERMISSIONS.grcManage, PERMISSIONS.auditRead, PERMISSIONS.usersManage,
  ],
  [SYSTEM_ROLES.analystL1]: [
    PERMISSIONS.dashboardRead, PERMISSIONS.eventsRead, PERMISSIONS.incidentsRead,
    PERMISSIONS.incidentsCreate, PERMISSIONS.incidentsInvestigate,
    PERMISSIONS.assetsRead, PERMISSIONS.grcRead,
  ],
  [SYSTEM_ROLES.analystL2]: [
    PERMISSIONS.dashboardRead, PERMISSIONS.eventsRead, PERMISSIONS.eventsIngest,
    PERMISSIONS.incidentsRead, PERMISSIONS.incidentsCreate, PERMISSIONS.incidentsInvestigate,
    PERMISSIONS.incidentsAssign, PERMISSIONS.responseSimulate,
    PERMISSIONS.assetsRead, PERMISSIONS.grcRead,
  ],
  [SYSTEM_ROLES.auditor]: [
    PERMISSIONS.dashboardRead, PERMISSIONS.eventsRead, PERMISSIONS.incidentsRead,
    PERMISSIONS.assetsRead, PERMISSIONS.grcRead, PERMISSIONS.auditRead,
  ],
  [SYSTEM_ROLES.viewer]: [
    PERMISSIONS.dashboardRead, PERMISSIONS.eventsRead, PERMISSIONS.incidentsRead,
    PERMISSIONS.assetsRead, PERMISSIONS.grcRead,
  ],
};

export function hasPermission(
  role: SystemRole,
  permission: Permission,
): boolean {
  return ROLE_PERMISSIONS[role]?.includes(permission) ?? false;
}
