import { GovernanceError, PRIVACY_OFFICER, type Principal } from "./types.js";

/** Every governance operation is tenant-scoped and needs the privacy_officer role of THAT tenant. */
export function requireOfficer(p: Principal, tenantId: string): void {
  if (p.tenantId !== tenantId || !p.roles.includes(PRIVACY_OFFICER))
    throw new GovernanceError("forbidden", "privacy_officer role required for this tenant");
}
