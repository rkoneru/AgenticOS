import { ROLE_RANK } from "@axis/control-plane";
import { forbidden } from "./errors.js";
import type { PlatformPrincipal, Principal, TenantPrincipal } from "./types.js";

/** Minimum control-plane role rank per action (the control plane's role ladder: owner > admin > builder/operator > auditor/billing > viewer). */
export const ACTION_MIN_RANK = {
  "registry.read": ROLE_RANK.viewer,
  "registry.publish": ROLE_RANK.builder,
  "registry.yank": ROLE_RANK.admin,
  "registry.keys.manage": ROLE_RANK.admin,
  "registry.namespace.claim": ROLE_RANK.admin,
} as const;
export type RegistryAction = keyof typeof ACTION_MIN_RANK;

export function isTenant(p: Principal): p is TenantPrincipal {
  return p.kind === "tenant";
}

/** Throws `forbidden` unless a tenant principal's role reaches the action's minimum. Unknown roles/actions are denied. */
export function requireTenant(p: Principal, action: RegistryAction): TenantPrincipal {
  if (!isTenant(p)) throw forbidden("tenant credential required");
  const need = ACTION_MIN_RANK[action];
  const have = (ROLE_RANK as Record<string, number | undefined>)[p.role];
  if (need === undefined || have === undefined || have < need)
    throw forbidden(`role ${String(p.role)} may not ${action}`);
  return p;
}

export function requirePlatform(
  p: Principal,
  service: PlatformPrincipal["service"] = "marketplace",
): PlatformPrincipal {
  if (p.kind !== "platform" || p.service !== service)
    throw forbidden("platform credential required");
  return p;
}
