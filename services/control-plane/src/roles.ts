export const ROLES = [
  "owner",
  "admin",
  "builder",
  "operator",
  "auditor",
  "billing",
  "viewer",
  "privacy_officer",
] as const;
export type Role = (typeof ROLES)[number];

/** Privilege rank. A member may grant or modify only roles at or below their own (the role ceiling). */
export const ROLE_RANK: Readonly<Record<Role, number>> = {
  owner: 100,
  admin: 80,
  builder: 50,
  operator: 50,
  auditor: 40,
  billing: 40,
  viewer: 10,
  // Handles personal-data requests (DSAR, legal holds, retention); no other privilege (ADR 0111).
  privacy_officer: 40,
};

export const isRole = (v: unknown): v is Role =>
  typeof v === "string" && (ROLES as readonly string[]).includes(v);

/** Roles an IdP (SCIM, JIT) may ever produce. `owner` is never assignable from outside the tenant's own admins. */
export const EXTERNAL_ROLES: readonly Role[] = [
  "admin",
  "builder",
  "operator",
  "auditor",
  "billing",
  "viewer",
  "privacy_officer",
];
export const isExternalRole = (v: unknown): v is Role =>
  isRole(v) && (EXTERNAL_ROLES as readonly string[]).includes(v);

/** True when `actor` may grant `target` to someone, or may act on a member who currently holds `target`. */
export const withinCeiling = (actor: Role, target: Role): boolean =>
  ROLE_RANK[target] <= ROLE_RANK[actor];

export const maxRole = (roles: readonly Role[]): Role | undefined =>
  roles.reduce<Role | undefined>(
    (m, r) => (m === undefined || ROLE_RANK[r] > ROLE_RANK[m] ? r : m),
    undefined,
  );
