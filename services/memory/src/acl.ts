import { createHash } from "node:crypto";
import { MemoryError, type Acl, type Principal } from "./types.js";

const MAX_ENTRIES = 100;
const MAX_LEN = 256;

export interface CanonicalAcl {
  users: string[];
  roles: string[];
  tenant: boolean;
}

function names(v: unknown, what: string): string[] {
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.length > MAX_ENTRIES)
    throw new MemoryError(
      "INVALID",
      `acl.${what} must be a list of at most ${MAX_ENTRIES} strings`,
    );
  for (const s of v)
    if (typeof s !== "string" || s === "" || s.length > MAX_LEN)
      throw new MemoryError("INVALID", `acl.${what} entries must be non-empty strings`);
  return [...new Set(v as string[])].sort();
}

/** Validates and canonicalises an ACL (sorted, deduplicated, unknown keys rejected). */
export function canonicalAcl(acl: Acl | undefined): CanonicalAcl {
  const a = (acl ?? {}) as Record<string, unknown>;
  for (const k of Object.keys(a))
    if (k !== "users" && k !== "roles" && k !== "tenant")
      throw new MemoryError("INVALID", `unknown acl key ${JSON.stringify(k)}`);
  if (a["tenant"] !== undefined && typeof a["tenant"] !== "boolean")
    throw new MemoryError("INVALID", "acl.tenant must be a boolean");
  return {
    users: names(a["users"], "users"),
    roles: names(a["roles"], "roles"),
    tenant: a["tenant"] === true,
  };
}

export function aclKey(acl: CanonicalAcl): string {
  return JSON.stringify({ roles: acl.roles, tenant: acl.tenant, users: acl.users });
}

export function hashContent(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

/**
 * The reference semantics of the ACL, used by tests as the oracle for the SQL predicate.
 * A principal may read iff the ACL is tenant-wide, lists the principal, or shares a group with it. Empty = nobody.
 */
export function aclAllows(acl: CanonicalAcl, who: Principal): boolean {
  if (acl.tenant) return true;
  if (acl.users.includes(who.id)) return true;
  return who.groups.some((g) => acl.roles.includes(g));
}

export function validatePrincipal(p: Principal): Principal {
  if (typeof p?.id !== "string" || p.id === "" || p.id.length > MAX_LEN)
    throw new MemoryError("INVALID", "principal.id required");
  if (!Array.isArray(p.groups) || p.groups.length > MAX_ENTRIES)
    throw new MemoryError("INVALID", "principal.groups must be a list");
  for (const g of p.groups)
    if (typeof g !== "string" || g === "" || g.length > MAX_LEN)
      throw new MemoryError("INVALID", "principal.groups entries must be non-empty strings");
  return { id: p.id, groups: [...new Set(p.groups)].sort() };
}

/**
 * SQL predicate mirroring `aclAllows`, with `$idParam` = principal id (text) and `$groupsParam` = groups (text[]).
 * Placed in the WHERE clause that selects rows, so unreadable rows never reach ORDER BY / LIMIT, scores or counts.
 */
export function aclSql(alias: string, idParam: number, groupsParam: number): string {
  return `(COALESCE(${alias}.acl @> '{"tenant": true}'::jsonb, false)
    OR COALESCE((${alias}.acl -> 'users') ? $${idParam}::text, false)
    OR COALESCE((${alias}.acl -> 'roles') ?| $${groupsParam}::text[], false))`;
}
