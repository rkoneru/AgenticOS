import { ROLE_RANK } from "@axis/control-plane";
import { RegistryError, forbidden, type RegistryService, type ServiceAudit } from "@axis/registry";
import { randomUUID } from "node:crypto";
import { DocConflict, DocForbidden, type DocStore } from "./docstore.js";
import type { StaffPrincipal, TenantPrincipal } from "./types.js";

export const MIN_RANK = {
  read: ROLE_RANK.viewer,
  publish: ROLE_RANK.builder, // submit reviews, create listings
  admin: ROLE_RANK.admin, // verification, baselines, installs, consent
} as const;
export type Need = keyof typeof MIN_RANK;

export interface Ctx {
  docs: DocStore;
  registry: RegistryService;
  audit: ServiceAudit;
  now: () => Date;
  newId: () => string;
}

export function makeCtx(c: Omit<Ctx, "now" | "newId"> & Partial<Pick<Ctx, "now" | "newId">>): Ctx {
  return { ...c, now: c.now ?? (() => new Date()), newId: c.newId ?? randomUUID };
}

export function requireRole(p: TenantPrincipal, need: Need): TenantPrincipal {
  if (p?.kind !== "tenant") throw forbidden("tenant credential required");
  const have = (ROLE_RANK as Record<string, number | undefined>)[p.role];
  if (have === undefined || have < MIN_RANK[need])
    throw forbidden(`role ${String(p.role)} is not allowed`);
  return p;
}

export function requireStaff(p: StaffPrincipal, kind: StaffPrincipal["kind"]): StaffPrincipal {
  if (p?.kind !== kind || typeof p.subject !== "string" || p.subject === "")
    throw forbidden(`${kind} credential required`);
  return p;
}

/** Translates store-level conflicts into API errors. */
export async function guarded<T>(fn: () => Promise<T>, what: string): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof DocConflict)
      throw new RegistryError(
        "conflict",
        `${what}: conflicting concurrent change or already exists`,
      );
    if (e instanceof DocForbidden) throw forbidden(`${what}: not permitted`);
    throw e;
  }
}

/**
 * authorize (caller) -> audit the decision into `tenantId`'s chain -> perform -> audit the outcome. A decision that cannot be written
 * is not performed; a failed action is audited as DENY with its code.
 */
export async function mutate<T>(
  c: Ctx,
  tenantId: string,
  actor: { type: "human" | "system"; id: string },
  action: string,
  detail: Record<string, unknown>,
  fn: () => Promise<T>,
): Promise<T> {
  await c.audit.record({
    tenantId,
    actor,
    action,
    decision: "ALLOW",
    reason: "authorized",
    inputs: detail,
  });
  try {
    const out = await fn();
    await c.audit
      .record({
        tenantId,
        actor,
        action: `${action}.done`,
        decision: "ALLOW",
        reason: "ok",
        inputs: detail,
      })
      .catch(() => undefined);
    return out;
  } catch (err) {
    const code = err instanceof RegistryError ? err.code : "error";
    const checks = err instanceof RegistryError ? err.checks.join(",") : "";
    await c.audit
      .record({
        tenantId,
        actor,
        action: `${action}.failed`,
        decision: "DENY",
        reason: `code=${code} checks=${checks}`,
        inputs: detail,
      })
      .catch(() => undefined);
    throw err;
  }
}

export async function denyAudit(
  c: Ctx,
  tenantId: string,
  actor: string,
  action: string,
  err: unknown,
): Promise<never> {
  await c.audit
    .record({
      tenantId,
      actor: { type: "human", id: actor },
      action,
      decision: "DENY",
      reason: `code=${err instanceof RegistryError ? err.code : "error"}`,
    })
    .catch(() => undefined);
  throw err;
}

export const iso = (d: Date): string => d.toISOString();
