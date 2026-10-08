import { randomUUID } from "node:crypto";
import { ServiceAudit } from "@axis/registry";
import { DocConflict, DocForbidden, type DocStore } from "./docstore.js";
import { HubError, conflict, forbidden } from "./errors.js";
import { actorOf } from "./authz.js";
import type { RedactionHook } from "./redact.js";
import type { BlueprintRef, HubPrincipal } from "./types.js";

/** Looks up who published a blueprint version (registry). Used to keep the publisher out of the human review queue. */
export interface PublisherLookup {
  publisherOf(tenantId: string, blueprint: BlueprintRef): Promise<string | null>;
}

export interface Ctx {
  docs: DocStore;
  audit: ServiceAudit;
  now: () => Date;
  newId: () => string;
  redact?: RedactionHook;
  publishers?: PublisherLookup;
  /** How long a reviewer's claim on a task holds (default 30 min). */
  claimTtlMs: number;
  /** Largest dataset (cases). */
  maxCases: number;
  log?: (msg: string, fields?: Record<string, unknown>) => void;
}

export interface CtxOptions {
  docs: DocStore;
  audit: ServiceAudit;
  now?: () => Date;
  newId?: () => string;
  redact?: RedactionHook;
  publishers?: PublisherLookup;
  claimTtlMs?: number;
  maxCases?: number;
  log?: Ctx["log"];
}

export function makeCtx(o: CtxOptions): Ctx {
  return {
    docs: o.docs,
    audit: o.audit,
    now: o.now ?? (() => new Date()),
    newId: o.newId ?? randomUUID,
    ...(o.redact ? { redact: o.redact } : {}),
    ...(o.publishers ? { publishers: o.publishers } : {}),
    claimTtlMs: o.claimTtlMs ?? 30 * 60_000,
    maxCases: o.maxCases ?? 5000,
    ...(o.log ? { log: o.log } : {}),
  };
}

export const iso = (d: Date): string => d.toISOString();

/** Translates store-level conflicts into API errors. */
export async function guarded<T>(fn: () => Promise<T>, what: string): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof DocConflict)
      throw conflict(`${what}: conflicting concurrent change or already exists`);
    if (e instanceof DocForbidden) throw forbidden(`${what}: not permitted`);
    throw e;
  }
}

/**
 * authorize (caller) -> audit the decision into the tenant's chain -> perform -> audit the outcome. A decision that cannot be written
 * is not performed (the audit throws `unavailable`); a failed action is audited as DENY with its code.
 */
export async function mutate<T>(
  c: Ctx,
  p: HubPrincipal,
  action: string,
  detail: Record<string, unknown>,
  fn: () => Promise<T>,
): Promise<T> {
  const actor = actorOf(p);
  const tenantId = p.tenantId;
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
    const code = err instanceof HubError ? err.code : "error";
    const checks = err instanceof HubError ? err.checks.join(",") : "";
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

/** Audits a refused call (authorization failure) and rethrows. */
export async function denyAudit(
  c: Ctx,
  p: HubPrincipal,
  action: string,
  err: unknown,
): Promise<never> {
  if (p && typeof p.tenantId === "string")
    await c.audit
      .record({
        tenantId: p.tenantId,
        actor: actorOf(p),
        action,
        decision: "DENY",
        reason: `code=${err instanceof HubError ? err.code : "error"}`,
      })
      .catch(() => undefined);
  throw err;
}
