import { randomUUID } from "node:crypto";
import type { ComplianceActor } from "./authz.js";
import type { ComplianceAudit } from "./audit.js";
import { DocConflict, DocForbidden, type DocStore } from "./docstore.js";
import { ComplianceError, conflict, forbidden } from "./errors.js";

export interface Ctx {
  docs: DocStore;
  audit: ComplianceAudit;
  now: () => Date;
  newId: () => string;
  /** How long an assessment may wait for review before it is reported overdue (default 14 days). */
  reviewGraceMs: number;
}

export interface CtxOptions {
  docs: DocStore;
  audit: ComplianceAudit;
  now?: () => Date;
  newId?: () => string;
  reviewGraceMs?: number;
}

export function makeCtx(o: CtxOptions): Ctx {
  return {
    docs: o.docs,
    audit: o.audit,
    now: o.now ?? (() => new Date()),
    newId: o.newId ?? randomUUID,
    reviewGraceMs: o.reviewGraceMs ?? 14 * 86_400_000,
  };
}

export const actorOf = (p: ComplianceActor): { type: "human"; id: string } => ({
  type: "human",
  id: p.subject,
});

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
  p: ComplianceActor,
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
    const code = err instanceof ComplianceError ? err.code : "error";
    const checks = err instanceof ComplianceError ? err.checks.join(",") : "";
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
  p: ComplianceActor,
  action: string,
  err: unknown,
): Promise<never> {
  if (p && typeof p.tenantId === "string" && p.tenantId !== "")
    await c.audit
      .record({
        tenantId: p.tenantId,
        actor: actorOf(p),
        action,
        decision: "DENY",
        reason: `code=${err instanceof ComplianceError ? err.code : "error"}`,
      })
      .catch(() => undefined);
  throw err;
}

export const iso = (d: Date): string => d.toISOString();
