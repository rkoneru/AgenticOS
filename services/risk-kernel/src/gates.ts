import type { CounterStore, KillScope, KillSwitchStore } from "./stores.js";
import type { GateRequest, PolicyGate } from "./types.js";

export interface GateEnv {
  now: number;
  req: GateRequest;
  killSwitches: KillSwitchStore;
  counters: CounterStore;
}

export interface GateResult {
  pass: boolean;
  /** Never contains request values (PHI-safe); names fields and limits only. */
  reason: string;
  /** Undoes a reservation this gate made; the kernel calls it if a later gate or the audit append fails. */
  rollback?: () => Promise<void>;
}

const FUTURE_SKEW_MS = 5000;

/** Injection-proof counter key: each part is JSON-encoded, so ':' (or any char) in an agent/target name cannot collide. */
export const key = (...parts: string[]): string => JSON.stringify(parts);

export function getPath(obj: unknown, path: string): unknown {
  let cur: unknown = obj;
  for (const part of path.split(".")) {
    if (typeof cur !== "object" || cur === null || !Object.prototype.hasOwnProperty.call(cur, part))
      return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

const fail = (id: string, why: string): GateResult => ({
  pass: false,
  reason: `gate ${id}: ${why}`,
});
const ok = (id: string, why = "ok"): GateResult => ({ pass: true, reason: `gate ${id}: ${why}` });

const num = (v: unknown): number | undefined =>
  typeof v === "number" && Number.isFinite(v) ? v : undefined;

function utc(nowMs: number): { h: string; d: string; m: string } {
  const iso = new Date(nowMs).toISOString(); // 2026-01-02T03:04:05.000Z
  return { h: iso.slice(0, 13), d: iso.slice(0, 10), m: iso.slice(0, 7) };
}

/**
 * Key under which TKI (Phase 3) accumulates spend that `budget` gates read.
 * Format is a contract between the kernel and TKI: changing it needs an ADR.
 */
export function budgetKey(
  tenantId: string,
  agent: string,
  metric: string,
  window: string,
  nowMs: number,
  runId = "",
): string {
  const t = utc(nowMs);
  const w =
    window === "run"
      ? `run:${runId}`
      : window === "hour"
        ? `h:${t.h}`
        : window === "day"
          ? `d:${t.d}`
          : `m:${t.m}`;
  return key("spent", tenantId, agent, metric, w);
}

async function killSwitch(g: PolicyGate, env: GateEnv): Promise<GateResult> {
  const scope = g.scope as KillScope | undefined;
  if (scope !== "global" && scope !== "tenant" && scope !== "agent" && scope !== "tool")
    return fail(g.id, "invalid scope");
  const engaged = await env.killSwitches.isEngaged(scope, {
    tenantId: env.req.tenant_id,
    agent: env.req.blueprint.name,
    tool: getPath(env.req.context, "tool.name") as string | undefined,
  });
  return engaged ? fail(g.id, `kill-switch engaged (${scope})`) : ok(g.id);
}

function staleness(g: PolicyGate, env: GateEnv): GateResult {
  const field = g.params["field"];
  const maxAge = num(g.params["maxAgeSeconds"]);
  if (typeof field !== "string" || maxAge === undefined) return fail(g.id, "invalid params");
  const raw = getPath(env.req.context, field);
  const ts = typeof raw === "number" ? raw : typeof raw === "string" ? Date.parse(raw) : NaN;
  if (!Number.isFinite(ts)) return fail(g.id, `${field} missing or not a timestamp`);
  const age = env.now - ts;
  if (age < -FUTURE_SKEW_MS) return fail(g.id, `${field} is in the future`);
  return age > maxAge * 1000 ? fail(g.id, `${field} older than ${maxAge}s`) : ok(g.id);
}

function amountCap(g: PolicyGate, env: GateEnv): GateResult {
  const field = g.params["field"];
  const max = num(g.params["max"]);
  if (typeof field !== "string" || max === undefined) return fail(g.id, "invalid params");
  const v = num(getPath(env.req.context, field));
  if (v === undefined) return fail(g.id, `${field} missing or not a number`);
  return v > max ? fail(g.id, `${field} exceeds cap ${max}`) : ok(g.id);
}

async function targetCap(g: PolicyGate, env: GateEnv): Promise<GateResult> {
  const field = g.params["field"];
  const max = num(g.params["max"]);
  if (typeof field !== "string" || max === undefined) return fail(g.id, "invalid params");
  const v = num(getPath(env.req.context, field));
  if (v === undefined || v < 0) return fail(g.id, `${field} missing, not a number or negative`);
  const targetRaw =
    getPath(env.req.context, "args.target") ?? getPath(env.req.context, "tool.name");
  const target =
    g.params["perTarget"] === false ? "*" : typeof targetRaw === "string" ? targetRaw : undefined;
  if (target === undefined) return fail(g.id, "no target to attribute the amount to");
  const ctr = key(
    "target",
    env.req.tenant_id,
    env.req.blueprint.name,
    g.id,
    target,
    utc(env.now).d,
  );
  // Atomic reserve: parallel requests cannot each pass a read-then-add check and jointly exceed the cap.
  if (!(await env.counters.reserve(ctr, v, max)))
    return fail(g.id, `cumulative cap ${max} would be exceeded`);
  return {
    pass: true,
    reason: `gate ${g.id}: ok`,
    rollback: async () => void (await env.counters.add(ctr, -v)),
  };
}

async function budget(g: PolicyGate, env: GateEnv): Promise<GateResult> {
  const metric = g.params["metric"];
  const window = g.params["window"];
  const hard = num(g.params["hard"]);
  const soft = num(g.params["soft"]);
  if (
    typeof metric !== "string" ||
    typeof window !== "string" ||
    (hard === undefined && soft === undefined)
  ) {
    return fail(g.id, "invalid params");
  }
  const runId = getPath(env.req.context, "run.id");
  if (window === "run" && typeof runId !== "string")
    return fail(g.id, "run.id missing for run-scoped budget");
  const spent = await env.counters.get(
    budgetKey(
      env.req.tenant_id,
      env.req.blueprint.name,
      metric,
      window,
      env.now,
      typeof runId === "string" ? runId : "",
    ),
  );
  if (hard !== undefined && spent >= hard) return fail(g.id, `hard ${metric} budget reached`);
  if (soft !== undefined && spent >= soft) return ok(g.id, `soft ${metric} budget crossed`);
  return ok(g.id);
}

async function rateLimit(g: PolicyGate, env: GateEnv): Promise<GateResult> {
  const max = num(g.params["max"]);
  const windowSeconds = num(g.params["windowSeconds"]);
  if (max === undefined || windowSeconds === undefined) return fail(g.id, "invalid params");
  const by = (g.params["key"] as string | undefined) ?? "agent";
  const parts: Record<string, string | undefined> = {
    tenant: "*",
    agent: env.req.blueprint.name,
    tool: getPath(env.req.context, "tool.name") as string | undefined,
    actor: `${env.req.actor.type}:${env.req.actor.id}`,
  };
  const who = parts[by];
  if (who === undefined) return fail(g.id, `cannot resolve rate-limit key "${by}"`);
  const count = await env.counters.hit(
    key("rate", env.req.tenant_id, g.id, by, who),
    windowSeconds * 1000,
    env.now,
  );
  return count > max ? fail(g.id, `rate limit ${max}/${windowSeconds}s exceeded`) : ok(g.id);
}

/** Evaluates one gate. Any exception, unknown type or bad params is a failed gate (fail-closed). */
export async function evaluateGate(g: PolicyGate, env: GateEnv): Promise<GateResult> {
  try {
    switch (g.type) {
      case "kill_switch":
        return await killSwitch(g, env);
      case "staleness":
        return staleness(g, env);
      case "amount_cap":
        return amountCap(g, env);
      case "target_cap":
        return await targetCap(g, env);
      case "budget":
        return await budget(g, env);
      case "rate_limit":
        return await rateLimit(g, env);
      default:
        return fail(g.id, `unknown gate type "${g.type}"`);
    }
  } catch {
    return fail(g.id, "evaluation error");
  }
}
