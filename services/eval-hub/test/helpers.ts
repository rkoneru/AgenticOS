import { randomBytes, randomUUID } from "node:crypto";
import { MemoryAuditLog } from "@axis/audit";
import { ServiceAudit, generatePublisherKey } from "@axis/registry";
import pg from "pg";
import { inject } from "vitest";
import {
  MemoryDocStore,
  PgDocStore,
  createEvalHub,
  type BlueprintRef,
  type DocStore,
  type EvalHub,
  type EvalRunDoc,
  type HubPrincipal,
  type HubRole,
  type PublisherLookup,
  type Suite,
} from "../src/index.js";

export const hex = (n: number): string => randomBytes(n / 2).toString("hex");
export const newPool = (max = 10): pg.Pool =>
  new pg.Pool({ connectionString: inject("dbUrl"), max });

export class Clock {
  constructor(public t: Date) {}
  now = (): Date => new Date(this.t.getTime());
  advance(ms: number): void {
    this.t = new Date(this.t.getTime() + ms);
  }
}
export const DAY = 86_400_000;
export const HOUR = 3_600_000;

export async function adminClient(): Promise<pg.Client> {
  const c = new pg.Client({ connectionString: inject("dbUrl") });
  await c.connect();
  return c;
}
export async function newTenantRow(admin: pg.Client): Promise<string> {
  const id = randomUUID();
  await admin.query(
    "INSERT INTO tenants (id, slug, name, region) VALUES ($1, $2, $2, 'us-east-1')",
    [id, `t-${hex(10)}`],
  );
  return id;
}

export const user = (
  tenantId: string,
  role: HubRole = "admin",
  subject = `user-${role}`,
): HubPrincipal => ({
  kind: "tenant",
  tenantId,
  subject,
  role,
});
export const runnerOf = (tenantId: string, runnerId = "runner-1"): HubPrincipal => ({
  kind: "runner",
  tenantId,
  runnerId,
});

export const HASH_A = "a".repeat(64);
export const HASH_B = "b".repeat(64);
export const bp = (
  hash = HASH_A,
  name = "support-agent",
  version = "1.0.0",
  namespace: string | null = null,
): BlueprintRef => ({
  namespace,
  name,
  version,
  content_hash: hash,
});

export interface World {
  hub: EvalHub;
  docs: DocStore;
  audit: MemoryAuditLog;
  clock: Clock;
  tenant: string;
  admin: HubPrincipal;
  builder: HubPrincipal;
  runner: HubPrincipal;
}

export const publishers = (m: Record<string, string>): PublisherLookup => ({
  publisherOf: (_t, b) => Promise.resolve(m[`${b.name}@${b.version}`] ?? null),
});

export function world(
  o: {
    docs?: DocStore;
    tenant?: string;
    publishers?: PublisherLookup;
    start?: string;
    sink?: never;
  } = {},
): World {
  const clock = new Clock(new Date(o.start ?? "2026-10-08T12:00:00Z"));
  const audit = new MemoryAuditLog({ now: clock.now });
  const docs = o.docs ?? new MemoryDocStore();
  const tenant = o.tenant ?? randomUUID();
  const hub = createEvalHub({
    docs,
    audit: new ServiceAudit(audit, "eval-hub", clock.now),
    now: clock.now,
    ...(o.publishers ? { publishers: o.publishers } : {}),
  });
  return {
    hub,
    docs,
    audit,
    clock,
    tenant,
    admin: user(tenant, "admin", "alice-admin"),
    builder: user(tenant, "builder", "bob-builder"),
    runner: runnerOf(tenant),
  };
}

export const CASES = ["c1", "c2", "c3", "c4"].map((id) => ({
  id,
  input: { q: `question ${id}` },
  expected: `answer ${id}`,
}));

export const DET = { id: "exact", type: "deterministic", kind: "exact", weight: 1 };
export const DET2 = { id: "contains", type: "deterministic", kind: "contains", weight: 1 };
export const HUMAN = {
  id: "human",
  type: "human",
  rubric: "Is the answer helpful?",
  weight: 1,
  sla_hours: 24,
};

/** dataset `ds@1` with CASES and suite `smoke@1.0.0` (graders given), pass_threshold 0.8. */
export async function seedSuite(
  w: World,
  o: {
    graders?: unknown[];
    pass_threshold?: number;
    tolerance?: number;
    cases?: unknown[];
    suite?: Record<string, unknown>;
    phi?: boolean;
    ref?: string;
  } = {},
): Promise<Suite> {
  await w.hub.datasets.create(w.builder, {
    name: "ds",
    cases: o.cases ?? CASES,
    ...(o.phi ? { phi: true } : {}),
  });
  const latest = await w.hub.datasets.get(w.builder, "ds@latest");
  return w.hub.suites.create(w.builder, {
    ref: o.ref ?? "smoke@1.0.0",
    dataset_ref: latest.ref,
    graders: o.graders ?? [DET, DET2],
    pass_threshold: o.pass_threshold ?? 0.8,
    ...(o.tolerance !== undefined ? { tolerance: o.tolerance } : {}),
    ...(o.suite ?? {}),
  });
}

export async function registerRunner(w: World, id = "runner-1"): Promise<void> {
  await w.hub.runs.registerRunner(w.admin, id);
}

export const PROV = { runner_version: "axis-runner/0.1.0", model_ids: ["scripted-1"], seed: 7 };

/** Per-case scores: `s[caseId]` is either a number (all graders) or a grader map. Aggregate computed by the caller or by `claimFor`. */
export function caseResults(
  ids: string[],
  graders: string[],
  score: number | ((id: string, g: string) => number | null),
): Record<string, unknown>[] {
  return ids.map((id) => ({
    case_id: id,
    scores: Object.fromEntries(
      graders.map((g) => [g, typeof score === "number" ? score : score(id, g)]),
    ),
    cost_usd: 0.01,
  }));
}

export const mean = (xs: number[]): number => xs.reduce((a, b) => a + b, 0) / xs.length;

/** Runs the whole flow for equal-weight graders: start as runner, submit uniform per-case scores, return the final run. */
export async function runWithScore(
  w: World,
  o: {
    hash?: string;
    score?: number | ((id: string, g: string) => number);
    suite?: string;
    graders?: string[];
    name?: string;
    version?: string;
    namespace?: string | null;
    runner?: HubPrincipal;
  } = {},
): Promise<EvalRunDoc> {
  const graders = o.graders ?? ["exact", "contains"];
  const runner = o.runner ?? w.runner;
  const run = await w.hub.runs.startAsRunner(runner, {
    suite_ref: o.suite ?? "smoke@1.0.0",
    blueprint: bp(
      o.hash ?? HASH_A,
      o.name ?? "support-agent",
      o.version ?? "1.0.0",
      o.namespace ?? null,
    ),
  });
  const score = o.score ?? 1;
  const results = caseResults(["c1", "c2", "c3", "c4"], graders, score);
  const per = results.map((r) => mean(Object.values(r["scores"] as Record<string, number>)));
  const perGrader = Object.fromEntries(
    graders.map((g) => [
      g,
      mean(results.map((r) => (r["scores"] as Record<string, number>)[g] as number)),
    ]),
  );
  return w.hub.runs.submitResults(runner, run.id, {
    case_results: results,
    scores: { overall: mean(per), per_grader: perGrader },
    provenance: PROV,
  });
}

export { generatePublisherKey, PgDocStore };

/** The tenant's audit events (optionally only these actions). */
export async function events(w: World, ...actions: string[]) {
  const all = await w.audit.read(w.tenant);
  return actions.length === 0 ? all : all.filter((e) => actions.includes(e.action));
}
