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
  recompute,
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

export const DET = { id: "exact", kind: "deterministic", weight: 1, config: { type: "exact" } };
export const DET2 = { id: "contains", kind: "deterministic", weight: 1, config: { type: "contains", values: ["x"] } };
export const HUMAN = { id: "human", kind: "human", weight: 1, config: { rubric: "Is the answer helpful?", sla_hours: 24 } };

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
  await w.hub.datasets.create(w.builder, { name: "ds", cases: o.cases ?? CASES, ...(o.phi ? { phi: true } : {}) });
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

export type ScoreFn = number | ((caseId: string, graderId: string) => number | null);

/** Runner-shaped case results: one grade per grader; `null` from a ScoreFn = a pending (human) grade. */
export function caseResults(ids: string[], graders: string[], score: ScoreFn, kinds: Record<string, string> = {}): CaseResultIn[] {
  return ids.map((id) => ({
    case_id: id,
    status: "completed",
    attempts: 1,
    seed: 11,
    error: null,
    score: null,
    output: `answer ${id}`,
    grades: graders.map((g) => {
      const v = typeof score === "number" ? score : score(id, g);
      const kind = kinds[g] ?? (g === "human" ? "human" : "deterministic");
      return v === null
        ? { grader_id: g, kind, status: "pending", score: 0, detail: "awaiting_human_review", provenance: {} }
        : { grader_id: g, kind, status: "scored", score: v, detail: "", provenance: {} };
    }),
    trace: { trace_id: `tr-${id}`, cost_usd: "0.001000" },
  }));
}
export interface CaseResultIn {
  case_id: string;
  status: string;
  attempts: number;
  seed: number;
  error: string | null;
  score: number | null;
  output: string | null;
  grades: { grader_id: string; kind: string; status: string; score: number; detail: string; provenance: object }[];
  trace: object | null;
}

export const ZERO_COST = { agent_usd: "0.004", judge_usd: "0", total_usd: "0.004", tokens: 40, judge_tokens: 0 };

/** The honest submission for a run: aggregate computed with the hub's own algorithm (tests of the algorithm use the shared vectors). */
export async function payloadFor(
  w: World,
  run: EvalRunDoc,
  results: CaseResultIn[],
  o: { status?: "completed" | "pending_human" | "failed"; runnerId?: string; patch?: (p: Record<string, unknown>) => void } = {},
): Promise<Record<string, unknown>> {
  const suite = await w.hub.suites.get(w.admin, run.suite_ref);
  const agg = recompute(results as never, suite);
  const withScores = results.map((r) => ({ ...r, score: agg.status === "complete" ? (agg.per_case[r.case_id] ?? null) : null }));
  const p: Record<string, unknown> = {
    runner_id: o.runnerId ?? "runner-1",
    run_id: run.id,
    mode: run.mode,
    status: o.status ?? (agg.status === "complete" ? "completed" : "pending_human"),
    suite_ref: run.suite_ref,
    blueprint: { name: run.blueprint.name, version: run.blueprint.version, content_hash: run.content_hash },
    started_at: "2026-10-08T12:00:00Z",
    finished_at: "2026-10-08T12:00:05Z",
    scores: agg,
    case_results: withScores,
    cost: ZERO_COST,
    provenance: {
      runner_version: "1.0.0",
      runner_id: o.runnerId ?? "runner-1",
      aggregation_version: 1,
      seed: run.seed,
      model_ids: ["scripted/model-1"],
      blueprint_content_hash: run.content_hash,
      dataset_ref: run.dataset_ref,
      dataset_version_hash: run.dataset_hash,
      suite_ref: run.suite_ref,
      judges: {},
      eval_mode: { allow_sandboxed: [] },
    },
  };
  o.patch?.(p);
  return p;
}

/** Runs the whole flow with uniform per-case scores for the suite's non-human graders and returns the stored run. */
export async function runWithScore(
  w: World,
  o: {
    hash?: string;
    score?: ScoreFn;
    suite?: string;
    graders?: string[];
    name?: string;
    version?: string;
    namespace?: string | null;
    runner?: HubPrincipal;
    patch?: (p: Record<string, unknown>) => void;
  } = {},
): Promise<EvalRunDoc> {
  const graders = o.graders ?? ["exact", "contains"];
  const runner = o.runner ?? w.runner;
  const run = await w.hub.runs.startAsRunner(runner, {
    suite_ref: o.suite ?? "smoke@1.0.0",
    blueprint: bp(o.hash ?? HASH_A, o.name ?? "support-agent", o.version ?? "1.0.0", o.namespace ?? null),
  });
  const results = caseResults(["c1", "c2", "c3", "c4"], graders, o.score ?? 1);
  const runnerId = (runner as { runnerId: string }).runnerId;
  return w.hub.runs.submitResults(runner, run.id, await payloadFor(w, run, results, { runnerId, ...(o.patch ? { patch: o.patch } : {}) }));
}

/** The tenant's audit events (optionally only these actions). */
export async function events(w: World, ...actions: string[]) {
  const all = await w.audit.read(w.tenant);
  return actions.length === 0 ? all : all.filter((e) => actions.includes(e.action));
}
export const mean = (xs: number[]): number => xs.reduce((a, b) => a + b, 0) / xs.length;
