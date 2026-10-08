import { createHash } from "node:crypto";
import { AggregationError, SCORE_EPSILON, mismatches, type Aggregate } from "./scoring.js";
import { attestationFor, type AttestationSink, type HubSigningKey } from "./attest.js";
import { actorOf, requireReader, requireRunner, requireTenant } from "./authz.js";
import { denyAudit, guarded, iso, mutate, type Ctx } from "./context.js";
import { DocConflict, type Doc } from "./docstore.js";
import {
  HubError,
  conflict,
  forbidden,
  integrityFailed,
  invalid,
  notFound,
  unavailable,
} from "./errors.js";
import { recompute, recordHashOf } from "./integrity.js";
import {
  HASH_RE,
  ID_RE,
  NAME_RE,
  SUITE_REF_RE,
  type BlueprintRef,
  type CaseResult,
  type DatasetVersion,
  type GradeRecord,
  type RunCost,
  type RunScores,
  type EvalRunDoc,
  type HubPrincipal,
  type ReviewTaskDoc,
  type RunMode,
  type RunnerActor,
  type Suite,
} from "./types.js";
import { FINAL } from "./types.js";

export interface RunnerDoc {
  runner_id: string;
  description: string | null;
  registered_by: string;
  registered_at: string;
  revoked_at: string | null;
  revoked_by: string | null;
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

export interface StartInput {
  suite_ref: unknown;
  blueprint: unknown;
  mode?: unknown;
}

/** The runner's submission (docs/spec/evals-runner.md section 7). Its `scores` are a CLAIM: the hub recomputes and rejects a mismatch. */
export type SubmitInput = Record<string, unknown>;
const AGGREGATION_VERSION = 1;

export interface ListFilter {
  status?: string;
  suite_ref?: string;
  blueprint_name?: string;
  content_hash?: string;
  mode?: string;
  limit?: number;
  cursor?: string;
}

const encodeCursor = (r: EvalRunDoc): string =>
  Buffer.from(`${r.created_at}|${r.id}`, "utf8").toString("base64url");
function decodeCursor(c: string): [string, string] {
  const t = Buffer.from(c, "base64url").toString("utf8");
  const i = t.indexOf("|");
  if (i < 0) throw invalid("malformed cursor", ["cursor"]);
  return [t.slice(0, i), t.slice(i + 1)];
}

export class RunService {
  constructor(
    private readonly c: Ctx,
    private readonly o: { signing?: HubSigningKey; sink?: AttestationSink } = {},
  ) {}

  // ---------------------------------------------------------------- runners
  /** Registers (or re-registers an unknown id) an eval runner for the tenant. A revoked id can never be used again. */
  async registerRunner(
    p: HubPrincipal,
    runnerId: string,
    description?: unknown,
  ): Promise<RunnerDoc> {
    try {
      requireTenant(p, "evals.admin");
    } catch (e) {
      return denyAudit(this.c, p, "evals.runner.register", e);
    }
    if (!ID_RE.test(runnerId)) throw invalid("runner id is malformed", ["runner_id"]);
    if (description !== undefined && (typeof description !== "string" || description.length > 500))
      throw invalid("description must be a string of at most 500 characters", ["description"]);
    const rec: RunnerDoc = {
      runner_id: runnerId,
      description: (description as string | undefined) ?? null,
      registered_by: (p as { subject: string }).subject,
      registered_at: iso(this.c.now()),
      revoked_at: null,
      revoked_by: null,
    };
    return mutate(this.c, p, "evals.runner.register", { runner_id: runnerId }, async () => {
      await guarded(() => this.c.docs.insert(p.tenantId, "runners", runnerId, rec), "runner");
      return rec;
    });
  }

  async revokeRunner(p: HubPrincipal, runnerId: string): Promise<RunnerDoc> {
    try {
      requireTenant(p, "evals.admin");
    } catch (e) {
      return denyAudit(this.c, p, "evals.runner.revoke", e);
    }
    return mutate(this.c, p, "evals.runner.revoke", { runner_id: runnerId }, async () => {
      const d = await this.c.docs.get<RunnerDoc>(p.tenantId, "runners", runnerId);
      if (!d) throw notFound("runner not found");
      if (d.data.revoked_at !== null) return d.data;
      const next = {
        ...d.data,
        revoked_at: iso(this.c.now()),
        revoked_by: (p as { subject: string }).subject,
      };
      await guarded(
        () => this.c.docs.update(p.tenantId, "runners", runnerId, d.rev, next),
        "runner",
      );
      return next;
    });
  }

  async listRunners(p: HubPrincipal): Promise<RunnerDoc[]> {
    requireTenant(p, "evals.admin");
    return (await this.c.docs.find<RunnerDoc>(p.tenantId, "runners")).map((d) => d.data);
  }

  /** Is `runnerId` registered for the tenant and not revoked? */
  async runnerActive(tenantId: string, runnerId: string): Promise<boolean> {
    const d = await this.c.docs.get<RunnerDoc>(tenantId, "runners", runnerId);
    return d !== undefined && d.data.revoked_at === null;
  }

  private async requireActiveRunner(p: RunnerActor): Promise<void> {
    if (!(await this.runnerActive(p.tenantId, p.runnerId)))
      throw forbidden("runner is not registered for this tenant");
  }

  // ---------------------------------------------------------------- starting runs
  private parseStart(input: StartInput): {
    suiteRef: string;
    blueprint: BlueprintRef;
    mode: RunMode;
  } {
    if (typeof input.suite_ref !== "string" || !SUITE_REF_RE.test(input.suite_ref))
      throw invalid("suite_ref must be name@version", ["suite_ref"]);
    const b = input.blueprint;
    if (!isObj(b)) throw invalid("blueprint is required", ["blueprint"]);
    if (typeof b["name"] !== "string" || !NAME_RE.test(b["name"]))
      throw invalid("blueprint.name is malformed", ["blueprint.name"]);
    if (typeof b["version"] !== "string" || b["version"].length === 0 || b["version"].length > 64)
      throw invalid("blueprint.version is malformed", ["blueprint.version"]);
    if (typeof b["content_hash"] !== "string" || !HASH_RE.test(b["content_hash"]))
      throw invalid("blueprint.content_hash must be a SHA-256 hex digest", [
        "blueprint.content_hash",
      ]);
    if (
      b["namespace"] !== undefined &&
      b["namespace"] !== null &&
      (typeof b["namespace"] !== "string" || !NAME_RE.test(b["namespace"]))
    )
      throw invalid("blueprint.namespace is malformed", ["blueprint.namespace"]);
    const mode = input.mode === undefined ? "ci" : input.mode;
    if (mode !== "ci" && mode !== "manual")
      throw invalid("mode must be ci or manual (online results use the sampling endpoint)", [
        "mode",
      ]);
    return {
      suiteRef: input.suite_ref,
      mode,
      blueprint: {
        namespace: (b["namespace"] as string | null | undefined) ?? null,
        name: b["name"],
        version: b["version"],
        content_hash: b["content_hash"],
      },
    };
  }

  private async newRun(
    tenantId: string,
    starter: string,
    runner: string | null,
    parsed: ReturnType<RunService["parseStart"]>,
  ): Promise<EvalRunDoc> {
    const suiteDoc = await this.c.docs.get<Suite>(tenantId, "suites", parsed.suiteRef);
    if (!suiteDoc) throw invalid("suite not found", ["suite_ref"]);
    const suite = suiteDoc.data;
    const now = iso(this.c.now());
    // Who published the blueprint decides who may NOT review it. When a lookup is wired and cannot answer, the run is not created
    // (fail-closed): a missing answer must not silently let the publisher into the review queue. `null` = not a registry blueprint.
    let publisher: string | null = null;
    try {
      publisher = (await this.c.publishers?.publisherOf(tenantId, parsed.blueprint)) ?? null;
    } catch {
      throw unavailable("the blueprint's publisher could not be determined");
    }
    const id = this.c.newId();
    const run: EvalRunDoc = {
      id,
      suite_ref: suite.ref,
      suite_hash: suite.suite_hash,
      dataset_ref: suite.dataset_ref,
      dataset_hash: suite.dataset_hash,
      pass_threshold: suite.pass_threshold,
      seed: parseInt(createHash("sha256").update(`seed|${id}`).digest("hex").slice(0, 8), 16) & 0x7fffffff,
      blueprint: parsed.blueprint,
      blueprint_name: parsed.blueprint.name,
      content_hash: parsed.blueprint.content_hash,
      mode: parsed.mode,
      status: runner === null ? "queued" : "running",
      requested_by: starter,
      publisher,
      runner_id: runner,
      created_at: now,
      started_at: runner === null ? null : now,
      finished_at: null,
      scores: null,
      case_results: [],
      sample_size: 0,
      cost: { agent_usd: "0", judge_usd: "0", total_usd: "0", tokens: 0, judge_tokens: 0 },
      provenance: null,
      pending_human: 0,
      passed: null,
      failure_reason: null,
      record_hash: null,
    };
    await guarded(() => this.c.docs.insert(tenantId, "runs", run.id, run), "run");
    return run;
  }

  /** A tenant member asks for a run: it is queued for a registered runner to pick up. */
  async request(p: HubPrincipal, input: StartInput): Promise<EvalRunDoc> {
    try {
      requireTenant(p, "evals.write");
    } catch (e) {
      return denyAudit(this.c, p, "evals.run.request", e);
    }
    const parsed = this.parseStart(input);
    return mutate(
      this.c,
      p,
      "evals.run.request",
      { suite_ref: parsed.suiteRef, content_hash: parsed.blueprint.content_hash },
      () => this.newRun(p.tenantId, (p as { subject: string }).subject, null, parsed),
    );
  }

  /** A registered runner starts a run itself (CI): it is `running` and owned by that runner from the first instant. */
  async startAsRunner(p: HubPrincipal, input: StartInput): Promise<EvalRunDoc> {
    const r = requireRunner(p);
    await this.requireActiveRunner(r);
    const parsed = this.parseStart(input);
    return mutate(
      this.c,
      p,
      "evals.run.start",
      { suite_ref: parsed.suiteRef, content_hash: parsed.blueprint.content_hash },
      () => this.newRun(p.tenantId, `runner:${r.runnerId}`, r.runnerId, parsed),
    );
  }

  /** The first registered runner to claim a queued run owns it. */
  async claim(p: HubPrincipal, runId: string): Promise<EvalRunDoc> {
    const r = requireRunner(p);
    await this.requireActiveRunner(r);
    return mutate(this.c, p, "evals.run.claim", { run_id: runId }, async () => {
      const d = await this.c.docs.get<EvalRunDoc>(p.tenantId, "runs", runId);
      if (!d) throw notFound("run not found");
      if (d.data.status !== "queued") throw conflict("run is not queued");
      const next: EvalRunDoc = {
        ...d.data,
        status: "running",
        runner_id: r.runnerId,
        started_at: iso(this.c.now()),
      };
      await guarded(() => this.c.docs.update(p.tenantId, "runs", runId, d.rev, next), "run");
      return next;
    });
  }

  /** `POST /runner/claim`: the runner takes the OLDEST queued run it can win (a lost race moves on to the next). `null` = nothing queued. */
  async claimNext(p: HubPrincipal): Promise<EvalRunDoc | null> {
    const r = requireRunner(p);
    await this.requireActiveRunner(r);
    const queued = (await this.c.docs.find<EvalRunDoc>(p.tenantId, "runs", { status: "queued" }))
      .map((d) => d.data)
      .sort((a, b) => (a.created_at === b.created_at ? (a.id < b.id ? -1 : 1) : a.created_at < b.created_at ? -1 : 1));
    for (const q of queued) {
      try {
        return await this.claim(p, q.id);
      } catch (e) {
        if (!(e instanceof HubError && e.code === "conflict")) throw e;
      }
    }
    return null;
  }

  // ---------------------------------------------------------------- results
  private async load(
    tenantId: string,
    suiteRef: string,
    run: EvalRunDoc,
  ): Promise<{ suite: Suite; dataset: DatasetVersion }> {
    const s = await this.c.docs.get<Suite>(tenantId, "suites", suiteRef);
    if (!s) throw notFound("suite not found");
    if (s.data.suite_hash !== run.suite_hash || s.data.dataset_hash !== run.dataset_hash)
      throw integrityFailed("the suite changed since the run was created", ["suite_hash"]);
    const d = await this.c.docs.get<DatasetVersion>(tenantId, "datasets", s.data.dataset_ref);
    if (!d || d.data.content_hash !== run.dataset_hash)
      throw integrityFailed("the dataset changed since the run was created", ["dataset_hash"]);
    return { suite: s.data, dataset: d.data };
  }

  /** The runner's provenance must be about THIS run: its blueprint hash, dataset hash and suite. Stored as reported. */
  private parseProvenance(raw: unknown, run: EvalRunDoc, runnerId: string): Record<string, unknown> {
    if (!isObj(raw)) throw invalid("provenance is required", ["provenance"]);
    if (JSON.stringify(raw).length > 100_000) throw invalid("provenance is too large", ["provenance"]);
    const v = raw["runner_version"];
    if (typeof v !== "string" || v === "" || v.length > 100)
      throw invalid("provenance.runner_version is required", ["provenance.runner_version"]);
    if (raw["runner_id"] !== runnerId)
      throw integrityFailed("provenance names another runner", ["provenance.runner_id"]);
    if (raw["aggregation_version"] !== AGGREGATION_VERSION)
      throw invalid(`aggregation_version must be ${AGGREGATION_VERSION}`, ["provenance.aggregation_version"]);
    if (raw["blueprint_content_hash"] !== run.content_hash)
      throw integrityFailed("the run was executed against different blueprint content", ["provenance.blueprint_content_hash"]);
    if (raw["dataset_version_hash"] !== run.dataset_hash)
      throw integrityFailed("the run was executed against a different dataset", ["provenance.dataset_version_hash"]);
    if (raw["suite_ref"] !== run.suite_ref)
      throw integrityFailed("provenance names another suite", ["provenance.suite_ref"]);
    if (raw["seed"] !== run.seed) throw integrityFailed("provenance carries another seed", ["provenance.seed"]);
    const ids = raw["model_ids"];
    if (!Array.isArray(ids) || ids.length > 50 || ids.some((x) => typeof x !== "string" || x.length > 200))
      throw invalid("provenance.model_ids must be an array of model ids", ["provenance.model_ids"]);
    return { ...raw };
  }

  private parseCost(raw: unknown): RunCost {
    if (!isObj(raw)) throw invalid("cost is required", ["cost"]);
    const usd = (k: string): bigint => {
      const v = raw[k];
      if (typeof v !== "string" || !/^\d{1,12}(\.\d{1,6})?$/.test(v))
        throw invalid(`cost.${k} must be a decimal string with at most 6 decimals`, [`cost.${k}`]);
      const [w, f = ""] = v.split(".");
      return BigInt(w as string) * 1_000_000n + BigInt(f.padEnd(6, "0"));
    };
    const int = (k: string): number => {
      const v = raw[k];
      if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) throw invalid(`cost.${k} must be a non-negative integer`, [`cost.${k}`]);
      return v;
    };
    if (usd("agent_usd") + usd("judge_usd") !== usd("total_usd"))
      throw integrityFailed("cost.total_usd is not agent_usd + judge_usd", ["cost.total_usd"]);
    return {
      agent_usd: raw["agent_usd"] as string,
      judge_usd: raw["judge_usd"] as string,
      total_usd: raw["total_usd"] as string,
      tokens: int("tokens"),
      judge_tokens: int("judge_tokens"),
    };
  }

  private parseCaseResults(raw: unknown, suite: Suite, dataset: DatasetVersion): CaseResult[] {
    if (!Array.isArray(raw)) throw invalid("case_results must be an array", ["case_results"]);
    const want = new Set(dataset.cases.map((x) => x.id));
    const seen = new Set<string>();
    const byGrader = new Map(suite.graders.map((g) => [g.id, g]));
    const out = raw.map((x: unknown, i): CaseResult => {
      const path = `case_results[${i}]`;
      if (!isObj(x)) throw invalid("case result must be an object", [path]);
      const id = x["case_id"];
      if (typeof id !== "string" || !want.has(id)) throw invalid("case_id is not in the dataset", [`${path}.case_id`]);
      if (seen.has(id)) throw invalid(`duplicate result for case ${id}`, [`${path}.case_id`]);
      seen.add(id);
      const status = x["status"];
      if (typeof status !== "string" || status === "" || status.length > 40)
        throw invalid("status is malformed", [`${path}.status`]);
      for (const k of ["attempts", "seed"])
        if (typeof x[k] !== "number" || !Number.isSafeInteger(x[k]) || (x[k] as number) < 0)
          throw invalid(`${k} must be a non-negative integer`, [`${path}.${k}`]);
      const er = x["error"];
      if (er !== undefined && er !== null && (typeof er !== "string" || er.length > 1000))
        throw invalid("error must be a string of at most 1000 characters", [`${path}.error`]);
      const sc = x["score"];
      if (sc !== undefined && sc !== null && (typeof sc !== "number" || !Number.isFinite(sc)))
        throw invalid("score must be a number or null", [`${path}.score`]);
      const out_ = x["output"];
      if (out_ !== undefined && out_ !== null && (typeof out_ !== "string" || out_.length > 20_000))
        throw invalid("output must be a string of at most 20000 characters", [`${path}.output`]);
      const trace = x["trace"];
      if (trace !== undefined && trace !== null && (!isObj(trace) || JSON.stringify(trace).length > 100_000))
        throw invalid("trace must be an object of at most 100000 characters", [`${path}.trace`]);
      const gradesRaw = x["grades"];
      if (!Array.isArray(gradesRaw) || gradesRaw.length > byGrader.size)
        throw invalid("grades must be an array with at most one grade per grader", [`${path}.grades`]);
      const gseen = new Set<string>();
      const grades: GradeRecord[] = gradesRaw.map((g: unknown, j): GradeRecord => {
        const gp = `${path}.grades[${j}]`;
        if (!isObj(g)) throw invalid("grade must be an object", [gp]);
        const spec = typeof g["grader_id"] === "string" ? byGrader.get(g["grader_id"]) : undefined;
        if (!spec) throw invalid("grade for a grader the suite does not declare", [`${gp}.grader_id`]);
        if (gseen.has(spec.id)) throw invalid(`duplicate grade for ${spec.id}`, [`${gp}.grader_id`]);
        gseen.add(spec.id);
        if (g["kind"] !== spec.kind) throw invalid("grade kind does not match the suite's grader", [`${gp}.kind`]);
        const gs = g["status"];
        if (gs !== "scored" && gs !== "ungraded" && gs !== "pending" && gs !== "error")
          throw invalid("grade status must be scored, ungraded, pending or error", [`${gp}.status`]);
        if (spec.kind === "human" && gs !== "pending")
          throw invalid("human grader scores come only from the review queue", [`${gp}.status`]);
        if (spec.kind !== "human" && gs === "pending")
          throw invalid("only a human grader can be pending", [`${gp}.status`]);
        const score = g["score"];
        if (typeof score !== "number" || !Number.isFinite(score)) throw invalid("grade score must be a finite number", [`${gp}.score`]);
        const detail = g["detail"] === undefined ? "" : g["detail"];
        if (typeof detail !== "string" || detail.length > 4000) throw invalid("detail must be a string of at most 4000 characters", [`${gp}.detail`]);
        const prov = g["provenance"] === undefined ? {} : g["provenance"];
        if (!isObj(prov) || JSON.stringify(prov).length > 20_000) throw invalid("provenance must be an object of at most 20000 characters", [`${gp}.provenance`]);
        return { grader_id: spec.id, kind: spec.kind, status: gs, score, detail, provenance: prov };
      });
      return {
        case_id: id,
        status,
        attempts: x["attempts"] as number,
        seed: x["seed"] as number,
        error: (er as string | null | undefined) ?? null,
        score: (sc as number | null | undefined) ?? null,
        output: (out_ as string | null | undefined) ?? null,
        grades,
        trace: (trace as Record<string, unknown> | null | undefined) ?? null,
      };
    });
    const missing = [...want].filter((id) => !seen.has(id));
    if (missing.length > 0)
      throw invalid(`results must cover every case of the dataset (missing ${missing.length})`, ["case_results"]);
    return out.sort((a, b) => (a.case_id < b.case_id ? -1 : a.case_id > b.case_id ? 1 : 0));
  }

  private requireOwnRun(d: Doc<EvalRunDoc> | undefined, r: RunnerActor): Doc<EvalRunDoc> {
    if (!d) throw notFound("run not found");
    if (d.data.status !== "running") throw conflict("run is not running");
    if (d.data.runner_id !== r.runnerId) throw forbidden("run belongs to another runner");
    return d;
  }

  /**
   * The runner submits a run (docs/spec/evals-runner.md section 7): per-case results with per-grader grades. The hub validates them
   * against the run, the suite and the dataset, RECOMPUTES the aggregate from the grades with the shared algorithm and rejects a payload
   * whose reported numbers differ (422 `integrity_failed`); what is stored is the hub's own aggregate. A pending human grade leaves the
   * run `running` until the review queue has produced every human score. A `failed` payload ends the run `errored`.
   */
  async submitResults(p: HubPrincipal, runId: string, input: SubmitInput): Promise<EvalRunDoc> {
    const r = requireRunner(p);
    return mutate(this.c, p, "evals.run.submit", { run_id: runId }, async () => {
      await this.requireActiveRunner(r);
      if (!isObj(input)) throw invalid("body must be an object", []);
      const d = this.requireOwnRun(await this.c.docs.get<EvalRunDoc>(p.tenantId, "runs", runId), r);
      const run = d.data;
      if (input["runner_id"] !== r.runnerId)
        throw integrityFailed("payload names another runner", ["runner_id"]);
      if (input["run_id"] !== runId) throw integrityFailed("payload names another run", ["run_id"]);
      if (input["suite_ref"] !== run.suite_ref) throw integrityFailed("payload names another suite", ["suite_ref"]);
      const b = input["blueprint"];
      if (!isObj(b) || b["name"] !== run.blueprint.name || b["version"] !== run.blueprint.version || b["content_hash"] !== run.content_hash)
        throw integrityFailed("payload names another blueprint", ["blueprint"]);
      if (input["mode"] !== run.mode) throw integrityFailed("payload names another mode", ["mode"]);
      if (input["status"] === "failed") return this.failRun(p.tenantId, d, input["reason"]);
      if (input["status"] !== "completed" && input["status"] !== "pending_human")
        throw invalid("status must be completed, pending_human or failed", ["status"]);
      const { suite, dataset } = await this.load(p.tenantId, run.suite_ref, run);
      const provenance = this.parseProvenance(input["provenance"], run, r.runnerId);
      const results = this.parseCaseResults(input["case_results"], suite, dataset);
      const cost = this.parseCost(input["cost"]);
      let agg: Aggregate;
      try {
        agg = recompute(results, suite);
      } catch (e) {
        if (e instanceof AggregationError) throw invalid(e.message, ["case_results"]);
        throw e;
      }
      const bad = mismatches(input["scores"], agg);
      if (agg.status === "complete") {
        for (const x of results) {
          const want = agg.per_case[x.case_id];
          if (typeof x.score !== "number" || want === undefined || Math.abs(x.score - want) > SCORE_EPSILON)
            bad.push(`case_score.${x.case_id}`);
        }
      }
      if ((input["status"] === "pending_human") !== (agg.status === "pending_human")) bad.push("status");
      if (bad.length > 0)
        throw integrityFailed("the submitted aggregate does not match the per-case grades", bad.map((b) => `mismatch.${b}`));
      const started = run.started_at;
      const base: EvalRunDoc = {
        ...run,
        case_results: results,
        sample_size: results.length,
        cost,
        provenance,
        started_at: typeof input["started_at"] === "string" ? input["started_at"] : started,
        pending_human: results.reduce((n, x) => n + x.grades.filter((g) => g.status === "pending").length, 0),
      };
      if (agg.status === "pending_human") {
        await guarded(() => this.c.docs.update(p.tenantId, "runs", runId, d.rev, base), "run");
        return base;
      }
      return this.finalize(p.tenantId, d.rev, base, agg);
    });
  }

  /** The runner reports that the run could not be executed (`reason`, e.g. `refused:blueprint_hash_mismatch`). Terminal; never passes a gate. */
  async fail(p: HubPrincipal, runId: string, reason: unknown): Promise<EvalRunDoc> {
    const r = requireRunner(p);
    return mutate(this.c, p, "evals.run.fail", { run_id: runId }, async () => {
      await this.requireActiveRunner(r);
      const d = this.requireOwnRun(await this.c.docs.get<EvalRunDoc>(p.tenantId, "runs", runId), r);
      return this.failRun(p.tenantId, d, reason);
    });
  }

  private async failRun(tenantId: string, d: Doc<EvalRunDoc>, reason: unknown): Promise<EvalRunDoc> {
    if (typeof reason !== "string" || reason.trim() === "" || reason.length > 500)
      throw invalid("reason must be a string of 1-500 characters", ["reason"]);
    const next: EvalRunDoc = {
      ...d.data,
      status: "errored",
      finished_at: iso(this.c.now()),
      failure_reason: reason,
      passed: false,
      pending_human: 0,
    };
    next.record_hash = recordHashOf(next);
    await this.recordFinal(tenantId, next);
    await guarded(() => this.c.docs.update(tenantId, "runs", d.data.id, d.rev, next), "run");
    return next;
  }

  private async recordFinal(tenantId: string, run: EvalRunDoc): Promise<void> {
    await this.c.audit.record({
      tenantId,
      actor: { type: "system", id: `eval-hub:${run.runner_id ?? "-"}` },
      action: "evals.run.final",
      decision: run.status === "passed" ? "ALLOW" : "DENY",
      reason: `run=${run.id} suite=${run.suite_ref} status=${run.status}`,
      inputs: { run_id: run.id, suite_ref: run.suite_ref, content_hash: run.content_hash },
      outputs: {
        status: run.status,
        overall: run.scores?.overall ?? null,
        record_hash: run.record_hash,
        runner_id: run.runner_id,
      },
    });
  }

  /** Takes the final status from the hub's own aggregate, seals the record, audits it, then stores it. */
  private async finalize(tenantId: string, rev: number, run: EvalRunDoc, agg: Aggregate): Promise<EvalRunDoc> {
    const scores: RunScores = {
      status: "complete",
      overall: agg.overall,
      per_grader: agg.per_grader,
      per_case: agg.per_case,
      passed: agg.passed,
      failures: agg.failures,
      ungraded: agg.ungraded,
    };
    const final: EvalRunDoc = {
      ...run,
      status: agg.passed ? "passed" : "failed",
      passed: agg.passed === true,
      finished_at: iso(this.c.now()),
      scores,
      case_results: run.case_results.map((x) => ({ ...x, score: agg.per_case[x.case_id] ?? null })),
      pending_human: 0,
    };
    final.record_hash = recordHashOf(final);
    await this.recordFinal(tenantId, final); // fail-closed: a result that cannot be audited is not stored
    await guarded(() => this.c.docs.update(tenantId, "runs", final.id, rev, final), "run");
    const suite = (await this.c.docs.get<Suite>(tenantId, "suites", final.suite_ref))?.data;
    if (suite) await this.attest(tenantId, final, suite);
    return final;
  }

  private async attest(tenantId: string, run: EvalRunDoc, suite: Suite): Promise<void> {
    const ns = run.blueprint.namespace;
    if (!this.o.signing || !this.o.sink || ns === null) return;
    try {
      await this.o.sink.attach(
        tenantId,
        { namespace: ns, name: run.blueprint.name, version: run.blueprint.version },
        attestationFor(run, suite, this.o.signing),
      );
    } catch (e) {
      await this.c.audit
        .record({
          tenantId,
          actor: { type: "system", id: "eval-hub" },
          action: "evals.attestation.failed",
          decision: "DENY",
          reason: `run=${run.id} code=${e instanceof HubError ? e.code : "error"}`,
        })
        .catch(() => undefined);
    }
  }

  /** The signed summary of a finished run (for a registry that did not receive it, or an auditor). */
  async attestation(p: HubPrincipal, runId: string): Promise<unknown> {
    requireReader(p);
    const run = await this.get(p, runId);
    if (!this.o.signing) throw conflict("no attestation key is configured");
    if (run.status !== "passed" && run.status !== "failed") throw conflict("run is not finished");
    const s = await this.c.docs.get<Suite>(p.tenantId, "suites", run.suite_ref);
    if (!s) throw notFound("suite not found");
    return attestationFor(run, s.data, this.o.signing);
  }

  // ---------------------------------------------------------------- human review plumbing
  /**
   * The runner posts one review task per pending (case, human grader) cell after submitting a `pending_human` run. Idempotent: a task
   * that exists is left alone. A task for a cell that is not pending, or for a grader that is not a human grader, is refused.
   */
  async createReviewTasks(p: HubPrincipal, runId: string, input: { tasks?: unknown }): Promise<{ created: number; existing: number }> {
    const r = requireRunner(p);
    return mutate(this.c, p, "evals.run.review_tasks", { run_id: runId }, async () => {
      await this.requireActiveRunner(r);
      const d = this.requireOwnRun(await this.c.docs.get<EvalRunDoc>(p.tenantId, "runs", runId), r);
      const run = d.data;
      const { suite } = await this.load(p.tenantId, run.suite_ref, run);
      if (!Array.isArray(input.tasks) || input.tasks.length === 0 || input.tasks.length > 5000)
        throw invalid("tasks must be an array of 1-5000 review tasks", ["tasks"]);
      const conflicts = [...new Set([run.requested_by, run.publisher].filter((x): x is string => typeof x === "string"))];
      const created = this.c.now();
      let made = 0;
      let existing = 0;
      for (const [i, t] of input.tasks.entries()) {
        const path = `tasks[${i}]`;
        if (!isObj(t)) throw invalid("task must be an object", [path]);
        const cr = run.case_results.find((x) => x.case_id === t["case_id"]);
        const spec = suite.graders.find((g) => g.id === t["grader_id"]);
        if (!cr || !spec || spec.kind !== "human") throw invalid("task must name a case of the run and a human grader", [path]);
        if (!cr.grades.some((g) => g.grader_id === spec.id && g.status === "pending")) throw invalid("that grade is not pending", [path]);
        const rubric = t["rubric"] === undefined ? String(spec.config["rubric"]) : t["rubric"];
        if (typeof rubric !== "string" || rubric === "" || rubric.length > 4000) throw invalid("rubric must be a string of 1-4000 characters", [`${path}.rubric`]);
        const output = t["output"] === undefined ? null : t["output"];
        if (output !== null && (typeof output !== "string" || output.length > 20_000)) throw invalid("output must be a string of at most 20000 characters", [`${path}.output`]);
        if (JSON.stringify(t["input"] ?? null).length > 64_000 || JSON.stringify(t["expected"] ?? null).length > 64_000)
          throw invalid("input/expected are too large", [path]);
        const id = `rt-${createHash("sha256").update(`${runId}|${cr.case_id}|${spec.id}`).digest("hex").slice(0, 32)}`;
        const task: ReviewTaskDoc = {
          id,
          run_id: run.id,
          suite_ref: run.suite_ref,
          case_id: cr.case_id,
          grader_id: spec.id,
          rubric,
          blueprint: run.blueprint,
          case_input: t["input"] ?? null,
          case_output: output,
          case_expected: t["expected"] ?? null,
          state: "open",
          created_at: iso(created),
          sla_deadline: iso(new Date(created.getTime() + (spec.config["sla_hours"] as number) * 3_600_000)),
          double_grade: spec.config["double_grade"] === true,
          agreement_tolerance: spec.config["agreement_tolerance"] as number,
          conflicts,
          claimed_by: null,
          claim_expires_at: null,
          skipped_by: [],
          grades: [],
          resolution: null,
          resolved_at: null,
          sla_breached_at: null,
        };
        try {
          await this.c.docs.insert(p.tenantId, "tasks", id, task);
          made++;
        } catch (e) {
          if (!(e instanceof DocConflict)) throw e;
          existing++;
        }
      }
      return { created: made, existing };
    });
  }

  /** Called when a review task resolves: write the human score into the run's grid and finalize it when no pending grade is left. */
  async humanResolved(tenantId: string, runId: string): Promise<void> {
    for (let attempt = 0; attempt < 5; attempt++) {
      const d = await this.c.docs.get<EvalRunDoc>(tenantId, "runs", runId);
      if (!d || d.data.status !== "running") return;
      const tasks = (await this.c.docs.find<ReviewTaskDoc>(tenantId, "tasks", { run_id: runId })).map((t) => t.data);
      const { suite } = await this.load(tenantId, d.data.suite_ref, d.data);
      const results: CaseResult[] = d.data.case_results.map((x) => ({ ...x, grades: x.grades.map((g) => ({ ...g })) }));
      for (const t of tasks) {
        if (t.resolution === null) continue;
        const g = results.find((x) => x.case_id === t.case_id)?.grades.find((y) => y.grader_id === t.grader_id);
        if (g && g.status === "pending") {
          g.status = "scored";
          g.score = t.resolution.score;
          g.detail = `human_review:${t.resolution.method}`;
        }
      }
      const pending = results.reduce((n, x) => n + x.grades.filter((g) => g.status === "pending").length, 0);
      const base: EvalRunDoc = { ...d.data, case_results: results, pending_human: pending };
      try {
        if (pending > 0) {
          await this.c.docs.update(tenantId, "runs", runId, d.rev, base);
          return;
        }
        await this.finalize(tenantId, d.rev, base, recompute(results, suite));
        return;
      } catch (e) {
        if (attempt === 4 || !(e instanceof HubError && e.code === "conflict")) throw e;
      }
    }
  }

  // ---------------------------------------------------------------- reads
  async get(p: HubPrincipal, runId: string): Promise<EvalRunDoc> {
    requireReader(p);
    const d = await this.c.docs.get<EvalRunDoc>(p.tenantId, "runs", runId);
    if (!d) throw notFound("run not found");
    return d.data;
  }

  /** Newest first. `limit` <= 200 (default 50); `cursor` is opaque. */
  async list(
    p: HubPrincipal,
    f: ListFilter = {},
  ): Promise<{ items: EvalRunDoc[]; next_cursor: string | null }> {
    requireReader(p);
    const filter: Record<string, string> = {};
    for (const k of ["status", "suite_ref", "blueprint_name", "content_hash", "mode"] as const) {
      const v = f[k];
      if (v !== undefined) {
        if (typeof v !== "string" || v.length > 200) throw invalid(`${k} is malformed`, [k]);
        filter[k] = v;
      }
    }
    const limit = Math.min(Math.max(Math.trunc(f.limit ?? 50), 1), 200);
    let items = (await this.c.docs.find<EvalRunDoc>(p.tenantId, "runs", filter))
      .map((d: Doc<EvalRunDoc>) => d.data)
      .sort((a, b) =>
        a.created_at === b.created_at
          ? a.id < b.id
            ? 1
            : -1
          : a.created_at < b.created_at
            ? 1
            : -1,
      );
    if (f.cursor !== undefined) {
      const [at, id] = decodeCursor(f.cursor);
      items = items.filter((r) => r.created_at < at || (r.created_at === at && r.id < id));
    }
    const page = items.slice(0, limit);
    const last = page[page.length - 1];
    return { items: page, next_cursor: items.length > limit && last ? encodeCursor(last) : null };
  }
}

export { FINAL, SCORE_EPSILON, actorOf };
