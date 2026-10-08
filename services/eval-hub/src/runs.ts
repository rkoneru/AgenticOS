import { SCORE_EPSILON, aggregate, mismatches, round9 } from "./scoring.js";
import { attestationFor, type AttestationSink, type HubSigningKey } from "./attest.js";
import { actorOf, requireReader, requireRunner, requireTenant } from "./authz.js";
import { denyAudit, guarded, iso, mutate, type Ctx } from "./context.js";
import type { Doc } from "./docstore.js";
import {
  HubError,
  conflict,
  forbidden,
  integrityFailed,
  invalid,
  notFound,
  unavailable,
} from "./errors.js";
import { recordHashOf } from "./integrity.js";
import {
  HASH_RE,
  ID_RE,
  NAME_RE,
  SUITE_REF_RE,
  type BlueprintRef,
  type CaseResult,
  type DatasetVersion,
  type EvalRunDoc,
  type HubPrincipal,
  type ReviewTaskDoc,
  type RunMode,
  type RunProvenance,
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

export interface SubmitInput {
  case_results: unknown;
  /** The runner's CLAIM. Never stored: the hub recomputes and rejects a mismatch. */
  scores?: unknown;
  cost?: unknown;
  provenance: unknown;
}

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
    const run: EvalRunDoc = {
      id: this.c.newId(),
      suite_ref: suite.ref,
      suite_hash: suite.suite_hash,
      dataset_ref: suite.dataset_ref,
      dataset_hash: suite.dataset_hash,
      pass_threshold: suite.pass_threshold,
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
      cost: { total_usd: 0 },
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

  private parseProvenance(raw: unknown): RunProvenance {
    if (!isObj(raw)) throw invalid("provenance is required", ["provenance"]);
    const v = raw["runner_version"];
    if (typeof v !== "string" || v === "" || v.length > 100)
      throw invalid("provenance.runner_version is required", ["provenance.runner_version"]);
    const ids = raw["model_ids"];
    if (
      !Array.isArray(ids) ||
      ids.length > 20 ||
      ids.some((x) => typeof x !== "string" || x === "" || x.length > 200)
    )
      throw invalid("provenance.model_ids must be an array of model ids", ["provenance.model_ids"]);
    const seed = raw["seed"];
    if (
      !(typeof seed === "string" || (typeof seed === "number" && Number.isFinite(seed))) ||
      String(seed).length > 100
    )
      throw invalid("provenance.seed is required", ["provenance.seed"]);
    return { runner_version: v, model_ids: ids as string[], seed: String(seed) };
  }

  private parseCaseResults(raw: unknown, suite: Suite, dataset: DatasetVersion): CaseResult[] {
    if (!Array.isArray(raw)) throw invalid("case_results must be an array", ["case_results"]);
    const want = new Set(dataset.cases.map((x) => x.id));
    const seen = new Set<string>();
    const human = new Set(suite.graders.filter((g) => g.type === "human").map((g) => g.id));
    const graderIds = new Set(suite.graders.map((g) => g.id));
    const out = raw.map((x: unknown, i): CaseResult => {
      const path = `case_results[${i}]`;
      if (!isObj(x)) throw invalid("case result must be an object", [path]);
      const id = x["case_id"];
      if (typeof id !== "string" || !want.has(id))
        throw invalid("case_id is not in the dataset", [`${path}.case_id`]);
      if (seen.has(id)) throw invalid(`duplicate result for case ${id}`, [`${path}.case_id`]);
      seen.add(id);
      const sc = x["scores"];
      if (!isObj(sc)) throw invalid("scores must be an object", [`${path}.scores`]);
      const scores: Record<string, number | null> = {};
      for (const k of Object.keys(sc))
        if (!graderIds.has(k)) throw invalid(`unknown grader ${k}`, [`${path}.scores.${k}`]);
      for (const g of suite.graders) {
        const v = sc[g.id];
        if (human.has(g.id)) {
          if (v !== undefined && v !== null)
            throw invalid("human grader scores come only from the review queue", [
              `${path}.scores.${g.id}`,
            ]);
          scores[g.id] = null;
        } else {
          if (typeof v !== "number" || !Number.isFinite(v) || v < 0 || v > 1)
            throw invalid(`score for ${g.id} must be a number in [0, 1]`, [
              `${path}.scores.${g.id}`,
            ]);
          scores[g.id] = v;
        }
      }
      const cost = x["cost_usd"] === undefined ? 0 : x["cost_usd"];
      if (typeof cost !== "number" || !Number.isFinite(cost) || cost < 0 || cost > 1e6)
        throw invalid("cost_usd must be a non-negative number", [`${path}.cost_usd`]);
      const lat = x["latency_ms"];
      if (
        lat !== undefined &&
        lat !== null &&
        (typeof lat !== "number" || !Number.isFinite(lat) || lat < 0)
      )
        throw invalid("latency_ms must be a non-negative number", [`${path}.latency_ms`]);
      const tr = x["trace_id"];
      if (tr !== undefined && tr !== null && (typeof tr !== "string" || tr.length > 100))
        throw invalid("trace_id is malformed", [`${path}.trace_id`]);
      const er = x["error"];
      if (er !== undefined && er !== null && (typeof er !== "string" || er.length > 500))
        throw invalid("error must be a string of at most 500 characters", [`${path}.error`]);
      return {
        case_id: id,
        scores,
        case_score: null,
        cost_usd: cost,
        latency_ms: (lat as number | null | undefined) ?? null,
        trace_id: (tr as string | null | undefined) ?? null,
        error: (er as string | null | undefined) ?? null,
      };
    });
    const missing = [...want].filter((id) => !seen.has(id));
    if (missing.length > 0)
      throw invalid(`results must cover every case of the dataset (missing ${missing.length})`, [
        "case_results",
      ]);
    return out.sort((a, b) => (a.case_id < b.case_id ? -1 : a.case_id > b.case_id ? 1 : 0));
  }

  /**
   * The runner submits per-case grader scores. The hub validates them against the suite and the dataset, RECOMPUTES the aggregate with
   * the suite's rules and rejects a runner claim that differs (422 `integrity_failed`). Human graders leave the run `running` with
   * review tasks; the run is finalized when the last task resolves. The stored scores are always the hub's own.
   */
  async submitResults(p: HubPrincipal, runId: string, input: SubmitInput): Promise<EvalRunDoc> {
    const r = requireRunner(p);
    return mutate(this.c, p, "evals.run.submit", { run_id: runId }, async () => {
      await this.requireActiveRunner(r);
      const d = await this.c.docs.get<EvalRunDoc>(p.tenantId, "runs", runId);
      if (!d) throw notFound("run not found");
      if (d.data.status !== "running") throw conflict("run is not running");
      if (d.data.runner_id !== r.runnerId) throw forbidden("run belongs to another runner");
      const { suite, dataset } = await this.load(p.tenantId, d.data.suite_ref, d.data);
      const provenance = this.parseProvenance(input.provenance);
      const results = this.parseCaseResults(input.case_results, suite, dataset);
      const humanIds = suite.graders.filter((g) => g.type === "human");
      const pending = humanIds.length * results.length;
      const total = round9(results.reduce((s, x) => s + x.cost_usd, 0));
      if (input.cost !== undefined) {
        const claim = isObj(input.cost) ? input.cost["total_usd"] : undefined;
        if (typeof claim !== "number" || Math.abs(claim - total) > 1e-6)
          throw integrityFailed("claimed cost does not equal the sum of the case costs", [
            "cost.total_usd",
          ]);
      }
      let scores: EvalRunDoc["scores"] = null;
      if (pending === 0) {
        const claimed = input.scores;
        if (!isObj(claimed))
          throw invalid("scores (overall) is required when no human grader is involved", [
            "scores",
          ]);
        scores = aggregate(
          suite.graders,
          results.map((x) => ({ case_id: x.case_id, scores: x.scores as Record<string, number> })),
        );
        const bad = mismatches(claimed, scores);
        if (bad.length > 0)
          throw integrityFailed(
            "the submitted aggregate does not match the per-case results",
            bad.map((b) => `mismatch.${b}`),
          );
      } else if (input.scores !== undefined) {
        throw invalid("send no aggregate while human grading is pending; the hub computes it", [
          "scores",
        ]);
      }
      const base: EvalRunDoc = {
        ...d.data,
        case_results: results,
        sample_size: results.length,
        cost: { total_usd: total },
        provenance,
        pending_human: pending,
      };
      if (pending > 0) {
        await guarded(() => this.c.docs.update(p.tenantId, "runs", runId, d.rev, base), "run");
        await this.createTasks(p.tenantId, base, suite, dataset);
        return base;
      }
      return this.finalize(
        p.tenantId,
        d.rev,
        base,
        suite,
        scores as NonNullable<EvalRunDoc["scores"]>,
      );
    });
  }

  /** The runner reports that the run could not be executed. The run becomes `errored` (terminal) and never satisfies a gate. */
  async fail(p: HubPrincipal, runId: string, reason: unknown): Promise<EvalRunDoc> {
    const r = requireRunner(p);
    if (typeof reason !== "string" || reason.trim() === "" || reason.length > 500)
      throw invalid("reason must be a string of 1-500 characters", ["reason"]);
    return mutate(this.c, p, "evals.run.fail", { run_id: runId }, async () => {
      await this.requireActiveRunner(r);
      const d = await this.c.docs.get<EvalRunDoc>(p.tenantId, "runs", runId);
      if (!d) throw notFound("run not found");
      if (d.data.status !== "running") throw conflict("run is not running");
      if (d.data.runner_id !== r.runnerId) throw forbidden("run belongs to another runner");
      const next: EvalRunDoc = {
        ...d.data,
        status: "errored",
        finished_at: iso(this.c.now()),
        failure_reason: reason,
        passed: false,
        pending_human: 0,
      };
      next.record_hash = recordHashOf(next);
      await this.recordFinal(p.tenantId, next);
      await guarded(() => this.c.docs.update(p.tenantId, "runs", runId, d.rev, next), "run");
      return next;
    });
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

  /** Computes the final status from the hub's own aggregate, seals the record, audits it, then stores it. */
  private async finalize(
    tenantId: string,
    rev: number,
    run: EvalRunDoc,
    suite: Suite,
    scores: NonNullable<EvalRunDoc["scores"]>,
  ): Promise<EvalRunDoc> {
    const passed = scores.overall >= suite.pass_threshold;
    const final: EvalRunDoc = {
      ...run,
      status: passed ? "passed" : "failed",
      passed,
      finished_at: iso(this.c.now()),
      scores,
      case_results: run.case_results.map((x) => ({
        ...x,
        case_score: scores.per_case[x.case_id] ?? null,
      })),
      pending_human: 0,
    };
    final.record_hash = recordHashOf(final);
    await this.recordFinal(tenantId, final); // fail-closed: a result that cannot be audited is not stored
    await guarded(() => this.c.docs.update(tenantId, "runs", final.id, rev, final), "run");
    await this.attest(tenantId, final, suite);
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
  private async createTasks(
    tenantId: string,
    run: EvalRunDoc,
    suite: Suite,
    dataset: DatasetVersion,
  ): Promise<void> {
    const byId = new Map(dataset.cases.map((x) => [x.id, x]));
    const conflicts = [run.requested_by, run.publisher].filter(
      (x): x is string => typeof x === "string",
    );
    const created = this.c.now();
    for (const g of suite.graders) {
      if (g.type !== "human") continue;
      for (const cr of run.case_results) {
        const cs = byId.get(cr.case_id);
        const task: ReviewTaskDoc = {
          id: this.c.newId(),
          run_id: run.id,
          suite_ref: run.suite_ref,
          case_id: cr.case_id,
          grader_id: g.id,
          rubric: g.rubric,
          blueprint: run.blueprint,
          case_input: cs?.input ?? null,
          case_expected: cs?.expected ?? null,
          state: "open",
          created_at: iso(created),
          sla_deadline: iso(new Date(created.getTime() + g.sla_hours * 3_600_000)),
          double_grade: g.double_grade,
          agreement_tolerance: g.agreement_tolerance,
          conflicts: [...new Set(conflicts)],
          claimed_by: null,
          claim_expires_at: null,
          skipped_by: [],
          grades: [],
          resolution: null,
          resolved_at: null,
          sla_breached_at: null,
        };
        await guarded(() => this.c.docs.insert(tenantId, "tasks", task.id, task), "review task");
      }
    }
  }

  /** Called when a review task resolves: copy the human score into the run and finalize it when none are left. */
  async humanResolved(tenantId: string, runId: string): Promise<void> {
    for (let attempt = 0; attempt < 5; attempt++) {
      const d = await this.c.docs.get<EvalRunDoc>(tenantId, "runs", runId);
      if (!d || d.data.status !== "running") return;
      const tasks = (
        await this.c.docs.find<ReviewTaskDoc>(tenantId, "tasks", { run_id: runId })
      ).map((t) => t.data);
      const { suite } = await this.load(tenantId, d.data.suite_ref, d.data);
      const results = d.data.case_results.map((x) => ({ ...x, scores: { ...x.scores } }));
      let open = 0;
      for (const t of tasks) {
        if (t.resolution === null) {
          open++;
          continue;
        }
        const row = results.find((x) => x.case_id === t.case_id);
        if (row) row.scores[t.grader_id] = t.resolution.score;
      }
      const base: EvalRunDoc = { ...d.data, case_results: results, pending_human: open };
      try {
        if (open > 0) {
          await this.c.docs.update(tenantId, "runs", runId, d.rev, base);
          return;
        }
        const scores = aggregate(
          suite.graders,
          results.map((x) => ({ case_id: x.case_id, scores: x.scores as Record<string, number> })),
        );
        await this.finalize(tenantId, d.rev, base, suite, scores);
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
