import { requireReader, requireTenant } from "./authz.js";
import { denyAudit, guarded, iso, mutate, type Ctx } from "./context.js";
import { conflict, integrityFailed, invalid, notFound } from "./errors.js";
import { verifyStoredRun } from "./integrity.js";
import { compareRuns } from "./scoring.js";
import type { BaselineDoc, Comparison, EvalRunDoc, HubPrincipal, Suite } from "./types.js";
import { NAME_RE, SUITE_REF_RE } from "./types.js";

const keyOf = (name: string, suite: string, seq: number): string =>
  `${name}|${suite}|${String(seq).padStart(8, "0")}`;

/**
 * Baselines: per (blueprint name, suite) the run a release was last judged against. Append-only: setting a baseline adds a row; the
 * CURRENT baseline is the highest `seq`. A baseline row only points at a run; the comparison re-verifies that run's stored record
 * every time, so editing a baseline's run (or the row) cannot lower the bar silently.
 */
export class BaselineService {
  constructor(private readonly c: Ctx) {}

  async history(tenantId: string, name: string, suiteRef: string): Promise<BaselineDoc[]> {
    return (
      await this.c.docs.find<BaselineDoc>(tenantId, "baselines", {
        blueprint_name: name,
        suite_ref: suiteRef,
      })
    )
      .map((d) => d.data)
      .sort((a, b) => a.seq - b.seq);
  }

  async current(
    tenantId: string,
    name: string,
    suiteRef: string,
  ): Promise<BaselineDoc | undefined> {
    const h = await this.history(tenantId, name, suiteRef);
    return h[h.length - 1];
  }

  /** Admin: promote a finished, PASSED, intact run to be the baseline for its blueprint name and suite. */
  async set(p: HubPrincipal, input: { run_id: unknown }): Promise<BaselineDoc> {
    try {
      requireTenant(p, "evals.admin");
    } catch (e) {
      return denyAudit(this.c, p, "evals.baseline.set", e);
    }
    if (typeof input.run_id !== "string") throw invalid("run_id is required", ["run_id"]);
    return mutate(this.c, p, "evals.baseline.set", { run_id: input.run_id }, () =>
      this.promote(p.tenantId, input.run_id as string, (p as { subject: string }).subject),
    );
  }

  /** Shared by `set` and the post-release hook. */
  async promote(tenantId: string, runId: string, by: string): Promise<BaselineDoc> {
    const d = await this.c.docs.get<EvalRunDoc>(tenantId, "runs", runId);
    if (!d) throw notFound("run not found");
    const run = d.data;
    if (run.status !== "passed") throw conflict("only a passed run can be a baseline");
    const s = await this.c.docs.get<Suite>(tenantId, "suites", run.suite_ref);
    if (!s) throw notFound("suite not found");
    const bad = verifyStoredRun(run, s.data);
    if (bad.length > 0) throw integrityFailed("the run does not verify", bad);
    const prev = await this.current(tenantId, run.blueprint_name, run.suite_ref);
    if (prev?.run_id === run.id) return prev; // already the baseline: nothing to append
    const seq = (prev?.seq ?? 0) + 1;
    const rec: BaselineDoc = {
      blueprint_name: run.blueprint_name,
      suite_ref: run.suite_ref,
      seq,
      run_id: run.id,
      overall: (run.scores as NonNullable<EvalRunDoc["scores"]>).overall,
      record_hash: run.record_hash as string,
      set_by: by,
      at: iso(this.c.now()),
    };
    await guarded(
      () =>
        this.c.docs.insert(
          tenantId,
          "baselines",
          keyOf(rec.blueprint_name, rec.suite_ref, seq),
          rec,
        ),
      "baseline",
    );
    return rec;
  }

  async list(
    p: HubPrincipal,
    q: { blueprint_name?: unknown; suite_ref?: unknown },
  ): Promise<BaselineDoc[]> {
    requireReader(p);
    if (typeof q.blueprint_name !== "string" || !NAME_RE.test(q.blueprint_name))
      throw invalid("blueprint_name is required", ["blueprint_name"]);
    if (typeof q.suite_ref !== "string" || !SUITE_REF_RE.test(q.suite_ref))
      throw invalid("suite_ref is required", ["suite_ref"]);
    return this.history(p.tenantId, q.blueprint_name, q.suite_ref);
  }

  /**
   * Compares `run` with the current baseline of its blueprint name and suite. `undefined` = no baseline. A baseline whose run no longer
   * verifies (or cannot be found, or does not match the recorded hash) yields a NON-comparable result: callers treat that as a failure.
   */
  async compare(tenantId: string, run: EvalRunDoc, suite: Suite): Promise<Comparison | undefined> {
    const base = await this.current(tenantId, run.blueprint_name, run.suite_ref);
    if (!base || base.run_id === run.id) return undefined;
    const bad: Comparison = {
      comparable: false,
      baseline_run_id: base.run_id,
      delta: null,
      per_grader_delta: {},
      tolerance: suite.tolerance,
      regression: false,
      blocking: false,
      significance: null,
    };
    const bd = await this.c.docs.get<EvalRunDoc>(tenantId, "runs", base.run_id);
    if (!bd || !bd.data.scores || !run.scores) return bad;
    const b = bd.data;
    if (
      b.status !== "passed" ||
      b.record_hash !== base.record_hash ||
      verifyStoredRun(b, suite).length > 0
    )
      return bad;
    return compareRuns(
      {
        id: run.id,
        record_hash: run.record_hash as string,
        suite_hash: run.suite_hash,
        dataset_hash: run.dataset_hash,
        scores: run.scores,
      },
      {
        id: b.id,
        record_hash: b.record_hash as string,
        suite_hash: b.suite_hash,
        dataset_hash: b.dataset_hash,
        scores: b.scores as NonNullable<EvalRunDoc["scores"]>,
      },
      {
        tolerance: suite.tolerance,
        alpha: suite.alpha,
        requiresSignificance: suite.regression_requires_significance,
      },
    );
  }

  /** `GET /runs/{id}/comparison`. */
  async compareRun(p: HubPrincipal, runId: string): Promise<Comparison | null> {
    requireReader(p);
    const d = await this.c.docs.get<EvalRunDoc>(p.tenantId, "runs", runId);
    if (!d) throw notFound("run not found");
    const s = await this.c.docs.get<Suite>(p.tenantId, "suites", d.data.suite_ref);
    if (!s) throw notFound("suite not found");
    if (d.data.status !== "passed" && d.data.status !== "failed")
      throw conflict("run is not finished");
    return (await this.compare(p.tenantId, d.data, s.data)) ?? null;
  }
}
