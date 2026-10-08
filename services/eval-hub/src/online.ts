import { createHash } from "node:crypto";
import { redactPatterns } from "@axis/channels";
import { requireReader, requireRunner, requireTenant } from "./authz.js";
import { denyAudit, guarded, iso, mutate, type Ctx } from "./context.js";
import type { Doc } from "./docstore.js";
import { HubError, integrityFailed, invalid, notFound } from "./errors.js";
import { DocConflict } from "./docstore.js";
import type { RunService } from "./runs.js";
import {
  AggregationError,
  SCORE_EPSILON,
  aggregateGrid,
  round9,
  type GradeCell,
} from "./scoring.js";
import {
  HASH_RE,
  ID_RE,
  NAME_RE,
  SUITE_REF_RE,
  type HubPrincipal,
  type OnlineResult,
  type ReviewTaskDoc,
  type SamplingConfig,
  type Suite,
} from "./types.js";

const HOUR_MS = 3_600_000;
const ALERT_WINDOW = 20;
const ALERT_MIN = 5;

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

export interface OnlineSummary {
  sampling_id: string;
  blueprint_name: string;
  suite_ref: string;
  enabled: boolean;
  count: number;
  mean: number | null;
  window: { count: number; mean: number | null };
  alert_threshold: number | null;
  alerting: boolean;
  recent: { at: string; score: number; blueprint_version: string; trace_id: string | null }[];
}

/**
 * Online sampling. Sampled PRODUCTION runs are graded asynchronously by a runner; the hub stores the scores (and ids only: no input or
 * output text ever reaches the hub on this path), enforces the config's hourly cap, and raises an alert event when the recent mean falls
 * below the config's alert threshold.
 *
 * ISOLATION (a tested property): online results live in their own collection and are never read by the gate, the baseline logic or the
 * registry. They can alert and show history; they can never allow, block, release or alter anything.
 */
export class OnlineService {
  constructor(
    private readonly c: Ctx,
    private readonly runs: RunService,
  ) {}

  async put(p: HubPrincipal, id: string, input: Record<string, unknown>): Promise<SamplingConfig> {
    try {
      requireTenant(p, "evals.admin");
    } catch (e) {
      return denyAudit(this.c, p, "evals.sampling.put", e);
    }
    if (!ID_RE.test(id)) throw invalid("sampling id is malformed", ["id"]);
    if (typeof input["blueprint_name"] !== "string" || !NAME_RE.test(input["blueprint_name"]))
      throw invalid("blueprint_name is malformed", ["blueprint_name"]);
    if (typeof input["suite_ref"] !== "string" || !SUITE_REF_RE.test(input["suite_ref"]))
      throw invalid("suite_ref must be name@version", ["suite_ref"]);
    const rate = input["rate"];
    if (typeof rate !== "number" || !Number.isFinite(rate) || rate < 0 || rate > 1)
      throw invalid("rate must be a number in [0, 1]", ["rate"]);
    const cap = input["max_per_hour"];
    if (typeof cap !== "number" || !Number.isInteger(cap) || cap < 1 || cap > 100_000)
      throw invalid("max_per_hour must be an integer in [1, 100000]", ["max_per_hour"]);
    const red = input["redaction"] === undefined ? "phi" : input["redaction"];
    if (red !== "phi" && red !== "always")
      throw invalid("redaction must be phi or always", ["redaction"]);
    if (input["enabled"] !== undefined && typeof input["enabled"] !== "boolean")
      throw invalid("enabled must be a boolean", ["enabled"]);
    const at = input["alert_threshold"];
    if (
      at !== undefined &&
      at !== null &&
      (typeof at !== "number" || !Number.isFinite(at) || at < 0 || at > 1)
    )
      throw invalid("alert_threshold must be a number in [0, 1] or null", ["alert_threshold"]);
    const suite = await this.c.docs.get<Suite>(p.tenantId, "suites", input["suite_ref"]);
    if (!suite) throw invalid("suite not found", ["suite_ref"]);
    const rec: SamplingConfig = {
      id,
      blueprint_name: input["blueprint_name"],
      suite_ref: input["suite_ref"],
      rate,
      max_per_hour: cap,
      redaction: red,
      enabled: input["enabled"] !== false,
      alert_threshold: (at as number | null | undefined) ?? null,
      updated_by: (p as { subject: string }).subject,
      updated_at: iso(this.c.now()),
    };
    return mutate(
      this.c,
      p,
      "evals.sampling.put",
      { id, suite_ref: rec.suite_ref, rate, max_per_hour: cap },
      async () => {
        const cur = await this.c.docs.get<SamplingConfig>(p.tenantId, "sampling", id);
        if (cur)
          await guarded(
            () => this.c.docs.update(p.tenantId, "sampling", id, cur.rev, rec),
            "sampling",
          );
        else await guarded(() => this.c.docs.insert(p.tenantId, "sampling", id, rec), "sampling");
        return rec;
      },
    );
  }

  async disable(p: HubPrincipal, id: string): Promise<SamplingConfig> {
    try {
      requireTenant(p, "evals.admin");
    } catch (e) {
      return denyAudit(this.c, p, "evals.sampling.disable", e);
    }
    return mutate(this.c, p, "evals.sampling.disable", { id }, async () => {
      const cur = await this.c.docs.get<SamplingConfig>(p.tenantId, "sampling", id);
      if (!cur) throw notFound("sampling config not found");
      const next = {
        ...cur.data,
        enabled: false,
        updated_by: (p as { subject: string }).subject,
        updated_at: iso(this.c.now()),
      };
      await guarded(
        () => this.c.docs.update(p.tenantId, "sampling", id, cur.rev, next),
        "sampling",
      );
      return next;
    });
  }

  async list(p: HubPrincipal): Promise<SamplingConfig[]> {
    requireReader(p);
    return (await this.c.docs.find<SamplingConfig>(p.tenantId, "sampling")).map((d) => d.data);
  }

  /** `GET /online/configs`: what the runner's sampler needs (`{blueprint, suite_ref, rate, max_per_hour, redaction}`), enabled configs only. */
  async runnerConfigs(p: HubPrincipal): Promise<
    {
      blueprint: string;
      suite_ref: string;
      rate: number;
      max_per_hour: number;
      redaction: string;
    }[]
  > {
    requireRunner(p);
    return (await this.list(p))
      .filter((c) => c.enabled)
      .map((c) => ({
        blueprint: c.blueprint_name,
        suite_ref: c.suite_ref,
        rate: c.rate,
        max_per_hour: c.max_per_hour,
        redaction: c.redaction,
      }));
  }

  /**
   * A registered runner posts one sampled production run (docs/spec/evals-runner.md section 9): grades per grader, status and score. The
   * hub recomputes the score from the grades and rejects a mismatch. Only scores and ids are stored: the sampled output, trace and
   * review tasks are NOT kept (nothing of a production conversation is persisted by this path).
   *
   * EXCEPTION, by design: a result still waiting for a human grade carries `review_tasks` (the runner's already-redacted case input
   * and output). The hub redacts them AGAIN and keeps them only as review tasks (the reviewer has to read something); the online
   * record itself still holds scores and ids only. When every task resolves the hub appends a completed record.
   */
  async ingest(p: HubPrincipal, input: Record<string, unknown>): Promise<OnlineResult> {
    const r = requireRunner(p);
    return mutate(
      this.c,
      p,
      "evals.online.ingest",
      { suite_ref: input["suite_ref"] ?? null },
      async () => {
        if (!(await this.runs.runnerActive(p.tenantId, r.runnerId)))
          throw new HubError("forbidden", "runner is not registered for this tenant");
        if (input["mode"] !== "online") throw invalid("mode must be online", ["mode"]);
        if (input["runner_id"] !== r.runnerId)
          throw integrityFailed("payload names another runner", ["runner_id"]);
        const b = input["blueprint"];
        if (
          !isObj(b) ||
          typeof b["name"] !== "string" ||
          typeof b["version"] !== "string" ||
          b["version"].length === 0 ||
          b["version"].length > 64 ||
          typeof b["content_hash"] !== "string" ||
          !HASH_RE.test(b["content_hash"])
        )
          throw invalid("blueprint needs a name, a version and a content_hash", ["blueprint"]);
        const cfg = (await this.list(p)).find(
          (c) => c.enabled && c.blueprint_name === b["name"] && c.suite_ref === input["suite_ref"],
        );
        if (!cfg) throw notFound("no enabled sampling configuration for this blueprint and suite");
        const suiteDoc = await this.c.docs.get<Suite>(p.tenantId, "suites", cfg.suite_ref);
        if (!suiteDoc) throw notFound("suite not found");
        const suite = suiteDoc.data;
        const gr = input["grades"];
        if (!Array.isArray(gr) || gr.length === 0 || gr.length > suite.graders.length)
          throw invalid("grades must be an array with one grade per grader", ["grades"]);
        const row: Record<string, GradeCell> = {};
        const scores: Record<string, number> = {};
        for (const [i, g] of gr.entries()) {
          const spec = isObj(g) ? suite.graders.find((x) => x.id === g["grader_id"]) : undefined;
          if (!isObj(g) || !spec || g["kind"] !== spec.kind)
            throw invalid("grade for a grader the suite does not declare", [`grades[${i}]`]);
          if (spec.id in row) throw invalid(`duplicate grade for ${spec.id}`, [`grades[${i}]`]);
          const st = g["status"];
          if (st !== "scored" && st !== "ungraded" && st !== "pending" && st !== "error")
            throw invalid("grade status is malformed", [`grades[${i}].status`]);
          if (
            (spec.kind === "human") !== (st === "pending") &&
            !(spec.kind !== "human" && st !== "pending")
          )
            throw invalid("only a human grader can be pending, and it always is", [
              `grades[${i}].status`,
            ]);
          row[spec.id] = { status: st, score: g["score"] };
          if (
            st === "scored" &&
            typeof g["score"] === "number" &&
            g["score"] >= 0 &&
            g["score"] <= 1
          )
            scores[spec.id] = g["score"];
        }
        let agg;
        try {
          agg = aggregateGrid(suite.graders, { sample: row }, { pass_threshold: 0 });
        } catch (e) {
          if (e instanceof AggregationError) throw invalid(e.message, ["grades"]);
          throw e;
        }
        const claimed = input["score"];
        const want = agg.status === "complete" ? (agg.per_case["sample"] as number) : null;
        if (
          input["status"] !== agg.status ||
          (want === null
            ? claimed !== null && claimed !== undefined
            : typeof claimed !== "number" || Math.abs(claimed - want) > SCORE_EPSILON)
        )
          throw integrityFailed("the reported status or score does not match the grades", [
            "mismatch.score",
          ]);
        for (const k of ["source_run_id", "completed_at"])
          if (
            input[k] !== undefined &&
            input[k] !== null &&
            (typeof input[k] !== "string" || (input[k] as string).length > 128)
          )
            throw invalid(`${k} is malformed`, [k]);
        const trace = input["trace"];
        const traceId =
          isObj(trace) && typeof trace["trace_id"] === "string" && trace["trace_id"].length <= 100
            ? trace["trace_id"]
            : null;
        const now = this.c.now();
        const recent = (
          await this.c.docs.find<OnlineResult>(p.tenantId, "online", { sampling_id: cfg.id })
        ).filter((d) => new Date(d.data.at).getTime() > now.getTime() - HOUR_MS);
        if (recent.length >= cfg.max_per_hour)
          throw new HubError("rate_limited", "the hourly sampling cap of this config is reached");
        const rec: OnlineResult = {
          id: this.c.newId(),
          sampling_id: cfg.id,
          blueprint: {
            namespace: null,
            name: b["name"],
            version: b["version"],
            content_hash: b["content_hash"],
          },
          suite_ref: cfg.suite_ref,
          source_run_id: (input["source_run_id"] as string | null | undefined) ?? null,
          trace_id: traceId,
          scores,
          score: want,
          status: agg.status,
          runner_id: r.runnerId,
          at: iso(now),
        };
        await guarded(
          () => this.c.docs.insert(p.tenantId, "online", `${rec.at}|${rec.id}`, rec),
          "online result",
        );
        if (agg.status === "pending_human")
          await this.queueTasks(p.tenantId, rec, suite, input["review_tasks"], cfg.redaction);
        await this.maybeAlert(p.tenantId, cfg, now);
        return rec;
      },
    );
  }

  /** One review task per pending human cell of a sampled result. Idempotent; a task that does not match a human grader is refused. */
  private async queueTasks(
    tenantId: string,
    rec: OnlineResult,
    suite: Suite,
    raw: unknown,
    redaction: "phi" | "always",
  ): Promise<void> {
    if (raw === undefined || raw === null || (Array.isArray(raw) && raw.length === 0)) return; // stays pending; nothing to review
    if (!Array.isArray(raw) || raw.length > 50)
      throw invalid("review_tasks must be an array of at most 50", ["review_tasks"]);
    let publisher: string | null = null;
    try {
      publisher = (await this.c.publishers?.publisherOf(tenantId, rec.blueprint)) ?? null;
    } catch {
      throw new HubError("unavailable", "the blueprint's publisher could not be determined");
    }
    const created = this.c.now();
    const scrub = (v: unknown): unknown =>
      typeof v === "string"
        ? redactPatterns(v)
        : Array.isArray(v)
          ? v.map(scrub)
          : isObj(v)
            ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, scrub(x)]))
            : v;
    void redaction; // the runner redacts per its configuration; the hub's own pass is unconditional
    for (const [i, t] of raw.entries()) {
      const path = `review_tasks[${i}]`;
      const spec = isObj(t) ? suite.graders.find((g) => g.id === t["grader_id"]) : undefined;
      if (!isObj(t) || !spec || spec.kind !== "human")
        throw invalid("task must name a human grader of the suite", [path]);
      const output = t["output"] === undefined || t["output"] === null ? null : t["output"];
      if (output !== null && (typeof output !== "string" || output.length > 20_000))
        throw invalid("output must be a string of at most 20000 characters", [`${path}.output`]);
      if (
        JSON.stringify(t["input"] ?? null).length > 64_000 ||
        JSON.stringify(t["expected"] ?? null).length > 64_000
      )
        throw invalid("input/expected are too large", [path]);
      const rubric = t["rubric"] === undefined ? String(spec.config["rubric"]) : t["rubric"];
      if (typeof rubric !== "string" || rubric === "" || rubric.length > 4000)
        throw invalid("rubric must be a string of 1-4000 characters", [`${path}.rubric`]);
      const id = `ot-${createHash("sha256").update(`${rec.id}|${spec.id}`).digest("hex").slice(0, 32)}`;
      const task: ReviewTaskDoc = {
        id,
        run_id: `online:${rec.id}`,
        suite_ref: rec.suite_ref,
        case_id: (rec.source_run_id ?? rec.id).slice(0, 128),
        grader_id: spec.id,
        rubric,
        blueprint: rec.blueprint,
        case_input: scrub(t["input"] ?? null),
        case_output: output === null ? null : redactPatterns(output as string),
        case_expected: scrub(t["expected"] ?? null),
        state: "open",
        created_at: iso(created),
        sla_deadline: iso(
          new Date(created.getTime() + (spec.config["sla_hours"] as number) * 3_600_000),
        ),
        double_grade: spec.config["double_grade"] === true,
        agreement_tolerance: spec.config["agreement_tolerance"] as number,
        conflicts: publisher === null ? [] : [publisher],
        claimed_by: null,
        claim_expires_at: null,
        skipped_by: [],
        grades: [],
        resolution: null,
        resolved_at: null,
        sla_breached_at: null,
      };
      try {
        await this.c.docs.insert(tenantId, "tasks", id, task);
      } catch (e) {
        if (!(e instanceof DocConflict)) throw e;
      }
    }
  }

  /**
   * Called when a review task of a sampled result resolves. When no task of the result is left open, appends the COMPLETED record
   * (score recomputed from the scored cells and the human scores, exactly as for a run). Online data stays out of every gate.
   */
  async humanResolved(tenantId: string, resultId: string): Promise<void> {
    const pending = (
      await this.c.docs.find<OnlineResult>(tenantId, "online", { id: resultId })
    ).find((d) => d.data.status === "pending_human")?.data;
    if (!pending) return;
    const tasks = (
      await this.c.docs.find<ReviewTaskDoc>(tenantId, "tasks", { run_id: `online:${resultId}` })
    ).map((d) => d.data);
    if (tasks.length === 0 || tasks.some((t) => t.resolution === null)) return;
    const suiteDoc = await this.c.docs.get<Suite>(tenantId, "suites", pending.suite_ref);
    if (!suiteDoc) return;
    const scores: Record<string, number> = { ...pending.scores };
    for (const g of suiteDoc.data.graders) {
      const t = tasks.find((x) => x.grader_id === g.id);
      if (t?.resolution) scores[g.id] = t.resolution.score;
    }
    const grid: Record<string, GradeCell> = {};
    for (const g of suiteDoc.data.graders) {
      const v = scores[g.id];
      grid[g.id] =
        v === undefined ? { status: "ungraded", score: 0 } : { status: "scored", score: v };
    }
    const agg = aggregateGrid(suiteDoc.data.graders, { sample: grid }, { pass_threshold: 0 });
    if (agg.status !== "complete") return;
    const at = iso(this.c.now());
    const done: OnlineResult = {
      ...pending,
      id: this.c.newId(),
      scores,
      score: agg.per_case["sample"] as number,
      status: "complete",
      at,
      resolves: pending.id,
    };
    try {
      await this.c.docs.insert(tenantId, "online", `resolved|${pending.id}`, done);
    } catch (e) {
      if (!(e instanceof DocConflict)) throw e; // already completed
    }
  }

  /** Sampled results that carry a score (a result still waiting for a human grade has none). */
  private async results(
    tenantId: string,
    sid: string,
  ): Promise<(OnlineResult & { score: number })[]> {
    return (await this.c.docs.find<OnlineResult>(tenantId, "online", { sampling_id: sid }))
      .map((d: Doc<OnlineResult>) => d.data)
      .filter((x): x is OnlineResult & { score: number } => x.score !== null)
      .sort((a, b) => (a.at === b.at ? (a.id < b.id ? -1 : 1) : a.at < b.at ? -1 : 1));
  }

  private async maybeAlert(tenantId: string, cfg: SamplingConfig, now: Date): Promise<void> {
    if (cfg.alert_threshold === null) return;
    const w = (await this.results(tenantId, cfg.id)).slice(-ALERT_WINDOW);
    if (w.length < ALERT_MIN) return;
    const mean = w.reduce((s, x) => s + x.score, 0) / w.length;
    if (mean >= cfg.alert_threshold) return;
    const bucket = Math.floor(now.getTime() / HOUR_MS);
    try {
      await this.c.docs.insert(tenantId, "events", `alert|${cfg.id}|${bucket}`, { at: iso(now) });
    } catch {
      return; // already alerted this hour
    }
    // An alert is a signal for humans. It changes nothing: no gate, no release, no policy reads it.
    await this.c.audit.record({
      tenantId,
      actor: { type: "system", id: "eval-hub" },
      action: "evals.online.alert",
      decision: "DENY",
      reason: `sampling=${cfg.id} suite=${cfg.suite_ref} mean=${round9(mean)} threshold=${cfg.alert_threshold} n=${w.length}`,
    });
  }

  async summary(
    p: HubPrincipal,
    q: { blueprint_name?: unknown; suite_ref?: unknown },
  ): Promise<OnlineSummary[]> {
    requireReader(p);
    const out: OnlineSummary[] = [];
    for (const d of await this.c.docs.find<SamplingConfig>(p.tenantId, "sampling")) {
      const cfg = d.data;
      if (q.blueprint_name !== undefined && cfg.blueprint_name !== q.blueprint_name) continue;
      if (q.suite_ref !== undefined && cfg.suite_ref !== q.suite_ref) continue;
      const all = await this.results(p.tenantId, cfg.id);
      const win = all.slice(-ALERT_WINDOW);
      const mean = (xs: (OnlineResult & { score: number })[]): number | null =>
        xs.length === 0 ? null : round9(xs.reduce((s, x) => s + x.score, 0) / xs.length);
      const wm = mean(win);
      out.push({
        sampling_id: cfg.id,
        blueprint_name: cfg.blueprint_name,
        suite_ref: cfg.suite_ref,
        enabled: cfg.enabled,
        count: all.length,
        mean: mean(all),
        window: { count: win.length, mean: wm },
        alert_threshold: cfg.alert_threshold,
        alerting:
          cfg.alert_threshold !== null &&
          win.length >= ALERT_MIN &&
          wm !== null &&
          wm < cfg.alert_threshold,
        recent: all
          .slice(-50)
          .reverse()
          .map((x) => ({
            at: x.at,
            score: x.score,
            blueprint_version: x.blueprint.version,
            trace_id: x.trace_id,
          })),
      });
    }
    return out.sort((a, b) => (a.sampling_id < b.sampling_id ? -1 : 1));
  }
}
