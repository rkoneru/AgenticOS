import { requireReader, requireRunner, requireTenant } from "./authz.js";
import { denyAudit, guarded, iso, mutate, type Ctx } from "./context.js";
import type { Doc } from "./docstore.js";
import { HubError, conflict, invalid, notFound } from "./errors.js";
import type { RunService } from "./runs.js";
import { round9 } from "./scoring.js";
import {
  HASH_RE,
  ID_RE,
  NAME_RE,
  SUITE_REF_RE,
  type HubPrincipal,
  type OnlineResult,
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
    const red = input["redaction"] === undefined ? "redact" : input["redaction"];
    if (red !== "redact" && red !== "hash_only") throw invalid("redaction must be redact or hash_only", ["redaction"]);
    if (input["enabled"] !== undefined && typeof input["enabled"] !== "boolean")
      throw invalid("enabled must be a boolean", ["enabled"]);
    const at = input["alert_threshold"];
    if (at !== undefined && at !== null && (typeof at !== "number" || !Number.isFinite(at) || at < 0 || at > 1))
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
    return mutate(this.c, p, "evals.sampling.put", { id, suite_ref: rec.suite_ref, rate, max_per_hour: cap }, async () => {
      const cur = await this.c.docs.get<SamplingConfig>(p.tenantId, "sampling", id);
      if (cur) await guarded(() => this.c.docs.update(p.tenantId, "sampling", id, cur.rev, rec), "sampling");
      else await guarded(() => this.c.docs.insert(p.tenantId, "sampling", id, rec), "sampling");
      return rec;
    });
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
      const next = { ...cur.data, enabled: false, updated_by: (p as { subject: string }).subject, updated_at: iso(this.c.now()) };
      await guarded(() => this.c.docs.update(p.tenantId, "sampling", id, cur.rev, next), "sampling");
      return next;
    });
  }

  async list(p: HubPrincipal): Promise<SamplingConfig[]> {
    requireReader(p);
    return (await this.c.docs.find<SamplingConfig>(p.tenantId, "sampling")).map((d) => d.data);
  }

  /** A registered runner posts the scores of one sampled production run. */
  async ingest(p: HubPrincipal, input: Record<string, unknown>): Promise<OnlineResult> {
    const r = requireRunner(p);
    return mutate(this.c, p, "evals.online.ingest", { sampling_id: input["sampling_id"] ?? null }, async () => {
      if (!(await this.runs.runnerActive(p.tenantId, r.runnerId)))
        throw new HubError("forbidden", "runner is not registered for this tenant");
      const sid = input["sampling_id"];
      if (typeof sid !== "string" || !ID_RE.test(sid)) throw invalid("sampling_id is required", ["sampling_id"]);
      const cfgDoc = await this.c.docs.get<SamplingConfig>(p.tenantId, "sampling", sid);
      if (!cfgDoc) throw notFound("sampling config not found");
      const cfg = cfgDoc.data;
      if (!cfg.enabled) throw conflict("sampling is disabled");
      const b = input["blueprint"];
      if (
        !isObj(b) ||
        b["name"] !== cfg.blueprint_name ||
        typeof b["version"] !== "string" ||
        b["version"].length === 0 ||
        b["version"].length > 64 ||
        typeof b["content_hash"] !== "string" ||
        !HASH_RE.test(b["content_hash"])
      )
        throw invalid("blueprint must name the configured blueprint with a version and content_hash", ["blueprint"]);
      const suiteDoc = await this.c.docs.get<Suite>(p.tenantId, "suites", cfg.suite_ref);
      if (!suiteDoc) throw notFound("suite not found");
      const graders = suiteDoc.data.graders.filter((g) => g.type !== "human");
      const sc = input["scores"];
      if (!isObj(sc) || Object.keys(sc).length === 0) throw invalid("scores are required", ["scores"]);
      const scores: Record<string, number> = {};
      for (const [k, v] of Object.entries(sc)) {
        if (!graders.some((g) => g.id === k)) throw invalid(`${k} is not an automated grader of the suite`, [`scores.${k}`]);
        if (typeof v !== "number" || !Number.isFinite(v) || v < 0 || v > 1)
          throw invalid(`score for ${k} must be a number in [0, 1]`, [`scores.${k}`]);
        scores[k] = v;
      }
      for (const k of ["source_run_id", "trace_id"])
        if (input[k] !== undefined && input[k] !== null && (typeof input[k] !== "string" || (input[k] as string).length > 100))
          throw invalid(`${k} is malformed`, [k]);
      const now = this.c.now();
      const recent = (await this.c.docs.find<OnlineResult>(p.tenantId, "online", { sampling_id: sid })).filter(
        (d) => new Date(d.data.at).getTime() > now.getTime() - HOUR_MS,
      );
      if (recent.length >= cfg.max_per_hour)
        throw new HubError("rate_limited", "the hourly sampling cap of this config is reached");
      let wsum = 0;
      let total = 0;
      for (const g of graders)
        if (g.id in scores) {
          wsum += g.weight;
          total += g.weight * (scores[g.id] as number);
        }
      const rec: OnlineResult = {
        id: this.c.newId(),
        sampling_id: sid,
        blueprint: {
          namespace: null,
          name: cfg.blueprint_name,
          version: b["version"],
          content_hash: b["content_hash"],
        },
        suite_ref: cfg.suite_ref,
        source_run_id: (input["source_run_id"] as string | null | undefined) ?? null,
        trace_id: (input["trace_id"] as string | null | undefined) ?? null,
        scores,
        score: round9(total / wsum),
        runner_id: r.runnerId,
        at: iso(now),
      };
      await guarded(() => this.c.docs.insert(p.tenantId, "online", `${rec.at}|${rec.id}`, rec), "online result");
      await this.maybeAlert(p.tenantId, cfg, now);
      return rec;
    });
  }

  private async results(tenantId: string, sid: string): Promise<OnlineResult[]> {
    return (await this.c.docs.find<OnlineResult>(tenantId, "online", { sampling_id: sid }))
      .map((d: Doc<OnlineResult>) => d.data)
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

  async summary(p: HubPrincipal, q: { blueprint_name?: unknown; suite_ref?: unknown }): Promise<OnlineSummary[]> {
    requireReader(p);
    const out: OnlineSummary[] = [];
    for (const d of await this.c.docs.find<SamplingConfig>(p.tenantId, "sampling")) {
      const cfg = d.data;
      if (q.blueprint_name !== undefined && cfg.blueprint_name !== q.blueprint_name) continue;
      if (q.suite_ref !== undefined && cfg.suite_ref !== q.suite_ref) continue;
      const all = await this.results(p.tenantId, cfg.id);
      const win = all.slice(-ALERT_WINDOW);
      const mean = (xs: OnlineResult[]): number | null =>
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
        alerting: cfg.alert_threshold !== null && win.length >= ALERT_MIN && wm !== null && wm < cfg.alert_threshold,
        recent: all
          .slice(-50)
          .reverse()
          .map((x) => ({ at: x.at, score: x.score, blueprint_version: x.blueprint.version, trace_id: x.trace_id })),
      });
    }
    return out.sort((a, b) => (a.sampling_id < b.sampling_id ? -1 : 1));
  }
}
