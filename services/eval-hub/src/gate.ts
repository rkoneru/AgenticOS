import type { EvalGateInput, EvalGatePort, EvalGateResult } from "@axis/registry";
import { requirePlatform, requireTenant } from "./authz.js";
import type { BaselineService } from "./baselines.js";
import { actorOf } from "./authz.js";
import { iso, type Ctx } from "./context.js";
import { maxSatisfying, parseRange } from "@axis/registry";
import { HubError, invalid } from "./errors.js";
import { verifyStoredRun } from "./integrity.js";
import type { RunService } from "./runs.js";
import {
  GATE_REF_RE,
  HASH_RE,
  NAME_RE,
  SUITE_REF_RE,
  type Comparison,
  type DatasetVersion,
  type EvalRunDoc,
  type HubPrincipal,
  type Suite,
} from "./types.js";

export interface GateReason {
  code: string;
  suite_ref?: string;
  message: string;
}

export interface GateRunSummary {
  suite_ref: string;
  run_id: string | null;
  overall: number | null;
  /** The bar applied: max(the blueprint's declared threshold, the suite's pass_threshold). */
  required_threshold: number;
  sample_size: number | null;
  finished_at: string | null;
  baseline_run_id: string | null;
  delta: number | null;
  regression: boolean | null;
  p_value: number | null;
}

export interface GateResult {
  allowed: boolean;
  blueprint: { namespace: string | null; name: string; version: string; content_hash: string };
  reasons: GateReason[];
  runs: GateRunSummary[];
  checked_at: string;
}

export interface GateRequest {
  blueprint: unknown;
  suites: unknown;
}

const DAY_MS = 86_400_000;
const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * The release gate. FAIL-CLOSED: it allows only when, for EVERY required suite, a run exists that
 *   1. is final, not errored, of mode ci/manual (online results are never read here),
 *   2. is bound to the blueprint's CONTENT HASH and to the suite as it is now (suite and dataset hashes),
 *   3. was produced by a runner that is registered for the tenant and not revoked,
 *   4. is the LATEST such run (no cherry-picking of a lucky run), is not older than the suite's `max_age_days`,
 *   5. covers at least `min_samples` cases (default: the whole dataset),
 *   6. re-verifies (record hash and scores recomputed from the case results),
 *   7. has `overall >= max(declared threshold, suite.pass_threshold)`,
 *   8. shows no regression beyond the suite's tolerance against the current baseline, when a baseline exists
 *      (a baseline that cannot be verified or compared is itself a failure).
 * Every reason found is reported; any reason blocks. An error anywhere blocks.
 */
export class GateService {
  constructor(
    private readonly c: Ctx,
    private readonly runs: RunService,
    private readonly baselines: BaselineService,
  ) {}

  private parse(req: GateRequest): {
    bp: GateResult["blueprint"];
    suites: Map<string, number | undefined>;
  } {
    const b = req.blueprint;
    if (!isObj(b)) throw invalid("blueprint is required", ["blueprint"]);
    if (typeof b["name"] !== "string" || !NAME_RE.test(b["name"]))
      throw invalid("blueprint.name is malformed", ["blueprint.name"]);
    if (typeof b["version"] !== "string" || b["version"] === "" || b["version"].length > 64)
      throw invalid("blueprint.version is malformed", ["blueprint.version"]);
    if (typeof b["content_hash"] !== "string" || !HASH_RE.test(b["content_hash"]))
      throw invalid("blueprint.content_hash must be a SHA-256 hex digest", ["blueprint.content_hash"]);
    const ns = b["namespace"];
    if (ns !== undefined && ns !== null && (typeof ns !== "string" || !NAME_RE.test(ns)))
      throw invalid("blueprint.namespace is malformed", ["blueprint.namespace"]);
    const suites = new Map<string, number | undefined>();
    const raw = req.suites === undefined ? [] : req.suites;
    if (!Array.isArray(raw) || raw.length > 50) throw invalid("suites must be an array of up to 50", ["suites"]);
    raw.forEach((s: unknown, i) => {
      if (!isObj(s) || typeof s["ref"] !== "string" || !GATE_REF_RE.test(s["ref"]))
        throw invalid("suite ref must be [namespace/]name@version-or-range", [`suites[${i}].ref`]);
      const t = s["threshold"];
      if (t !== undefined && (typeof t !== "number" || !Number.isFinite(t) || t < 0 || t > 1))
        throw invalid("threshold must be a number in [0, 1]", [`suites[${i}].threshold`]);
      const prev = suites.get(s["ref"]);
      suites.set(s["ref"], prev === undefined ? (t as number | undefined) : Math.max(prev, (t as number | undefined) ?? 0));
    });
    return {
      bp: {
        namespace: (ns as string | null | undefined) ?? null,
        name: b["name"],
        version: b["version"],
        content_hash: b["content_hash"],
      },
      suites,
    };
  }

  /** Evaluates the gate for the caller's tenant. Tenant members (read) and the registry/marketplace may ask. */
  async check(p: HubPrincipal, req: GateRequest): Promise<GateResult> {
    if (p?.kind === "platform") requirePlatform(p);
    else requireTenant(p, "evals.read");
    const { bp, suites } = this.parse(req);
    const tenantId = p.tenantId;
    // Tenant-required suites: added even if the blueprint did not declare them.
    for (const s of await this.c.docs.find<Suite>(tenantId, "suites"))
      if (s.data.required_for_release && s.data.applies_to.includes(bp.name) && !suites.has(s.data.ref))
        suites.set(s.data.ref, s.data.pass_threshold);

    const reasons: GateReason[] = [];
    const runs: GateRunSummary[] = [];
    for (const [ref, declared] of [...suites.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
      try {
        const out = await this.evaluate(tenantId, bp, ref, declared, await this.resolve(tenantId, ref));
        reasons.push(...out.reasons);
        runs.push(out.run);
      } catch (e) {
        // Fail closed on anything unexpected, without leaking it.
        this.c.log?.("gate evaluation failed", { error: e instanceof Error ? e.message : String(e) });
        reasons.push({ code: "gate_error", suite_ref: ref, message: "the suite could not be evaluated" });
        runs.push(emptyRun(ref, declared ?? 0));
      }
    }
    const result: GateResult = {
      allowed: reasons.length === 0,
      blueprint: bp,
      reasons,
      runs,
      checked_at: iso(this.c.now()),
    };
    // The decision is part of the tenant's audit chain; a decision that cannot be recorded is not returned (HubError unavailable).
    await this.c.audit.record({
      tenantId,
      actor: actorOf(p),
      action: "evals.gate",
      decision: result.allowed ? "ALLOW" : "DENY",
      reason: result.allowed
        ? `blueprint=${bp.name}@${bp.version} suites=${runs.length}`
        : `blueprint=${bp.name}@${bp.version} blocked=${[...new Set(reasons.map((r) => r.code))].join(",")}`.slice(0, 900),
      inputs: { blueprint: bp, suites: [...suites.entries()] },
      outputs: { allowed: result.allowed, runs: runs.map((r) => r.run_id) },
    });
    return result;
  }

  /** An exact `name@x.y.z` is itself; a range resolves to the highest suite version of that name that satisfies it. */
  private async resolve(tenantId: string, raw: string): Promise<string | undefined> {
    if (SUITE_REF_RE.test(raw)) return raw;
    const i = raw.lastIndexOf("@");
    let range;
    try {
      range = parseRange(raw.slice(i + 1));
    } catch {
      return undefined;
    }
    const name = raw.slice(0, i);
    const versions = (await this.c.docs.find<Suite>(tenantId, "suites"))
      .map((d) => d.data)
      .filter((s) => s.name === name)
      .map((s) => s.version);
    const best = maxSatisfying(versions, range);
    return best === undefined ? undefined : `${name}@${best}`;
  }

  private async evaluate(
    tenantId: string,
    bp: GateResult["blueprint"],
    raw: string,
    declared: number | undefined,
    exact: string | undefined,
  ): Promise<{ reasons: GateReason[]; run: GateRunSummary }> {
    const reasons: GateReason[] = [];
    const ref = exact ?? raw;
    const fail = (code: string, message: string): void => void reasons.push({ code, suite_ref: raw, message });
    const sd = exact === undefined ? undefined : await this.c.docs.get<Suite>(tenantId, "suites", exact);
    if (!sd) {
      fail("suite_not_found", `suite ${raw} does not exist for this tenant`);
      return { reasons, run: emptyRun(raw, declared ?? 0) };
    }
    const suite = sd.data;
    const required = Math.max(declared ?? 0, suite.pass_threshold);
    const summary = emptyRun(ref, required);

    const sameSuite = (await this.c.docs.find<EvalRunDoc>(tenantId, "runs", { suite_ref: ref, blueprint_name: bp.name }))
      .map((d) => d.data)
      .filter((r) => r.mode === "ci" || r.mode === "manual");
    const forHash = sameSuite.filter((r) => r.content_hash === bp.content_hash);
    const finals = forHash.filter((r) => r.status === "passed" || r.status === "failed" || r.status === "errored");
    const trusted: EvalRunDoc[] = [];
    for (const r of finals)
      if (r.runner_id !== null && (await this.runs.runnerActive(tenantId, r.runner_id))) trusted.push(r);
    trusted.sort((a, b) => ((a.finished_at as string) === (b.finished_at as string) ? (a.id < b.id ? 1 : -1) : (a.finished_at as string) < (b.finished_at as string) ? 1 : -1));
    const latest = trusted[0];

    const waiting = forHash.filter((r) => r.status === "running" && r.pending_human > 0);
    if (waiting.length > 0 && (!latest || waiting.some((w) => w.created_at > (latest.finished_at as string))))
      fail("run_in_progress", "a run for this blueprint is waiting for human review");

    if (!latest) {
      if (finals.length > 0)
        fail("runner_not_registered", "the runs for this blueprint came from a runner that is not (or no longer) registered");
      else if (sameSuite.length > 0 && waiting.length === 0)
        fail("no_run_for_content_hash", "runs exist only for a different version of this blueprint's content");
      else if (waiting.length === 0) fail("missing_run", `no finished run of ${ref} for this blueprint version`);
      return { reasons, run: summary };
    }

    summary.run_id = latest.id;
    summary.overall = latest.scores?.overall ?? null;
    summary.sample_size = latest.sample_size;
    summary.finished_at = latest.finished_at;

    const bad = verifyStoredRun(latest, suite);
    if (bad.length > 0) {
      fail("integrity_failed", `the stored run does not verify (${bad.slice(0, 5).join(", ")})`);
      return { reasons, run: summary };
    }
    if (latest.status === "errored") {
      fail("run_errored", "the latest run did not complete");
      return { reasons, run: summary };
    }
    const age = this.c.now().getTime() - new Date(latest.finished_at as string).getTime();
    if (age > suite.max_age_days * DAY_MS)
      fail("stale_run", `the latest run is older than ${suite.max_age_days} days`);
    const ds = await this.c.docs.get<DatasetVersion>(tenantId, "datasets", suite.dataset_ref);
    if (!ds) {
      fail("integrity_failed", "the suite's dataset is missing");
      return { reasons, run: summary };
    }
    const needed = Math.max(1, suite.min_samples ?? ds.data.case_count);
    if (latest.sample_size < needed)
      fail("insufficient_samples", `the run covers ${latest.sample_size} cases, ${needed} are required`);
    const overall = (latest.scores as NonNullable<EvalRunDoc["scores"]>).overall;
    if (overall < required) fail("below_threshold", `score ${overall} is below the required ${required}`);

    let cmp: Comparison | undefined;
    try {
      cmp = await this.baselines.compare(tenantId, latest, suite);
    } catch {
      cmp = undefined;
      fail("baseline_invalid", "the baseline could not be evaluated");
    }
    if (cmp) {
      summary.baseline_run_id = cmp.baseline_run_id;
      summary.delta = cmp.delta;
      summary.regression = cmp.regression;
      summary.p_value = cmp.significance?.p_value ?? null;
      if (!cmp.comparable) fail("baseline_invalid", "the baseline cannot be verified or compared with this run");
      else if (cmp.blocking)
        fail("regression", `score dropped by ${-(cmp.delta as number)} vs the baseline (tolerance ${cmp.tolerance})`);
    }
    return { reasons, run: summary };
  }
}

function emptyRun(ref: string, required: number): GateRunSummary {
  return {
    suite_ref: ref,
    run_id: null,
    overall: null,
    required_threshold: required,
    sample_size: null,
    finished_at: null,
    baseline_run_id: null,
    delta: null,
    regression: null,
    p_value: null,
  };
}

/**
 * The registry/marketplace's view of the hub (`EvalGatePort`). `check` never throws: any failure is a refusal. `released` promotes the
 * allowed run to the baseline after a release went through (best effort).
 */
export class HubGatePort implements EvalGatePort {
  constructor(
    private readonly gate: GateService,
    private readonly baselines: BaselineService,
  ) {}

  private principal(i: EvalGateInput): HubPrincipal {
    return {
      kind: "platform",
      service: i.purpose === "release" ? "registry" : "marketplace",
      subject: i.actor,
      tenantId: i.tenantId,
    };
  }

  private request(i: EvalGateInput): GateRequest {
    return {
      blueprint: {
        namespace: i.blueprint.namespace,
        name: i.blueprint.name,
        version: i.blueprint.version,
        content_hash: i.blueprint.contentHash,
      },
      suites: i.suites,
    };
  }

  async check(i: EvalGateInput): Promise<EvalGateResult> {
    try {
      const r = await this.gate.check(this.principal(i), this.request(i));
      return { allowed: r.allowed, reasons: r.reasons };
    } catch (e) {
      const code = e instanceof HubError ? e.code : "error";
      return {
        allowed: false,
        reasons: [{ code: "gate_unavailable", message: `the eval gate failed (${code})` }],
      };
    }
  }

  async released(i: EvalGateInput): Promise<void> {
    const r = await this.gate.check(this.principal(i), this.request(i));
    if (!r.allowed) return;
    for (const run of r.runs)
      if (run.run_id !== null && run.baseline_run_id !== run.run_id)
        await this.baselines.promote(i.tenantId, run.run_id, `release:${i.actor}`);
  }
}
