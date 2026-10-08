import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { ServiceAudit } from "@axis/registry";
import {
  HubError,
  MemoryDocStore,
  createEvalHub,
  recordHashOf,
  type BaselineDoc,
  type DocStore,
  type EvalRunDoc,
  type HubPrincipal,
} from "../src/index.js";
import {
  DAY,
  events,
  HASH_A,
  HASH_B,
  bp,
  caseResults,
  hex,
  registerRunner,
  runWithScore,
  runnerOf,
  seedSuite,
  user,
  world,
  type World,
  PROV,
} from "./helpers.js";

const codes = (r: { reasons: { code: string }[] }): string[] => r.reasons.map((x) => x.code);
const ask = (
  w: World,
  hash = HASH_A,
  suites: unknown = [{ ref: "smoke@1.0.0", threshold: 0.8 }],
  p: HubPrincipal = w.builder,
) => w.hub.gate.check(p, { blueprint: bp(hash), suites });

async function ready(o: Parameters<typeof seedSuite>[1] = {}): Promise<World> {
  const w = world();
  await seedSuite(w, o);
  await registerRunner(w);
  return w;
}

/** Inserts a FINAL run the service would never have produced (what an attacker with database write access, or a bug, could leave). */
async function plant(
  w: World,
  base: EvalRunDoc,
  patch: (r: EvalRunDoc) => void,
  seal = true,
): Promise<EvalRunDoc> {
  const r: EvalRunDoc = JSON.parse(JSON.stringify(base));
  r.id = randomUUID();
  r.created_at = new Date(w.clock.t.getTime() + 1).toISOString();
  r.finished_at = new Date(w.clock.t.getTime() + 1).toISOString();
  patch(r);
  if (seal) r.record_hash = recordHashOf(r);
  await w.docs.insert(w.tenant, "runs", r.id, r);
  return r;
}

describe("allowing", () => {
  it("allows a fresh, passing, registered-runner run bound to the content hash, and audits the decision", async () => {
    const w = await ready();
    const run = await runWithScore(w, { score: 0.9 });
    const r = await ask(w);
    expect(r).toMatchObject({ allowed: true, reasons: [] });
    expect(r.runs[0]).toMatchObject({
      suite_ref: "smoke@1.0.0",
      run_id: run.id,
      overall: 0.9,
      required_threshold: 0.8,
      sample_size: 4,
    });
    expect(r.blueprint.content_hash).toBe(HASH_A);
    const gates = await events(w, "evals.gate");
    expect(gates).toHaveLength(1);
    expect(gates[0]).toMatchObject({
      decision: "ALLOW",
      enforcement_point: "admin",
      actor: { id: "bob-builder" },
    });
    expect(gates[0]?.inputs_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("a blueprint that asks for no suites and has no tenant-required suites is allowed", async () => {
    const w = await ready();
    expect(await ask(w, HASH_A, [])).toMatchObject({ allowed: true, reasons: [] });
    expect(await w.hub.gate.check(w.builder, { blueprint: bp(), suites: undefined })).toMatchObject(
      { allowed: true },
    );
  });

  it("the stricter of the declared threshold and the suite's own applies", async () => {
    const w = await ready({ pass_threshold: 0.6 });
    await runWithScore(w, { score: 0.7 });
    expect(
      (await ask(w, HASH_A, [{ ref: "smoke@1.0.0", threshold: 0.9 }])).reasons[0],
    ).toMatchObject({ code: "below_threshold" });
    expect((await ask(w, HASH_A, [{ ref: "smoke@1.0.0", threshold: 0.5 }])).allowed).toBe(true);
    expect((await ask(w, HASH_A, [{ ref: "smoke@1.0.0" }])).allowed).toBe(true);
    // exactly at the threshold passes
    const w2 = await ready({ pass_threshold: 0.7 });
    await runWithScore(w2, { score: 0.7 });
    expect((await ask(w2, HASH_A, [{ ref: "smoke@1.0.0", threshold: 0.7 }])).allowed).toBe(true);
  });

  it("resolves a semver range to the highest matching suite version", async () => {
    const w = await ready();
    await w.hub.suites.create(w.builder, {
      ref: "smoke@1.2.0",
      dataset_ref: "ds@1",
      graders: [
        { id: "exact", type: "deterministic", kind: "exact" },
        { id: "contains", type: "deterministic", kind: "contains" },
      ],
      pass_threshold: 0.8,
    });
    await runWithScore(w, { suite: "smoke@1.2.0", score: 1 });
    const r = await ask(w, HASH_A, [{ ref: "smoke@^1.0.0", threshold: 0.8 }]);
    expect(r.allowed).toBe(true);
    expect(r.runs[0]?.suite_ref).toBe("smoke@1.2.0"); // the resolved suite
    expect((await ask(w, HASH_A, [{ ref: "smoke@^2.0.0" }])).reasons[0]?.code).toBe(
      "suite_not_found",
    );
    expect((await ask(w, HASH_A, [{ ref: "smoke@not-a-range" }])).reasons[0]?.code).toBe(
      "suite_not_found",
    );
    expect((await ask(w, HASH_A, [{ ref: "ghost@^1.0.0" }])).reasons[0]?.code).toBe(
      "suite_not_found",
    );
  });
});

describe("blocking (fail closed)", () => {
  it("blocks when there is no run at all", async () => {
    const w = await ready();
    const r = await ask(w);
    expect(r.allowed).toBe(false);
    expect(codes(r)).toEqual(["missing_run"]);
    const gates = await events(w, "evals.gate");
    expect(gates[0]).toMatchObject({ decision: "DENY" });
    expect(gates[0]?.reason).toContain("blocked=missing_run");
  });

  it("blocks when the suite does not exist for the tenant", async () => {
    const w = await ready();
    expect(codes(await ask(w, HASH_A, [{ ref: "nope@1.0.0" }]))).toEqual(["suite_not_found"]);
  });

  it("is bound to the CONTENT HASH: a passing run for another hash never counts", async () => {
    const w = await ready();
    await runWithScore(w, { hash: HASH_B, score: 1 });
    const r = await ask(w, HASH_A);
    expect(r.allowed).toBe(false);
    expect(codes(r)).toEqual(["no_run_for_content_hash"]);
    expect((await ask(w, HASH_B)).allowed).toBe(true);
  });

  it("ignores runs of other blueprints with the same suite", async () => {
    const w = await ready();
    await runWithScore(w, { name: "other-agent", score: 1 });
    expect(codes(await ask(w, HASH_A))).toEqual(["missing_run"]);
  });

  it("blocks a failed run and an errored run", async () => {
    const w = await ready();
    await runWithScore(w, { score: 0.1 });
    expect(codes(await ask(w))).toEqual(["below_threshold"]);
    const w2 = await ready();
    const run = await w2.hub.runs.startAsRunner(w2.runner, {
      suite_ref: "smoke@1.0.0",
      blueprint: bp(),
    });
    await w2.hub.runs.fail(w2.runner, run.id, "boom");
    expect(codes(await ask(w2))).toEqual(["run_errored"]);
  });

  it("the LATEST run decides: a later failure supersedes an earlier pass (no cherry-picking)", async () => {
    const w = await ready();
    await runWithScore(w, { score: 1 });
    w.clock.advance(1000);
    await runWithScore(w, { score: 0.2 });
    expect(codes(await ask(w))).toEqual(["below_threshold"]);
    w.clock.advance(1000);
    await runWithScore(w, { score: 1 });
    expect((await ask(w)).allowed).toBe(true);
  });

  it("blocks a stale run (replay of an old passing run)", async () => {
    const w = await ready({ suite: { max_age_days: 7 } });
    await runWithScore(w, { score: 1 });
    w.clock.advance(7 * DAY);
    expect((await ask(w)).allowed).toBe(true);
    w.clock.advance(1000);
    expect(codes(await ask(w))).toEqual(["stale_run"]);
  });

  it("does not trust runs from a runner that was revoked", async () => {
    const w = await ready();
    await runWithScore(w, { score: 1 });
    expect((await ask(w)).allowed).toBe(true);
    await w.hub.runs.revokeRunner(w.admin, "runner-1");
    expect(codes(await ask(w))).toEqual(["runner_not_registered"]);
    // a newer run from a new, registered runner does count
    await registerRunner(w, "runner-2");
    w.clock.advance(1000);
    await runWithScore(w, { score: 1, runner: runnerOf(w.tenant, "runner-2") });
    expect((await ask(w)).allowed).toBe(true);
  });

  it("does not accept a run planted for an unregistered runner id or with no runner", async () => {
    const w = await ready();
    const real = await runWithScore(w, { hash: HASH_B, score: 1 });
    await plant(w, real, (r) => {
      r.content_hash = HASH_A;
      r.blueprint.content_hash = HASH_A;
      r.runner_id = "ghost-runner";
    });
    expect(codes(await ask(w, HASH_A))).toEqual(["runner_not_registered"]);
    await plant(w, real, (r) => {
      r.content_hash = HASH_A;
      r.blueprint.content_hash = HASH_A;
      r.runner_id = null;
    });
    expect(codes(await ask(w, HASH_A))).toEqual(["runner_not_registered"]);
  });

  it("blocks a stored run whose record or scores were tampered with", async () => {
    const w = await ready();
    const real = await runWithScore(w, { hash: HASH_B, score: 0.1 });
    // forged aggregate, record hash left stale
    await plant(
      w,
      real,
      (r) => {
        r.content_hash = HASH_A;
        r.blueprint.content_hash = HASH_A;
        (r.scores as { overall: number }).overall = 0.99;
        r.status = "passed";
        r.passed = true;
      },
      false,
    );
    const r1 = await ask(w, HASH_A);
    expect(codes(r1)).toEqual(["integrity_failed"]);
    // forged aggregate AND a re-sealed record hash: the recomputation still catches it
    w.clock.advance(5);
    await plant(w, real, (r) => {
      r.content_hash = HASH_A;
      r.blueprint.content_hash = HASH_A;
      (r.scores as { overall: number }).overall = 0.99;
      r.status = "passed";
      r.passed = true;
    });
    const r2 = await ask(w, HASH_A);
    expect(codes(r2)).toEqual(["integrity_failed"]);
    expect(r2.reasons[0]?.message).toMatch(/recompute/);
  });

  it("blocks a consistent but too-small run (insufficient samples)", async () => {
    const w = await ready();
    const real = await runWithScore(w, { score: 1 });
    await plant(w, real, (r) => {
      r.case_results = r.case_results.slice(0, 2);
      r.sample_size = 2;
      (r.scores as { per_case: Record<string, number> }).per_case = Object.fromEntries(
        Object.entries((r.scores as { per_case: Record<string, number> }).per_case).slice(0, 2),
      );
    });
    w.clock.advance(5);
    expect(codes(await ask(w))).toEqual(["insufficient_samples"]);
  });

  it("blocks when the suite's dataset is gone", async () => {
    const w = new MemoryDocStore();
    const w1 = world({ docs: w });
    await seedSuite(w1);
    await registerRunner(w1);
    await runWithScore(w1, { score: 1 });
    // simulate a lost dataset document
    const rows = (w as unknown as { rows: Map<string, unknown> }).rows;
    for (const k of [...rows.keys()]) if (k.includes("\u0000datasets\u0000")) rows.delete(k);
    expect(codes(await ask(w1))).toEqual(["integrity_failed"]);
  });

  it("blocks while a human review of a newer run is pending", async () => {
    const w = world();
    await seedSuite(w, {
      graders: [
        { id: "exact", type: "deterministic", kind: "exact" },
        { id: "human", type: "human", rubric: "ok?", sla_hours: 24 },
      ],
    });
    await registerRunner(w);
    const run = await w.hub.runs.startAsRunner(w.runner, {
      suite_ref: "smoke@1.0.0",
      blueprint: bp(),
    });
    await w.hub.runs.submitResults(w.runner, run.id, {
      case_results: caseResults(["c1", "c2", "c3", "c4"], ["exact", "human"], (_i, g) =>
        g === "human" ? null : 1,
      ),
      provenance: PROV,
    });
    const r = await ask(w);
    expect(r.allowed).toBe(false);
    expect(codes(r)).toContain("run_in_progress");
  });

  it("adds tenant-required suites that apply to the blueprint even when the blueprint does not declare them", async () => {
    const w = await ready({ suite: { applies_to: ["support-agent"], required_for_release: true } });
    const r = await ask(w, HASH_A, []);
    expect(r.allowed).toBe(false);
    expect(codes(r)).toEqual(["missing_run"]);
    await runWithScore(w, { score: 1 });
    expect((await ask(w, HASH_A, [])).allowed).toBe(true);
    // not required: ignored
    const w2 = await ready({
      suite: { applies_to: ["support-agent"], required_for_release: false },
    });
    expect((await ask(w2, HASH_A, [])).allowed).toBe(true);
  });

  it("another tenant's runs and suites do not exist for the caller", async () => {
    const w = await ready();
    await runWithScore(w, { score: 1 });
    const stranger = user("00000000-0000-4000-8000-0000000000aa", "owner");
    expect(codes(await ask(w, HASH_A, [], stranger))).toEqual([]);
    expect(codes(await ask(w, HASH_A, [{ ref: "smoke@1.0.0" }], stranger))).toEqual([
      "suite_not_found",
    ]);
  });

  it("online results are never read by the gate", async () => {
    const w = await ready();
    await w.hub.online.put(w.admin, "prod-1", {
      blueprint_name: "support-agent",
      suite_ref: "smoke@1.0.0",
      rate: 1,
      max_per_hour: 100,
    });
    for (let i = 0; i < 6; i++)
      await w.hub.online.ingest(w.runner, {
        sampling_id: "prod-1",
        blueprint: bp(),
        scores: { exact: 1, contains: 1 },
      });
    const r = await ask(w);
    expect(r.allowed).toBe(false);
    expect(codes(r)).toEqual(["missing_run"]);
  });
});

describe("regression against the baseline", () => {
  async function baselined(opts: Parameters<typeof seedSuite>[1] = {}) {
    const w = await ready({ tolerance: 0.05, ...opts });
    const base = await runWithScore(w, { hash: HASH_A, score: 0.95 });
    await w.hub.baselines.set(w.admin, { run_id: base.id });
    w.clock.advance(1000);
    return { w, base };
  }

  it("blocks a drop beyond the tolerance, allows a drop within it, and an improvement", async () => {
    const { w } = await baselined();
    await runWithScore(w, { hash: HASH_B, score: 0.85 });
    const bad = await ask(w, HASH_B);
    expect(codes(bad)).toEqual(["regression"]);
    expect(bad.runs[0]).toMatchObject({ regression: true });
    expect(bad.runs[0]?.delta).toBeCloseTo(-0.1, 9);
    w.clock.advance(1000);
    await runWithScore(w, { hash: HASH_B, score: 0.9 }); // exactly the tolerance
    expect((await ask(w, HASH_B)).allowed).toBe(true);
    w.clock.advance(1000);
    await runWithScore(w, { hash: HASH_B, score: 1 });
    const better = await ask(w, HASH_B);
    expect(better.allowed).toBe(true);
    expect(better.runs[0]?.delta).toBeCloseTo(0.05, 9);
  });

  it("score above the threshold but regressed still blocks (threshold AND regression)", async () => {
    const { w } = await baselined({ pass_threshold: 0.5 });
    await runWithScore(w, { hash: HASH_B, score: 0.7 });
    const r = await ask(w, HASH_B, [{ ref: "smoke@1.0.0", threshold: 0.5 }]);
    expect(codes(r)).toEqual(["regression"]);
  });

  it("can require statistical significance before a regression blocks", async () => {
    const { w } = await baselined({ suite: { regression_requires_significance: true } });
    // one case worse by 0.4 only: mean drop 0.1 (> 0.05) but not significant with 4 pairs
    await runWithScore(w, { hash: HASH_B, score: (id) => (id === "c1" ? 0.55 : 0.95) });
    const r = await ask(w, HASH_B);
    expect(r.allowed).toBe(true);
    expect(r.runs[0]).toMatchObject({ regression: true });
  });

  it("without a baseline there is nothing to regress against", async () => {
    const w = await ready();
    await runWithScore(w, { hash: HASH_B, score: 0.81 });
    expect((await ask(w, HASH_B)).allowed).toBe(true);
  });

  it("the baseline run itself is not compared with itself", async () => {
    const { w } = await baselined();
    const r = await ask(w, HASH_A);
    expect(r.allowed).toBe(true);
    expect(r.runs[0]?.baseline_run_id).toBeNull();
  });

  it("a baseline that points at a tampered or foreign run is invalid, never ignored", async () => {
    const { w, base } = await baselined();
    await runWithScore(w, { hash: HASH_B, score: 0.99 });
    // forge a second baseline row naming a planted run whose record hash differs from the recorded one
    const planted = await plant(w, base, (r) => {
      (r.scores as { overall: number }).overall = 0.1;
    });
    const row: BaselineDoc = {
      blueprint_name: "support-agent",
      suite_ref: "smoke@1.0.0",
      seq: 2,
      run_id: planted.id,
      overall: 0.1,
      record_hash: "f".repeat(64),
      set_by: "evil",
      at: w.clock.now().toISOString(),
    };
    await w.docs.insert(w.tenant, "baselines", "support-agent|smoke@1.0.0|00000002", row);
    const r = await ask(w, HASH_B);
    expect(codes(r)).toEqual(["baseline_invalid"]);
    // a baseline row naming a missing run
    await w.docs.insert(w.tenant, "baselines", "support-agent|smoke@1.0.0|00000003", {
      ...row,
      seq: 3,
      run_id: randomUUID(),
    });
    expect(codes(await ask(w, HASH_B))).toEqual(["baseline_invalid"]);
  });

  it("a baseline row whose recorded hash differs from the (intact) run it points to is invalid", async () => {
    const { w, base } = await baselined();
    await runWithScore(w, { hash: HASH_B, score: 0.99 });
    // an intact, sealed copy of the baseline run under another id: valid on its own, but not what the row recorded
    const copy = await plant(w, base, () => undefined);
    const row: BaselineDoc = {
      blueprint_name: "support-agent",
      suite_ref: "smoke@1.0.0",
      seq: 2,
      run_id: copy.id,
      overall: copy.scores?.overall ?? 0,
      record_hash: base.record_hash as string,
      set_by: "evil",
      at: w.clock.now().toISOString(),
    };
    await w.docs.insert(w.tenant, "baselines", "support-agent|smoke@1.0.0|00000002", row);
    expect(codes(await ask(w, HASH_B))).toEqual(["baseline_invalid"]);
  });

  it("only an admin sets a baseline, from a passed, intact run; history is append-only", async () => {
    const w = await ready();
    const bad = await runWithScore(w, { hash: HASH_B, score: 0.1 });
    const good = await runWithScore(w, { hash: HASH_A, score: 0.9 });
    await expect(w.hub.baselines.set(w.builder, { run_id: good.id })).rejects.toThrow(
      /evals.admin/,
    );
    await expect(w.hub.baselines.set(w.admin, { run_id: bad.id })).rejects.toThrow(
      /only a passed run/,
    );
    await expect(w.hub.baselines.set(w.admin, { run_id: "nope" })).rejects.toThrow(/not found/);
    await expect(w.hub.baselines.set(w.admin, { run_id: 5 as never })).rejects.toThrow(/run_id/);
    const b1 = await w.hub.baselines.set(w.admin, { run_id: good.id });
    expect(b1).toMatchObject({ seq: 1, run_id: good.id, overall: 0.9 });
    expect((await w.hub.baselines.set(w.admin, { run_id: good.id })).seq).toBe(1); // already current
    w.clock.advance(1000);
    const better = await runWithScore(w, { hash: HASH_B, score: 1 });
    expect((await w.hub.baselines.set(w.admin, { run_id: better.id })).seq).toBe(2);
    const hist = await w.hub.baselines.list(w.builder, {
      blueprint_name: "support-agent",
      suite_ref: "smoke@1.0.0",
    });
    expect(hist.map((h) => h.seq)).toEqual([1, 2]);
    await expect(
      w.docs.update(w.tenant, "baselines", "support-agent|smoke@1.0.0|00000001", 1, {}),
    ).rejects.toThrow(/immutable/);
    await expect(
      w.hub.baselines.list(w.builder, { blueprint_name: "Bad", suite_ref: "smoke@1.0.0" }),
    ).rejects.toThrow(/blueprint_name/);
    await expect(
      w.hub.baselines.list(w.builder, { blueprint_name: "support-agent", suite_ref: "x" }),
    ).rejects.toThrow(/suite_ref/);
    // comparison endpoint
    expect(await w.hub.baselines.compareRun(w.builder, better.id)).toBeNull();
    const cmp = await w.hub.baselines.compareRun(w.builder, bad.id);
    expect(cmp?.comparable).toBe(true);
    expect(cmp?.regression).toBe(true);
    await expect(w.hub.baselines.compareRun(w.builder, "ghost")).rejects.toThrow(/not found/);
    const q = await w.hub.runs.request(w.builder, {
      suite_ref: "smoke@1.0.0",
      blueprint: bp(HASH_B),
    });
    await expect(w.hub.baselines.compareRun(w.builder, q.id)).rejects.toThrow(/not finished/);
  });
});

describe("failures of the gate itself", () => {
  it("rejects malformed requests", async () => {
    const w = await ready();
    const t = (b: unknown, s: unknown = []) =>
      w.hub.gate.check(w.builder, { blueprint: b, suites: s }).then(
        () => "ok",
        (e: HubError) => `${e.code}:${e.checks.join(",")}`,
      );
    expect(await t(5)).toBe("invalid:blueprint");
    expect(await t({ ...bp(), name: "Bad" })).toBe("invalid:blueprint.name");
    expect(await t({ ...bp(), version: "" })).toBe("invalid:blueprint.version");
    expect(await t({ ...bp(), content_hash: "x" })).toBe("invalid:blueprint.content_hash");
    expect(await t({ ...bp(), namespace: "Bad Ns" })).toBe("invalid:blueprint.namespace");
    expect(await t(bp(), "x")).toBe("invalid:suites");
    expect(await t(bp(), [5])).toBe("invalid:suites[0].ref");
    expect(await t(bp(), [{ ref: "no-version" }])).toBe("invalid:suites[0].ref");
    expect(await t(bp(), [{ ref: "smoke@1.0.0", threshold: 2 }])).toBe(
      "invalid:suites[0].threshold",
    );
    expect(
      await t({ ...bp(), namespace: "acme" }, [
        { ref: "smoke@1.0.0", threshold: 0.1 },
        { ref: "smoke@1.0.0", threshold: 0.9 },
      ]),
    ).toBe("ok");
    expect(
      await w.hub.gate.check(w.runner, { blueprint: bp(), suites: [] }).then(
        () => "ok",
        (e: HubError) => e.code,
      ),
    ).toBe("forbidden");
    expect(
      await w.hub.gate.check(user(w.tenant, "reviewer"), { blueprint: bp(), suites: [] }).then(
        () => "ok",
        (e: HubError) => e.code,
      ),
    ).toBe("ok");
    expect(
      await w.hub.gate
        .check(
          { kind: "platform", service: "eval-hub" as never, subject: "x", tenantId: w.tenant },
          { blueprint: bp(), suites: [] },
        )
        .then(
          () => "ok",
          (e: HubError) => e.code,
        ),
    ).toBe("forbidden");
  });

  it("an unexpected error while evaluating a suite blocks (gate_error)", async () => {
    const inner = new MemoryDocStore();
    let boom = false;
    const flaky: DocStore = {
      get: (...a) => inner.get(...a),
      insert: (...a) => inner.insert(...a),
      update: (...a) => inner.update(...a),
      find: (t, c, f) =>
        boom && c === "runs" ? Promise.reject(new Error("db down")) : inner.find(t, c, f),
    };
    const w = world({ docs: flaky });
    await seedSuite(w);
    await registerRunner(w);
    await runWithScore(w, { score: 1 });
    expect((await ask(w)).allowed).toBe(true);
    boom = true;
    const r = await ask(w);
    expect(r.allowed).toBe(false);
    expect(codes(r)).toEqual(["gate_error"]);
    expect(JSON.stringify(r)).not.toContain("db down");
  });

  it("a gate decision that cannot be audited is not returned", async () => {
    const w = await ready();
    await runWithScore(w, { score: 1 });
    const failing = createEvalHub({
      docs: w.docs,
      audit: new ServiceAudit(
        { append: () => Promise.reject(new Error("audit down")) } as never,
        "eval-hub",
      ),
      now: w.clock.now,
    });
    await expect(
      failing.gate.check(w.builder, { blueprint: bp(), suites: [{ ref: "smoke@1.0.0" }] }),
    ).rejects.toMatchObject({ code: "unavailable" });
    // ... and the registry-facing port turns that into a refusal, never an exception or an allow
    const res = await failing.gatePort.check({
      tenantId: w.tenant,
      blueprint: {
        namespace: "acme",
        name: "support-agent",
        version: "1.0.0",
        contentHash: HASH_A,
      },
      suites: [{ ref: "smoke@1.0.0", threshold: 0.5 }],
      actor: "u",
      purpose: "release",
    });
    expect(res.allowed).toBe(false);
    expect(res.reasons[0]?.code).toBe("gate_unavailable");
    void hex;
  });
});

describe("the registry-facing port", () => {
  const input = (w: World, hash = HASH_A) => ({
    tenantId: w.tenant,
    blueprint: { namespace: "acme", name: "support-agent", version: "1.0.0", contentHash: hash },
    suites: [{ ref: "smoke@1.0.0", threshold: 0.8 }],
    actor: "marketplace-bot",
    purpose: "release" as const,
  });

  it("checks as the platform principal and returns the reasons", async () => {
    const w = await ready();
    expect(await w.hub.gatePort.check(input(w))).toMatchObject({
      allowed: false,
      reasons: [{ code: "missing_run" }],
    });
    await runWithScore(w, { score: 1 });
    expect((await w.hub.gatePort.check(input(w))).allowed).toBe(true);
    expect(
      (await w.hub.gatePort.check({ ...input(w), purpose: "marketplace_submit" })).allowed,
    ).toBe(true);
    expect(
      (
        await w.hub.gatePort.check({
          ...input(w),
          tenantId: "00000000-0000-4000-8000-0000000000ab",
        })
      ).allowed,
    ).toBe(false);
  });

  it("promotes the released run to the baseline, once", async () => {
    const w = await ready();
    const run = await runWithScore(w, { score: 0.9 });
    await w.hub.gatePort.released?.(input(w));
    await w.hub.gatePort.released?.(input(w));
    const hist = await w.hub.baselines.list(w.admin, {
      blueprint_name: "support-agent",
      suite_ref: "smoke@1.0.0",
    });
    expect(hist).toHaveLength(1);
    expect(hist[0]).toMatchObject({ run_id: run.id, set_by: "release:marketplace-bot" });
    // not allowed: nothing is promoted
    const w2 = await ready();
    await runWithScore(w2, { score: 0.1 });
    await w2.hub.gatePort.released?.(input(w2));
    expect(
      await w2.hub.baselines.list(w2.admin, {
        blueprint_name: "support-agent",
        suite_ref: "smoke@1.0.0",
      }),
    ).toEqual([]);
  });
});
