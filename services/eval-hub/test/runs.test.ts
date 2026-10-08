import { describe, expect, it } from "vitest";
import { HubError, recordHashOf, verifyStoredRun, type EvalRunDoc } from "../src/index.js";
import { hashJson } from "@axis/contracts";
import {
  events,
  HASH_A,
  HASH_B,
  PROV,
  bp,
  caseResults,
  mean,
  registerRunner,
  runWithScore,
  runnerOf,
  seedSuite,
  user,
  world,
} from "./helpers.js";

const code = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "ok";
  } catch (e) {
    return e instanceof HubError ? `${e.code}:${e.checks.join(",")}` : `error:${String(e)}`;
  }
};

const submit = (
  w: ReturnType<typeof world>,
  runId: string,
  o: {
    results?: unknown;
    scores?: unknown;
    cost?: unknown;
    provenance?: unknown;
    runner?: ReturnType<typeof runnerOf>;
  } = {},
) =>
  w.hub.runs.submitResults(o.runner ?? w.runner, runId, {
    case_results: o.results ?? caseResults(["c1", "c2", "c3", "c4"], ["exact", "contains"], 1),
    ...("scores" in o
      ? { scores: o.scores }
      : { scores: { overall: 1, per_grader: { exact: 1, contains: 1 } } }),
    ...("cost" in o ? { cost: o.cost } : {}),
    provenance: "provenance" in o ? o.provenance : PROV,
  } as never);

async function started(w: ReturnType<typeof world>) {
  await seedSuite(w);
  await registerRunner(w);
  return w.hub.runs.startAsRunner(w.runner, { suite_ref: "smoke@1.0.0", blueprint: bp() });
}

describe("runners", () => {
  it("are registered by an admin, listed, revoked one-way", async () => {
    const w = world();
    await expect(w.hub.runs.registerRunner(w.builder, "r1")).rejects.toThrow(/may not evals.admin/);
    const r = await w.hub.runs.registerRunner(w.admin, "r1", "ci worker");
    expect(r).toMatchObject({ runner_id: "r1", description: "ci worker", revoked_at: null });
    expect(await code(w.hub.runs.registerRunner(w.admin, "r1"))).toBe("conflict:");
    expect(await code(w.hub.runs.registerRunner(w.admin, "bad id"))).toMatch(/^invalid/);
    expect(await code(w.hub.runs.registerRunner(w.admin, "r2", 5))).toMatch(/^invalid/);
    expect(await w.hub.runs.listRunners(w.admin)).toHaveLength(1);
    expect(await w.hub.runs.runnerActive(w.tenant, "r1")).toBe(true);
    const rv = await w.hub.runs.revokeRunner(w.admin, "r1");
    expect(rv.revoked_at).not.toBeNull();
    expect((await w.hub.runs.revokeRunner(w.admin, "r1")).revoked_at).toBe(rv.revoked_at);
    expect(await w.hub.runs.runnerActive(w.tenant, "r1")).toBe(false);
    expect(await code(w.hub.runs.revokeRunner(w.admin, "ghost"))).toBe("not_found:");
    expect(await code(w.hub.runs.revokeRunner(w.builder, "r1"))).toBe("forbidden:");
    // a revoked id can not come back
    expect(await code(w.hub.runs.registerRunner(w.admin, "r1"))).toBe("conflict:");
  });

  it("an unregistered or revoked runner can start, claim and submit nothing", async () => {
    const w = world();
    await seedSuite(w);
    expect(
      await code(w.hub.runs.startAsRunner(w.runner, { suite_ref: "smoke@1.0.0", blueprint: bp() })),
    ).toBe("forbidden:");
    await registerRunner(w);
    const run = await w.hub.runs.startAsRunner(w.runner, {
      suite_ref: "smoke@1.0.0",
      blueprint: bp(),
    });
    await w.hub.runs.revokeRunner(w.admin, "runner-1");
    expect(await code(submit(w, run.id))).toBe("forbidden:");
    const queued = await w.hub.runs.request(w.builder, {
      suite_ref: "smoke@1.0.0",
      blueprint: bp(HASH_B),
    });
    expect(await code(w.hub.runs.claim(w.runner, queued.id))).toBe("forbidden:");
    expect(await code(w.hub.runs.fail(w.runner, run.id, "x"))).toBe("forbidden:");
  });
});

describe("starting and claiming", () => {
  it("a member queues a run, a registered runner claims it exactly once", async () => {
    const w = world();
    await seedSuite(w);
    await registerRunner(w);
    await registerRunner(w, "runner-2");
    const q = await w.hub.runs.request(w.builder, {
      suite_ref: "smoke@1.0.0",
      blueprint: bp(HASH_A, "support-agent", "1.0.0", "acme"),
      mode: "manual",
    });
    expect(q).toMatchObject({
      status: "queued",
      runner_id: null,
      requested_by: "bob-builder",
      mode: "manual",
      blueprint_name: "support-agent",
    });
    expect(q.blueprint.namespace).toBe("acme");
    const mine = await w.hub.runs.list(w.runner, { status: "queued" });
    expect(mine.items.map((r) => r.id)).toEqual([q.id]);
    const c = await w.hub.runs.claim(w.runner, q.id);
    expect(c).toMatchObject({ status: "running", runner_id: "runner-1" });
    expect(await code(w.hub.runs.claim(runnerOf(w.tenant, "runner-2"), q.id))).toBe("conflict:");
    expect(await code(w.hub.runs.claim(w.runner, "ghost"))).toBe("not_found:");
  });

  it("validates the request and needs the right credential", async () => {
    const w = world();
    await seedSuite(w);
    await registerRunner(w);
    const req = (o: Record<string, unknown>) =>
      code(
        w.hub.runs.request(w.builder, { suite_ref: "smoke@1.0.0", blueprint: bp(), ...o } as never),
      );
    expect(await req({ suite_ref: "bad" })).toMatch(/^invalid:suite_ref/);
    expect(await req({ suite_ref: "other@1.0.0" })).toMatch(/^invalid:suite_ref/);
    expect(await req({ blueprint: 5 })).toMatch(/^invalid:blueprint/);
    expect(await req({ blueprint: { ...bp(), name: "Bad" } })).toMatch(/blueprint.name/);
    expect(await req({ blueprint: { ...bp(), version: "" } })).toMatch(/blueprint.version/);
    expect(await req({ blueprint: { ...bp(), content_hash: "abc" } })).toMatch(/content_hash/);
    expect(await req({ blueprint: { ...bp(), namespace: "Bad Ns" } })).toMatch(/namespace/);
    expect(await req({ mode: "online" })).toMatch(/^invalid:mode/);
    expect(
      await code(
        w.hub.runs.request(user(w.tenant, "viewer"), { suite_ref: "smoke@1.0.0", blueprint: bp() }),
      ),
    ).toBe("forbidden:");
    expect(
      await code(w.hub.runs.request(w.runner, { suite_ref: "smoke@1.0.0", blueprint: bp() })),
    ).toBe("forbidden:");
    expect(
      await code(
        w.hub.runs.startAsRunner(w.builder, { suite_ref: "smoke@1.0.0", blueprint: bp() }),
      ),
    ).toBe("forbidden:");
    expect(await code(w.hub.runs.claim(w.builder, "x"))).toBe("forbidden:");
  });
});

describe("submitting results: the hub recomputes", () => {
  it("stores the hub's own aggregate, seals the record and audits it", async () => {
    const w = world();
    const run = await started(w);
    const done = await submit(w, run.id, { cost: { total_usd: 0.04 } });
    expect(done).toMatchObject({
      status: "passed",
      passed: true,
      pending_human: 0,
      sample_size: 4,
      provenance: { seed: "7" },
    });
    expect(done.scores?.overall).toBe(1);
    expect(done.cost.total_usd).toBe(0.04);
    expect(done.record_hash).toBe(recordHashOf(done));
    expect(done.case_results.every((c) => c.case_score === 1)).toBe(true);
    expect(await w.hub.runs.get(w.admin, run.id)).toEqual(done);
    const fin = await events(w, "evals.run.final");
    expect(fin).toHaveLength(1);
    expect(fin[0]).toMatchObject({ decision: "ALLOW" });
    expect(fin[0]?.outputs_hash).toBe(
      hashJson({
        status: "passed",
        overall: 1,
        record_hash: done.record_hash,
        runner_id: "runner-1",
      }),
    );
    expect(await w.audit.verify(w.tenant)).toMatchObject({ ok: true });
    expect(await code(submit(w, run.id))).toBe("conflict:"); // finished runs are closed
    const suite = await w.hub.suites.get(w.admin, "smoke@1.0.0");
    expect(verifyStoredRun(done, suite)).toEqual([]);
  });

  it("marks a run below the suite threshold as failed", async () => {
    const w = world();
    await started(w);
    const done = await runWithScore(w, { hash: HASH_B, score: 0.5 });
    expect(done).toMatchObject({ status: "failed", passed: false });
    expect(done.scores?.overall).toBe(0.5);
  });

  it("REJECTS a runner-supplied aggregate that does not match the per-case results", async () => {
    const w = world();
    const run = await started(w);
    const results = caseResults(["c1", "c2", "c3", "c4"], ["exact", "contains"], 0.5);
    expect(
      await code(
        submit(w, run.id, {
          results,
          scores: { overall: 1, per_grader: { exact: 0.5, contains: 0.5 } },
        }),
      ),
    ).toBe("integrity_failed:mismatch.overall");
    expect(
      await code(
        submit(w, run.id, {
          results,
          scores: { overall: 0.5, per_grader: { exact: 0.9, contains: 0.5 } },
        }),
      ),
    ).toBe("integrity_failed:mismatch.per_grader.exact");
    expect(await code(submit(w, run.id, { results, scores: {} }))).toBe(
      "integrity_failed:mismatch.overall",
    );
    expect(await code(submit(w, run.id, { results, scores: undefined }))).toMatch(
      /^invalid:scores/,
    );
    expect(await code(submit(w, run.id, { results, scores: "1" }))).toMatch(/^invalid:scores/);
    // nothing was stored by the failed attempts, the run is still open and accepts the honest submission
    expect((await w.hub.runs.get(w.admin, run.id)).status).toBe("running");
    const ok = await submit(w, run.id, { results, scores: { overall: 0.5 } });
    expect(ok.status).toBe("failed");
  });

  it("rejects a mismatched cost claim", async () => {
    const w = world();
    const run = await started(w);
    expect(await code(submit(w, run.id, { cost: { total_usd: 99 } }))).toBe(
      "integrity_failed:cost.total_usd",
    );
    expect(await code(submit(w, run.id, { cost: "free" }))).toBe("integrity_failed:cost.total_usd");
  });

  it("rejects incomplete, duplicate, unknown or out-of-range results", async () => {
    const w = world();
    const run = await started(w);
    const all = caseResults(["c1", "c2", "c3", "c4"], ["exact", "contains"], 1) as {
      case_id: string;
      scores: Record<string, unknown>;
    }[];
    const t = (results: unknown) => code(submit(w, run.id, { results }));
    expect(await t("x")).toMatch(/^invalid:case_results/);
    expect(await t(all.slice(0, 3))).toMatch(/^invalid:case_results/);
    expect(await t([...all, all[0]])).toMatch(/duplicate|invalid/);
    expect(await t([{ ...all[0], case_id: "zzz" }, ...all.slice(1)])).toMatch(
      /case_results\[0\].case_id/,
    );
    expect(await t([5, ...all.slice(1)])).toMatch(/case_results\[0\]/);
    expect(await t([{ ...all[0], scores: 5 }, ...all.slice(1)])).toMatch(/scores/);
    expect(
      await t([{ ...all[0], scores: { exact: 1, contains: 1, extra: 1 } }, ...all.slice(1)]),
    ).toMatch(/scores.extra/);
    expect(await t([{ ...all[0], scores: { exact: 1 } }, ...all.slice(1)])).toMatch(
      /scores.contains/,
    );
    expect(await t([{ ...all[0], scores: { exact: 1.2, contains: 1 } }, ...all.slice(1)])).toMatch(
      /scores.exact/,
    );
    expect(
      await t([{ ...all[0], scores: { exact: Number.NaN, contains: 1 } }, ...all.slice(1)]),
    ).toMatch(/scores.exact/);
    expect(await t([{ ...all[0], cost_usd: -1 }, ...all.slice(1)])).toMatch(/cost_usd/);
    expect(await t([{ ...all[0], latency_ms: "x" }, ...all.slice(1)])).toMatch(/latency_ms/);
    expect(await t([{ ...all[0], trace_id: 5 }, ...all.slice(1)])).toMatch(/trace_id/);
    expect(await t([{ ...all[0], error: 5 }, ...all.slice(1)])).toMatch(/error/);
    const good = [
      { ...all[0], latency_ms: 12, trace_id: "tr1", error: "judge timeout" },
      ...all.slice(1),
    ];
    const done = await submit(w, run.id, { results: good });
    expect(done.case_results[0]).toMatchObject({
      latency_ms: 12,
      trace_id: "tr1",
      error: "judge timeout",
    });
  });

  it("requires provenance", async () => {
    const w = world();
    const run = await started(w);
    for (const p of [
      undefined,
      "x",
      { ...PROV, runner_version: "" },
      { ...PROV, model_ids: "m" },
      { ...PROV, model_ids: [1] },
      { ...PROV, seed: undefined },
      { ...PROV, seed: {} },
    ])
      expect(await code(submit(w, run.id, { provenance: p }))).toMatch(/^invalid:provenance/);
  });

  it("only the owning, active runner of a running run may submit", async () => {
    const w = world();
    const run = await started(w);
    await registerRunner(w, "runner-2");
    expect(await code(submit(w, run.id, { runner: runnerOf(w.tenant, "runner-2") }))).toBe(
      "forbidden:",
    );
    expect(await code(submit(w, "ghost"))).toBe("not_found:");
    expect(await code(w.hub.runs.submitResults(w.builder, run.id, {} as never))).toBe("forbidden:");
    const queued = await w.hub.runs.request(w.builder, {
      suite_ref: "smoke@1.0.0",
      blueprint: bp(HASH_B),
    });
    expect(await code(submit(w, queued.id))).toBe("conflict:");
  });

  it("detects a suite or dataset that changed under a run", async () => {
    const w = world();
    const run = await started(w);
    const d = await w.docs.get(w.tenant, "runs", run.id);
    await w.docs.update(w.tenant, "runs", run.id, d?.rev as number, {
      ...(d?.data as object),
      suite_hash: "0".repeat(64),
    });
    expect(await code(submit(w, run.id))).toBe("integrity_failed:suite_hash");
  });

  it("a failed run is terminal and never counts as passed", async () => {
    const w = world();
    const run = await started(w);
    await expect(w.hub.runs.fail(w.runner, run.id, "")).rejects.toThrow(/reason/);
    const f = await w.hub.runs.fail(w.runner, run.id, "judge model unreachable");
    expect(f).toMatchObject({
      status: "errored",
      passed: false,
      failure_reason: "judge model unreachable",
    });
    expect(f.record_hash).toBe(recordHashOf(f));
    expect(await code(submit(w, run.id))).toBe("conflict:");
    expect(await code(w.hub.runs.fail(w.runner, run.id, "again"))).toBe("conflict:");
    expect(await code(w.hub.runs.fail(w.runner, "ghost", "x"))).toBe("not_found:");
    await registerRunner(w, "runner-2");
    const other = await w.hub.runs.startAsRunner(w.runner, {
      suite_ref: "smoke@1.0.0",
      blueprint: bp(HASH_B),
    });
    expect(await code(w.hub.runs.fail(runnerOf(w.tenant, "runner-2"), other.id, "x"))).toBe(
      "forbidden:",
    );
  });
});

describe("a finished run cannot be changed", () => {
  it("the store refuses to update it, and a tampered copy fails verification", async () => {
    const w = world();
    const done = await (async () => {
      await started(w);
      return runWithScore(w, { hash: HASH_B, score: 0.5 });
    })();
    const d = await w.docs.get<EvalRunDoc>(w.tenant, "runs", done.id);
    await expect(
      w.docs.update(w.tenant, "runs", done.id, d?.rev as number, { ...done, status: "passed" }),
    ).rejects.toThrow(/immutable/);
    const suite = await w.hub.suites.get(w.admin, "smoke@1.0.0");
    const forged: EvalRunDoc = JSON.parse(JSON.stringify(done));
    forged.scores = { ...(forged.scores as NonNullable<EvalRunDoc["scores"]>), overall: 0.99 };
    expect(verifyStoredRun(forged, suite)).toContain("record_hash");
    // even with a re-sealed record hash, the scores no longer recompute from the case results
    forged.record_hash = recordHashOf(forged);
    const bad = verifyStoredRun(forged, suite);
    expect(bad).toContain("recompute.overall");
    const flipped: EvalRunDoc = JSON.parse(JSON.stringify(done));
    flipped.status = "passed";
    flipped.passed = true;
    flipped.record_hash = recordHashOf(flipped);
    expect(verifyStoredRun(flipped, suite)).toContain("status");
    const noScores: EvalRunDoc = { ...JSON.parse(JSON.stringify(done)), scores: null };
    noScores.record_hash = recordHashOf(noScores);
    expect(verifyStoredRun(noScores, suite)).toContain("scores_missing");
    const pending: EvalRunDoc = JSON.parse(JSON.stringify(done));
    (pending.case_results[0] as { scores: Record<string, number | null> }).scores["exact"] = null;
    pending.record_hash = recordHashOf(pending);
    expect(verifyStoredRun(pending, suite)).toContain("recompute");
    const wrongSuite = { ...suite, suite_hash: "1".repeat(64), dataset_hash: "2".repeat(64) };
    expect(verifyStoredRun(done, wrongSuite)).toEqual(
      expect.arrayContaining(
        ["suite_hash", "dataset_hash", "record_hash"].filter((x) => x !== "record_hash"),
      ),
    );
    const hashMismatch: EvalRunDoc = JSON.parse(JSON.stringify(done));
    hashMismatch.content_hash = HASH_A;
    hashMismatch.record_hash = recordHashOf(hashMismatch);
    expect(verifyStoredRun(hashMismatch, suite)).toContain("content_hash");
    const short: EvalRunDoc = JSON.parse(JSON.stringify(done));
    short.sample_size = 9;
    short.record_hash = recordHashOf(short);
    expect(verifyStoredRun(short, suite)).toContain("sample_size");
    const errored: EvalRunDoc = {
      ...JSON.parse(JSON.stringify(done)),
      status: "errored",
      scores: null,
    };
    errored.record_hash = recordHashOf(errored);
    expect(verifyStoredRun(errored, suite)).toEqual([]);
  });
});

describe("listing and tenancy", () => {
  it("lists newest first with filters and cursor paging", async () => {
    const w = world();
    await seedSuite(w);
    await registerRunner(w);
    const ids: string[] = [];
    for (let i = 0; i < 5; i++) {
      w.clock.advance(1000);
      ids.push(
        (
          await w.hub.runs.request(w.builder, {
            suite_ref: "smoke@1.0.0",
            blueprint: bp(i % 2 ? HASH_A : HASH_B),
          })
        ).id,
      );
    }
    const p1 = await w.hub.runs.list(w.admin, { limit: 2 });
    expect(p1.items.map((r) => r.id)).toEqual([ids[4], ids[3]]);
    expect(p1.next_cursor).not.toBeNull();
    const p2 = await w.hub.runs.list(w.admin, { limit: 2, cursor: p1.next_cursor as string });
    expect(p2.items.map((r) => r.id)).toEqual([ids[2], ids[1]]);
    const p3 = await w.hub.runs.list(w.admin, { limit: 2, cursor: p2.next_cursor as string });
    expect(p3.items.map((r) => r.id)).toEqual([ids[0]]);
    expect(p3.next_cursor).toBeNull();
    expect((await w.hub.runs.list(w.admin, { content_hash: HASH_A })).items).toHaveLength(2);
    expect((await w.hub.runs.list(w.admin, { status: "running" })).items).toHaveLength(0);
    expect(
      (
        await w.hub.runs.list(w.admin, {
          suite_ref: "smoke@1.0.0",
          blueprint_name: "support-agent",
          mode: "ci",
        })
      ).items,
    ).toHaveLength(5);
    expect(await code(w.hub.runs.list(w.admin, { status: 5 as never }))).toMatch(/^invalid/);
    expect(await code(w.hub.runs.list(w.admin, { cursor: "AAAA" }))).toMatch(/^invalid:cursor/);
    expect((await w.hub.runs.list(w.admin, { limit: 0 })).items).toHaveLength(1);
  });

  it("another tenant sees none of it", async () => {
    const w = world();
    const run = await started(w);
    const other = user("00000000-0000-4000-8000-000000000009", "owner");
    expect(await code(w.hub.runs.get(other, run.id))).toBe("not_found:");
    expect((await w.hub.runs.list(other)).items).toEqual([]);
    expect(await code(w.hub.runs.get(user(w.tenant, "viewer"), run.id))).toBe("ok");
    expect(
      await code(
        w.hub.runs.get(
          { kind: "platform", service: "registry", subject: "x", tenantId: w.tenant },
          run.id,
        ),
      ),
    ).toBe("forbidden:");
    void mean;
  });

  it("attestation needs a signing key and a finished run", async () => {
    const w = world();
    const run = await started(w);
    expect(await code(w.hub.runs.attestation(w.admin, run.id))).toBe("conflict:");
  });
});
