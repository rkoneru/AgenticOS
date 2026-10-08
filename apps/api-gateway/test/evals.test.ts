import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { UnavailableEvals } from "../src/index.js";
import { call, makeWorld, seed, type Seed, type World } from "./world.js";

/** The Phase 8 operations (OpenAPI 1.3.0, ADR 0057) beyond the spec-derived contract walk. */
let w: World;
let s: Seed;
let other: Awaited<ReturnType<World["tenant"]>>;

beforeAll(async () => {
  w = await makeWorld({
    rate: { burst: 1e6, perSecond: 1e6 },
    unauthRate: { burst: 1e6, perSecond: 1e6 },
  });
  s = await seed(w);
  other = await w.tenant();
});
afterAll(() => w.close());

const as = (c: { token: string }, method: string, path: string, body?: unknown) =>
  call(w, method, path, { token: c.token, ...(body !== undefined ? { body } : {}) });

describe("startEvalRun", () => {
  it("queues a run bound to the CONTENT hash of the stored blueprint (the caller never supplies it)", async () => {
    const r = await as(s.owner, "POST", "/evals/runs", {
      suite: s.evals.plainSuite,
      blueprint: s.blueprint,
    });
    expect(r.status, r.text).toBe(202);
    expect(r.headers.get("location")).toBe(`/v1/evals/runs/${r.body.id}`);
    expect(r.body).toMatchObject({
      suite: s.evals.plainSuite,
      status: "queued",
      mode: "ci",
      threshold: 0.8,
      score: null,
    });
    expect(r.body.blueprint).toMatchObject({
      name: s.blueprint.name,
      version: s.blueprint.version,
      content_hash: s.evals.contentHash,
    });
    const again = await as(s.owner, "GET", `/evals/runs/${r.body.id}`);
    expect(again.body.case_results).toEqual([]);
    // an unknown blueprint version is a 404, an unknown suite a 422, and the hash cannot be smuggled in
    expect(
      (
        await as(s.owner, "POST", "/evals/runs", {
          suite: s.evals.plainSuite,
          blueprint: { name: "claims", version: "9.9.9" },
        })
      ).status,
    ).toBe(404);
    const noSuite = await as(s.owner, "POST", "/evals/runs", {
      suite: "ghost@1.0.0",
      blueprint: s.blueprint,
    });
    expect(noSuite.status).toBe(422);
    expect(noSuite.body.errors[0].path).toBe("/suite_ref");
    const smuggled = await as(s.owner, "POST", "/evals/runs", {
      suite: s.evals.plainSuite,
      blueprint: { ...s.blueprint, content_hash: "a".repeat(64) },
    });
    expect(smuggled.body.blueprint.content_hash).toBe(s.evals.contentHash);
  });

  it("resolves a registry blueprint by namespace through the registry (and refuses a stranger's)", async () => {
    const r = await as(s.owner, "POST", "/evals/runs", {
      suite: s.evals.plainSuite,
      mode: "manual",
      blueprint: { namespace: s.own.namespace, name: s.own.name, version: "1.0.0" },
    });
    expect(r.status, r.text).toBe(202);
    expect(r.body).toMatchObject({
      mode: "manual",
      blueprint: { namespace: s.own.namespace, version: "1.0.0" },
    });
    const stranger = await as(other, "POST", "/evals/runs", {
      suite: s.evals.plainSuite,
      blueprint: { namespace: s.own.namespace, name: s.own.name, version: "1.0.0" },
    });
    expect(stranger.status).toBe(404);
  });

  it("is idempotent under an Idempotency-Key", async () => {
    const body = { suite: s.evals.plainSuite, blueprint: s.blueprint };
    const key = `idem-${Math.random().toString(16).slice(2)}-eval`;
    const a = await call(w, "POST", "/evals/runs", {
      token: s.owner.token,
      body,
      headers: { "idempotency-key": key },
    });
    const b = await call(w, "POST", "/evals/runs", {
      token: s.owner.token,
      body,
      headers: { "idempotency-key": key },
    });
    expect(a.status).toBe(202);
    expect(b.body.id).toBe(a.body.id);
  });
});

describe("reading", () => {
  it("lists runs newest first with a signed cursor, filtered by suite, blueprint, hash and status", async () => {
    const p1 = await as(s.owner, "GET", "/evals/runs?limit=2");
    expect(p1.status).toBe(200);
    expect(p1.body.items).toHaveLength(2);
    expect(typeof p1.body.next_cursor).toBe("string");
    const p2 = await as(
      s.owner,
      "GET",
      `/evals/runs?limit=2&cursor=${encodeURIComponent(p1.body.next_cursor)}`,
    );
    expect(p2.status).toBe(200);
    expect(p2.body.items.map((x: { id: string }) => x.id)).not.toEqual(
      expect.arrayContaining(p1.body.items.map((x: { id: string }) => x.id)),
    );
    const forged = await as(s.owner, "GET", "/evals/runs?cursor=AAAA");
    expect(forged.status).toBe(422);
    const byHash = await as(
      s.owner,
      "GET",
      `/evals/runs?content_hash=${s.evals.contentHash}&status=passed`,
    );
    expect(byHash.body.items.map((x: { id: string }) => x.id)).toEqual([s.evals.runId]);
    // a cursor from another tenant does not decode
    const theirs = await as(
      other,
      "GET",
      `/evals/runs?cursor=${encodeURIComponent(p1.body.next_cursor)}`,
    );
    expect(theirs.status).toBe(422);
  });

  it("returns the recomputed scores, the per-case grades and the comparison with the baseline", async () => {
    const run = await as(s.owner, "GET", `/evals/runs/${s.evals.runId}`);
    expect(run.body).toMatchObject({
      status: "passed",
      score: 0.95,
      scores: { status: "complete", overall: 0.95, passed: true, failures: [] },
    });
    expect(run.body.case_results).toHaveLength(3);
    expect(run.body.case_results[0].grades).toHaveLength(2);
    expect(run.body.record_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(run.body)).not.toContain("suite_hash");
    const cmp = await as(s.owner, "GET", `/evals/runs/${s.evals.run2Id}/comparison`);
    expect(cmp.body.comparison).toMatchObject({
      comparable: true,
      regression: true,
      blocking: true,
    });
    expect(cmp.body.comparison.delta).toBeCloseTo(-0.1, 6);
    const none = await as(s.owner, "GET", `/evals/runs/${s.evals.runId}/comparison`);
    expect(none.body).toEqual({});
  });

  it("another tenant sees none of it", async () => {
    expect((await as(other, "GET", `/evals/runs/${s.evals.runId}`)).status).toBe(404);
    expect((await as(other, "GET", "/evals/runs")).body.items).toEqual([]);
    expect((await as(other, "GET", "/evals/suites")).body.items).toEqual([]);
    expect((await as(other, "GET", "/evals/datasets")).body.items).toEqual([]);
    expect((await as(other, "GET", "/evals/suites/seed-plain%401.0.0")).status).toBe(404);
    expect((await as(other, "GET", "/evals/datasets/seed-ds/versions/1")).status).toBe(404);
    expect((await as(other, "GET", "/evals/reviews/tasks")).body.items).toEqual([]);
    expect((await as(other, "GET", "/evals/sampling")).body.items).toEqual([]);
    expect((await as(other, "GET", "/evals/runners")).body.items).toEqual([]);
    expect(
      (await as(other, "POST", `/evals/reviews/tasks/${s.evals.claimTask}/claim`)).status,
    ).toBe(404);
  });

  it("dataset versions: integer or latest only; the suite is addressed by its encoded ref", async () => {
    expect(
      (await as(s.owner, "GET", "/evals/datasets/seed-ds/versions/1")).body.cases,
    ).toHaveLength(3);
    expect((await as(s.owner, "GET", "/evals/datasets/seed-ds/versions/0")).status).toBe(404);
    expect((await as(s.owner, "GET", "/evals/datasets/seed-ds/versions/x")).status).toBe(404);
    expect((await as(s.owner, "GET", "/evals/datasets/Bad_Name/versions/1")).status).toBe(404);
    expect(
      (await as(s.owner, "GET", "/evals/suites/seed-plain%401.0.0")).body.graders[0],
    ).toMatchObject({ kind: "deterministic", weight: 1 });
  });
});

describe("the release gate over the API", () => {
  const ask = (suites: unknown, hash = s.evals.contentHash) =>
    as(s.owner, "POST", "/evals/gate", {
      blueprint: { name: s.blueprint.name, version: s.blueprint.version, content_hash: hash },
      suites,
    });

  it("allows the passing, baselined run and blocks every other hash, listing why", async () => {
    const ok = await ask([{ ref: s.evals.plainSuite, threshold: 0.8 }]);
    expect(ok.body).toMatchObject({ allowed: true, reasons: [] });
    expect(ok.body.runs[0]).toMatchObject({ run_id: s.evals.runId, overall: 0.95 });
    // content that is not the stored version's content is refused, never answered
    const stale = await ask([{ ref: s.evals.plainSuite }], "c".repeat(64));
    expect(stale.status).toBe(422);
    expect(stale.body.errors[0].path).toBe("/blueprint/content_hash");
    // a version that is not stored is a hypothetical question: answered for the suites given, fail-closed
    const hypo = await as(s.owner, "POST", "/evals/gate", {
      blueprint: { name: s.blueprint.name, version: "8.8.8", content_hash: "c".repeat(64) },
      suites: [{ ref: s.evals.plainSuite }],
    });
    expect(hypo.body.reasons.map((r: { code: string }) => r.code)).toEqual([
      "no_run_for_content_hash",
    ]);
    const regress = await as(s.owner, "POST", "/evals/gate", {
      blueprint: { name: s.blueprint.name, version: "9.9.9", content_hash: "f".repeat(64) },
      suites: [{ ref: s.evals.plainSuite }],
    });
    expect(regress.body.reasons.map((r: { code: string }) => r.code)).toEqual(["regression"]);
    const bad = await ask([{ ref: "no-version" }]);
    expect(bad.status).toBe(422);
    expect((await ask([{ ref: s.evals.plainSuite, threshold: 2 }])).status).toBe(422);
  });

  it("always asks the suites the STORED blueprint declares, even when the caller leaves `suites` out", async () => {
    // publish a version whose ABL declares a suite nothing has ever run
    const abl = {
      apiVersion: "abl.axis.dev/v1",
      kind: "Agent",
      metadata: { name: "declares-evals", version: "1.0.0" },
      spec: {
        riskClassification: {
          level: "minimal",
          rationale: "Answers questions; no decisions about people.",
        },
        model: { primary: { provider: "openai", model: "gpt-4o" } },
        instructions: { system: "You answer." },
        evals: { suites: [{ ref: s.evals.plainSuite, threshold: 0.8 }] },
      },
    };
    const pub = await as(s.owner, "POST", "/blueprints", { abl });
    expect(pub.status, pub.text).toBe(201);
    const none = await as(s.owner, "POST", "/evals/gate", {
      blueprint: { name: "declares-evals", version: "1.0.0", content_hash: pub.body.content_hash },
    });
    expect(none.status, none.text).toBe(200);
    expect(none.body.allowed).toBe(false);
    expect(none.body.reasons.map((r: { code: string }) => r.code)).toEqual(["missing_run"]);
    expect(none.body.reasons[0].suite_ref).toBe(s.evals.plainSuite);
  });

  it("a viewer may ask; the gate is audited in the tenant's chain", async () => {
    const viewer = await w.member(s.owner.tenantId, "viewer");
    expect(
      (
        await as(viewer, "POST", "/evals/gate", {
          blueprint: { name: "claims", version: "1.0.0", content_hash: s.evals.contentHash },
          suites: [],
        })
      ).body.allowed,
    ).toBe(true);
    const head = await w.audit.read(s.owner.tenantId);
    expect(head.some((e) => e.action === "evals.gate")).toBe(true);
  });
});

describe("roles and scopes (the control-plane pack decides)", () => {
  const matrix: [string, string, string, unknown, number][] = [
    // role, method, path, body, expected status
    ["viewer", "GET", "/evals/runs", undefined, 200],
    ["viewer", "POST", "/evals/datasets", { name: "v-ds", cases: [{ id: "a", input: 1 }] }, 403],
    ["viewer", "POST", "/evals/reviews/tasks/x/claim", undefined, 403],
    ["auditor", "GET", "/evals/runs", undefined, 200],
    [
      "auditor",
      "POST",
      "/evals/runs",
      { suite: "x@1.0.0", blueprint: { name: "claims", version: "1.0.0" } },
      403,
    ],
    ["operator", "GET", "/evals/reviews/tasks", undefined, 200],
    ["operator", "POST", "/evals/datasets", { name: "v-ds", cases: [{ id: "a", input: 1 }] }, 403],
    [
      "operator",
      "POST",
      "/evals/runs",
      { suite: "x@1.0.0", blueprint: { name: "claims", version: "1.0.0" } },
      403,
    ],
    ["builder", "POST", "/evals/datasets", { name: "b-ds", cases: [{ id: "a", input: 1 }] }, 201],
    ["builder", "PUT", "/evals/runners/b-runner", {}, 403],
    [
      "builder",
      "POST",
      "/evals/baselines",
      { run_id: "00000000-0000-4000-8000-000000000000" },
      403,
    ],
    ["billing", "GET", "/evals/runs", undefined, 403],
  ];
  for (const [role, method, path, body, status] of matrix)
    it(`${role} ${method} ${path} -> ${status}`, async () => {
      const m = await w.member(s.owner.tenantId, role as never);
      expect((await as(m, method, path, body)).status).toBe(status);
    });

  it("an API key needs evals:read to read and evals:write to run, write, review or administer", async () => {
    const read = await w.apiKey(s.owner, ["evals:read"]);
    const write = await w.apiKey(s.owner, ["evals:write"]);
    expect((await call(w, "GET", "/evals/runs", { key: read })).status).toBe(200);
    expect((await call(w, "GET", "/evals/runs", { key: write })).status).toBe(403);
    expect(
      (await call(w, "PUT", "/evals/runners/key-runner", { key: read, body: {} })).status,
    ).toBe(403);
    expect(
      (await call(w, "PUT", "/evals/runners/key-runner", { key: write, body: {} })).status,
    ).toBe(200);
    expect(
      (
        await call(w, "POST", "/evals/gate", {
          key: read,
          body: { blueprint: { name: "claims", version: "1", content_hash: "a".repeat(64) } },
        })
      ).status,
    ).toBe(200);
  });
});

describe("human review over the API", () => {
  it("the publisher/starter rule and a double-check on the claim surface as 403/409 problems", async () => {
    const rita = await w.member(s.owner.tenantId, "operator");
    const t = await as(rita, "GET", "/evals/reviews/tasks?state=open");
    expect(t.status).toBe(200);
    const open = t.body.items as { id: string }[];
    expect(open.length).toBeGreaterThan(0);
    // grading needs a claim first
    const early = await as(rita, "POST", `/evals/reviews/tasks/${open[0]?.id}/grade`, {
      score: 1,
      comment: "ok",
    });
    expect(early.status).toBe(409);
    expect((await as(rita, "POST", `/evals/reviews/tasks/${open[0]?.id}/claim`)).status).toBe(200);
    const done = await as(rita, "POST", `/evals/reviews/tasks/${open[0]?.id}/grade`, {
      score: 1,
      comment: "ok",
    });
    expect(done.body).toMatchObject({
      state: "resolved",
      resolution: { score: 1, method: "single" },
    });
    expect(
      (
        await as(rita, "POST", `/evals/reviews/tasks/${open[0]?.id}/grade`, {
          score: 1,
          comment: "again",
        })
      ).status,
    ).toBe(403);
    expect((await as(rita, "POST", "/evals/reviews/tasks/ghost/claim")).status).toBe(404);
    expect(
      (
        await as(rita, "POST", `/evals/reviews/tasks/${open[1]?.id}/grade`, {
          score: 5,
          comment: "x",
        })
      ).status,
    ).toBe(422);
  });
});

describe("a gateway without an Eval Hub fails closed", () => {
  it("answers 503, never an empty success", async () => {
    const w2 = await makeWorld(
      { rate: { burst: 1e6, perSecond: 1e6 } },
      { evals: new UnavailableEvals() },
    );
    try {
      const t = await w2.tenant();
      for (const [m, p] of [
        ["GET", "/evals/runs"],
        ["GET", "/evals/suites"],
        ["GET", "/evals/runners"],
      ] as const) {
        const r = await call(w2, m, p, { token: t.token });
        expect(r.status).toBe(503);
        expect(r.body.code).toBe("internal");
      }
      const gate = await call(w2, "POST", "/evals/gate", {
        token: t.token,
        body: { blueprint: { name: "claims", version: "1", content_hash: "a".repeat(64) } },
      });
      expect(gate.status).toBe(503);
    } finally {
      await w2.close();
    }
  });
});
