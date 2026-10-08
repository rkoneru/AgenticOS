import { describe, expect, it } from "vitest";
import { hashJson } from "@axis/contracts";
import { HubError, parseGraders, redactJson } from "../src/index.js";
import { CASES, events, DET, HUMAN, seedSuite, user, world } from "./helpers.js";

const code = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "ok";
  } catch (e) {
    return e instanceof HubError ? `${e.code}:${e.checks.join(",")}` : "error";
  }
};

describe("datasets", () => {
  it("creates immutable, numbered versions with a content hash", async () => {
    const w = world();
    const v1 = await w.hub.datasets.create(w.builder, { name: "ds", cases: CASES });
    const v2 = await w.hub.datasets.create(w.builder, {
      name: "ds",
      cases: [...CASES, { id: "c5", input: "x" }],
    });
    expect([v1.version, v2.version]).toEqual([1, 2]);
    expect(v1.ref).toBe("ds@1");
    expect(v1.content_hash).toBe(hashJson(v1.cases));
    expect(v1.content_hash).not.toBe(v2.content_hash);
    expect(v1.case_count).toBe(4);
    expect((await w.hub.datasets.get(w.admin, "ds@1")).content_hash).toBe(v1.content_hash);
    expect((await w.hub.datasets.get(w.admin, "ds@latest")).version).toBe(2);
    const list = await w.hub.datasets.list(w.admin);
    expect(list.map((d) => d.ref)).toEqual(["ds@1", "ds@2"]);
    expect("cases" in (list[0] as object)).toBe(false);
    expect(await w.hub.datasets.list(w.admin, "nope")).toEqual([]);
    // there is no update path: the stored document is frozen
    await expect(w.docs.update(w.tenant, "datasets", "ds@1", 1, {})).rejects.toThrow(/immutable/);
  });

  it("validates names and cases", async () => {
    const w = world();
    const bad = (input: Record<string, unknown>) => code(w.hub.datasets.create(w.builder, input as never));
    expect(await bad({ name: "Bad Name", cases: CASES })).toMatch(/^invalid/);
    expect(await bad({ name: "ds", cases: [] })).toMatch(/^invalid:cases/);
    expect(await bad({ name: "ds", cases: "x" })).toMatch(/^invalid/);
    expect(await bad({ name: "ds", cases: [1] })).toMatch(/^invalid:cases\[0\]/);
    expect(await bad({ name: "ds", cases: [{ id: "a b", input: 1 }] })).toMatch(/^invalid:cases\[0\].id/);
    expect(await bad({ name: "ds", cases: [{ id: "a", input: 1 }, { id: "a", input: 2 }] })).toMatch(/duplicate|invalid/);
    expect(await bad({ name: "ds", cases: [{ id: "a" }] })).toMatch(/^invalid:cases\[0\].input/);
    expect(await bad({ name: "ds", cases: [{ id: "a", input: 1, tags: "x" }] })).toMatch(/tags/);
    expect(await bad({ name: "ds", cases: [{ id: "a", input: 1, metadata: [] }] })).toMatch(/metadata/);
    expect(await bad({ name: "ds", cases: [{ id: "a", input: "x".repeat(70_000) }] })).toMatch(/^invalid/);
    expect(await bad({ name: "ds", cases: CASES, phi: "yes" })).toMatch(/^invalid:phi/);
    expect(await bad({ name: "ds", cases: CASES, description: 5 })).toMatch(/^invalid:description/);
  });

  it("redacts PHI before anything is persisted, hashes the redacted cases, and PHI never downgrades", async () => {
    const w = world();
    const raw = [
      { id: "p1", input: "Patient jane.doe@example.com SSN 123-45-6789 call +1 415 555 0100", expected: { note: "card 4111 1111 1111 1111" } },
    ];
    const v1 = await w.hub.datasets.create(w.builder, { name: "phi-ds", cases: raw, phi: true });
    expect(v1.phi && v1.redacted).toBe(true);
    const stored = JSON.stringify((await w.docs.get(w.tenant, "datasets", "phi-ds@1"))?.data);
    for (const leak of ["jane.doe", "123-45-6789", "555 0100", "4111"]) expect(stored).not.toContain(leak);
    expect(stored).toContain("[email]");
    expect(v1.content_hash).toBe(hashJson(v1.cases));
    // a later version without the flag stays PHI (cannot be downgraded)
    const v2 = await w.hub.datasets.create(w.builder, { name: "phi-ds", cases: raw });
    expect(v2.phi).toBe(true);
    expect(JSON.stringify(v2.cases)).not.toContain("jane.doe");
    // non-PHI data is stored as given
    const plain = await w.hub.datasets.create(w.builder, { name: "plain", cases: raw });
    expect(plain.redacted).toBe(false);
    expect(JSON.stringify(plain.cases)).toContain("jane.doe");
  });

  it("applies the tenant hook after the built-in net, and withholds a value if the hook throws", () => {
    expect(redactJson({ a: "Acme Corp" }, (s) => s.replace("Acme", "[org]"))).toEqual({ a: "[org] Corp" });
    expect(
      redactJson(["secret"], () => {
        throw new Error("boom");
      }),
    ).toEqual(["[redacted:error]"]);
    let deep: unknown = "x@y.io";
    for (let i = 0; i < 20; i++) deep = [deep];
    expect(JSON.stringify(redactJson(deep))).toContain("[redacted:depth]");
    expect(redactJson({ n: 1, b: true, z: null })).toEqual({ n: 1, b: true, z: null });
  });

  it("needs the builder role to write and a tenant credential to read; other tenants see nothing", async () => {
    const w = world();
    expect(await code(w.hub.datasets.create(user(w.tenant, "viewer"), { name: "ds", cases: CASES }))).toBe("forbidden:");
    expect(await code(w.hub.datasets.create(w.runner, { name: "ds", cases: CASES }))).toBe("forbidden:");
    expect(await code(w.hub.datasets.create(user(w.tenant, "reviewer"), { name: "ds", cases: CASES }))).toBe("forbidden:");
    await w.hub.datasets.create(w.builder, { name: "ds", cases: CASES });
    expect(await code(w.hub.datasets.get(user(w.tenant, "viewer"), "ds@1"))).toBe("ok");
    const other = user("00000000-0000-4000-8000-000000000002", "owner");
    expect(await code(w.hub.datasets.get(other, "ds@1"))).toBe("not_found:");
    expect(await code(w.hub.datasets.get(w.admin, "ds@latest"))).toBe("ok");
    expect(await code(w.hub.datasets.get(w.admin, "bad ref"))).toBe("not_found:");
    expect(await code(w.hub.datasets.get(w.admin, "ghost@latest"))).toBe("not_found:");
    expect(await code(w.hub.datasets.get(w.admin, "ghost@3"))).toBe("not_found:");
    expect((await w.hub.datasets.list(other)).length).toBe(0);
    // refused writes are audited as DENY, accepted ones as ALLOW + done
    const ev = await events(w, "evals.dataset.create", "evals.dataset.create.done");
    expect(ev.filter((e) => e.decision === "DENY")).toHaveLength(3);
    expect(ev.filter((e) => e.action.endsWith(".done"))).toHaveLength(1);
  });
});

describe("graders", () => {
  it("accepts every deterministic kind, a model grader and a human grader", () => {
    const gs = parseGraders([
      { id: "g1", type: "deterministic", kind: "exact" },
      { id: "g2", type: "deterministic", kind: "contains", params: { case_sensitive: false } },
      { id: "g3", type: "deterministic", kind: "regex", params: { pattern: "^a+$", flags: "i" } },
      { id: "g4", type: "deterministic", kind: "json_schema", params: { schema: { type: "object" } } },
      { id: "g5", type: "deterministic", kind: "numeric_tolerance", params: { abs: 0.5, rel: 0.1 } },
      { id: "g6", type: "deterministic", kind: "tool_call_sequence", params: { mode: "subsequence" } },
      { id: "g7", type: "deterministic", kind: "policy_decision", params: { expected: "DENY" } },
      { id: "g8", type: "deterministic", kind: "cost_latency_budget", params: { max_cost_usd: 0.1, max_latency_ms: 5000 } },
      { id: "m1", type: "model", rubric: "Score faithfulness.", judge_model: "judge-1", weight: 2 },
      { id: "h1", type: "human", rubric: "Helpful?", double_grade: true, agreement_tolerance: 0.2 },
    ]);
    expect(gs).toHaveLength(10);
    expect(gs[9]).toMatchObject({ sla_hours: 72, double_grade: true, agreement_tolerance: 0.2, weight: 1 });
    expect(gs[0]).toMatchObject({ weight: 1, params: {} });
  });

  it("rejects malformed configuration with the offending path", () => {
    const e = (g: unknown) => {
      try {
        parseGraders(g);
        return "ok";
      } catch (x) {
        return (x as HubError).checks.join(",");
      }
    };
    const d = (extra: Record<string, unknown>) => [{ id: "g", type: "deterministic", ...extra }];
    expect(e("x")).toBe("graders");
    expect(e([])).toBe("graders");
    expect(e(new Array(21).fill(DET))).toBe("graders");
    expect(e([1])).toBe("graders[0]");
    expect(e([{ id: "Bad", type: "model" }])).toBe("graders[0].id");
    expect(e([DET, DET])).toBe("graders[1].id");
    expect(e([{ ...DET, weight: 0 }])).toBe("graders[0].weight");
    expect(e([{ ...DET, weight: 101 }])).toBe("graders[0].weight");
    expect(e([{ id: "g", type: "x" }])).toBe("graders[0].type");
    expect(e(d({ kind: "nope" }))).toBe("graders[0].kind");
    expect(e(d({ kind: "exact", params: 5 }))).toBe("graders[0].params");
    expect(e(d({ kind: "exact", params: { surprise: 1 } }))).toBe("graders[0].params.surprise");
    expect(e(d({ kind: "exact", params: { trim: "yes" } }))).toBe("graders[0].params.trim");
    expect(e(d({ kind: "contains", params: { case_sensitive: 1 } }))).toBe("graders[0].params.case_sensitive");
    expect(e(d({ kind: "regex", params: {} }))).toBe("graders[0].params.pattern");
    expect(e(d({ kind: "regex", params: { pattern: "x".repeat(201) } }))).toBe("graders[0].params.pattern");
    expect(e(d({ kind: "regex", params: { pattern: "(", flags: "" } }))).toBe("graders[0].params.pattern");
    expect(e(d({ kind: "regex", params: { pattern: "a", flags: "g" } }))).toBe("graders[0].params.flags");
    expect(e(d({ kind: "json_schema", params: { schema: [] } }))).toBe("graders[0].params.schema");
    expect(e(d({ kind: "numeric_tolerance", params: {} }))).toBe("graders[0].params");
    expect(e(d({ kind: "numeric_tolerance", params: { abs: -1 } }))).toBe("graders[0].params.abs");
    expect(e(d({ kind: "tool_call_sequence", params: { mode: "any" } }))).toBe("graders[0].params.mode");
    expect(e(d({ kind: "policy_decision", params: { expected: "MAYBE" } }))).toBe("graders[0].params.expected");
    expect(e(d({ kind: "cost_latency_budget", params: {} }))).toBe("graders[0].params");
    expect(e([{ id: "m", type: "model", rubric: "", judge_model: "j" }])).toBe("graders[0].rubric");
    expect(e([{ id: "m", type: "model", rubric: "r" }])).toBe("graders[0].judge_model");
    expect(e([{ id: "h", type: "human", rubric: "r", sla_hours: 0 }])).toBe("graders[0].sla_hours");
    expect(e([{ id: "h", type: "human", rubric: "r", double_grade: "y" }])).toBe("graders[0].double_grade");
    expect(e([{ id: "h", type: "human", rubric: "r", agreement_tolerance: 2 }])).toBe("graders[0].agreement_tolerance");
  });
});

describe("suites", () => {
  it("pins the dataset version and hash, is immutable, and listed per tenant", async () => {
    const w = world();
    const s = await seedSuite(w, { graders: [DET, HUMAN], tolerance: 0.1, suite: { applies_to: ["b-agent", "a-agent", "a-agent"], min_samples: 2 } });
    const ds = await w.hub.datasets.get(w.admin, "ds@1");
    expect(s).toMatchObject({ ref: "smoke@1.0.0", name: "smoke", version: "1.0.0", dataset_hash: ds.content_hash, tolerance: 0.1, min_samples: 2, required_for_release: true });
    expect(s.applies_to).toEqual(["a-agent", "b-agent"]);
    expect(s.suite_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(await code(w.hub.suites.create(w.builder, { ref: "smoke@1.0.0", dataset_ref: "ds@1", graders: [DET], pass_threshold: 0.1 }))).toBe("conflict:");
    expect((await w.hub.suites.get(w.admin, "smoke@1.0.0")).suite_hash).toBe(s.suite_hash);
    expect(await w.hub.suites.list(w.admin)).toHaveLength(1);
    expect(await code(w.hub.suites.get(w.admin, "ghost@1.0.0"))).toBe("not_found:");
    expect(await w.hub.suites.list(user("00000000-0000-4000-8000-000000000003", "owner"))).toEqual([]);
  });

  it("validates its fields", async () => {
    const w = world();
    await w.hub.datasets.create(w.builder, { name: "ds", cases: CASES });
    const mk = (o: Record<string, unknown>) =>
      code(w.hub.suites.create(w.builder, { ref: "smoke@1.0.0", dataset_ref: "ds@1", graders: [DET], pass_threshold: 0.5, ...o } as never));
    expect(await mk({ ref: "bad" })).toMatch(/^invalid:ref/);
    expect(await mk({ ref: 5 })).toMatch(/^invalid:ref/);
    expect(await mk({ dataset_ref: "ds" })).toMatch(/^invalid:dataset_ref/);
    expect(await mk({ dataset_ref: "ghost@1" })).toMatch(/^invalid:dataset_ref/);
    expect(await mk({ graders: [] })).toMatch(/^invalid:graders/);
    expect(await mk({ pass_threshold: undefined })).toMatch(/^invalid:pass_threshold/);
    expect(await mk({ pass_threshold: 2 })).toMatch(/^invalid:pass_threshold/);
    expect(await mk({ tolerance: -1 })).toMatch(/^invalid:tolerance/);
    expect(await mk({ alpha: 0 })).toMatch(/^invalid:alpha/);
    expect(await mk({ max_age_days: 0.5 })).toMatch(/^invalid:max_age_days/);
    expect(await mk({ min_samples: 1.5 })).toMatch(/^invalid:min_samples/);
    expect(await mk({ min_samples: 99 })).toMatch(/^invalid:min_samples/);
    expect(await mk({ required_for_release: "yes" })).toMatch(/^invalid:required_for_release/);
    expect(await mk({ regression_requires_significance: 1 })).toMatch(/^invalid:regression_requires_significance/);
    expect(await mk({ applies_to: ["Bad Name"] })).toMatch(/^invalid:applies_to/);
    expect(await mk({ applies_to: "x" })).toMatch(/^invalid:applies_to/);
    expect(await code(w.hub.suites.create(user(w.tenant, "viewer"), { ref: "smoke@2.0.0", dataset_ref: "ds@1", graders: [DET], pass_threshold: 0.5 }))).toBe("forbidden:");
  });
});
