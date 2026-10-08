import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { hashJson } from "@axis/contracts";
import { HubError, canonicalAscii, parseGraders, redactJson } from "../src/index.js";
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

  it("hashes the cases exactly as the runner does (pinned by the runner's own fixture), sorted by id and ASCII-escaped", async () => {
    const wire = JSON.parse(
      readFileSync(
        fileURLToPath(new URL("./fixtures/eval-hub-wire-examples.json", import.meta.url)),
        "utf8",
      ),
    ) as {
      dataset: { version_hash: string; cases: unknown[]; phi: boolean };
    };
    const w = world();
    const v = await w.hub.datasets.create(w.builder, {
      name: "refund-cases",
      cases: wire.dataset.cases,
    });
    expect(v.version_hash).toBe(wire.dataset.version_hash);
    expect(v.content_hash).toBe(wire.dataset.version_hash);
    // the order the cases were listed in does not matter; non-ASCII and DEL are escaped like Python's ensure_ascii
    const a = await w.hub.datasets.create(w.builder, {
      name: "ord",
      cases: [
        { id: "b", input: "x" },
        { id: "a", input: "caf\u00e9\u007f" },
      ],
    });
    const b = await w.hub.datasets.create(w.builder, {
      name: "ord2",
      cases: [
        { id: "a", input: "caf\u00e9\u007f" },
        { id: "b", input: "x" },
      ],
    });
    expect(a.version_hash).toBe(b.version_hash);
    expect(canonicalAscii({ k: "caf\u00e9\u007f\n", n: [1, 2.5, null, true], z: {} })).toBe(
      '{"k":"caf\\u00e9\\u007f\\n","n":[1,2.5,null,true],"z":{}}',
    );
    expect(() => canonicalAscii(Number.NaN)).toThrow();
    expect(() => canonicalAscii(undefined)).toThrow();
    // a missing `expected` is the wire's null
    expect(a.cases[0]).toMatchObject({ id: "b", expected: null, tags: [], metadata: {} });
  });

  it("validates names and cases", async () => {
    const w = world();
    const bad = (input: Record<string, unknown>) =>
      code(w.hub.datasets.create(w.builder, input as never));
    expect(await bad({ name: "Bad Name", cases: CASES })).toMatch(/^invalid/);
    expect(await bad({ name: "ds", cases: [] })).toMatch(/^invalid:cases/);
    expect(await bad({ name: "ds", cases: "x" })).toMatch(/^invalid/);
    expect(await bad({ name: "ds", cases: [1] })).toMatch(/^invalid:cases\[0\]/);
    expect(await bad({ name: "ds", cases: [{ id: "a b", input: 1 }] })).toMatch(
      /^invalid:cases\[0\].id/,
    );
    expect(
      await bad({
        name: "ds",
        cases: [
          { id: "a", input: 1 },
          { id: "a", input: 2 },
        ],
      }),
    ).toMatch(/duplicate|invalid/);
    expect(await bad({ name: "ds", cases: [{ id: "a" }] })).toMatch(/^invalid:cases\[0\].input/);
    expect(await bad({ name: "ds", cases: [{ id: "a", input: 1, tags: "x" }] })).toMatch(/tags/);
    expect(await bad({ name: "ds", cases: [{ id: "a", input: 1, metadata: [] }] })).toMatch(
      /metadata/,
    );
    expect(await bad({ name: "ds", cases: [{ id: "a", input: "x".repeat(70_000) }] })).toMatch(
      /^invalid/,
    );
    expect(await bad({ name: "ds", cases: CASES, phi: "yes" })).toMatch(/^invalid:phi/);
    expect(await bad({ name: "ds", cases: CASES, description: 5 })).toMatch(/^invalid:description/);
  });

  it("redacts PHI before anything is persisted, hashes the redacted cases, and PHI never downgrades", async () => {
    const w = world();
    const raw = [
      {
        id: "p1",
        input: "Patient jane.doe@example.com SSN 123-45-6789 call +1 415 555 0100",
        expected: { note: "card 4111 1111 1111 1111" },
      },
    ];
    const v1 = await w.hub.datasets.create(w.builder, { name: "phi-ds", cases: raw, phi: true });
    expect(v1.phi && v1.redacted).toBe(true);
    const stored = JSON.stringify((await w.docs.get(w.tenant, "datasets", "phi-ds@1"))?.data);
    for (const leak of ["jane.doe", "123-45-6789", "555 0100", "4111"])
      expect(stored).not.toContain(leak);
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
    expect(redactJson({ a: "Acme Corp" }, (s) => s.replace("Acme", "[org]"))).toEqual({
      a: "[org] Corp",
    });
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
    expect(
      await code(w.hub.datasets.create(user(w.tenant, "viewer"), { name: "ds", cases: CASES })),
    ).toBe("forbidden:");
    expect(await code(w.hub.datasets.create(w.runner, { name: "ds", cases: CASES }))).toBe(
      "forbidden:",
    );
    expect(
      await code(w.hub.datasets.create(user(w.tenant, "reviewer"), { name: "ds", cases: CASES })),
    ).toBe("forbidden:");
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
  const d = (type: string, extra: Record<string, unknown> = {}) => ({
    id: "g",
    kind: "deterministic",
    config: { type, ...extra },
  });

  it("accepts every deterministic type, a model grader and a human grader, in the runner's shape", () => {
    const gs = parseGraders([
      ...[
        "exact",
        "contains",
        "not_contains",
        "json_schema",
        "numeric_tolerance",
        "tool_sequence",
        "tool_subsequence",
        "policy_decision",
        "budget",
      ].map((t, i) => ({
        id: `g${i}`,
        kind: "deterministic",
        config: { type: t },
      })),
      {
        id: "re",
        kind: "deterministic",
        weight: 2,
        min_mean: 0.9,
        config: { type: "regex", pattern: "^a+$" },
      },
      {
        id: "m1",
        kind: "model",
        weight: 2,
        config: { provider: "openai", model: "judge-1", rubric: "Score faithfulness." },
      },
      {
        id: "h1",
        kind: "human",
        config: { rubric: "Helpful?", double_grade: true, agreement_tolerance: 0.2 },
      },
    ]);
    expect(gs).toHaveLength(12);
    expect(gs[9]).toMatchObject({ weight: 2, min_mean: 0.9 });
    expect(gs[11]?.config).toMatchObject({
      sla_hours: 72,
      double_grade: true,
      agreement_tolerance: 0.2,
    });
    expect(gs[0]).toMatchObject({ weight: 1, min_mean: null });
    expect(
      parseGraders([{ id: "h", kind: "human", config: { rubric: "r" } }])[0]?.config,
    ).toMatchObject({ double_grade: false, agreement_tolerance: 0.1 });
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
    expect(e("x")).toBe("graders");
    expect(e([])).toBe("graders");
    expect(e(new Array(21).fill(DET))).toBe("graders");
    expect(e([1])).toBe("graders[0]");
    expect(e([{ id: "bad id", kind: "model" }])).toBe("graders[0].id");
    expect(e([DET, DET])).toBe("graders[1].id");
    expect(e([{ ...DET, weight: 0 }])).toBe("graders[0].weight");
    expect(e([{ ...DET, weight: 101 }])).toBe("graders[0].weight");
    expect(e([{ ...DET, min_mean: 2 }])).toBe("graders[0].min_mean");
    expect(e([{ id: "g", kind: "x" }])).toBe("graders[0].kind");
    expect(e([{ ...DET, config: 5 }])).toBe("graders[0].config");
    expect(e([{ ...DET, config: { type: "exact", blob: "x".repeat(21_000) } }])).toBe(
      "graders[0].config",
    );
    expect(e([d("nope")])).toBe("graders[0].config.type");
    expect(e([{ id: "g", kind: "deterministic" }])).toBe("graders[0].config.type");
    expect(e([d("regex")])).toBe("graders[0].config.pattern");
    expect(e([d("regex", { pattern: "x".repeat(1001) })])).toBe("graders[0].config.pattern");
    expect(e([{ id: "m", kind: "model", config: { model: "m", rubric: "r" } }])).toBe(
      "graders[0].config.provider",
    );
    expect(e([{ id: "m", kind: "model", config: { provider: "p", rubric: "r" } }])).toBe(
      "graders[0].config.model",
    );
    expect(e([{ id: "m", kind: "model", config: { provider: "p", model: "m" } }])).toBe(
      "graders[0].config.rubric",
    );
    expect(e([{ id: "h", kind: "human", config: {} }])).toBe("graders[0].config.rubric");
    expect(e([{ id: "h", kind: "human", config: { rubric: "r", sla_hours: 0 } }])).toBe(
      "graders[0].config.sla_hours",
    );
    expect(e([{ id: "h", kind: "human", config: { rubric: "r", double_grade: "y" } }])).toBe(
      "graders[0].config.double_grade",
    );
    expect(e([{ id: "h", kind: "human", config: { rubric: "r", agreement_tolerance: 2 } }])).toBe(
      "graders[0].config.agreement_tolerance",
    );
  });
});

describe("suites", () => {
  it("pins the dataset version and hash, is immutable, and listed per tenant", async () => {
    const w = world();
    const s = await seedSuite(w, {
      graders: [DET, HUMAN],
      tolerance: 0.1,
      suite: { applies_to: ["b-agent", "a-agent", "a-agent"], min_samples: 2 },
    });
    const ds = await w.hub.datasets.get(w.admin, "ds@1");
    expect(s).toMatchObject({
      ref: "smoke@1.0.0",
      name: "smoke",
      version: "1.0.0",
      dataset_hash: ds.content_hash,
      tolerance: 0.1,
      min_samples: 2,
      required_for_release: true,
    });
    expect(s.applies_to).toEqual(["a-agent", "b-agent"]);
    expect(s.suite_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(
      await code(
        w.hub.suites.create(w.builder, {
          ref: "smoke@1.0.0",
          dataset_ref: "ds@1",
          graders: [DET],
          pass_threshold: 0.1,
        }),
      ),
    ).toBe("conflict:");
    expect((await w.hub.suites.get(w.admin, "smoke@1.0.0")).suite_hash).toBe(s.suite_hash);
    expect(await w.hub.suites.list(w.admin)).toHaveLength(1);
    expect(await code(w.hub.suites.get(w.admin, "ghost@1.0.0"))).toBe("not_found:");
    expect(await w.hub.suites.list(user("00000000-0000-4000-8000-000000000003", "owner"))).toEqual(
      [],
    );
  });

  it("validates its fields", async () => {
    const w = world();
    await w.hub.datasets.create(w.builder, { name: "ds", cases: CASES });
    const mk = (o: Record<string, unknown>) =>
      code(
        w.hub.suites.create(w.builder, {
          ref: "smoke@1.0.0",
          dataset_ref: "ds@1",
          graders: [DET],
          pass_threshold: 0.5,
          ...o,
        } as never),
      );
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
    expect(await mk({ regression_requires_significance: 1 })).toMatch(
      /^invalid:regression_requires_significance/,
    );
    expect(await mk({ applies_to: ["Bad Name"] })).toMatch(/^invalid:applies_to/);
    expect(await mk({ applies_to: "x" })).toMatch(/^invalid:applies_to/);
    expect(
      await code(
        w.hub.suites.create(user(w.tenant, "viewer"), {
          ref: "smoke@2.0.0",
          dataset_ref: "ds@1",
          graders: [DET],
          pass_threshold: 0.5,
        }),
      ),
    ).toBe("forbidden:");
  });
});
