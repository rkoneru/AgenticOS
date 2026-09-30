import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import {
  compilePolicySet,
  lit,
  opaBuildWasm,
  opaCheck,
  opaEval,
  type CompileResult,
} from "../src/index.js";

const pack = (extra: Record<string, unknown> = {}, rules?: unknown[], gates?: unknown[]) => ({
  apiVersion: "policy.axis.dev/v1",
  kind: "PolicyPack",
  metadata: { name: "pk", version: "1.0.0" },
  spec: {
    defaultDecision: "DENY",
    ...(gates ? { gates } : {}),
    rules: rules ?? [{ id: "rl", enforcementPoints: ["tool_call"], decision: "DENY" }],
    ...extra,
  },
});
const rule = (when: unknown, decision = "ALLOW", id = "rl") => ({
  id,
  enforcementPoints: ["tool_call"],
  decision,
  when,
});
const ok = (r: CompileResult) => {
  if (!r.ok) throw new Error(JSON.stringify(r.issues));
  return r;
};
const codes = (r: CompileResult) => (r.ok ? [] : r.issues.map((i) => i.code));

describe("lit", () => {
  it("emits sorted-key Rego terms", () => {
    expect(lit({ b: [1, "x", null, true], a: { z: 1, y: 2 } })).toBe(
      '{"a": {"y": 2, "z": 1}, "b": [1, "x", null, true]}',
    );
  });
});

describe("compilePolicySet: structure and determinism", () => {
  const docs = ["baseline-deny/pack.yaml", "phi-redaction/pack.yaml"].map((f) =>
    parse(readFileSync(new URL(`../../../policies/${f}`, import.meta.url), "utf8")),
  );

  it("is deterministic, order independent across packs, and does not mutate input", () => {
    const before = JSON.stringify(docs);
    const a = ok(compilePolicySet(docs));
    const b = ok(compilePolicySet([...docs].reverse()));
    expect(a.rego).toBe(b.rego);
    expect(JSON.stringify(docs)).toBe(before);
    expect(a.policyVersion).toBe("baseline-deny@1.0.0,phi-redaction@1.1.0");
    expect(a.ruleIds).toContain("phi-redaction/deny-phi-to-code");
  });

  it("matches the checked-in golden Rego (regenerate deliberately if the compiler changes)", () => {
    const golden = readFileSync(
      new URL("../../../policies/golden/default-set.rego", import.meta.url),
      "utf8",
    );
    expect(ok(compilePolicySet(docs)).rego).toBe(golden);
  });

  it("output passes opa check --strict and builds to Wasm", () => {
    const { rego } = ok(compilePolicySet(docs));
    expect(() => opaCheck(rego)).not.toThrow();
    expect(opaBuildWasm(rego).length).toBeGreaterThan(1000);
  });

  it("rejects an empty set and schema-invalid documents with positions", () => {
    expect(codes(compilePolicySet([]))).toEqual(["POLICY_EMPTY_SET"]);
    const r = compilePolicySet([{ apiVersion: "policy.axis.dev/v1" }]);
    expect(r.ok).toBe(false);
    if (!r.ok)
      expect(r.issues.every((i) => i.doc === 0 && i.code.startsWith("SCHEMA_"))).toBe(true);
  });

  it("rejects default-allow at the schema layer", () => {
    expect(compilePolicySet([pack({ defaultDecision: "ALLOW" })]).ok).toBe(false);
  });
});

describe("compilePolicySet: semantic errors", () => {
  it.each([
    ["duplicate pack", [pack(), pack()], "POLICY_DUPLICATE_PACK"],
    [
      "duplicate rule",
      [pack({}, [rule(undefined, "DENY"), rule(undefined, "DENY")])],
      "POLICY_DUPLICATE_RULE",
    ],
    [
      "duplicate gate",
      [
        pack({}, undefined, [
          { id: "gg", type: "kill_switch", scope: "tenant" },
          { id: "gg", type: "kill_switch", scope: "agent" },
        ]),
      ],
      "POLICY_DUPLICATE_GATE",
    ],
    [
      "unknown gate",
      [
        pack({}, [
          { id: "rl", enforcementPoints: ["tool_call"], decision: "ALLOW", gates: ["nope"] },
        ]),
      ],
      "POLICY_UNKNOWN_GATE",
    ],
    [
      "unknown root",
      [pack({}, [rule({ field: "secrets.key", op: "eq", value: 1 })])],
      "POLICY_UNKNOWN_FIELD_ROOT",
    ],
    [
      "eq with array",
      [pack({}, [rule({ field: "tool.name", op: "eq", value: ["a"] })])],
      "POLICY_BAD_VALUE",
    ],
    [
      "in with scalar",
      [pack({}, [rule({ field: "tool.name", op: "in", value: "a" })])],
      "POLICY_BAD_VALUE",
    ],
    [
      "in with empty array",
      [pack({}, [rule({ field: "tool.name", op: "not_in", value: [] })])],
      "POLICY_BAD_VALUE",
    ],
    [
      "gt with string",
      [pack({}, [rule({ field: "args.n", op: "gt", value: "5" })])],
      "POLICY_BAD_VALUE",
    ],
    [
      "matches with bad regex",
      [pack({}, [rule({ field: "tool.name", op: "matches", value: "(" })])],
      "POLICY_BAD_VALUE",
    ],
    [
      "matches with number",
      [pack({}, [rule({ field: "tool.name", op: "matches", value: 3 })])],
      "POLICY_BAD_VALUE",
    ],
    [
      "exists with string",
      [pack({}, [rule({ field: "tool.name", op: "exists", value: "yes" })])],
      "POLICY_BAD_VALUE",
    ],
  ])("%s", (_n, docs, code) => {
    expect(codes(compilePolicySet(docs))).toContain(code);
  });

  it("errors carry the path to the offending node inside nested conditions", () => {
    const r = compilePolicySet([
      pack({}, [rule({ all: [{ not: { field: "tool.name", op: "in", value: "x" } }] })]),
    ]);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.issues[0]?.path).toBe("/spec/rules/0/when/all/0/not/value");
  });

  it("warns about ALLOW rules that match everything", () => {
    const r = ok(
      compilePolicySet([
        pack({}, [{ id: "rl", enforcementPoints: ["tool_call"], decision: "ALLOW" }]),
      ]),
    );
    expect(r.warnings.map((w) => w.code)).toEqual(["POLICY_ALLOW_ALL"]);
    const gated = ok(
      compilePolicySet([
        pack(
          {},
          [{ id: "rl", enforcementPoints: ["tool_call"], decision: "ALLOW", gates: ["gg"] }],
          [{ id: "gg", type: "kill_switch", scope: "tenant" }],
        ),
      ]),
    );
    expect(gated.warnings).toEqual([]);
  });
});

/** Differential tests: compile a one-rule policy and evaluate it with the real OPA. */
describe("generated Rego semantics (evaluated by real OPA)", () => {
  const decide = (when: unknown, input: unknown, decision = "ALLOW") => {
    const { rego } = ok(compilePolicySet([pack({}, [rule(when, decision)])]));
    return opaEval(rego, { enforcement_point: "tool_call", ...(input as object) })["decision"];
  };

  it.each([
    ["eq match", { field: "tool.name", op: "eq", value: "a" }, { tool: { name: "a" } }, "ALLOW"],
    ["eq mismatch", { field: "tool.name", op: "eq", value: "a" }, { tool: { name: "b" } }, "DENY"],
    ["eq type strict", { field: "args.n", op: "eq", value: 1 }, { args: { n: "1" } }, "DENY"],
    ["eq null", { field: "args.n", op: "eq", value: null }, { args: { n: null } }, "ALLOW"],
    [
      "eq false value",
      { field: "data.phi", op: "eq", value: false },
      { data: { phi: false } },
      "ALLOW",
    ],
    ["neq match", { field: "tool.name", op: "neq", value: "a" }, { tool: { name: "b" } }, "ALLOW"],
    ["neq missing field is false", { field: "tool.name", op: "neq", value: "a" }, {}, "DENY"],
    [
      "in match",
      { field: "tool.name", op: "in", value: ["a", "b"] },
      { tool: { name: "b" } },
      "ALLOW",
    ],
    [
      "in miss",
      { field: "tool.name", op: "in", value: ["a", "b"] },
      { tool: { name: "c" } },
      "DENY",
    ],
    ["in missing field is false", { field: "tool.name", op: "in", value: ["a"] }, {}, "DENY"],
    [
      "not_in match",
      { field: "tool.name", op: "not_in", value: ["a"] },
      { tool: { name: "c" } },
      "ALLOW",
    ],
    [
      "not_in hit",
      { field: "tool.name", op: "not_in", value: ["a"] },
      { tool: { name: "a" } },
      "DENY",
    ],
    [
      "not_in missing field is false",
      { field: "tool.name", op: "not_in", value: ["a"] },
      {},
      "DENY",
    ],
    ["gt true", { field: "args.n", op: "gt", value: 5 }, { args: { n: 6 } }, "ALLOW"],
    ["gt boundary", { field: "args.n", op: "gt", value: 5 }, { args: { n: 5 } }, "DENY"],
    ["gte boundary", { field: "args.n", op: "gte", value: 5 }, { args: { n: 5 } }, "ALLOW"],
    ["lt true", { field: "args.n", op: "lt", value: 5 }, { args: { n: 4 } }, "ALLOW"],
    ["lte boundary", { field: "args.n", op: "lte", value: 5 }, { args: { n: 5 } }, "ALLOW"],
    [
      "lt string input is not numeric",
      { field: "args.n", op: "lt", value: 5 },
      { args: { n: "1" } },
      "DENY",
    ],
    [
      "matches true",
      { field: "args.url", op: "matches", value: "^https://ex\\.com/" },
      { args: { url: "https://ex.com/a" } },
      "ALLOW",
    ],
    [
      "matches false",
      { field: "args.url", op: "matches", value: "^https://ex\\.com/" },
      { args: { url: "https://evil.com/" } },
      "DENY",
    ],
    [
      "matches non-string",
      { field: "args.url", op: "matches", value: ".*" },
      { args: { url: 5 } },
      "DENY",
    ],
    ["exists true", { field: "args.x", op: "exists" }, { args: { x: false } }, "ALLOW"],
    ["exists missing", { field: "args.x", op: "exists" }, { args: {} }, "DENY"],
    [
      "exists false when missing",
      { field: "args.x", op: "exists", value: false },
      { args: {} },
      "ALLOW",
    ],
    [
      "exists false when present",
      { field: "args.x", op: "exists", value: false },
      { args: { x: 1 } },
      "DENY",
    ],
    [
      "all with one missing operand is false",
      {
        all: [
          { field: "args.b", op: "eq", value: 1 },
          { field: "args.c", op: "eq", value: 2 },
        ],
      },
      { args: { c: 2 } },
      "DENY",
    ],
    [
      "any true",
      {
        any: [
          { field: "args.a", op: "eq", value: 1 },
          { field: "args.b", op: "eq", value: 2 },
        ],
      },
      { args: { b: 2 } },
      "ALLOW",
    ],
    [
      "any none",
      {
        any: [
          { field: "args.a", op: "eq", value: 1 },
          { field: "args.b", op: "eq", value: 2 },
        ],
      },
      { args: {} },
      "DENY",
    ],
    ["not of missing is true", { not: { field: "args.a", op: "eq", value: 1 } }, {}, "ALLOW"],
    [
      "not of true is false",
      { not: { field: "args.a", op: "eq", value: 1 } },
      { args: { a: 1 } },
      "DENY",
    ],
    [
      "string with quotes and unicode",
      { field: "args.s", op: "eq", value: 'he said "hi" é' },
      { args: { s: 'he said "hi" é' } },
      "ALLOW",
    ],
  ])("%s", (_n, when, input, want) => {
    expect(decide(when, input)).toBe(want);
  });

  it("a rule without `when` matches only at its enforcement points", () => {
    const { rego } = ok(
      compilePolicySet([
        pack({}, [{ id: "rl", enforcementPoints: ["tool_call"], decision: "ALLOW" }]),
      ]),
    );
    expect(opaEval(rego, { enforcement_point: "tool_call" })["decision"]).toBe("ALLOW");
    expect(opaEval(rego, { enforcement_point: "mcp_call" })["decision"]).toBe("DENY");
    expect(opaEval(rego, {})["decision"]).toBe("DENY");
  });

  it("priority beats restrictiveness; equal priority: DENY beats REQUIRE_APPROVAL beats REDACTION beats ALLOW", () => {
    const ep = ["tool_call"];
    const approval = { roles: ["r"], slaSeconds: 5 };
    const rules = [
      { id: "a-allow", enforcementPoints: ep, decision: "ALLOW", priority: 200 },
      { id: "b-deny-low", enforcementPoints: ep, decision: "DENY", priority: 100 },
    ];
    const hi = ok(compilePolicySet([pack({}, rules)]));
    expect(opaEval(hi.rego, { enforcement_point: "tool_call" })["decision"]).toBe("ALLOW");

    const eq = [
      { id: "aa", enforcementPoints: ep, decision: "ALLOW" },
      { id: "bb", enforcementPoints: ep, decision: "ALLOW_WITH_REDACTION", redact: ["x"] },
      { id: "cc", enforcementPoints: ep, decision: "REQUIRE_APPROVAL", approval },
    ];
    const order: [unknown[], string][] = [
      [eq.slice(0, 1), "ALLOW"],
      [eq.slice(0, 2), "ALLOW_WITH_REDACTION"],
      [eq, "REQUIRE_APPROVAL"],
      [[...eq, { id: "dd", enforcementPoints: ep, decision: "DENY" }], "DENY"],
    ];
    for (const [rs, want] of order) {
      const c = ok(compilePolicySet([pack({}, rs)]));
      expect(opaEval(c.rego, { enforcement_point: "tool_call" })["decision"]).toBe(want);
    }
  });

  it("winners at the same decision union their redactions and gates; approval comes from the first id", () => {
    const ep = ["tool_call"];
    const gates = [
      { id: "gx", type: "kill_switch", scope: "tenant" },
      { id: "gy", type: "kill_switch", scope: "agent" },
    ];
    const rules = [
      {
        id: "bb",
        enforcementPoints: ep,
        decision: "ALLOW_WITH_REDACTION",
        redact: ["y", "x"],
        gates: ["gy"],
      },
      {
        id: "aa",
        enforcementPoints: ep,
        decision: "ALLOW_WITH_REDACTION",
        redact: ["x", "z"],
        gates: ["gx"],
      },
    ];
    const c = ok(compilePolicySet([pack({}, rules, gates)]));
    const r = opaEval(c.rego, { enforcement_point: "tool_call" });
    expect(r["winners"]).toEqual(["pk/aa", "pk/bb"]);
    expect(r["redact"]).toEqual(["x", "y", "z"]);
    expect((r["gates"] as { id: string }[]).map((g) => g.id)).toEqual(["pk/gx", "pk/gy"]);
    expect(r["policy_version"]).toBe("pk@1.0.0");
  });

  it("approval metadata is surfaced with the SLA and DENY on timeout", () => {
    const rules = [
      {
        id: "rl",
        enforcementPoints: ["tool_call"],
        decision: "REQUIRE_APPROVAL",
        approval: { roles: ["fin"], slaSeconds: 60, escalateTo: ["cfo"] },
      },
    ];
    const c = ok(compilePolicySet([pack({}, rules)]));
    expect(opaEval(c.rego, { enforcement_point: "tool_call" })["approval"]).toEqual({
      roles: ["fin"],
      sla_seconds: 60,
      escalate_to: ["cfo"],
      on_timeout: "DENY",
    });
  });
});
