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
  re2Problem,
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
    [
      "not of unknown is unknown, so an ALLOW rule does not match",
      { not: { field: "args.a", op: "eq", value: 1 } },
      {},
      "DENY",
    ],
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

describe("missing or mistyped data is UNKNOWN and always resolves toward DENY (review finding 2)", () => {
  const denyDecides = (when: unknown, input: unknown) => {
    const rules = [
      {
        id: "allow-all",
        enforcementPoints: ["tool_call"],
        decision: "ALLOW",
        priority: 10,
        gates: ["gg"],
      },
      { id: "deny-when", enforcementPoints: ["tool_call"], decision: "DENY", priority: 500, when },
    ];
    const { rego } = ok(
      compilePolicySet([pack({}, rules, [{ id: "gg", type: "kill_switch", scope: "tenant" }])]),
    );
    return opaEval(rego, { enforcement_point: "tool_call", ...(input as object) })["decision"];
  };

  it.each([
    // The reviewer's probe: deny unless region is EU. A missing region must be DENIED, not allowed.
    [
      "neq: missing field fires the deny",
      { field: "args.region", op: "neq", value: "EU" },
      {},
      "DENY",
    ],
    [
      "neq: present and different fires",
      { field: "args.region", op: "neq", value: "EU" },
      { args: { region: "US" } },
      "DENY",
    ],
    [
      "neq: present and equal does not fire",
      { field: "args.region", op: "neq", value: "EU" },
      { args: { region: "EU" } },
      "ALLOW",
    ],
    [
      "not_in: missing field fires the deny",
      { field: "tool.name", op: "not_in", value: ["a"] },
      {},
      "DENY",
    ],
    [
      "not_in: present and listed does not fire",
      { field: "tool.name", op: "not_in", value: ["a"] },
      { tool: { name: "a" } },
      "ALLOW",
    ],
    [
      "not(eq): missing fires the deny",
      { not: { field: "args.x", op: "eq", value: 1 } },
      {},
      "DENY",
    ],
    [
      "not(eq): present and equal does not fire",
      { not: { field: "args.x", op: "eq", value: 1 } },
      { args: { x: 1 } },
      "ALLOW",
    ],
    [
      "gt: wrong type is unknown and fires",
      { field: "args.n", op: "gt", value: 5 },
      { args: { n: "9999" } },
      "DENY",
    ],
    [
      "gt: present and below does not fire",
      { field: "args.n", op: "gt", value: 5 },
      { args: { n: 1 } },
      "ALLOW",
    ],
    [
      "matches: non-string is unknown and fires",
      { field: "args.s", op: "matches", value: "^ok$" },
      { args: { s: 5 } },
      "DENY",
    ],
    ["in: missing is unknown and fires", { field: "args.k", op: "in", value: ["a"] }, {}, "DENY"],
    [
      "all: one unknown operand keeps the deny possible",
      {
        all: [
          { field: "args.a", op: "eq", value: 1 },
          { field: "args.b", op: "eq", value: 2 },
        ],
      },
      { args: { a: 1 } },
      "DENY",
    ],
    [
      "all: a definitely-false operand kills it",
      {
        all: [
          { field: "args.a", op: "eq", value: 1 },
          { field: "args.b", op: "eq", value: 2 },
        ],
      },
      { args: { a: 9 } },
      "ALLOW",
    ],
    [
      "any: a definitely-true operand fires",
      {
        any: [
          { field: "args.a", op: "eq", value: 1 },
          { field: "args.b", op: "eq", value: 2 },
        ],
      },
      { args: { a: 1 } },
      "DENY",
    ],
    [
      "any: unknown operand keeps it possible",
      {
        any: [
          { field: "args.a", op: "eq", value: 1 },
          { field: "args.b", op: "eq", value: 2 },
        ],
      },
      { args: { a: 9 } },
      "DENY",
    ],
    [
      "exists is always definite: absent does not fire exists=true",
      { field: "args.x", op: "exists" },
      {},
      "ALLOW",
    ],
  ])("DENY rule: %s", (_n, when, input, want) => {
    expect(denyDecides(when, input)).toBe(want);
  });

  it("non-DENY rules still require definitely-true: unknown never allows, redacts or requests approval", () => {
    const when = { field: "args.region", op: "neq", value: "EU" };
    for (const decision of ["ALLOW", "ALLOW_WITH_REDACTION", "REQUIRE_APPROVAL"]) {
      const extra =
        decision === "ALLOW_WITH_REDACTION"
          ? { redact: ["x"] }
          : decision === "REQUIRE_APPROVAL"
            ? { approval: { roles: ["r"], slaSeconds: 5 } }
            : {};
      const { rego } = ok(
        compilePolicySet([
          pack({}, [{ id: "rl", enforcementPoints: ["tool_call"], decision, when, ...extra }]),
        ]),
      );
      expect(opaEval(rego, { enforcement_point: "tool_call" })["decision"], decision).toBe("DENY");
      expect(
        opaEval(rego, { enforcement_point: "tool_call", args: { region: "US" } })["decision"],
        decision,
      ).toBe(decision);
    }
  });
});

/** Independent reference implementation of the documented three-valued semantics (true / false / unknown). */
type Tri = "T" | "F" | "U";
type Leaf = { field: string; op: string; value?: unknown };
type C = Leaf | { all: C[] } | { any: C[] } | { not: C };
const get = (o: unknown, path: string): unknown =>
  path
    .split(".")
    .reduce<unknown>(
      (a, k) =>
        a && typeof a === "object" && k in a ? (a as Record<string, unknown>)[k] : undefined,
      o,
    );
function tri(c: C, input: unknown): Tri {
  if ("all" in c) {
    const r = c.all.map((x) => tri(x, input));
    return r.includes("F") ? "F" : r.includes("U") ? "U" : "T";
  }
  if ("any" in c) {
    const r = c.any.map((x) => tri(x, input));
    return r.includes("T") ? "T" : r.includes("U") ? "U" : "F";
  }
  if ("not" in c) {
    const r = tri(c.not, input);
    return r === "T" ? "F" : r === "F" ? "T" : "U";
  }
  const v = get(input, c.field);
  if (c.op === "exists") return (v !== undefined) === (c.value !== false) ? "T" : "F";
  if (v === undefined) return "U";
  const val = c.value;
  if (["gt", "gte", "lt", "lte"].includes(c.op)) {
    if (typeof v !== "number") return "U";
    const n = val as number;
    return ({ gt: v > n, gte: v >= n, lt: v < n, lte: v <= n } as Record<string, boolean>)[c.op]
      ? "T"
      : "F";
  }
  if (c.op === "eq") return v === val ? "T" : "F";
  if (c.op === "neq") return v !== val ? "T" : "F";
  if (c.op === "in") return (val as unknown[]).includes(v) ? "T" : "F";
  return (val as unknown[]).includes(v) ? "F" : "T"; // not_in
}

describe("differential: compiled Rego (real OPA) == reference three-valued evaluator", () => {
  let seed = 12345;
  const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  const pick = <T>(xs: T[]): T => xs[Math.floor(rnd() * xs.length)] as T;
  const fields = ["args.a", "args.b", "tool.name", "data.phi"];
  let withExists = true;
  const leaf = (): Leaf => {
    const op = pick(["eq", "neq", "in", "not_in", "gt", "lte", ...(withExists ? ["exists"] : [])]);
    const field = pick(fields);
    if (op === "in" || op === "not_in")
      return { field, op, value: pick([[1, 2], ["x", "y"], [true]]) };
    if (op === "gt" || op === "lte") return { field, op, value: pick([0, 5]) };
    if (op === "exists") return { field, op, ...(rnd() < 0.5 ? { value: false } : {}) };
    return { field, op, value: pick([1, "x", true, 5]) };
  };
  const tree = (d: number): C => {
    const r = rnd();
    if (d === 0 || r < 0.4) return leaf();
    if (r < 0.6) return { not: tree(d - 1) };
    return r < 0.8 ? { all: [tree(d - 1), tree(d - 1)] } : { any: [tree(d - 1), tree(d - 1)] };
  };
  const input = () => {
    const o: Record<string, Record<string, unknown>> = {};
    for (const f of fields) {
      if (rnd() < 0.35) continue; // missing
      const [root, key] = f.split(".") as [string, string];
      (o[root] ??= {})[key] = pick([1, 2, 5, 7, "x", "y", true, false, null, "9"]);
    }
    return o;
  };

  it("agrees on 60 random conditions x inputs, for ALLOW (needs T) and DENY (fires on T or U) rules", () => {
    for (let i = 0; i < 60; i++) {
      const cond = tree(3);
      const inp = input();
      const want = tri(cond, inp);
      const allow = ok(compilePolicySet([pack({}, [rule(cond, "ALLOW")])]));
      expect(
        opaEval(allow.rego, { enforcement_point: "tool_call", ...inp })["decision"],
        JSON.stringify({ cond, inp }),
      ).toBe(want === "T" ? "ALLOW" : "DENY");
      const deny = ok(
        compilePolicySet([
          pack(
            {},
            [
              { id: "a-low", enforcementPoints: ["tool_call"], decision: "ALLOW", priority: 1 },
              rule(cond, "DENY", "dn"),
            ].map((r, n) => (n === 1 ? { ...r, priority: 500 } : r)),
          ),
        ]),
      );
      expect(
        opaEval(deny.rego, { enforcement_point: "tool_call", ...inp })["decision"],
        JSON.stringify({ cond, inp }),
      ).toBe(want === "F" ? "ALLOW" : "DENY");
    }
  });

  // `exists` is definite by design ("allow only when the field is absent" is expressible), so monotonicity
  // holds for every operator except `exists`; the property test therefore generates conditions without it.
  it("fail-closed monotonicity: removing a field never gains an ALLOW match or loses a DENY match", () => {
    withExists = false;
    for (let i = 0; i < 500; i++) {
      const cond = tree(3);
      const inp = input();
      const fewer = JSON.parse(JSON.stringify(inp));
      const victim = pick(fields).split(".") as [string, string];
      if (fewer[victim[0]]) delete fewer[victim[0]][victim[1]];
      const allowFull = tri(cond, inp) === "T";
      const allowLess = tri(cond, fewer) === "T";
      const denyFull = tri(cond, inp) !== "F";
      const denyLess = tri(cond, fewer) !== "F";
      // Less data can only lose an ALLOW match or gain a DENY match.
      expect(allowLess && !allowFull, JSON.stringify({ cond, inp, fewer })).toBe(false);
      expect(denyFull && !denyLess, JSON.stringify({ cond, inp, fewer })).toBe(false);
    }
    withExists = true;
  });
});

describe("matches: only syntax that means the same in RE2 and JS is accepted (review finding 3)", () => {
  it.each([
    ["^(?!safe).*", "plain-group"],
    ["(?=x)a", "lookahead"],
    ["(?<=a)b", "lookbehind"],
    ["(?<n>a)", "named group"],
    ["(?i)abc", "inline flag"],
    ["(?>a+)b", "atomic group"],
    ["(a)\\1", "backreference"],
    ["\\k<n>", "named backreference"],
    ["\\p{L}+", "unicode class"],
    ["\\u0041", "unicode escape"],
    ["[unterminated", "unterminated class"],
    ["(", "unbalanced"],
    ["abc\\", "trailing backslash"],
  ])("rejects %s (%s)", (pattern) => {
    expect(re2Problem(pattern)).toBeTypeOf("string");
    expect(
      codes(
        compilePolicySet([pack({}, [rule({ field: "tool.name", op: "matches", value: pattern })])]),
      ),
    ).toContain("POLICY_BAD_VALUE");
  });

  it.each(["^https://ex\\.com/", "^(?:a|b)+$", "[^\\]]x", "[]a]", "\\d{3}-\\d{4}", "a.*b", "^$"])(
    "accepts %s",
    (pattern) => {
      expect(re2Problem(pattern)).toBeUndefined();
    },
  );

  it("every accepted pattern is also accepted by real OPA", () => {
    for (const pattern of ["^https://ex\\.com/", "^(?:a|b)+$", "[^\\]]x", "\\d{3}-\\d{4}"]) {
      const { rego } = ok(
        compilePolicySet([pack({}, [rule({ field: "args.u", op: "matches", value: pattern })])]),
      );
      expect(() => opaCheck(rego)).not.toThrow();
      expect(() => opaBuildWasm(rego)).not.toThrow();
    }
  });
});
