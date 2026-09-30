import { describe, expect, it } from "vitest";
import { LINT_RULES, compileAbl, lintAbl, type Finding } from "../src/index.js";
import { baseDoc, highDoc, type Doc } from "./helpers.js";

const codes = (doc: unknown): string[] => lintAbl(doc).map((f) => f.code);
const tool = (name: string, extra: object = {}) => ({ name, kind: "function", ...extra });

interface Case {
  code: string;
  severity: "error" | "warning";
  path: string;
  /** Produces a document that triggers exactly this rule (others may also fire). */
  bad: () => Doc;
  /** Produces a near-identical document that must NOT trigger it. */
  good: () => Doc;
}

const cases: Case[] = [
  {
    code: "ABL001",
    severity: "error",
    path: "/spec/tools/1/name",
    bad: () => {
      const d = baseDoc();
      d.spec.tools = [tool("dup", { sideEffects: "none" }), tool("dup", { sideEffects: "none" })];
      return d;
    },
    good: () => {
      const d = baseDoc();
      d.spec.tools = [tool("one", { sideEffects: "none" }), tool("two", { sideEffects: "none" })];
      return d;
    },
  },
  {
    code: "ABL002",
    severity: "error",
    path: "/spec/budgets/costUsd",
    bad: () => {
      const d = baseDoc();
      d.spec.budgets.costUsd = { soft: 5, hard: 2.5 };
      return d;
    },
    good: () => {
      const d = baseDoc();
      d.spec.budgets.costUsd = { soft: 2.5, hard: 2.5 }; // equal is fine
      d.spec.budgets.toolCalls = { soft: 5 }; // soft alone is fine
      return d;
    },
  },
  {
    code: "ABL003",
    severity: "error",
    path: "/spec/model/fallbacks/1",
    bad: () => {
      const d = baseDoc();
      d.spec.model.fallbacks = [
        { provider: "openai", model: "gpt-4o" },
        { provider: "anthropic", model: "claude-sonnet-5-5" },
      ];
      return d;
    },
    good: () => {
      const d = baseDoc();
      d.spec.model.fallbacks = [
        { provider: "anthropic", model: "claude-haiku" }, // same provider, other model
        {
          provider: "anthropic",
          model: "claude-sonnet-5-5",
          endpoint: "https://proxy.example.com",
        },
      ];
      return d;
    },
  },
  {
    code: "ABL004",
    severity: "error",
    path: "/spec/evals",
    bad: () => {
      const d = highDoc();
      d.spec.evals = { suites: [] };
      return d;
    },
    good: () => highDoc(),
  },
  {
    code: "ABL005",
    severity: "error",
    path: "/spec/data",
    bad: () => {
      const d = baseDoc();
      d.spec.data = { phi: true };
      return d;
    },
    good: () => {
      const d = baseDoc();
      d.spec.data = { phi: true, residency: "eu-west-1" };
      return d;
    },
  },
  {
    code: "ABL006",
    severity: "error",
    path: "/spec/tools/0",
    bad: () => {
      const d = baseDoc();
      d.spec.tools = [tool("test-agent", { kind: "agent", sideEffects: "none" })];
      return d;
    },
    good: () => {
      const d = baseDoc();
      d.spec.tools = [tool("test-agent", { kind: "function", sideEffects: "none" })]; // only kind agent counts
      d.spec.tools.push(
        tool("helper", { kind: "agent", ref: "other-agent@^1.0.0", sideEffects: "none" }),
      );
      return d;
    },
  },
  {
    code: "ABL101",
    severity: "warning",
    path: "/spec/memory/knowledgeBases",
    bad: () => {
      const d = baseDoc();
      d.spec.memory = { knowledgeBases: ["handbook"] };
      return d;
    },
    good: () => {
      const d = baseDoc();
      d.spec.memory = { knowledgeBases: ["handbook"] };
      d.spec.routing = { stages: ["rag", "llm"] };
      return d;
    },
  },
  {
    code: "ABL102",
    severity: "warning",
    path: "/spec/policy",
    bad: () => {
      const d = baseDoc();
      d.spec.tools = [tool("writer", { sideEffects: "external" })];
      return d;
    },
    good: () => {
      const d = baseDoc();
      d.spec.tools = [
        tool("reader", { sideEffects: "read" }),
        tool("noop", { sideEffects: "none" }),
      ];
      return d;
    },
  },
  {
    code: "ABL103",
    severity: "warning",
    path: "/spec/budgets",
    bad: () => {
      const d = baseDoc();
      delete d.spec.budgets;
      return d;
    },
    good: () => {
      const d = baseDoc();
      d.spec.budgets = { toolCalls: { hard: 10 } };
      return d;
    },
  },
  {
    code: "ABL104",
    severity: "warning",
    path: "/spec/channels",
    bad: () => {
      const d = baseDoc();
      d.spec.channels = ["voice"];
      return d;
    },
    good: () => {
      const d = baseDoc();
      d.spec.channels = ["web", "slack"]; // not voice
      return d;
    },
  },
  {
    code: "ABL105",
    severity: "warning",
    path: "/spec/routing/stages",
    bad: () => {
      const d = baseDoc();
      d.spec.routing = { stages: ["rag", "llm"] };
      return d;
    },
    good: () => {
      const d = baseDoc();
      d.spec.routing = { stages: ["rag", "llm"] };
      d.spec.memory = { knowledgeBases: ["handbook"] };
      return d;
    },
  },
  {
    code: "ABL106",
    severity: "warning",
    path: "/spec/routing/stages",
    bad: () => {
      const d = baseDoc();
      d.spec.routing = { stages: ["cache", "rules"] };
      return d;
    },
    good: () => {
      const d = baseDoc();
      d.spec.routing = { stages: ["cache", "mpm", "llm"] }; // mpm is allowed
      return d;
    },
  },
  {
    code: "ABL107",
    severity: "warning",
    path: "/spec/process/maxRestarts",
    bad: () => {
      const d = baseDoc();
      d.spec.process = { maxRestarts: 3 };
      return d;
    },
    good: () => {
      const d = baseDoc();
      d.spec.process = { restartPolicy: "on-failure", maxRestarts: 3 };
      return d;
    },
  },
  {
    code: "ABL108",
    severity: "warning",
    path: "/spec/model/fallbacks/1",
    bad: () => {
      const d = baseDoc();
      d.spec.model.fallbacks = [
        { provider: "openai", model: "gpt-4o" },
        { provider: "openai", model: "gpt-4o" },
      ];
      return d;
    },
    good: () => {
      const d = baseDoc();
      d.spec.model.fallbacks = [
        { provider: "openai", model: "gpt-4o" },
        { provider: "openai", model: "gpt-4o-mini" },
      ];
      return d;
    },
  },
];

describe("lint rules", () => {
  it("the base documents lint clean", () => {
    expect(lintAbl(baseDoc())).toEqual([]);
    expect(lintAbl(highDoc())).toEqual([]);
  });

  it("every rule has a case, and codes are unique", () => {
    const ruleCodes = LINT_RULES.map((r) => r.code);
    expect(new Set(ruleCodes).size).toBe(ruleCodes.length);
    expect(cases.map((c) => c.code)).toEqual(ruleCodes);
    expect(LINT_RULES.map((r) => r.severity)).toEqual(cases.map((c) => c.severity));
  });

  for (const c of cases) {
    describe(c.code, () => {
      it("fires on the bad document with the right severity and path", () => {
        const f = lintAbl(c.bad()).filter((x: Finding) => x.code === c.code);
        expect(f).toHaveLength(1);
        expect(f[0]?.severity).toBe(c.severity);
        expect(f[0]?.path).toBe(c.path);
        expect(f[0]?.message.length).toBeGreaterThan(10);
      });
      it("stays quiet on the good document", () => {
        expect(codes(c.good())).not.toContain(c.code);
      });
      it(`${c.severity === "error" ? "fails" : "does not fail"} compilation`, () => {
        const r = compileAbl(c.bad());
        expect(r.ok).toBe(c.severity !== "error");
        expect(r.findings.some((x) => x.code === c.code)).toBe(true);
      });
    });
  }

  it("defaults count: omitted sideEffects is write, so it needs policy packs", () => {
    const d = baseDoc();
    d.spec.tools = [tool("implicit")];
    expect(codes(d)).toContain("ABL102");
    d.spec.policy = { packs: ["baseline-deny@^1.0.0"] };
    expect(codes(d)).not.toContain("ABL102");
  });

  it("voice with a transparency notice is fine", () => {
    const d = baseDoc();
    d.spec.channels = ["voice"];
    d.spec.riskClassification.transparencyNotice = "You are talking to an AI.";
    expect(codes(d)).not.toContain("ABL104");
  });

  it("an agent tool whose ref points at this blueprint is a self reference", () => {
    const d = baseDoc();
    d.spec.tools = [
      tool("delegate", { kind: "agent", ref: "test-agent@^1.0.0", sideEffects: "none" }),
    ];
    expect(codes(d)).toContain("ABL006");
  });

  it("high risk without an evals section at all is an error", () => {
    const d = highDoc();
    delete d.spec.evals;
    expect(codes(d)).toContain("ABL004");
    expect(compileAbl(d).ok).toBe(false);
  });

  it("minimal and limited risk do not need evals", () => {
    const d = baseDoc();
    expect(codes(d)).not.toContain("ABL004");
    d.spec.riskClassification = {
      level: "limited",
      rationale: "Customer facing chatbot.",
      transparencyNotice: "AI system.",
    };
    expect(codes(d)).not.toContain("ABL004");
  });

  it("phi false without residency is fine", () => {
    const d = baseDoc();
    d.spec.data = { phi: false };
    expect(codes(d)).not.toContain("ABL005");
  });

  it("reports every duplicate, not only the first", () => {
    const d = baseDoc();
    d.spec.tools = ["aa", "aa", "aa"].map((n) => tool(n, { sideEffects: "none" }));
    expect(
      lintAbl(d)
        .filter((f) => f.code === "ABL001")
        .map((f) => f.path),
    ).toEqual(["/spec/tools/1/name", "/spec/tools/2/name"]);
  });

  it("lintAbl returns no findings for a schema-invalid document (compileAbl reports the schema issues)", () => {
    expect(lintAbl({ nonsense: true })).toEqual([]);
    expect(lintAbl(null)).toEqual([]);
  });

  it("findings are ordered: rule order, then document order", () => {
    const d = baseDoc();
    d.spec.tools = [tool("xx"), tool("xx")];
    d.spec.data = { phi: true };
    delete d.spec.budgets;
    expect(codes(d)).toEqual(["ABL001", "ABL005", "ABL102", "ABL103"]);
  });
});
