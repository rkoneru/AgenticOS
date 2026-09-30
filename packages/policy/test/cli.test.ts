import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  casesToRegoTests,
  findCaseFiles,
  opaEval,
  opaTest,
  parseCaseFile,
  runCaseFile,
} from "../src/index.js";
import { main } from "../src/cli.js";

const policies = new URL("../../../policies/", import.meta.url).pathname;
const capture = () => {
  const lines: string[] = [];
  return { lines, out: (s: string) => void lines.push(s) };
};

describe("case files", () => {
  it("rejects malformed case files", () => {
    expect(() => parseCaseFile(null)).toThrow(/non-empty/);
    expect(() => parseCaseFile({ packs: ["a"], cases: [] })).toThrow(/non-empty/);
    expect(() =>
      parseCaseFile({
        packs: ["a"],
        cases: [{ name: "x", input: {}, expect: { decision: "MAYBE" } }],
      }),
    ).toThrow(/invalid case/);
    const c = { name: "x", input: {}, expect: { decision: "DENY" } };
    expect(() => parseCaseFile({ packs: ["a"], cases: [c, c] })).toThrow(/duplicate/);
  });

  it("generated test modules can FAIL: a wrong expectation is reported", () => {
    const rego =
      'package axis.policy\nimport rego.v1\nresult := {"decision": "DENY", "winners": [], "gates": [], "redact": [], "approval": null}\n';
    const wrong = casesToRegoTests([{ name: "w", input: {}, expect: { decision: "ALLOW" } }]);
    expect(() => opaTest({ "p.rego": rego, "t.rego": wrong })).toThrow(/FAIL/);
    const right = casesToRegoTests([
      { name: "r", input: {}, expect: { decision: "DENY", winners: [], gates: [], redact: [] } },
    ]);
    expect(opaTest({ "p.rego": rego, "t.rego": right })).toContain("PASS");
  });

  it("finds and runs every shipped case file", () => {
    const files = findCaseFiles(policies);
    expect(files.length).toBeGreaterThanOrEqual(2);
    for (const f of files) {
      const r = runCaseFile(f);
      expect(r.ok, r.output).toBe(true);
      expect(r.cases).toBeGreaterThan(0);
    }
  });

  it("runCaseFile reports compile errors and missing files without throwing", () => {
    const dir = mkdtempSync(join(tmpdir(), "axis-cases-"));
    writeFileSync(join(dir, "bad.yaml"), "apiVersion: policy.axis.dev/v1\n");
    writeFileSync(
      join(dir, "a.cases.yaml"),
      "packs: [bad.yaml]\ncases: [{name: x, input: {}, expect: {decision: DENY}}]\n",
    );
    const r = runCaseFile(join(dir, "a.cases.yaml"));
    expect(r.ok).toBe(false);
    expect(r.output).toMatch(/SCHEMA_/);
    expect(runCaseFile(join(dir, "missing.cases.yaml")).ok).toBe(false);
  });
});

describe("opa wrapper errors", () => {
  it("reports OPA errors and a missing binary clearly", () => {
    expect(() => opaEval("package axis.policy\nthis is not rego", {})).toThrow();
    const prev = process.env["OPA_BIN"];
    process.env["OPA_BIN"] = "/nonexistent/opa";
    try {
      expect(() => opaEval("package axis.policy\nimport rego.v1\nx := 1\n", {})).toThrow(
        /opa binary not found/,
      );
    } finally {
      if (prev === undefined) delete process.env["OPA_BIN"];
      else process.env["OPA_BIN"] = prev;
    }
  });

  it("opaEval throws when the policy has no result", () => {
    expect(() => opaEval("package axis.other\nimport rego.v1\nx := 1\n", {})).toThrow(/no result/);
  });
});

describe("cli", () => {
  it("compile prints Rego, writes -o, reports errors, and usage", () => {
    const c = capture();
    expect(main(["compile", join(policies, "baseline-deny/pack.yaml")], c.out)).toBe(0);
    expect(c.lines.join("\n")).toContain("package axis.policy");

    const dir = mkdtempSync(join(tmpdir(), "axis-cli-"));
    const o = capture();
    expect(
      main(
        ["compile", join(policies, "baseline-deny/pack.yaml"), "-o", join(dir, "out.rego")],
        o.out,
      ),
    ).toBe(0);
    expect(readFileSync(join(dir, "out.rego"), "utf8")).toContain("package axis.policy");

    writeFileSync(join(dir, "bad.yaml"), "apiVersion: nope\n");
    const e = capture();
    expect(main(["compile", join(dir, "bad.yaml")], e.out)).toBe(1);
    expect(e.lines[0]).toMatch(/^error SCHEMA_/);

    const w = capture();
    writeFileSync(
      join(dir, "warn.yaml"),
      "apiVersion: policy.axis.dev/v1\nkind: PolicyPack\nmetadata: {name: warn-pack, version: 1.0.0}\nspec:\n  defaultDecision: DENY\n  rules: [{id: rl, enforcementPoints: [tool_call], decision: ALLOW}]\n",
    );
    expect(main(["compile", join(dir, "warn.yaml")], w.out)).toBe(0);
    expect(w.lines[0]).toMatch(/^warning POLICY_ALLOW_ALL/);

    const u = capture();
    expect(main(["compile"], u.out)).toBe(2);
    expect(main([], u.out)).toBe(2);
  });

  it("test passes on the shipped policies, fails when a case fails or none exist", () => {
    const c = capture();
    expect(main(["test", policies], c.out)).toBe(0);
    expect(c.lines.filter((l) => l.startsWith("PASS")).length).toBeGreaterThanOrEqual(2);

    const dir = mkdtempSync(join(tmpdir(), "axis-cli-"));
    const n = capture();
    expect(main(["test", dir], n.out)).toBe(1);

    writeFileSync(join(dir, "p.yaml"), readFileSync(join(policies, "baseline-deny/pack.yaml")));
    writeFileSync(
      join(dir, "x.cases.yaml"),
      "packs: [p.yaml]\ncases:\n  - {name: wrong, input: {enforcement_point: tool_call, tool: {side_effects: read}}, expect: {decision: DENY}}\n",
    );
    const f = capture();
    expect(main(["test", dir], f.out)).toBe(1);
    expect(f.lines[0]).toMatch(/^FAIL/);
  });

  it("test defaults to ./policies relative to cwd", () => {
    const c = capture();
    const prev = process.cwd();
    process.chdir(new URL("../../../", import.meta.url).pathname);
    try {
      expect(main(["test"], c.out)).toBe(0);
    } finally {
      process.chdir(prev);
    }
  });
});
