import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parsePolicyYaml, validatePolicy } from "../src/index.js";

const dir = (p: string) => new URL(`../examples/policy/${p}/`, import.meta.url);
const read = (p: string, f: string) => parsePolicyYaml(readFileSync(new URL(f, dir(p)), "utf8"));

describe("policy DSL valid examples", () => {
  for (const f of readdirSync(dir("valid"))) {
    it(`${f} validates`, () => {
      expect(validatePolicy(read("valid", f)), JSON.stringify(validatePolicy.errors)).toBe(true);
    });
  }
});

// keyword + exact instancePath of the expected failure
const expected: Record<string, [string, string]> = {
  "default-allow": ["const", "/spec/defaultDecision"],
  "empty-rules": ["minItems", "/spec/rules"],
  "approval-without-approval-block": ["required", "/spec/rules/0"],
  "redaction-without-fields": ["required", "/spec/rules/0"],
  "allow-with-redact": ["not", "/spec/rules/0"],
  "unknown-enforcement-point": ["enum", "/spec/rules/0/enforcementPoints/0"],
  "amount-cap-without-params": ["required", "/spec/gates/0"],
  "kill-switch-without-scope": ["required", "/spec/gates/0"],
  "bad-condition-op": ["enum", "/spec/rules/0/when/op"],
  "timeout-allow": ["enum", "/spec/rules/0/approval/onTimeout"],
};

describe("policy DSL invalid examples fail for the stated reason", () => {
  it("has an expectation per file", () => {
    expect(
      readdirSync(dir("invalid"))
        .map((f) => f.replace(".yaml", ""))
        .sort(),
    ).toEqual(Object.keys(expected).sort());
  });
  for (const [name, [keyword, path]] of Object.entries(expected)) {
    it(`${name} -> ${keyword} at ${path}`, () => {
      expect(validatePolicy(read("invalid", `${name}.yaml`))).toBe(false);
      expect(
        validatePolicy.errors?.some((e) => e.keyword === keyword && e.instancePath === path),
        JSON.stringify(validatePolicy.errors),
      ).toBe(true);
    });
  }
});
