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

const expected: Record<string, string> = {
  "default-allow": "const",
  "empty-rules": "minItems",
  "approval-without-approval-block": "required",
  "redaction-without-fields": "required",
  "allow-with-redact": "not",
  "unknown-enforcement-point": "enum",
  "amount-cap-without-params": "required",
  "kill-switch-without-scope": "required",
  "bad-condition-op": "oneOf",
  "timeout-allow": "enum",
};

describe("policy DSL invalid examples fail for the stated reason", () => {
  it("has an expectation per file", () => {
    expect(
      readdirSync(dir("invalid"))
        .map((f) => f.replace(".yaml", ""))
        .sort(),
    ).toEqual(Object.keys(expected).sort());
  });
  for (const [name, keyword] of Object.entries(expected)) {
    it(`${name} -> ${keyword}`, () => {
      expect(validatePolicy(read("invalid", `${name}.yaml`))).toBe(false);
      expect(
        validatePolicy.errors?.some((e) => e.keyword === keyword),
        JSON.stringify(validatePolicy.errors),
      ).toBe(true);
    });
  }
});
