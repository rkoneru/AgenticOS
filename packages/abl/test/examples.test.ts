import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { validateAbl, validateAblYaml } from "../src/index.js";

const dir = (p: string) => new URL(`../examples/${p}/`, import.meta.url);
const read = (p: string, f: string) => readFileSync(new URL(f, dir(p)), "utf8");

describe("valid examples", () => {
  for (const f of readdirSync(dir("valid"))) {
    it(`${f} validates`, () => {
      const r = validateAblYaml(read("valid", f));
      expect(r.ok, JSON.stringify(r)).toBe(true);
    });
  }
});

// Each invalid example must fail for the stated reason, not just fail.
const expected: Record<string, { keyword: string; pathIncludes: string }> = {
  "missing-risk-classification": { keyword: "required", pathIncludes: "/spec" },
  "unacceptable-risk": { keyword: "enum", pathIncludes: "/riskClassification/level" },
  "high-without-oversight": { keyword: "required", pathIncludes: "/riskClassification" },
  "limited-without-notice": { keyword: "required", pathIncludes: "/riskClassification" },
  "bad-version": { keyword: "pattern", pathIncludes: "/metadata/version" },
  "unknown-field": { keyword: "additionalProperties", pathIncludes: "/spec" },
  "mcp-without-server": { keyword: "required", pathIncludes: "/tools/0" },
  "unknown-provider": { keyword: "enum", pathIncludes: "/provider" },
  "wrong-api-version": { keyword: "const", pathIncludes: "/apiVersion" },
};

describe("invalid examples", () => {
  const files = readdirSync(dir("invalid")).map((f) => f.replace(/\.yaml$/, ""));
  it("every invalid example has an expectation and vice versa", () => {
    expect(files.sort()).toEqual(Object.keys(expected).sort());
  });
  for (const [name, want] of Object.entries(expected)) {
    it(`${name} fails with ${want.keyword}`, () => {
      const r = validateAblYaml(read("invalid", `${name}.yaml`));
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(
          r.issues.some((i) => i.keyword === want.keyword && i.path.includes(want.pathIncludes)),
          JSON.stringify(r.issues),
        ).toBe(true);
      }
    });
  }
});

describe("validator api", () => {
  it("reports YAML syntax errors", () => {
    const r = validateAblYaml("a: [unclosed");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.issues[0]?.keyword).toBe("yaml");
  });
  it("rejects non-objects at the root path", () => {
    const r = validateAbl(42);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.issues[0]?.path).toBe("/");
  });
});
