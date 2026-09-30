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
const expected: Record<string, { keyword: string; path: string; param: string }> = {
  "missing-risk-classification": {
    keyword: "required",
    path: "/spec",
    param: "riskClassification",
  },
  "unacceptable-risk": {
    keyword: "enum",
    path: "/spec/riskClassification/level",
    param: "minimal",
  },
  "high-without-oversight": {
    keyword: "required",
    path: "/spec/riskClassification",
    param: "humanOversight",
  },
  "limited-without-notice": {
    keyword: "required",
    path: "/spec/riskClassification",
    param: "transparencyNotice",
  },
  "bad-version": { keyword: "pattern", path: "/metadata/version", param: "" },
  "unknown-field": { keyword: "additionalProperties", path: "/spec", param: "surprise" },
  "mcp-without-server": { keyword: "required", path: "/spec/tools/0", param: "mcpServer" },
  "unknown-provider": { keyword: "enum", path: "/spec/model/primary/provider", param: "anthropic" },
  "wrong-api-version": { keyword: "const", path: "/apiVersion", param: "abl.axis.dev/v1" },
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
          r.issues.some(
            (i) =>
              i.keyword === want.keyword &&
              i.path === want.path &&
              JSON.stringify(i.params).includes(want.param),
          ),
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
