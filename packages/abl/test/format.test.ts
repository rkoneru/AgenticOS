import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import {
  compileAbl,
  formatFindings,
  formatIssues,
  pointerToDotted,
  validateAblYaml,
  type AblIssue,
} from "../src/index.js";
import { baseDoc, exampleNames, readExample } from "./helpers.js";

const VERSION_PATTERN =
  "^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(-[0-9A-Za-z.-]+)?(\\+[0-9A-Za-z.-]+)?$";

// One entry per file in examples/invalid; the test below fails if a file is added without one.
const expectedLines: Record<string, string[]> = {
  "bad-version": [`metadata.version: must match pattern ${VERSION_PATTERN} (got "1.0")`],
  "high-without-oversight": ["spec.riskClassification.humanOversight: is required"],
  "limited-without-notice": ["spec.riskClassification.transparencyNotice: is required"],
  "mcp-without-server": ["spec.tools[0].mcpServer: is required"],
  "missing-risk-classification": ["spec.riskClassification: is required"],
  "unacceptable-risk": [
    'spec.riskClassification.level: must be one of minimal, limited, high (got "unacceptable")',
  ],
  "unknown-field": ["spec.surprise: unknown property"],
  "unknown-provider": [
    'spec.model.primary.provider: must be one of anthropic, openai, google, azure-openai, bedrock, openai-compatible (got "skynet")',
  ],
  "wrong-api-version": ['apiVersion: must be "abl.axis.dev/v1" (got "abl.axis.dev/v2")'],
};

describe("formatIssues on the invalid examples", () => {
  it("has an expectation for every invalid example", () => {
    expect(Object.keys(expectedLines).sort()).toEqual(exampleNames("invalid", ".yaml"));
  });
  for (const [name, lines] of Object.entries(expectedLines)) {
    it(`${name}`, () => {
      const r = validateAblYaml(readExample("invalid", `${name}.yaml`));
      expect(r.ok).toBe(false);
      if (!r.ok) expect(formatIssues(r.issues)).toEqual(lines);
    });
    it(`${name} via compileAbl gives the same lines`, () => {
      const r = compileAbl(parse(readExample("invalid", `${name}.yaml`)));
      expect(!r.ok && formatIssues(r.issues)).toEqual(lines);
    });
  }
});

const issue = (keyword: string, params: object, extra: Partial<AblIssue> = {}): AblIssue => ({
  path: "/spec/x",
  keyword,
  message: "raw ajv message",
  params: params as Record<string, unknown>,
  ...extra,
});

describe("formatIssues keyword coverage", () => {
  const cases: Array<[string, AblIssue, string]> = [
    [
      "type",
      issue("type", { type: "string" }, { value: 5 }),
      "spec.x: must be of type string (got 5)",
    ],
    [
      "format",
      issue("format", { format: "uri" }, { value: "nope" }),
      'spec.x: must be a valid uri (got "nope")',
    ],
    ["minimum", issue("minimum", { limit: 0 }, { value: -1 }), "spec.x: must be >= 0 (got -1)"],
    ["maximum", issue("maximum", { limit: 1 }, { value: 2 }), "spec.x: must be <= 1 (got 2)"],
    ["minLength", issue("minLength", { limit: 10 }), "spec.x: must be at least 10 characters long"],
    ["maxLength", issue("maxLength", { limit: 3 }), "spec.x: must be at most 3 characters long"],
    ["minItems", issue("minItems", { limit: 1 }), "spec.x: must have at least 1 items"],
    ["maxItems", issue("maxItems", { limit: 5 }), "spec.x: must have at most 5 items"],
    [
      "uniqueItems",
      issue("uniqueItems", { i: 1, j: 0 }),
      "spec.x: must not contain duplicate items",
    ],
    ["yaml", issue("yaml", {}, { path: "/" }), "(root): raw ajv message"],
    [
      "unknown keyword falls back to the raw message",
      issue("dependentRequired", {}),
      "spec.x: raw ajv message",
    ],
    [
      "required at the root",
      issue("required", { missingProperty: "spec" }, { path: "/" }),
      "spec: is required",
    ],
    [
      "additionalProperties at the root",
      issue("additionalProperties", { additionalProperty: "oops" }, { path: "/" }),
      "oops: unknown property",
    ],
  ];
  for (const [label, i, want] of cases) {
    it(label, () => expect(formatIssues([i])).toEqual([want]));
  }

  it("truncates long offending values", () => {
    const [line] = formatIssues([issue("pattern", { pattern: "^a$" }, { value: "b".repeat(200) })]);
    expect(line).toMatch(/\(got "b+\.\.\.\)$/);
    expect(line?.length).toBeLessThan(140);
  });

  it("drops the noisy if issues", () => {
    expect(formatIssues([issue("if", { failingKeyword: "then" })])).toEqual([]);
  });

  it("formats a real nested array path", () => {
    const d = baseDoc();
    d.spec.tools = [{ name: "BAD NAME", kind: "function" }];
    const r = compileAbl(d);
    expect(!r.ok && formatIssues(r.issues)[0]).toMatch(
      /^spec\.tools\[0\]\.name: must match pattern /,
    );
  });
});

describe("pointerToDotted", () => {
  it("converts pointers", () => {
    expect(pointerToDotted("/")).toBe("(root)");
    expect(pointerToDotted("/spec")).toBe("spec");
    expect(pointerToDotted("/spec/tools/2/name")).toBe("spec.tools[2].name");
    expect(pointerToDotted("/a/0/1")).toBe("a[0][1]");
  });
});

describe("formatFindings", () => {
  it("prints severity, code, dotted path and message", () => {
    expect(
      formatFindings([
        { code: "ABL004", severity: "error", path: "/spec/evals", message: "needs suites" },
      ]),
    ).toEqual(["error ABL004 spec.evals: needs suites"]);
  });
});
