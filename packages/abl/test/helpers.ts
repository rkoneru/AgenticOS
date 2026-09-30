import { readdirSync, readFileSync } from "node:fs";
import { parse } from "yaml";

export const exampleDir = (p: string) => new URL(`../examples/${p}/`, import.meta.url);
export const readExample = (p: string, f: string) =>
  readFileSync(new URL(f, exampleDir(p)), "utf8");
export const exampleNames = (p: string, ext: string) =>
  readdirSync(exampleDir(p))
    .filter((f) => f.endsWith(ext))
    .map((f) => f.slice(0, -ext.length))
    .sort();
export const loadValid = (name: string): unknown => parse(readExample("valid", `${name}.yaml`));

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Doc = any;

/** A clean minimal document: no findings except the no-hard-budget warning. */
export function baseDoc(): Doc {
  return {
    apiVersion: "abl.axis.dev/v1",
    kind: "Agent",
    metadata: { name: "test-agent", version: "1.0.0" },
    spec: {
      riskClassification: { level: "minimal", rationale: "Answers general questions only." },
      model: { primary: { provider: "anthropic", model: "claude-sonnet-5-5" } },
      instructions: { system: "Be helpful." },
      budgets: { tokens: { hard: 1000 } },
    },
  };
}

/** A clean high-risk document with everything the lint rules ask for. */
export function highDoc(): Doc {
  const d = baseDoc();
  d.spec.riskClassification = {
    level: "high",
    rationale: "Influences access to an essential service.",
    transparencyNotice: "You are talking to an AI.",
    humanOversight: { required: true, approverRoles: ["reviewer"] },
  };
  d.spec.evals = { suites: [{ ref: "suite@^1.0.0", threshold: 0.9 }] };
  return d;
}
