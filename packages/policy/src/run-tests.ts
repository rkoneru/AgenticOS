import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parse } from "yaml";
import { casesToRegoTests, parseCaseFile } from "./cases.js";
import { compilePolicySet, type PolicyIssue } from "./compile.js";
import { opaBuildWasm, opaCheck, opaTest } from "./opa.js";

export interface SuiteResult {
  file: string;
  ok: boolean;
  cases: number;
  output: string;
}

/** All `*.cases.yaml` files under `root`, sorted. */
export function findCaseFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (p: string): void => {
    if (statSync(p).isDirectory()) for (const f of readdirSync(p).sort()) walk(join(p, f));
    else if (p.endsWith(".cases.yaml")) out.push(p);
  };
  walk(root);
  return out;
}

const fmt = (issues: PolicyIssue[]): string =>
  issues.map((i) => `${i.code} ${i.path}: ${i.message}`).join("\n");

/**
 * `axis policy test` for one case file: compile the referenced packs, `opa check --strict`, prove Wasm builds,
 * then run the generated `opa test` module. Never throws for policy failures; returns ok:false with the report.
 */
export function runCaseFile(file: string): SuiteResult {
  try {
    const cf = parseCaseFile(parse(readFileSync(file, "utf8")));
    const docs = cf.packs.map(
      (p) => parse(readFileSync(resolve(dirname(file), p), "utf8")) as unknown,
    );
    const compiled = compilePolicySet(docs);
    if (!compiled.ok)
      return { file, ok: false, cases: cf.cases.length, output: fmt(compiled.issues) };
    opaCheck(compiled.rego);
    opaBuildWasm(compiled.rego);
    const output = opaTest({
      "policy.rego": compiled.rego,
      "policy_test.rego": casesToRegoTests(cf.cases),
    });
    return { file, ok: true, cases: cf.cases.length, output };
  } catch (err) {
    return { file, ok: false, cases: 0, output: (err as Error).message };
  }
}
