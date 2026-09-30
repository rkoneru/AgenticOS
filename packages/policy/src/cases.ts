import { lit } from "./compile.js";

export interface PolicyCase {
  name: string;
  input: Record<string, unknown>;
  expect: {
    decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL" | "ALLOW_WITH_REDACTION";
    winners?: string[];
    gates?: string[];
    redact?: string[];
    approval_roles?: string[];
  };
}

export interface CaseFile {
  packs: string[];
  cases: PolicyCase[];
}

const DECISIONS = ["ALLOW", "DENY", "REQUIRE_APPROVAL", "ALLOW_WITH_REDACTION"];

export function parseCaseFile(doc: unknown): CaseFile {
  const d = doc as Partial<CaseFile> | null;
  if (
    !d ||
    !Array.isArray(d.packs) ||
    d.packs.length === 0 ||
    !Array.isArray(d.cases) ||
    d.cases.length === 0
  ) {
    throw new Error("case file needs non-empty `packs` and `cases`");
  }
  const names = new Set<string>();
  for (const c of d.cases) {
    if (!c.name || !c.input || !c.expect || !DECISIONS.includes(c.expect.decision)) {
      throw new Error(
        `invalid case ${JSON.stringify(c?.name)}: needs name, input, expect.decision`,
      );
    }
    if (names.has(c.name)) throw new Error(`duplicate case name "${c.name}"`);
    names.add(c.name);
  }
  return d as CaseFile;
}

const ident = (s: string): string => s.replace(/[^a-zA-Z0-9]+/g, "_").replace(/^_+|_+$/g, "");

/** Rego `opa test` module asserting every case against the compiled policy (package axis.policy_test). */
export function casesToRegoTests(cases: PolicyCase[]): string {
  const out = ["package axis.policy_test", "", "import rego.v1", "", "import data.axis.policy", ""];
  cases.forEach((c, i) => {
    const e = c.expect;
    out.push(`test_${String(i).padStart(3, "0")}_${ident(c.name)} if {`);
    out.push(`\tr := policy.result with input as ${lit(c.input)}`);
    out.push(`\tr.decision == ${JSON.stringify(e.decision)}`);
    if (e.winners) out.push(`\tr.winners == ${lit(e.winners)}`);
    if (e.gates) out.push(`\t[g.id | some g in r.gates] == ${lit(e.gates)}`);
    if (e.redact) out.push(`\tr.redact == ${lit(e.redact)}`);
    if (e.approval_roles) out.push(`\tr.approval.roles == ${lit(e.approval_roles)}`);
    out.push("}", "");
  });
  return out.join("\n");
}
