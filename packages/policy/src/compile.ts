import { validatePolicy } from "@axis/contracts";

/** Entry point of the generated module (OPA query path / Wasm entrypoint). */
export const REGO_PACKAGE = "axis.policy";
export const REGO_ENTRYPOINT = "axis/policy/result";
export const REGO_QUERY = "data.axis.policy.result";

/** Top-level roots of the gate request context that policies may address (docs/plans/phase-2.md). */
export const CONTEXT_ROOTS = [
  "enforcement_point",
  "tool",
  "args",
  "data",
  "tenant",
  "agent",
  "run",
  "actor",
] as const;

export interface PolicyIssue {
  /** Index of the offending document in the input set. */
  doc: number;
  path: string;
  code: string;
  message: string;
}

export interface CompiledPolicy {
  rego: string;
  /** "name@version,name@version" sorted by pack name. */
  policyVersion: string;
  ruleIds: string[];
  warnings: PolicyIssue[];
}

export type CompileResult = ({ ok: true } & CompiledPolicy) | { ok: false; issues: PolicyIssue[] };

type Scalar = string | number | boolean | null;
interface Cond {
  all?: Cond[];
  any?: Cond[];
  not?: Cond;
  field?: string;
  op?: string;
  value?: Scalar | Scalar[];
}
interface Gate {
  id: string;
  type: string;
  scope?: string;
  params?: Record<string, unknown>;
}
interface Rule {
  id: string;
  priority?: number;
  enforcementPoints: string[];
  when?: Cond;
  gates?: string[];
  decision: string;
  redact?: string[];
  approval?: { roles: string[]; slaSeconds: number; escalateTo?: string[]; onTimeout?: string };
}
interface Pack {
  metadata: { name: string; version: string };
  spec: { gates?: Gate[]; rules: Rule[] };
}

/** Deterministic JSON (sorted keys). Valid Rego term syntax for strings, numbers, bools, null, arrays, objects. */
export function lit(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(lit).join(", ")}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj)
    .sort()
    .map((k) => `${JSON.stringify(k)}: ${lit(obj[k])}`)
    .join(", ")}}`;
}

const OP_SYMBOL: Record<string, string> = { gt: ">", gte: ">=", lt: "<", lte: "<=" };

class Emitter {
  readonly lines: string[] = [];
  readonly issues: PolicyIssue[] = [];
  private counter = 0;
  constructor(private readonly doc: number) {}

  issue(path: string, code: string, message: string): void {
    this.issues.push({ doc: this.doc, path, code, message });
  }

  /** Emit named, total boolean rules for a condition tree; returns the name of the root rule. */
  cond(c: Cond, rule: number, path: string): string {
    const name = `c${rule}_${this.counter++}`;
    this.lines.push(`default ${name} := false`);
    if (c.all) {
      const refs = c.all.map((x, i) => this.cond(x, rule, `${path}/all/${i}`));
      this.lines.push(`${name} if {`, ...refs.map((r) => `\t${r}`), "}");
    } else if (c.any) {
      const refs = c.any.map((x, i) => this.cond(x, rule, `${path}/any/${i}`));
      for (const r of refs) this.lines.push(`${name} if { ${r} }`);
    } else if (c.not) {
      const ref = this.cond(c.not, rule, `${path}/not`);
      this.lines.push(`${name} if { not ${ref} }`);
    } else {
      this.leaf(name, c, path);
    }
    this.lines.push("");
    return name;
  }

  private leaf(name: string, c: Cond, path: string): void {
    const field = c.field as string;
    const op = c.op as string;
    const root = field.split(".")[0] as string;
    if (!(CONTEXT_ROOTS as readonly string[]).includes(root)) {
      this.issue(
        `${path}/field`,
        "POLICY_UNKNOWN_FIELD_ROOT",
        `unknown context root "${root}" (allowed: ${CONTEXT_ROOTS.join(", ")})`,
      );
    }
    const ref = `input.${field}`;
    const v = c.value;
    const scalar = v === null || ["string", "number", "boolean"].includes(typeof v);
    switch (op) {
      case "eq":
      case "neq":
        if (!scalar) this.issue(`${path}/value`, "POLICY_BAD_VALUE", `${op} needs a scalar value`);
        this.lines.push(`${name} if { ${ref} ${op === "eq" ? "==" : "!="} ${lit(v)} }`);
        break;
      case "in":
      case "not_in":
        if (!Array.isArray(v) || v.length === 0) {
          this.issue(`${path}/value`, "POLICY_BAD_VALUE", `${op} needs a non-empty array`);
        }
        this.lines.push(
          op === "in"
            ? `${name} if { v := ${ref}; v in ${lit(v)} }`
            : `${name} if { v := ${ref}; not v in ${lit(v)} }`,
        );
        break;
      case "gt":
      case "gte":
      case "lt":
      case "lte":
        if (typeof v !== "number")
          this.issue(`${path}/value`, "POLICY_BAD_VALUE", `${op} needs a number`);
        this.lines.push(`${name} if { v := ${ref}; is_number(v); v ${OP_SYMBOL[op]} ${lit(v)} }`);
        break;
      case "matches":
        if (typeof v !== "string" || !validRegex(v)) {
          this.issue(
            `${path}/value`,
            "POLICY_BAD_VALUE",
            "matches needs a valid regular expression string",
          );
        }
        this.lines.push(`${name} if { v := ${ref}; is_string(v); regex.match(${lit(v)}, v) }`);
        break;
      default: {
        // exists
        if (v !== undefined && typeof v !== "boolean") {
          this.issue(`${path}/value`, "POLICY_BAD_VALUE", "exists takes an optional boolean");
        }
        const defined = `${name}_def`;
        this.lines.push(`${defined} if { v := ${ref} }`);
        this.lines.push(
          v === false ? `${name} if { not ${defined} }` : `${name} if { ${defined} }`,
        );
      }
    }
  }
}

function validRegex(p: string): boolean {
  try {
    new RegExp(p);
    return true;
  } catch {
    return false;
  }
}

/**
 * Compile a set of policy packs (YAML-parsed documents) into ONE Rego module (package axis.policy).
 * Rules from all packs compete together, so packs compose: rule ids are namespaced `<pack>/<rule>`.
 * Resolution (docs/spec/policy-dsl-v1.md): highest priority wins; at equal priority the most restrictive
 * decision wins (DENY > REQUIRE_APPROVAL > ALLOW_WITH_REDACTION > ALLOW); ties within the winning decision
 * union their gates and redactions and take the lexicographically first rule's approval. No match => DENY.
 */
export function compilePolicySet(docs: unknown[]): CompileResult {
  const issues: PolicyIssue[] = [];
  const warnings: PolicyIssue[] = [];
  if (docs.length === 0) {
    return {
      ok: false,
      issues: [
        {
          doc: -1,
          path: "/",
          code: "POLICY_EMPTY_SET",
          message: "at least one policy pack is required",
        },
      ],
    };
  }

  const packs: { pack: Pack; doc: number }[] = [];
  docs.forEach((d, doc) => {
    if (validatePolicy(d)) {
      packs.push({ pack: d as unknown as Pack, doc });
    } else {
      for (const e of validatePolicy.errors ?? []) {
        issues.push({
          doc,
          path: e.instancePath || "/",
          code: `SCHEMA_${e.keyword.toUpperCase()}`,
          message: String(e.message),
        });
      }
    }
  });
  if (issues.length > 0) return { ok: false, issues };

  const names = new Set<string>();
  for (const { pack, doc } of packs) {
    if (names.has(pack.metadata.name)) {
      issues.push({
        doc,
        path: "/metadata/name",
        code: "POLICY_DUPLICATE_PACK",
        message: `duplicate pack "${pack.metadata.name}"`,
      });
    }
    names.add(pack.metadata.name);
  }

  const sorted = [...packs].sort((a, b) => (a.pack.metadata.name < b.pack.metadata.name ? -1 : 1));
  const gateDefs: Record<string, unknown> = {};
  const ruleDefs: Record<string, unknown> = {};
  const ruleIds: string[] = [];
  const body: string[] = [];
  let ruleNo = 0;

  for (const { pack, doc } of sorted) {
    const ns = pack.metadata.name;
    const em = new Emitter(doc);
    const gateIds = new Set<string>();
    (pack.spec.gates ?? []).forEach((g, i) => {
      if (gateIds.has(g.id))
        em.issue(`/spec/gates/${i}/id`, "POLICY_DUPLICATE_GATE", `duplicate gate "${g.id}"`);
      gateIds.add(g.id);
      const def: Record<string, unknown> = {
        id: `${ns}/${g.id}`,
        type: g.type,
        params: g.params ?? {},
      };
      if (g.scope) def["scope"] = g.scope;
      gateDefs[`${ns}/${g.id}`] = def;
    });
    const seen = new Set<string>();
    pack.spec.rules.forEach((r, i) => {
      const p = `/spec/rules/${i}`;
      if (seen.has(r.id)) em.issue(`${p}/id`, "POLICY_DUPLICATE_RULE", `duplicate rule "${r.id}"`);
      seen.add(r.id);
      for (const [gi, g] of (r.gates ?? []).entries()) {
        if (!gateIds.has(g))
          em.issue(
            `${p}/gates/${gi}`,
            "POLICY_UNKNOWN_GATE",
            `rule references undefined gate "${g}"`,
          );
      }
      if (r.decision === "ALLOW" && !r.when && !(r.gates ?? []).length) {
        warnings.push({
          doc,
          path: p,
          code: "POLICY_ALLOW_ALL",
          message: `ALLOW rule "${r.id}" has no condition or gates: it matches every request at its enforcement points`,
        });
      }
      const fq = `${ns}/${r.id}`;
      ruleIds.push(fq);
      ruleDefs[fq] = {
        priority: r.priority ?? 100,
        decision: r.decision,
        gates: (r.gates ?? []).map((g) => `${ns}/${g}`),
        redact: r.redact ?? [],
        approval: r.approval
          ? {
              roles: r.approval.roles,
              sla_seconds: r.approval.slaSeconds,
              escalate_to: r.approval.escalateTo ?? [],
              on_timeout: "DENY",
            }
          : null,
      };
      const root = r.when ? em.cond(r.when, ruleNo, `${p}/when`) : undefined;
      em.lines.push(
        `matched contains ${JSON.stringify(fq)} if {`,
        `\tinput.enforcement_point in ${lit(r.enforcementPoints)}`,
        ...(root ? [`\t${root}`] : []),
        "}",
        "",
      );
      ruleNo++;
    });
    body.push(`# --- pack ${ns}@${pack.metadata.version}`, ...em.lines);
    issues.push(...em.issues);
  }
  if (issues.length > 0) return { ok: false, issues };

  const policyVersion = sorted
    .map(({ pack }) => `${pack.metadata.name}@${pack.metadata.version}`)
    .join(",");
  const rego = [
    "# Generated by @axis/policy. DO NOT EDIT.",
    `# Sources: ${policyVersion}`,
    `package ${REGO_PACKAGE}`,
    "",
    "import rego.v1",
    "",
    `policy_version := ${JSON.stringify(policyVersion)}`,
    "",
    'decision_rank := {"DENY": 4, "REQUIRE_APPROVAL": 3, "ALLOW_WITH_REDACTION": 2, "ALLOW": 1}',
    "",
    `gates := ${lit(gateDefs)}`,
    "",
    `rules := ${lit(ruleDefs)}`,
    "",
    ...body,
    resolution(policyVersion),
  ].join("\n");
  return { ok: true, rego, policyVersion, ruleIds, warnings };
}

const resolution = (
  version: string,
): string => `# --- resolution: highest priority, then most restrictive decision
candidates := {id | some id in matched}

top_priority := max({rules[id].priority | some id in candidates}) if count(candidates) > 0

top := {id | some id in candidates; rules[id].priority == top_priority}

top_rank := max({decision_rank[rules[id].decision] | some id in top}) if count(candidates) > 0

winners := {id | some id in top; decision_rank[rules[id].decision] == top_rank}

winner_ids := sort(winners)

default result := {
\t"decision": "DENY",
\t"reason": "no matching rule (default deny)",
\t"matched": [],
\t"winners": [],
\t"gates": [],
\t"redact": [],
\t"approval": null,
\t"policy_version": ${JSON.stringify(version)},
}

result := {
\t"decision": rules[winner_ids[0]].decision,
\t"reason": concat(", ", winner_ids),
\t"matched": sort(candidates),
\t"winners": winner_ids,
\t"gates": [gates[g] | some g in sort({g | some id in winners; some g in rules[id].gates})],
\t"redact": sort({x | some id in winners; some x in rules[id].redact}),
\t"approval": rules[winner_ids[0]].approval,
\t"policy_version": policy_version,
} if count(candidates) > 0
`;
