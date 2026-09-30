import { validatePolicy } from "@axis/contracts";
import { RE2JS } from "re2js";

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

const typeNameOf = (v: unknown): string =>
  v === null ? "null" : Array.isArray(v) ? "array" : typeof v;

/** Rego guard that the field's type is one of the types present in `values` (scalars only ever match scalar types). */
function typeTest(values: unknown[]): string {
  const names = [...new Set(values.map(typeNameOf))].filter((n) =>
    ["string", "number", "boolean", "null"].includes(n),
  );
  return names.length === 0 ? "false" : `type_name(v) in ${lit(names.sort())}`;
}

/** Names of the two generated booleans for a condition node: definitely-true and possibly-true. */
interface Node {
  t: string;
  p: string;
}

/**
 * Three-valued (Kleene) evaluation over possibly-missing data. Every condition node compiles to two total booleans:
 *   t = definitely TRUE      p = possibly true (TRUE or UNKNOWN)
 * A leaf over a missing field, or a field whose type does not fit the operator (e.g. a string under `gt`), is UNKNOWN.
 * not(x): t = !p(x), p = !t(x).  all: AND of each.  any: OR of each.
 * A rule whose decision is DENY matches on `p` (unknown data must not let a deny rule be skipped); every other decision
 * needs `t`. So missing data can only ever push a request toward DENY, including through negation.
 */
class Emitter {
  readonly lines: string[] = [];
  readonly issues: PolicyIssue[] = [];
  private counter = 0;
  constructor(
    private readonly doc: number,
    private readonly regexCheck: (pattern: string) => string | undefined,
  ) {}

  issue(path: string, code: string, message: string): void {
    this.issues.push({ doc: this.doc, path, code, message });
  }

  cond(c: Cond, rule: number, path: string): Node {
    const id = `${rule}_${this.counter++}`;
    const node: Node = { t: `t${id}`, p: `p${id}` };
    this.lines.push(`default ${node.t} := false`, `default ${node.p} := false`);
    if (c.all) {
      const kids = c.all.map((x, i) => this.cond(x, rule, `${path}/all/${i}`));
      this.lines.push(`${node.t} if {`, ...kids.map((k) => `\t${k.t}`), "}");
      this.lines.push(`${node.p} if {`, ...kids.map((k) => `\t${k.p}`), "}");
    } else if (c.any) {
      for (const [i, x] of c.any.entries()) {
        const k = this.cond(x, rule, `${path}/any/${i}`);
        this.lines.push(`${node.t} if { ${k.t} }`, `${node.p} if { ${k.p} }`);
      }
    } else if (c.not) {
      const k = this.cond(c.not, rule, `${path}/not`);
      this.lines.push(`${node.t} if { not ${k.p} }`, `${node.p} if { not ${k.t} }`);
    } else {
      this.leaf(id, node, c, path);
    }
    this.lines.push("");
    return node;
  }

  private leaf(id: string, node: Node, c: Cond, path: string): void {
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
    // Bracket notation: a field segment that is a Rego keyword (`in`, `not`, `default`...) cannot break the module.
    const ref = `input${field
      .split(".")
      .map((seg) => `[${JSON.stringify(seg)}]`)
      .join("")}`;
    const v = c.value;
    const scalar = v === null || ["string", "number", "boolean"].includes(typeof v);
    const known = `k${id}`;
    // `known` = the field is present with a type the operator can judge; otherwise the leaf is UNKNOWN.
    let typeGuard = "";
    let test: string;
    switch (op) {
      case "eq":
      case "neq":
        if (!scalar) this.issue(`${path}/value`, "POLICY_BAD_VALUE", `${op} needs a scalar value`);
        // A field of a different type than the value (or a non-scalar) cannot be judged: UNKNOWN, not "not equal".
        typeGuard = `${typeTest([v])}; `;
        test = `v ${op === "eq" ? "==" : "!="} ${lit(v)}`;
        break;
      case "in":
      case "not_in":
        if (!Array.isArray(v) || v.length === 0) {
          this.issue(`${path}/value`, "POLICY_BAD_VALUE", `${op} needs a non-empty array`);
        }
        typeGuard = `${typeTest(Array.isArray(v) ? v : [])}; `;
        test = op === "in" ? `v in ${lit(v)}` : `not v in ${lit(v)}`;
        break;
      case "gt":
      case "gte":
      case "lt":
      case "lte":
        if (typeof v !== "number")
          this.issue(`${path}/value`, "POLICY_BAD_VALUE", `${op} needs a number`);
        typeGuard = "is_number(v); ";
        test = `v ${OP_SYMBOL[op]} ${lit(v)}`;
        break;
      case "matches": {
        const why =
          typeof v === "string" ? this.regexCheck(v) : "matches needs a regular expression string";
        if (why) this.issue(`${path}/value`, "POLICY_BAD_VALUE", why);
        // `regex.is_valid`: a pattern OPA cannot compile is UNKNOWN (fires DENY rules), never a silent non-match.
        typeGuard = `is_string(v); regex.is_valid(${lit(v)}); `;
        test = `regex.match(${lit(v)}, v)`;
        break;
      }
      default: {
        // exists: always definite (present or absent), never UNKNOWN.
        if (v !== undefined && typeof v !== "boolean") {
          this.issue(`${path}/value`, "POLICY_BAD_VALUE", "exists takes an optional boolean");
        }
        const defined = `d${id}`;
        this.lines.push(`${defined} if { v := ${ref} }`);
        this.lines.push(
          v === false ? `${node.t} if { not ${defined} }` : `${node.t} if { ${defined} }`,
        );
        this.lines.push(`${node.p} if { ${node.t} }`);
        return;
      }
    }
    this.lines.push(
      typeGuard
        ? `${known} if { v := ${ref}; ${typeGuard.replace(/; $/, "")} }`
        : `${known} if { _ := ${ref} }`,
    );
    this.lines.push(`${node.t} if { v := ${ref}; ${typeGuard}${test} }`);
    this.lines.push(`${node.p} if { ${node.t} }`, `${node.p} if { not ${known} }`);
  }
}

/**
 * Policies are evaluated by OPA, whose regular expressions are Go RE2. `matches` patterns are therefore validated with a
 * real RE2 parser (re2js; agrees with OPA's `regex.is_valid` on every pattern we probed, including the ones JavaScript
 * accepts but RE2 rejects: `\\e`, `a{1001}`, `[a-\\d]`). Semantics are RE2's (POSIX classes, `\\A`/`\\z`, `\\Q..\\E`, inline
 * flags, `.` excluding only `\\n`), NOT JavaScript's. The generated Rego also guards every `matches` with
 * `regex.is_valid`, so a pattern the two parsers disagree on is UNKNOWN at runtime (fires DENY rules) instead of silently
 * failing. Returns a problem description, or undefined when the pattern is valid.
 */
export function re2Problem(pattern: string): string | undefined {
  try {
    RE2JS.compile(pattern);
    return undefined;
  } catch (err) {
    return `invalid RE2 regular expression: ${(err as Error).message}`.slice(0, 200);
  }
}

/**
 * Compile a set of policy packs (YAML-parsed documents) into ONE Rego module (package axis.policy).
 * Rules from all packs compete together, so packs compose: rule ids are namespaced `<pack>/<rule>`.
 * Resolution (docs/spec/policy-dsl-v1.md): highest priority wins; at equal priority the most restrictive
 * decision wins (DENY > REQUIRE_APPROVAL > ALLOW_WITH_REDACTION > ALLOW); ties within the winning decision
 * union their gates and redactions and take the lexicographically first rule's approval. No match => DENY.
 */
export interface CompileOptions {
  /** Test seam: replaces the RE2 syntax check (the runtime `regex.is_valid` guard remains). */
  regexCheck?: (pattern: string) => string | undefined;
}

export function compilePolicySet(docs: unknown[], opts: CompileOptions = {}): CompileResult {
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
    const em = new Emitter(doc, opts.regexCheck ?? re2Problem);
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
      // DENY rules fire when the condition is possibly true (unknown data must not skip a deny); others need definitely true.
      const gate = root ? (r.decision === "DENY" ? root.p : root.t) : undefined;
      em.lines.push(
        `matched contains ${JSON.stringify(fq)} if {`,
        `\tinput.enforcement_point in ${lit(r.enforcementPoints)}`,
        ...(gate ? [`\t${gate}`] : []),
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
