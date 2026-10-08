import { invalid } from "./errors.js";
import { DETERMINISTIC_KINDS, GRADER_ID_RE, type DeterministicKind, type Grader } from "./types.js";

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const MAX_GRADERS = 20;
const MAX_RUBRIC = 4000;

function weightOf(v: unknown, path: string): number {
  if (v === undefined) return 1;
  if (typeof v !== "number" || !Number.isFinite(v) || v <= 0 || v > 100)
    throw invalid("grader weight must be a number in (0, 100]", [`${path}.weight`]);
  return v;
}

function reqString(v: unknown, path: string, max: number): string {
  if (typeof v !== "string" || v.trim() === "" || v.length > max)
    throw invalid(`${path} must be a non-empty string of at most ${max} characters`, [path]);
  return v;
}

function numberIn(v: unknown, path: string, min: number, max: number): number {
  if (typeof v !== "number" || !Number.isFinite(v) || v < min || v > max)
    throw invalid(`${path} must be a number in [${min}, ${max}]`, [path]);
  return v;
}

/** Validates the parameters of one deterministic kind. Unknown parameters are refused (a typo must not silently weaken a grader). */
function deterministicParams(
  kind: DeterministicKind,
  raw: unknown,
  path: string,
): Record<string, unknown> {
  const p = raw === undefined ? {} : raw;
  if (!isObj(p)) throw invalid("params must be an object", [`${path}.params`]);
  const only = (allowed: string[]): void => {
    for (const k of Object.keys(p))
      if (!allowed.includes(k))
        throw invalid(`unknown parameter ${k} for ${kind}`, [`${path}.params.${k}`]);
  };
  switch (kind) {
    case "exact":
      only(["case_sensitive", "trim"]);
      for (const k of ["case_sensitive", "trim"])
        if (p[k] !== undefined && typeof p[k] !== "boolean")
          throw invalid(`${k} must be a boolean`, [`${path}.params.${k}`]);
      return { ...p };
    case "contains":
      only(["case_sensitive"]);
      if (p["case_sensitive"] !== undefined && typeof p["case_sensitive"] !== "boolean")
        throw invalid("case_sensitive must be a boolean", [`${path}.params.case_sensitive`]);
      return { ...p };
    case "regex": {
      only(["pattern", "flags"]);
      const pattern = reqString(p["pattern"], `${path}.params.pattern`, 200);
      const flags =
        p["flags"] === undefined || p["flags"] === ""
          ? ""
          : reqString(p["flags"], `${path}.params.flags`, 4);
      if (!/^[imsu]*$/.test(flags))
        throw invalid("flags may contain only i, m, s, u", [`${path}.params.flags`]);
      try {
        new RegExp(pattern, flags);
      } catch {
        throw invalid("pattern is not a valid regular expression", [`${path}.params.pattern`]);
      }
      return { pattern, flags };
    }
    case "json_schema":
      only(["schema"]);
      if (!isObj(p["schema"]) || JSON.stringify(p["schema"]).length > 20_000)
        throw invalid("schema must be a JSON object of at most 20000 characters", [
          `${path}.params.schema`,
        ]);
      return { schema: p["schema"] };
    case "numeric_tolerance": {
      only(["abs", "rel"]);
      if (p["abs"] === undefined && p["rel"] === undefined)
        throw invalid("numeric_tolerance needs abs and/or rel", [`${path}.params`]);
      const out: Record<string, unknown> = {};
      for (const k of ["abs", "rel"])
        if (p[k] !== undefined) out[k] = numberIn(p[k], `${path}.params.${k}`, 0, 1e12);
      return out;
    }
    case "tool_call_sequence": {
      only(["mode"]);
      const mode = p["mode"] === undefined ? "exact" : p["mode"];
      if (mode !== "exact" && mode !== "subsequence" && mode !== "set")
        throw invalid("mode must be exact, subsequence or set", [`${path}.params.mode`]);
      return { mode };
    }
    case "policy_decision": {
      only(["expected"]);
      const e = p["expected"];
      if (e !== undefined && e !== "ALLOW" && e !== "DENY" && e !== "REQUIRE_APPROVAL")
        throw invalid("expected must be ALLOW, DENY or REQUIRE_APPROVAL", [
          `${path}.params.expected`,
        ]);
      return e === undefined ? {} : { expected: e };
    }
    case "cost_latency_budget": {
      only(["max_cost_usd", "max_latency_ms"]);
      if (p["max_cost_usd"] === undefined && p["max_latency_ms"] === undefined)
        throw invalid("cost_latency_budget needs max_cost_usd and/or max_latency_ms", [
          `${path}.params`,
        ]);
      const out: Record<string, unknown> = {};
      if (p["max_cost_usd"] !== undefined)
        out["max_cost_usd"] = numberIn(p["max_cost_usd"], `${path}.params.max_cost_usd`, 0, 1e9);
      if (p["max_latency_ms"] !== undefined)
        out["max_latency_ms"] = numberIn(
          p["max_latency_ms"],
          `${path}.params.max_latency_ms`,
          0,
          1e9,
        );
      return out;
    }
  }
}

/** Validates and normalizes the graders of a suite. Throws `invalid` with the offending paths. */
export function parseGraders(raw: unknown): Grader[] {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > MAX_GRADERS)
    throw invalid(`graders must be an array of 1-${MAX_GRADERS} graders`, ["graders"]);
  const seen = new Set<string>();
  return raw.map((g: unknown, i): Grader => {
    const path = `graders[${i}]`;
    if (!isObj(g)) throw invalid("grader must be an object", [path]);
    const id = g["id"];
    if (typeof id !== "string" || !GRADER_ID_RE.test(id))
      throw invalid("grader id must match [a-z][a-z0-9_-]{0,40}", [`${path}.id`]);
    if (seen.has(id)) throw invalid(`duplicate grader id ${id}`, [`${path}.id`]);
    seen.add(id);
    const weight = weightOf(g["weight"], path);
    switch (g["type"]) {
      case "deterministic": {
        const kind = g["kind"];
        if (typeof kind !== "string" || !(DETERMINISTIC_KINDS as readonly string[]).includes(kind))
          throw invalid(`kind must be one of ${DETERMINISTIC_KINDS.join(", ")}`, [`${path}.kind`]);
        const k = kind as DeterministicKind;
        return {
          id,
          type: "deterministic",
          kind: k,
          weight,
          params: deterministicParams(k, g["params"], path),
        };
      }
      case "model":
        return {
          id,
          type: "model",
          rubric: reqString(g["rubric"], `${path}.rubric`, MAX_RUBRIC),
          judge_model: reqString(g["judge_model"], `${path}.judge_model`, 200),
          weight,
        };
      case "human": {
        const sla =
          g["sla_hours"] === undefined ? 72 : numberIn(g["sla_hours"], `${path}.sla_hours`, 1, 720);
        if (g["double_grade"] !== undefined && typeof g["double_grade"] !== "boolean")
          throw invalid("double_grade must be a boolean", [`${path}.double_grade`]);
        const tol =
          g["agreement_tolerance"] === undefined
            ? 0.1
            : numberIn(g["agreement_tolerance"], `${path}.agreement_tolerance`, 0, 1);
        return {
          id,
          type: "human",
          rubric: reqString(g["rubric"], `${path}.rubric`, MAX_RUBRIC),
          weight,
          sla_hours: sla,
          double_grade: g["double_grade"] === true,
          agreement_tolerance: tol,
        };
      }
      default:
        throw invalid("type must be deterministic, model or human", [`${path}.type`]);
    }
  });
}
