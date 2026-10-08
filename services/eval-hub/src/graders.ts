import { invalid } from "./errors.js";
import { DETERMINISTIC_TYPES, GRADER_KINDS, GRADER_ID_RE, type Grader, type GraderKind } from "./types.js";

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const MAX_GRADERS = 20;
const MAX_RUBRIC = 4000;
const MAX_CONFIG = 20_000;

const numIn = (v: unknown, path: string, min: number, max: number): number => {
  if (typeof v !== "number" || !Number.isFinite(v) || v < min || v > max)
    throw invalid(`${path} must be a number in [${min}, ${max}]`, [path]);
  return v;
};

function str(v: unknown, path: string, max: number): string {
  if (typeof v !== "string" || v.trim() === "" || v.length > max)
    throw invalid(`${path} must be a non-empty string of at most ${max} characters`, [path]);
  return v;
}

/**
 * Validates and normalizes the graders of a suite, in the runner's shape `{id, kind, weight, config, min_mean?}`. The hub checks what
 * it must be able to rely on (kinds, weights, thresholds, the human grader's SLA); the grader-specific `config` is the runner's
 * business (docs/spec/evals-runner.md sections 4-5) and is only bounded here.
 */
export function parseGraders(raw: unknown): Grader[] {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > MAX_GRADERS)
    throw invalid(`graders must be an array of 1-${MAX_GRADERS} graders`, ["graders"]);
  const seen = new Set<string>();
  return raw.map((g: unknown, i): Grader => {
    const path = `graders[${i}]`;
    if (!isObj(g)) throw invalid("grader must be an object", [path]);
    const id = g["id"];
    if (typeof id !== "string" || !GRADER_ID_RE.test(id))
      throw invalid("grader id must match [A-Za-z0-9][A-Za-z0-9._:-]{0,127}", [`${path}.id`]);
    if (seen.has(id)) throw invalid(`duplicate grader id ${id}`, [`${path}.id`]);
    seen.add(id);
    const kind = g["kind"];
    if (typeof kind !== "string" || !(GRADER_KINDS as readonly string[]).includes(kind))
      throw invalid(`kind must be one of ${GRADER_KINDS.join(", ")}`, [`${path}.kind`]);
    const weight = g["weight"] === undefined ? 1 : numIn(g["weight"], `${path}.weight`, 0.000001, 100);
    const cfgRaw = g["config"] === undefined ? {} : g["config"];
    if (!isObj(cfgRaw)) throw invalid("config must be an object", [`${path}.config`]);
    if (JSON.stringify(cfgRaw).length > MAX_CONFIG)
      throw invalid(`config exceeds ${MAX_CONFIG} characters`, [`${path}.config`]);
    const min_mean =
      g["min_mean"] === undefined || g["min_mean"] === null ? null : numIn(g["min_mean"], `${path}.min_mean`, 0, 1);
    const config: Record<string, unknown> = { ...cfgRaw };
    switch (kind as GraderKind) {
      case "deterministic": {
        const t = config["type"];
        if (typeof t !== "string" || !(DETERMINISTIC_TYPES as readonly string[]).includes(t))
          throw invalid(`config.type must be one of ${DETERMINISTIC_TYPES.join(", ")}`, [`${path}.config.type`]);
        if (t === "regex") str(config["pattern"], `${path}.config.pattern`, 1000);
        break;
      }
      case "model":
        str(config["provider"], `${path}.config.provider`, 100);
        str(config["model"], `${path}.config.model`, 200);
        str(config["rubric"], `${path}.config.rubric`, MAX_RUBRIC);
        break;
      case "human": {
        str(config["rubric"], `${path}.config.rubric`, MAX_RUBRIC);
        config["sla_hours"] = config["sla_hours"] === undefined ? 72 : numIn(config["sla_hours"], `${path}.config.sla_hours`, 1, 720);
        if (config["double_grade"] !== undefined && typeof config["double_grade"] !== "boolean")
          throw invalid("double_grade must be a boolean", [`${path}.config.double_grade`]);
        config["double_grade"] = config["double_grade"] === true;
        config["agreement_tolerance"] =
          config["agreement_tolerance"] === undefined ? 0.1 : numIn(config["agreement_tolerance"], `${path}.config.agreement_tolerance`, 0, 1);
        break;
      }
    }
    return { id, kind: kind as GraderKind, weight, config, min_mean };
  });
}
