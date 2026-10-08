import { invalid } from "../errors.js";
import type {
  AffectedGroup,
  AssessedRisk,
  BlueprintRef,
  Level3,
  LifecycleStage,
  RiskLevel,
  RiskRating,
  Stakeholder,
} from "../types.js";

/** Small strict validators: unknown shapes are refused with machine-readable paths, never coerced. */
export class Problems {
  readonly list: string[] = [];
  add(path: string): void {
    this.list.push(path);
  }
  done(what: string): void {
    if (this.list.length > 0) throw invalid(`${what}: invalid fields`, this.list);
  }
}

export const RISK_LEVELS: readonly RiskLevel[] = ["minimal", "limited", "high"];
export const LIFECYCLE_STAGES: readonly LifecycleStage[] = ["design", "development", "deployed", "retired"];
export const RATINGS: readonly RiskRating[] = ["low", "medium", "high", "critical"];
export const LEVELS: readonly Level3[] = ["low", "medium", "high"];

export const MAX_TEXT = 4000;
export const MAX_SHORT = 200;
export const MAX_ITEMS = 100;

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

export function text(
  pr: Problems,
  path: string,
  v: unknown,
  max = MAX_TEXT,
  required = true,
): string {
  if (typeof v !== "string" || v.trim() === "" || v.length > max) {
    if (required || v !== undefined) pr.add(path);
    return "";
  }
  return v.trim();
}

export function oneOf<T extends string>(
  pr: Problems,
  path: string,
  v: unknown,
  allowed: readonly T[],
  dflt?: T,
): T {
  if (v === undefined && dflt !== undefined) return dflt;
  if (typeof v !== "string" || !(allowed as readonly string[]).includes(v)) {
    pr.add(path);
    return allowed[0] as T;
  }
  return v as T;
}

function list<T>(
  pr: Problems,
  path: string,
  v: unknown,
  each: (item: unknown, p: string) => T,
): T[] {
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.length > MAX_ITEMS) {
    pr.add(path);
    return [];
  }
  return v.map((x, i) => each(x, `${path}/${i}`));
}

const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const NAME = /^[a-z][a-z0-9-]{1,62}$/;

export const blueprintRefs = (pr: Problems, path: string, v: unknown): BlueprintRef[] =>
  list(pr, path, v, (x, p) => {
    if (!isObj(x) || typeof x["name"] !== "string" || typeof x["version"] !== "string") {
      pr.add(p);
      return { name: "", version: "" };
    }
    if (!NAME.test(x["name"])) pr.add(`${p}/name`);
    if (!SEMVER.test(x["version"])) pr.add(`${p}/version`);
    return { name: x["name"], version: x["version"] };
  });

export const stakeholders = (pr: Problems, path: string, v: unknown): Stakeholder[] =>
  list(pr, path, v, (x, p) => {
    if (!isObj(x)) {
      pr.add(p);
      return { role: "", name: "" };
    }
    return {
      role: text(pr, `${p}/role`, x["role"], MAX_SHORT),
      name: text(pr, `${p}/name`, x["name"], MAX_SHORT),
    };
  });

export const affectedGroups = (pr: Problems, path: string, v: unknown): AffectedGroup[] =>
  list(pr, path, v, (x, p) => {
    if (!isObj(x)) {
      pr.add(p);
      return { group: "", impact: "" };
    }
    return {
      group: text(pr, `${p}/group`, x["group"], MAX_SHORT),
      impact: text(pr, `${p}/impact`, x["impact"]),
    };
  });

export const risks = (pr: Problems, path: string, v: unknown): AssessedRisk[] => {
  const out = list(pr, path, v, (x, p) => {
    if (!isObj(x)) {
      pr.add(p);
      return {
        id: "",
        description: "",
        likelihood: "low" as Level3,
        severity: "low" as Level3,
        mitigation: "",
        residual: "low" as Level3,
      };
    }
    return {
      id: text(pr, `${p}/id`, x["id"], 64),
      description: text(pr, `${p}/description`, x["description"]),
      likelihood: oneOf(pr, `${p}/likelihood`, x["likelihood"], LEVELS),
      severity: oneOf(pr, `${p}/severity`, x["severity"], LEVELS),
      mitigation: text(pr, `${p}/mitigation`, x["mitigation"]),
      residual: oneOf(pr, `${p}/residual`, x["residual"], LEVELS),
    };
  });
  const seen = new Set<string>();
  out.forEach((r, i) => {
    if (seen.has(r.id)) pr.add(`${path}/${i}/id`);
    seen.add(r.id);
  });
  return out;
};

export const strings = (pr: Problems, path: string, v: unknown, max = MAX_SHORT): string[] =>
  list(pr, path, v, (x, p) => text(pr, p, x, max));

/** A calendar date YYYY-MM-DD that exists. */
export function isoDate(pr: Problems, path: string, v: unknown): string {
  if (typeof v !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(v)) {
    pr.add(path);
    return "1970-01-01";
  }
  const d = new Date(`${v}T00:00:00.000Z`);
  if (Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== v) pr.add(path);
  return v;
}

export const SYSTEM_ID = /^[a-z][a-z0-9-]{1,62}$/;
