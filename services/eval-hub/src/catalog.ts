import { hashJson } from "@axis/contracts";
import { datasetHash } from "./canonical.js";
import { denyAudit, guarded, iso, mutate, type Ctx } from "./context.js";
import { requireReader, requireTenant } from "./authz.js";
import { invalid, notFound } from "./errors.js";
import { parseGraders } from "./graders.js";
import { redactJson } from "./redact.js";
import {
  DATASET_REF_RE,
  ID_RE,
  NAME_RE,
  SUITE_REF_RE,
  type DatasetVersion,
  type EvalCase,
  type HubPrincipal,
  type Suite,
} from "./types.js";

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const MAX_CASE_BYTES = 64_000;

/** Validates the cases of a dataset. Ids are unique; each case is bounded. Throws `invalid` with the offending paths. */
export function parseCases(raw: unknown, max: number): EvalCase[] {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > max)
    throw invalid(`cases must be an array of 1-${max} cases`, ["cases"]);
  const seen = new Set<string>();
  return raw.map((x: unknown, i): EvalCase => {
    const path = `cases[${i}]`;
    if (!isObj(x)) throw invalid("case must be an object", [path]);
    const id = x["id"];
    if (typeof id !== "string" || !ID_RE.test(id))
      throw invalid("case id is malformed", [`${path}.id`]);
    if (seen.has(id)) throw invalid(`duplicate case id ${id}`, [`${path}.id`]);
    seen.add(id);
    if (x["input"] === undefined) throw invalid("case input is required", [`${path}.input`]);
    const tags = x["tags"] === undefined ? [] : x["tags"];
    if (
      !Array.isArray(tags) ||
      tags.length > 20 ||
      tags.some((t) => typeof t !== "string" || t.length > 60)
    )
      throw invalid("tags must be up to 20 short strings", [`${path}.tags`]);
    const metadata = x["metadata"] === undefined ? {} : x["metadata"];
    if (!isObj(metadata)) throw invalid("metadata must be an object", [`${path}.metadata`]);
    const c: EvalCase = {
      id,
      input: x["input"],
      expected: x["expected"] === undefined ? null : x["expected"],
      tags: tags as string[],
      metadata,
    };
    if (JSON.stringify(c).length > MAX_CASE_BYTES)
      throw invalid(`case exceeds ${MAX_CASE_BYTES} bytes`, [path]);
    return c;
  });
}

export class DatasetService {
  constructor(private readonly c: Ctx) {}

  /**
   * Creates the next IMMUTABLE version of dataset `name` (versions are 1, 2, 3...). When `phi` is set (or an earlier version was PHI,
   * which can never be downgraded) every string is redacted BEFORE anything is persisted, and the content hash covers the redacted cases.
   */
  async create(
    p: HubPrincipal,
    input: { name: unknown; description?: unknown; phi?: unknown; cases: unknown },
  ): Promise<DatasetVersion> {
    try {
      requireTenant(p, "evals.write");
    } catch (e) {
      return denyAudit(this.c, p, "evals.dataset.create", e);
    }
    if (typeof input.name !== "string" || !NAME_RE.test(input.name))
      throw invalid("dataset name must match [a-z][a-z0-9-]{1,62}", ["name"]);
    if (input.phi !== undefined && typeof input.phi !== "boolean")
      throw invalid("phi must be a boolean", ["phi"]);
    if (
      input.description !== undefined &&
      (typeof input.description !== "string" || input.description.length > 2000)
    )
      throw invalid("description must be a string of at most 2000 characters", ["description"]);
    const cases = parseCases(input.cases, this.c.maxCases);
    const name = input.name;
    const tenantId = p.tenantId;
    return mutate(this.c, p, "evals.dataset.create", { name, cases: cases.length }, async () => {
      const prior = await this.c.docs.find<DatasetVersion>(tenantId, "datasets", { name });
      const phi = input.phi === true || prior.some((d) => d.data.phi);
      const version = prior.length + 1;
      const stored = phi ? (redactJson(cases, this.c.redact) as EvalCase[]) : cases;
      const rec: DatasetVersion = {
        name,
        version,
        ref: `${name}@${version}`,
        description: (input.description as string | undefined) ?? null,
        phi,
        redacted: phi,
        case_count: stored.length,
        content_hash: datasetHash(stored),
        version_hash: datasetHash(stored),
        cases: stored,
        created_at: iso(this.c.now()),
        created_by: (p as { subject: string }).subject,
      };
      await guarded(() => this.c.docs.insert(tenantId, "datasets", rec.ref, rec), "dataset");
      return rec;
    });
  }

  async get(p: HubPrincipal, ref: string): Promise<DatasetVersion> {
    requireReader(p);
    const m = /^(.*)@(latest|\d+)$/.exec(ref);
    if (!m) throw notFound("dataset not found");
    let key = ref;
    if (m[2] === "latest") {
      const all = await this.c.docs.find<DatasetVersion>(p.tenantId, "datasets", {
        name: m[1] as string,
      });
      const top = all.map((d) => d.data).sort((a, b) => b.version - a.version)[0];
      if (!top) throw notFound("dataset not found");
      return top;
    }
    key = `${m[1]}@${Number(m[2])}`;
    const d = await this.c.docs.get<DatasetVersion>(p.tenantId, "datasets", key);
    if (!d) throw notFound("dataset not found");
    return d.data;
  }

  /** Versions of every dataset, without their cases. */
  async list(p: HubPrincipal, name?: string): Promise<Omit<DatasetVersion, "cases">[]> {
    requireReader(p);
    const all = await this.c.docs.find<DatasetVersion>(
      p.tenantId,
      "datasets",
      name ? { name } : {},
    );
    return all
      .map((d) => {
        const { cases: _cases, ...rest } = d.data;
        void _cases;
        return rest;
      })
      .sort((a, b) => (a.name === b.name ? a.version - b.version : a.name < b.name ? -1 : 1));
  }
}

export interface SuiteInput {
  ref: unknown;
  dataset_ref: unknown;
  graders: unknown;
  pass_threshold: unknown;
  min_case_score?: unknown;
  settings?: unknown;
  tolerance?: unknown;
  required_for_release?: unknown;
  applies_to?: unknown;
  min_samples?: unknown;
  max_age_days?: unknown;
  regression_requires_significance?: unknown;
  alpha?: unknown;
}

const num = (v: unknown, path: string, min: number, max: number, dflt: number): number => {
  if (v === undefined) return dflt;
  if (typeof v !== "number" || !Number.isFinite(v) || v < min || v > max)
    throw invalid(`${path} must be a number in [${min}, ${max}]`, [path]);
  return v;
};

export class SuiteService {
  constructor(private readonly c: Ctx) {}

  /** Suites are immutable: a changed definition is a new `name@version`. The suite pins its dataset version and that version's hash. */
  async create(p: HubPrincipal, input: SuiteInput): Promise<Suite> {
    try {
      requireTenant(p, "evals.write");
    } catch (e) {
      return denyAudit(this.c, p, "evals.suite.create", e);
    }
    const m = typeof input.ref === "string" ? SUITE_REF_RE.exec(input.ref) : null;
    if (!m) throw invalid("suite ref must be name@version", ["ref"]);
    if (typeof input.dataset_ref !== "string" || !DATASET_REF_RE.test(input.dataset_ref))
      throw invalid("dataset_ref must be name@<integer version>", ["dataset_ref"]);
    const graders = parseGraders(input.graders);
    const pass_threshold = num(input.pass_threshold, "pass_threshold", 0, 1, NaN);
    if (Number.isNaN(pass_threshold))
      throw invalid("pass_threshold is required", ["pass_threshold"]);
    const tolerance = num(input.tolerance, "tolerance", 0, 1, 0.02);
    let min_case_score: number | null = null;
    if (input.min_case_score !== undefined && input.min_case_score !== null)
      min_case_score = num(input.min_case_score, "min_case_score", 0, 1, 0);
    const settings = input.settings === undefined ? {} : input.settings;
    if (!isObj(settings) || JSON.stringify(settings).length > 10_000)
      throw invalid("settings must be an object of at most 10000 characters", ["settings"]);
    const alpha = num(input.alpha, "alpha", 0.0001, 0.5, 0.05);
    const max_age_days = num(input.max_age_days, "max_age_days", 1, 365, 30);
    if (!Number.isInteger(max_age_days))
      throw invalid("max_age_days must be an integer", ["max_age_days"]);
    let min_samples: number | null = null;
    if (input.min_samples !== undefined) {
      min_samples = num(input.min_samples, "min_samples", 1, 100_000, 1);
      if (!Number.isInteger(min_samples))
        throw invalid("min_samples must be an integer", ["min_samples"]);
    }
    for (const k of ["required_for_release", "regression_requires_significance"] as const)
      if (input[k] !== undefined && typeof input[k] !== "boolean")
        throw invalid(`${k} must be a boolean`, [k]);
    const applies = input.applies_to === undefined ? [] : input.applies_to;
    if (
      !Array.isArray(applies) ||
      applies.length > 50 ||
      applies.some((a) => typeof a !== "string" || !NAME_RE.test(a))
    )
      throw invalid("applies_to must be up to 50 blueprint names", ["applies_to"]);
    const tenantId = p.tenantId;
    const ds = await this.c.docs.get<DatasetVersion>(tenantId, "datasets", input.dataset_ref);
    if (!ds) throw invalid("dataset version not found", ["dataset_ref"]);
    if (min_samples !== null && min_samples > ds.data.case_count)
      throw invalid("min_samples exceeds the dataset's case count", ["min_samples"]);
    const base = {
      ref: input.ref as string,
      name: m[1] as string,
      version: m[2] as string,
      dataset_ref: input.dataset_ref,
      dataset_hash: ds.data.content_hash,
      graders,
      pass_threshold,
      min_case_score,
      settings,
      tolerance,
      required_for_release: input.required_for_release !== false,
      applies_to: [...new Set(applies as string[])].sort(),
      min_samples,
      max_age_days,
      regression_requires_significance: input.regression_requires_significance === true,
      alpha,
    };
    const rec: Suite = {
      ...base,
      suite_hash: hashJson(base),
      created_at: iso(this.c.now()),
      created_by: (p as { subject: string }).subject,
    };
    return mutate(
      this.c,
      p,
      "evals.suite.create",
      { ref: rec.ref, suite_hash: rec.suite_hash },
      async () => {
        await guarded(() => this.c.docs.insert(tenantId, "suites", rec.ref, rec), "suite");
        return rec;
      },
    );
  }

  async get(p: HubPrincipal, ref: string): Promise<Suite> {
    requireReader(p);
    const d = await this.c.docs.get<Suite>(p.tenantId, "suites", ref);
    if (!d) throw notFound("suite not found");
    return d.data;
  }

  async list(p: HubPrincipal): Promise<Suite[]> {
    requireReader(p);
    return (await this.c.docs.find<Suite>(p.tenantId, "suites")).map((d) => d.data);
  }
}
