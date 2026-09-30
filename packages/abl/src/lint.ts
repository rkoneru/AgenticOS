import type { AblBudget, AblDocument, AblModelRef } from "./types.js";
import { validateAbl } from "./validate.js";

export type Severity = "error" | "warning";

export interface Finding {
  /** Stable identifier, see the lint-code table in docs/spec/abl-v1.md. Never reused. */
  code: string;
  severity: Severity;
  /** JSON pointer into the ABL document, e.g. `/spec/tools/1/name`. */
  path: string;
  message: string;
}

export interface LintRule {
  code: string;
  name: string;
  severity: Severity;
  check: (doc: AblDocument) => Array<{ path: string; message: string }>;
}

const modelKey = (m: AblModelRef): string => `${m.provider}|${m.model}|${m.endpoint ?? ""}`;
const hasRag = (doc: AblDocument): boolean => (doc.spec.routing?.stages ?? ["llm"]).includes("rag");
const effects = (doc: AblDocument): string[] =>
  (doc.spec.tools ?? []).map((t) => t.sideEffects ?? "write");

const BUDGET_METRICS = ["tokens", "costUsd", "runtimeSeconds", "toolCalls"] as const;
const budgetsOf = (doc: AblDocument): Array<[string, AblBudget]> =>
  BUDGET_METRICS.flatMap((k) => {
    const b = doc.spec.budgets?.[k];
    return b === undefined ? [] : [[k, b] as [string, AblBudget]];
  });

/** Rules run in this order; findings therefore come out in a stable order. */
export const LINT_RULES: readonly LintRule[] = [
  {
    code: "ABL001",
    name: "duplicate-tool-name",
    severity: "error",
    check: (doc) => {
      const seen = new Set<string>();
      const out: Array<{ path: string; message: string }> = [];
      (doc.spec.tools ?? []).forEach((t, i) => {
        if (seen.has(t.name)) {
          out.push({ path: `/spec/tools/${i}/name`, message: `duplicate tool name "${t.name}"` });
        }
        seen.add(t.name);
      });
      return out;
    },
  },
  {
    code: "ABL002",
    name: "budget-soft-exceeds-hard",
    severity: "error",
    check: (doc) =>
      budgetsOf(doc).flatMap(([k, b]) =>
        b.soft !== undefined && b.hard !== undefined && b.soft > b.hard
          ? [
              {
                path: `/spec/budgets/${k}`,
                message: `soft limit ${b.soft} exceeds hard limit ${b.hard}`,
              },
            ]
          : [],
      ),
  },
  {
    code: "ABL003",
    name: "fallback-equals-primary",
    severity: "error",
    check: (doc) =>
      (doc.spec.model.fallbacks ?? []).flatMap((f, i) =>
        modelKey(f) === modelKey(doc.spec.model.primary)
          ? [
              {
                path: `/spec/model/fallbacks/${i}`,
                message: `fallback ${f.provider}/${f.model} is identical to the primary model`,
              },
            ]
          : [],
      ),
  },
  {
    code: "ABL004",
    name: "high-risk-without-evals",
    severity: "error",
    check: (doc) =>
      doc.spec.riskClassification.level === "high" && (doc.spec.evals?.suites ?? []).length === 0
        ? [
            {
              path: "/spec/evals",
              message:
                "high-risk blueprints must declare at least one eval suite (spec.evals.suites)",
            },
          ]
        : [],
  },
  {
    code: "ABL005",
    name: "phi-without-residency",
    severity: "error",
    check: (doc) =>
      doc.spec.data?.phi === true && doc.spec.data.residency === undefined
        ? [
            {
              path: "/spec/data",
              message: "data.phi is true but data.residency is not set",
            },
          ]
        : [],
  },
  {
    code: "ABL006",
    name: "agent-tool-self-reference",
    severity: "error",
    check: (doc) =>
      (doc.spec.tools ?? []).flatMap((t, i) =>
        t.kind === "agent" &&
        (t.name === doc.metadata.name || t.ref?.split("@")[0] === doc.metadata.name)
          ? [
              {
                path: `/spec/tools/${i}`,
                message: `agent tool "${t.name}" references the blueprint itself (unbounded recursion)`,
              },
            ]
          : [],
      ),
  },
  {
    code: "ABL101",
    name: "knowledge-bases-without-rag",
    severity: "warning",
    check: (doc) =>
      (doc.spec.memory?.knowledgeBases ?? []).length > 0 && !hasRag(doc)
        ? [
            {
              path: "/spec/memory/knowledgeBases",
              message:
                "knowledge bases are declared but routing.stages has no 'rag' stage, so they are never queried",
            },
          ]
        : [],
  },
  {
    code: "ABL102",
    name: "side-effect-tools-without-policy-packs",
    severity: "warning",
    check: (doc) =>
      effects(doc).some((e) => e === "write" || e === "external") &&
      (doc.spec.policy?.packs ?? []).length === 0
        ? [
            {
              path: "/spec/policy",
              message:
                "tools with write/external side effects (omitted sideEffects counts as write) but no policy.packs; only the platform default applies",
            },
          ]
        : [],
  },
  {
    code: "ABL103",
    name: "no-hard-budget",
    severity: "warning",
    check: (doc) =>
      budgetsOf(doc).some(([, b]) => b.hard !== undefined)
        ? []
        : [
            {
              path: "/spec/budgets",
              message: "no hard budget is set; a runaway run is not capped",
            },
          ],
  },
  {
    code: "ABL104",
    name: "voice-without-transparency-notice",
    severity: "warning",
    check: (doc) =>
      doc.spec.channels?.includes("voice") === true &&
      doc.spec.riskClassification.transparencyNotice === undefined
        ? [
            {
              path: "/spec/channels",
              message:
                "voice channel without riskClassification.transparencyNotice; callers are not told they speak to an AI",
            },
          ]
        : [],
  },
  {
    code: "ABL105",
    name: "rag-stage-without-knowledge-bases",
    severity: "warning",
    check: (doc) =>
      (doc.spec.routing?.stages ?? []).includes("rag") &&
      (doc.spec.memory?.knowledgeBases ?? []).length === 0
        ? [
            {
              path: "/spec/routing/stages",
              message: "routing has a 'rag' stage but memory.knowledgeBases is empty",
            },
          ]
        : [],
  },
  {
    code: "ABL106",
    name: "routing-without-llm-stage",
    severity: "warning",
    check: (doc) =>
      doc.spec.routing?.stages !== undefined && !doc.spec.routing.stages.includes("llm")
        ? [
            {
              path: "/spec/routing/stages",
              message:
                "routing has no 'llm' stage; requests no earlier stage resolves have nowhere to go",
            },
          ]
        : [],
  },
  {
    code: "ABL107",
    name: "max-restarts-ignored",
    severity: "warning",
    check: (doc) =>
      (doc.spec.process?.restartPolicy ?? "never") === "never" &&
      (doc.spec.process?.maxRestarts ?? 0) > 0
        ? [
            {
              path: "/spec/process/maxRestarts",
              message:
                "maxRestarts is set but restartPolicy is 'never' (the default); it has no effect",
            },
          ]
        : [],
  },
  {
    code: "ABL108",
    name: "duplicate-fallback",
    severity: "warning",
    check: (doc) => {
      const seen = new Set<string>();
      const out: Array<{ path: string; message: string }> = [];
      (doc.spec.model.fallbacks ?? []).forEach((f, i) => {
        const k = modelKey(f);
        if (seen.has(k)) {
          out.push({
            path: `/spec/model/fallbacks/${i}`,
            message: `fallback ${f.provider}/${f.model} is listed more than once`,
          });
        }
        seen.add(k);
      });
      return out;
    },
  },
];

/** Lint a schema-valid document. Callers that hold an unvalidated value use `lintAbl`. */
export function lintValidated(doc: AblDocument): Finding[] {
  return LINT_RULES.flatMap((rule) =>
    rule.check(doc).map((f) => ({ code: rule.code, severity: rule.severity, ...f })),
  );
}

/**
 * Lint an ABL document. Findings need a schema-valid document to be meaningful, so a document that fails the
 * schema yields no findings here; use `compileAbl` (or `validateAbl`) to get the schema issues.
 */
export function lintAbl(doc: unknown): Finding[] {
  const r = validateAbl(doc);
  return r.ok ? lintValidated(r.doc as AblDocument) : [];
}
