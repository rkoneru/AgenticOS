import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Ajv2020, type ErrorObject } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { parse } from "yaml";
import { contentHash } from "./canonical.js";
import { lintValidated, type Finding } from "./lint.js";
import type { AblBudget, AblDocument, AblModelRef } from "./types.js";
import { toIssues, validateAbl, type AblIssue, type AblResult } from "./validate.js";

export interface ManifestBudget {
  soft: number | null;
  hard: number | null;
}

export interface ManifestModel {
  provider: string;
  model: string;
  endpoint: string | null;
  params: { temperature?: number; max_output_tokens?: number; top_p?: number };
}

export interface ManifestTool {
  name: string;
  kind: "function" | "mcp" | "code" | "browser" | "channel" | "agent";
  ref: string | null;
  mcp_server: string | null;
  side_effects: "none" | "read" | "write" | "external";
  timeout_seconds: number;
}

/** RuntimeManifest v1: output of the ABL compiler, input of the runtime. Shape fixed in docs/plans/phase-2.md. */
export interface RuntimeManifest {
  manifest_version: 1;
  blueprint: { name: string; version: string; content_hash: string };
  risk: {
    level: "minimal" | "limited" | "high";
    human_oversight_required: boolean;
    approver_roles: string[];
    transparency_notice: string | null;
  };
  models: { primary: ManifestModel; fallbacks: ManifestModel[] };
  routing: { stages: Array<"cache" | "rules" | "mpm" | "rag" | "llm"> };
  system_prompt: string;
  tools: ManifestTool[];
  memory: { run: boolean; session: boolean; long_term: boolean; knowledge_bases: string[] };
  budgets: {
    tokens: ManifestBudget;
    cost_usd: ManifestBudget;
    runtime_seconds: ManifestBudget;
    tool_calls: ManifestBudget;
  };
  process: {
    restart_policy: "never" | "on-failure" | "always";
    max_restarts: number;
    max_children: number;
    timeout_seconds: number | null;
    supervisor: "one-for-one" | "one-for-all" | "rest-for-one";
  };
  policy_packs: string[];
  channels: string[];
  data: { phi: boolean; residency: string | null };
  evals: Array<{ ref: string; threshold: number }>;
}

export type CompileResult =
  | { ok: true; manifest: RuntimeManifest; findings: Finding[] }
  | {
      ok: false;
      /** Schema violations (empty when compilation failed only because of lint errors). */
      issues: AblIssue[];
      /** Lint findings, errors and warnings (empty when the schema failed). */
      findings: Finding[];
    };

const budget = (b: AblBudget | undefined): ManifestBudget => ({
  soft: b?.soft ?? null,
  hard: b?.hard ?? null,
});

function model(m: AblModelRef): ManifestModel {
  const params: ManifestModel["params"] = {};
  if (m.params?.temperature !== undefined) params.temperature = m.params.temperature;
  if (m.params?.maxOutputTokens !== undefined) params.max_output_tokens = m.params.maxOutputTokens;
  if (m.params?.topP !== undefined) params.top_p = m.params.topP;
  return { provider: m.provider, model: m.model, endpoint: m.endpoint ?? null, params };
}

/** Pure mapping from a schema-valid document to its manifest. Applies every default; never mutates `doc`. */
function toManifest(doc: AblDocument): RuntimeManifest {
  const { spec, metadata } = doc;
  const rc = spec.riskClassification;
  return {
    manifest_version: 1,
    blueprint: { name: metadata.name, version: metadata.version, content_hash: contentHash(doc) },
    risk: {
      level: rc.level,
      human_oversight_required: rc.humanOversight?.required ?? false,
      approver_roles: [...(rc.humanOversight?.approverRoles ?? [])],
      transparency_notice: rc.transparencyNotice ?? null,
    },
    models: {
      primary: model(spec.model.primary),
      fallbacks: (spec.model.fallbacks ?? []).map(model),
    },
    routing: { stages: [...(spec.routing?.stages ?? ["llm"])] },
    system_prompt: spec.instructions.system,
    tools: (spec.tools ?? []).map((t) => ({
      name: t.name,
      kind: t.kind,
      ref: t.ref ?? null,
      mcp_server: t.mcpServer ?? null,
      side_effects: t.sideEffects ?? "write",
      timeout_seconds: t.timeoutSeconds ?? 60,
    })),
    memory: {
      run: spec.memory?.run ?? true,
      session: spec.memory?.session ?? false,
      long_term: spec.memory?.longTerm ?? false,
      knowledge_bases: [...(spec.memory?.knowledgeBases ?? [])],
    },
    budgets: {
      tokens: budget(spec.budgets?.tokens),
      cost_usd: budget(spec.budgets?.costUsd),
      runtime_seconds: budget(spec.budgets?.runtimeSeconds),
      tool_calls: budget(spec.budgets?.toolCalls),
    },
    process: {
      restart_policy: spec.process?.restartPolicy ?? "never",
      max_restarts: spec.process?.maxRestarts ?? 0,
      max_children: spec.process?.maxChildren ?? 0,
      timeout_seconds: spec.process?.timeoutSeconds ?? null,
      supervisor: spec.process?.supervisor ?? "one-for-one",
    },
    policy_packs: [...(spec.policy?.packs ?? [])],
    channels: [...(spec.channels ?? [])],
    data: { phi: spec.data?.phi ?? false, residency: spec.data?.residency ?? null },
    evals: (spec.evals?.suites ?? []).map((s) => ({ ref: s.ref, threshold: s.threshold })),
  };
}

/**
 * Compile a parsed ABL document to a RuntimeManifest. Pure and deterministic: the same document (regardless of key
 * order) always yields a byte-identical manifest. Schema violations and lint errors both yield `ok: false`;
 * warnings are returned alongside a successful manifest.
 */
export function compileAbl(doc: unknown): CompileResult {
  const v = validateAbl(doc);
  if (!v.ok) return { ok: false, issues: v.issues, findings: [] };
  const valid = v.doc as AblDocument;
  const findings = lintValidated(valid);
  if (findings.some((f) => f.severity === "error")) return { ok: false, issues: [], findings };
  return { ok: true, manifest: toManifest(valid), findings };
}

/** Parse YAML (or JSON) text and compile it. Syntax errors are reported as a single `yaml` issue. */
export function compileAblYaml(text: string): CompileResult {
  let doc: unknown;
  try {
    doc = parse(text);
  } catch (err) {
    return {
      ok: false,
      issues: [{ path: "/", keyword: "yaml", message: String(err), params: {} }],
      findings: [],
    };
  }
  return compileAbl(doc);
}

const manifestSchemaPath = fileURLToPath(
  new URL("../manifest/runtime-manifest-v1.schema.json", import.meta.url),
);
export const manifestSchema: object = JSON.parse(readFileSync(manifestSchemaPath, "utf8"));

const manifestAjv = new Ajv2020({ allErrors: true, strict: true, verbose: true });
addFormats.default(manifestAjv);
const validateManifestFn = manifestAjv.compile(manifestSchema);

/** Validate a RuntimeManifest v1 against its JSON Schema (used by the runtime before it accepts a manifest). */
export function validateManifest(manifest: unknown): AblResult {
  if (validateManifestFn(manifest)) return { ok: true, doc: manifest };
  return { ok: false, issues: toIssues(validateManifestFn.errors as ErrorObject[]) };
}
