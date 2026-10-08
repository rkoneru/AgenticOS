import { compileAbl, type AblDocument } from "@axis/abl";
import { canonicalJson, hashOf, sha256Hex } from "../canonical.js";
import type { BlueprintRef } from "../types.js";
import type {
  AuditStats,
  BlueprintSnapshot,
  EvalEvidence,
  Limitation,
  PolicyPackInfo,
  Sourced,
} from "./ports.js";

export const DOC_SCHEMA = "axis.compliance.annex-iv/1";

export const DISCLAIMER =
  "This document assembles evidence recorded by the AXIS platform for the preparation of technical documentation in the structure of " +
  "Annex IV of Regulation (EU) 2024/1689. It is designed for and evidence-ready toward that purpose. It is not a conformity assessment, " +
  "not legal advice and not a statement that any system meets the Regulation; the provider remains responsible for the content of the " +
  "technical documentation. Items the platform cannot evidence are listed as gaps.";

export type SectionStatus = "complete" | "partial" | "gap";

export interface Section {
  title: string;
  annex_iv: string[];
  status: SectionStatus;
  data: Record<string, unknown> | null;
  gaps: string[];
}

export interface Gap {
  section: string;
  item: string;
  reason: string;
}

export interface CoveragePoint {
  point: string;
  title: string;
  section: string | null;
  status: "evidenced" | "partial" | "gap";
  note: string | null;
}

export interface DocBody {
  schema: typeof DOC_SCHEMA;
  disclaimer: string;
  blueprint: BlueprintRef & { content_hash: string | null };
  sources: { name: string; status: "ok" | "gap"; reason: string | null }[];
  sections: Record<string, Section>;
  annex_iv_coverage: CoveragePoint[];
  gaps: Gap[];
}

export interface AssembleInput {
  ref: BlueprintRef;
  blueprint: Sourced<BlueprintSnapshot>;
  evals: Sourced<EvalEvidence>;
  policies: Sourced<PolicyPackInfo[]>;
  audit: Sourced<AuditStats>;
  limitations: Sourced<Limitation[]>;
}

export const SECTION_KEYS = [
  "general",
  "development",
  "oversight",
  "risk_management",
  "data_governance",
  "performance",
  "lifecycle",
  "record_keeping",
  "post_market",
  "limitations",
] as const;
export type SectionKey = (typeof SECTION_KEYS)[number];

/** A reason is one line of bounded length: it ends up in Markdown lists and table cells. */
function oneLine<T>(s: Sourced<T>): Sourced<T> {
  if (s.ok) return s;
  const r = s.reason.replace(/\s+/g, " ").trim().slice(0, 300);
  return { ok: false, reason: r === "" ? "source unavailable" : r };
}

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Sorts by `key`; items with the same key are ordered by their canonical JSON, so the order never depends on the input order. */
function sortedBy<T>(xs: readonly T[], key: (x: T) => string): T[] {
  return [...xs]
    .map((x) => ({ x, k: key(x), j: canonicalJson(x) }))
    .sort((a, b) => cmp(a.k, b.k) || cmp(a.j, b.j))
    .map((e) => e.x);
}

function sortedRecord(r: Record<string, number>): Record<string, number> {
  return Object.fromEntries(Object.entries(r).sort(([a], [b]) => cmp(a, b)));
}

class Builder {
  readonly gaps: Gap[] = [];
  readonly sections: Record<string, Section> = {};
  section(
    key: SectionKey,
    title: string,
    annex: string[],
    data: Record<string, unknown> | null,
    gaps: { item: string; reason: string }[],
    forceGap = false,
  ): void {
    for (const g of gaps) this.gaps.push({ section: key, item: g.item, reason: g.reason });
    this.sections[key] = {
      title,
      annex_iv: annex,
      status: forceGap || data === null ? "gap" : gaps.length > 0 ? "partial" : "complete",
      data,
      gaps: sortedBy(
        gaps.map((g) => `${g.item}: ${g.reason}`),
        (x) => x,
      ),
    };
  }
}

function modelsOf(abl: AblDocument): Record<string, unknown>[] {
  const m = abl.spec.model;
  const one = (r: typeof m.primary, role: string): Record<string, unknown> => ({
    role,
    provider: r.provider,
    model: r.model,
    custom_endpoint: r.endpoint !== undefined,
    params: r.params ?? null,
  });
  return [one(m.primary, "primary"), ...(m.fallbacks ?? []).map((f) => one(f, "fallback"))];
}

/**
 * Pure and deterministic: the same inputs give the same body, byte for byte after canonical serialisation. Nothing here reads a clock,
 * a random source or the environment. Every missing source or missing fact is recorded as a gap; nothing is invented.
 */
export function assemble(input: AssembleInput): DocBody {
  const i: AssembleInput = {
    ref: input.ref,
    blueprint: oneLine(input.blueprint),
    evals: oneLine(input.evals),
    policies: oneLine(input.policies),
    audit: oneLine(input.audit),
    limitations: oneLine(input.limitations),
  };
  const b = new Builder();
  const sources: DocBody["sources"] = [];
  const note = (name: string, s: Sourced<unknown>): void => {
    sources.push({ name, status: s.ok ? "ok" : "gap", reason: s.ok ? null : s.reason });
    if (!s.ok) b.gaps.push({ section: "sources", item: name, reason: s.reason });
  };
  note("audit", i.audit);
  note("blueprint", i.blueprint);
  note("evals", i.evals);
  note("limitations", i.limitations);
  note("policies", i.policies);

  const bp = i.blueprint.ok ? i.blueprint.value : null;
  const abl = bp?.abl ?? null;
  const spec = abl?.spec ?? null;

  // Compile once: the manifest hash and the lint findings are facts about the blueprint; a failure is a gap, not a guess.
  let lint: { code: string; severity: string; path: string }[] | null = null;
  let manifestHash: string | null = null;
  let compileGap: string | null = null;
  if (abl) {
    const c = compileAbl(abl);
    lint = sortedBy(
      c.findings.map((f) => ({ code: f.code, severity: f.severity, path: f.path })),
      (f) => `${f.code}${f.path}`,
    );
    if (c.ok) manifestHash = hashOf(c.manifest);
    else
      compileGap = `the blueprint does not compile (${c.issues.length} schema issue(s), ${c.findings.filter((f) => f.severity === "error").length} lint error(s))`;
  }

  const bpGaps: { item: string; reason: string }[] = i.blueprint.ok
    ? []
    : [{ item: "blueprint", reason: i.blueprint.reason }];

  // ---- 1. General description (Annex IV 1)
  if (abl && spec && bp) {
    const gaps: { item: string; reason: string }[] = [];
    if (spec.riskClassification.intendedPurpose === undefined)
      gaps.push({
        item: "intended_purpose",
        reason: "the blueprint does not declare riskClassification.intendedPurpose",
      });
    if (abl.metadata.owner === undefined)
      gaps.push({
        item: "provider_owner",
        reason: "the blueprint does not declare metadata.owner",
      });
    gaps.push({
      item: "hardware_and_deployer_instructions",
      reason:
        "hardware description and instructions for use are not produced by the platform; the provider supplies them",
    });
    b.section(
      "general",
      "General description of the AI system",
      ["1(a)", "1(b)", "1(c)", "1(d)", "1(g)"],
      {
        name: abl.metadata.name,
        version: abl.metadata.version,
        content_hash: bp.content_hash,
        description: abl.metadata.description ?? null,
        owner: abl.metadata.owner ?? null,
        origin: bp.origin,
        intended_purpose: spec.riskClassification.intendedPurpose ?? null,
        transparency_notice: spec.riskClassification.transparencyNotice ?? null,
        channels: sortedBy(spec.channels ?? [], (x) => x),
        models: modelsOf(abl),
        delivery: "software as a service (AXIS control plane and runtime)",
      },
      gaps,
    );
  } else
    b.section(
      "general",
      "General description of the AI system",
      ["1(a)", "1(b)", "1(c)", "1(d)", "1(g)"],
      null,
      bpGaps,
    );

  // ---- 2. Elements and development process (Annex IV 2)
  if (abl && spec && bp) {
    const gaps: { item: string; reason: string }[] = [];
    if (compileGap) gaps.push({ item: "compiled_manifest", reason: compileGap });
    if (bp.registry === null)
      gaps.push({
        item: "registry_provenance",
        reason:
          "the blueprint is not published in the registry; there is no signature or provenance to verify",
      });
    else if (!bp.registry.verification.ok)
      gaps.push({
        item: "registry_verification",
        reason: `registry verification failed: ${[...bp.registry.verification.checks].sort(cmp).join(",")}`,
      });
    b.section(
      "development",
      "Elements of the system and its development process",
      ["2(a)", "2(b)", "2(c)", "2(g)", "2(h)"],
      {
        tools: sortedBy(
          (spec.tools ?? []).map((t) => ({
            name: t.name,
            kind: t.kind,
            side_effects: t.sideEffects ?? "write",
            mcp_server: t.mcpServer ?? null,
            timeout_seconds: t.timeoutSeconds ?? 60,
          })),
          (t) => t.name,
        ),
        routing_stages: spec.routing?.stages ?? ["llm"],
        memory: {
          run: spec.memory?.run ?? true,
          session: spec.memory?.session ?? false,
          long_term: spec.memory?.longTerm ?? false,
          knowledge_bases: sortedBy(spec.memory?.knowledgeBases ?? [], (x) => x),
        },
        budgets: spec.budgets ?? null,
        process: spec.process ?? null,
        declared_policy_packs: sortedBy(spec.policy?.packs ?? [], (x) => x),
        system_instructions: {
          sha256: sha256Hex(spec.instructions.system),
          characters: spec.instructions.system.length,
          note: "the text is part of the signed blueprint version and is not copied into this document",
        },
        compiled_manifest_sha256: manifestHash,
        lint_findings: lint,
        registry: bp.registry
          ? {
              namespace: bp.registry.namespace,
              signature_key_id: bp.registry.signature_key_id,
              signed_at: bp.registry.signed_at,
              published_at: bp.registry.published_at,
              provenance_attached: bp.registry.provenance_attached,
              verification_ok: bp.registry.verification.ok,
              verification_checks: sortedBy(bp.registry.verification.checks, (x) => x),
            }
          : null,
      },
      gaps,
    );
  } else
    b.section(
      "development",
      "Elements of the system and its development process",
      ["2(a)", "2(b)", "2(c)", "2(g)", "2(h)"],
      null,
      bpGaps,
    );

  // ---- Human oversight and control (Annex IV 2(e), 3; Art. 14)
  if (spec) {
    const hv = spec.riskClassification.humanOversight;
    const gaps: { item: string; reason: string }[] = [];
    if (spec.riskClassification.level === "high" && !(hv?.required === true))
      gaps.push({
        item: "human_oversight",
        reason: "a high-risk blueprint without required human oversight",
      });
    if (!i.policies.ok) gaps.push({ item: "active_policy_packs", reason: i.policies.reason });
    b.section(
      "oversight",
      "Human oversight and control measures",
      ["2(e)", "3"],
      {
        human_oversight_required: hv?.required ?? false,
        approver_roles: sortedBy(hv?.approverRoles ?? [], (x) => x),
        enforcement:
          "every tool, memory-write and outbound action is decided by the Risk Kernel (fail-closed); REQUIRE_APPROVAL routes to the approvals service",
        active_policy_packs: i.policies.ok
          ? sortedBy(i.policies.value, (p) => `${p.id}@${p.version}`)
          : null,
      },
      gaps,
    );
  } else
    b.section("oversight", "Human oversight and control measures", ["2(e)", "3"], null, bpGaps);

  // ---- 5. Risk management (Annex IV 5; Art. 9)
  if (spec) {
    const gaps: { item: string; reason: string }[] = [];
    const errors = (lint ?? []).filter((f) => f.severity === "error").length;
    if (errors > 0)
      gaps.push({ item: "lint", reason: `${errors} blueprint lint error(s) present` });
    b.section(
      "risk_management",
      "Risk management system",
      ["5"],
      {
        level: spec.riskClassification.level,
        rationale: spec.riskClassification.rationale,
        lint_warnings: (lint ?? []).filter((f) => f.severity === "warning").length,
        lint_errors: errors,
        declared_eval_suites: sortedBy(spec.evals?.suites ?? [], (s) => s.ref),
        residual_risk_register:
          "kept as AI impact assessment records (services/compliance); not embedded in this document",
      },
      gaps,
    );
  } else b.section("risk_management", "Risk management system", ["5"], null, bpGaps);

  // ---- Data and data governance (Annex IV 2(d); Art. 10)
  if (spec) {
    b.section(
      "data_governance",
      "Data and data governance",
      ["2(d)"],
      {
        phi: spec.data?.phi ?? false,
        residency: spec.data?.residency ?? null,
        memory_scopes: {
          session: spec.memory?.session ?? false,
          long_term: spec.memory?.longTerm ?? false,
        },
        knowledge_bases: sortedBy(spec.memory?.knowledgeBases ?? [], (x) => x),
      },
      [
        {
          item: "training_data_datasheets",
          reason:
            "AXIS blueprints use third-party foundation models; training data documentation comes from the model provider and is not held by the platform",
        },
      ],
    );
  } else b.section("data_governance", "Data and data governance", ["2(d)"], null, bpGaps);

  // ---- Validation, testing, accuracy (Annex IV 2(g), 3, 4)
  {
    const gaps: { item: string; reason: string }[] = [];
    let data: Record<string, unknown> | null = null;
    if (i.evals.ok) {
      const ev = i.evals.value;
      const declared = sortedBy(spec?.evals?.suites ?? [], (s) => s.ref);
      for (const d of declared)
        if (!ev.runs.some((r) => r.declared_ref === d.ref && r.status === "passed"))
          gaps.push({
            item: `suite:${d.ref}`,
            reason: "no passing run of this declared suite for this blueprint content",
          });
      for (const g of ev.gate)
        if (!g.pass)
          gaps.push({
            item: `gate:${g.suite_ref}`,
            reason: `gate verdict is not a pass (${[...g.reasons].sort(cmp).join(",")})`,
          });
      for (const a of ev.attestations)
        if (!a.verified)
          gaps.push({ item: `attestation:${a.run_id}`, reason: "attestation did not verify" });
      data = {
        declared_suites: declared,
        runs: sortedBy(ev.runs, (r) => `${r.suite_ref}\u0000${r.run_id}`),
        attestations: sortedBy(ev.attestations, (a) => `${a.suite_ref}\u0000${a.run_id}`),
        gate_verdicts: sortedBy(ev.gate, (g) => g.suite_ref),
      };
    } else gaps.push({ item: "evals", reason: i.evals.reason });
    b.section(
      "performance",
      "Validation, testing and performance metrics",
      ["2(g)", "3", "4"],
      data,
      gaps,
    );
  }

  // ---- 6. Lifecycle changes
  if (bp) {
    const gaps: { item: string; reason: string }[] = [];
    if (bp.versions === null)
      gaps.push({
        item: "version_history",
        reason: "the source cannot list other versions of this blueprint",
      });
    b.section(
      "lifecycle",
      "Changes through the lifecycle",
      ["6"],
      {
        version: bp.abl.metadata.version,
        content_hash: bp.content_hash,
        versions: bp.versions ? sortedBy(bp.versions, (v) => v.version) : null,
      },
      gaps,
    );
  } else b.section("lifecycle", "Changes through the lifecycle", ["6"], null, bpGaps);

  // ---- Record-keeping (Art. 12)
  if (i.audit.ok) {
    const a = i.audit.value;
    const gaps: { item: string; reason: string }[] = [];
    if (!a.chain.verified)
      gaps.push({
        item: "audit_chain",
        reason: `chain verification FAILED${a.chain.reason ? `: ${a.chain.reason}` : ""}`,
      });
    b.section(
      "record_keeping",
      "Record-keeping (audit log)",
      ["2(g)", "3"],
      {
        event_count: a.event_count,
        head_seq: a.head_seq,
        head_hash: a.head_hash,
        first_event_at: a.first_ts,
        last_event_at: a.last_ts,
        by_decision: sortedRecord(a.by_decision),
        by_enforcement_point: sortedRecord(a.by_enforcement_point),
        chain_verified: a.chain.verified,
        chain_checked_through_seq: a.chain.checked_through_seq,
        chain_failure: a.chain.reason,
      },
      gaps,
    );
  } else
    b.section("record_keeping", "Record-keeping (audit log)", ["2(g)", "3"], null, [
      { item: "audit", reason: i.audit.reason },
    ]);

  // ---- 9. Post-market monitoring (Art. 72)
  {
    const gaps: { item: string; reason: string }[] = [];
    let data: Record<string, unknown> | null = null;
    if (i.evals.ok) {
      const online = i.evals.value.online;
      if (online === null)
        gaps.push({
          item: "online_sampling",
          reason: "the source cannot report production sampling",
        });
      else if (online.filter((o) => o.enabled).length === 0)
        gaps.push({
          item: "online_sampling",
          reason: "no enabled production sampling configuration",
        });
      data = {
        online_sampling: online ? sortedBy(online, (o) => o.id) : null,
        plan: "the post-market monitoring plan is a provider document; this section lists the platform's monitoring facts only",
      };
    } else gaps.push({ item: "evals", reason: i.evals.reason });
    b.section("post_market", "Post-market monitoring", ["9"], data, gaps);
  }

  // ---- Known limitations (Annex IV 3)
  if (i.limitations.ok)
    b.section(
      "limitations",
      "Known limitations of the platform",
      ["3"],
      { items: sortedBy(i.limitations.value, (l) => l.id) },
      [],
    );
  else
    b.section("limitations", "Known limitations of the platform", ["3"], null, [
      { item: "limitations", reason: i.limitations.reason },
    ]);

  const gaps = sortedBy(b.gaps, (g) => `${g.section}\u0000${g.item}\u0000${g.reason}`);
  const sections = b.sections;
  return {
    schema: DOC_SCHEMA,
    disclaimer: DISCLAIMER,
    blueprint: {
      name: i.ref.name,
      version: i.ref.version,
      content_hash: bp?.content_hash ?? null,
    },
    sources,
    sections: Object.fromEntries(SECTION_KEYS.map((k) => [k, sections[k] as Section])),
    annex_iv_coverage: coverage(sections),
    gaps,
  };
}

/** Annex IV points -> the sections that carry them. Points the platform never produces are always gaps. */
const POINTS: { point: string; title: string; section: SectionKey | null; note: string | null }[] =
  [
    { point: "1", title: "General description of the AI system", section: "general", note: null },
    {
      point: "2(a)-(c)",
      title: "Methods, design specifications, architecture",
      section: "development",
      note: null,
    },
    {
      point: "2(d)",
      title: "Data requirements and datasheets",
      section: "data_governance",
      note: null,
    },
    { point: "2(e)", title: "Human oversight measures", section: "oversight", note: null },
    {
      point: "2(g)",
      title: "Validation and testing, test logs",
      section: "performance",
      note: null,
    },
    {
      point: "2(h)",
      title: "Cybersecurity measures",
      section: "development",
      note: "see docs/security for the per-service threat models",
    },
    {
      point: "3",
      title: "Monitoring, functioning and control; limitations",
      section: "limitations",
      note: null,
    },
    {
      point: "4",
      title: "Appropriateness of performance metrics",
      section: "performance",
      note: null,
    },
    { point: "5", title: "Risk management system", section: "risk_management", note: null },
    {
      point: "6",
      title: "Relevant changes through the lifecycle",
      section: "lifecycle",
      note: null,
    },
    {
      point: "7",
      title: "Harmonised standards applied",
      section: null,
      note: "not produced by the platform",
    },
    {
      point: "8",
      title: "EU declaration of conformity",
      section: null,
      note: "issued by the provider after its own conformity assessment",
    },
    { point: "9", title: "Post-market monitoring system", section: "post_market", note: null },
  ];

function coverage(sections: Record<string, Section>): CoveragePoint[] {
  return POINTS.map((p) => {
    if (p.section === null)
      return { point: p.point, title: p.title, section: null, status: "gap", note: p.note };
    const s = sections[p.section] as Section;
    const status =
      s.status === "complete" ? "evidenced" : s.status === "partial" ? "partial" : "gap";
    return { point: p.point, title: p.title, section: p.section, status, note: p.note };
  });
}
