import type { AblDocument } from "@axis/abl";
import type { BlueprintRef } from "../types.js";

/**
 * A data source that may be unavailable. The generator NEVER invents data for a missing source and never drops it silently: an
 * unavailable source becomes an explicit gap in the document.
 */
export type Sourced<T> = { ok: true; value: T } | { ok: false; reason: string };

export const sourced = <T>(value: T): Sourced<T> => ({ ok: true, value });
export const missing = <T>(reason: string): Sourced<T> => ({ ok: false, reason });

export interface RegistryProvenance {
  namespace: string;
  signature_key_id: string;
  signed_at: string;
  published_at: string;
  /** The result of re-verifying hash, signature and provenance at generation time. */
  verification: { ok: boolean; checks: string[] };
  provenance_attached: boolean;
}

export interface BlueprintVersionInfo {
  version: string;
  content_hash: string;
  published_at: string | null;
  state: string;
}

export interface BlueprintSnapshot {
  abl: AblDocument;
  content_hash: string;
  origin: "registry" | "tenant";
  /** Present for registry blueprints. A tenant-local blueprint has no registry provenance: the document lists that as a gap. */
  registry: RegistryProvenance | null;
  /** Known versions of the blueprint (lifecycle changes), when the source can list them. */
  versions: BlueprintVersionInfo[] | null;
}

export interface BlueprintSourcePort {
  get(tenantId: string, ref: BlueprintRef): Promise<Sourced<BlueprintSnapshot>>;
}

export interface EvalRunInfo {
  run_id: string;
  /** The suite version the run used (`name@1.0.0`). */
  suite_ref: string;
  /** The suite reference the blueprint DECLARES (`name@^1.0.0`) that this run counts toward. */
  declared_ref: string;
  status: string;
  overall: number | null;
  threshold: number;
  mode: string;
  content_hash: string;
  finished_at: string | null;
}
export interface EvalAttestationInfo {
  run_id: string;
  suite_ref: string;
  overall: number;
  /** The signed attestation verified against the trusted hub keys and is about this blueprint version. */
  verified: boolean;
}
export interface GateVerdictInfo {
  suite_ref: string;
  threshold: number;
  pass: boolean;
  reasons: string[];
}
export interface OnlineSamplingInfo {
  id: string;
  suite_ref: string;
  rate: number;
  enabled: boolean;
}
export interface EvalEvidence {
  runs: EvalRunInfo[];
  attestations: EvalAttestationInfo[];
  gate: GateVerdictInfo[];
  /** Production sampling (post-market monitoring); null when the source cannot say. */
  online: OnlineSamplingInfo[] | null;
}
export interface EvalSourcePort {
  evidence(
    tenantId: string,
    bp: BlueprintRef & { content_hash: string },
    declared: { ref: string; threshold: number }[],
  ): Promise<Sourced<EvalEvidence>>;
}

export interface PolicyPackInfo {
  id: string;
  version: string;
  hash: string | null;
  active_since: string | null;
}
export interface PolicySourcePort {
  activePacks(tenantId: string): Promise<Sourced<PolicyPackInfo[]>>;
}

export interface AuditStats {
  event_count: number;
  head_seq: number;
  head_hash: string | null;
  first_ts: string | null;
  last_ts: string | null;
  by_decision: Record<string, number>;
  by_enforcement_point: Record<string, number>;
  chain: { verified: boolean; checked_through_seq: number; reason: string | null };
}
export interface AuditSourcePort {
  statistics(tenantId: string): Promise<Sourced<AuditStats>>;
}

export interface Limitation {
  id: string;
  title: string;
  detail: string | null;
  evidence: string | null;
}
export interface LimitationsSourcePort {
  list(tenantId: string, bp: BlueprintRef): Promise<Sourced<Limitation[]>>;
}

export interface SourcePorts {
  blueprints: BlueprintSourcePort;
  evals: EvalSourcePort;
  policies: PolicySourcePort;
  audit: AuditSourcePort;
  limitations: LimitationsSourcePort;
}
