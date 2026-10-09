import type { AuditEvent, ChainVerdict } from "@axis/contracts";
import type { Principal, Role } from "@axis/control-plane";

export type { Principal, Role };

/** The OpenAPI shapes the ports return (field names are the wire names). */
export interface BlueprintVersionDto {
  name: string;
  version: string;
  risk_level: "minimal" | "limited" | "high";
  content_hash: string;
  signature: string | null;
  created_at: string;
  abl: unknown;
}
export interface RunDto {
  id: string;
  init_pid?: string;
  blueprint: { name: string; version: string };
  state: string;
  exit_reason?: string | null;
  trace_id?: string;
  created_at: string;
  finished_at?: string | null;
}
export interface RunEventDto {
  sequence: number;
  type: string;
  pid: string;
  at: string;
  audit_event_id?: string;
  data?: Record<string, unknown>;
}
export interface ApprovalDto {
  id: string;
  status: "pending" | "approved" | "rejected" | "expired" | "escalated";
  run_id: string;
  pid?: string;
  action?: string;
  roles?: string[];
  requested_at: string;
  sla_deadline: string;
  decided_by?: string | null;
  decided_at?: string | null;
  comment?: string | null;
}
export interface PolicyPackDto {
  name: string;
  version: string;
  content_hash?: string;
  created_at: string;
  version_id?: string;
  active?: boolean;
}
export interface IdentityDto {
  tenant: { id: string; name?: string; region?: string };
  member: {
    id: string;
    email?: string;
    display_name?: string;
    role:
      | "owner"
      | "admin"
      | "builder"
      | "operator"
      | "auditor"
      | "billing"
      | "viewer"
      | "privacy_officer";
  };
  credential: { kind: "session" | "api_key"; scopes?: string[] };
}
export interface RegistryNamespaceDto {
  namespace: string;
  public?: boolean;
  created_at?: string;
}
export interface RegistryKeyDto {
  key_id: string;
  public_key: string;
  valid_from: string;
  valid_until?: string | null;
  revoked_at?: string | null;
  revoke_reason?: string | null;
}
export interface RegistryVersionDto {
  namespace: string;
  name: string;
  version: string;
  content_hash: string;
  risk_level: "minimal" | "limited" | "high";
  signature: { key_id: string; signed_at: string; sig: string };
  published_at: string;
  published_by?: string;
  state?: "active" | "deprecated" | "yanked";
  state_reason?: string | null;
}
export interface RegistryEvalAttestationDto {
  run_id: string;
  suite_ref: string;
  overall: number;
  content_hash: string;
  attached_at: string;
  verified: boolean;
  predicate: Record<string, unknown> | null;
  envelope: { payloadType: string; payload: string; signatures: { keyid: string; sig: string }[] };
}

export interface ResolvedBlueprintDto extends RegistryVersionDto {
  abl: unknown;
  provenance: unknown;
  verification: {
    key_id: string;
    builder?: string;
    source_ref?: string;
    compiler_version?: string;
  };
}
export interface CapabilityDto {
  key: string;
  level: number;
}
export interface MarketplaceListingDto {
  namespace: string;
  name: string;
  title: string;
  summary: string;
  categories: string[];
  publisher?: string;
  latest: {
    version: string;
    content_hash: string;
    risk_level: string;
    max_severity: string;
  } | null;
  versions: string[];
}
export interface InstallPreviewDto {
  namespace: string;
  name: string;
  version: string;
  content_hash: string;
  risk_level: string;
  max_severity: string;
  findings: { id: string; severity: string; path: string; message: string }[];
  capabilities: CapabilityDto[];
  diff: {
    added: {
      key: string;
      change: "new" | "raised";
      level: number;
      previous_level: number | null;
    }[];
    removed: { key: string; level: number; new_level: number | null }[];
    widening: boolean;
  };
  consent_digest: string;
}
export interface MarketplaceInstallDto {
  id: string;
  namespace: string;
  name: string;
  version: string;
  content_hash: string;
  state: "active" | "flagged" | "uninstalled";
  granted: CapabilityDto[];
  consented_by?: string;
  consented_at?: string;
  flag_reason?: string | null;
}
export interface KillSwitchDto {
  scope: "global" | "tenant" | "agent" | "tool";
  target?: string | null;
  engaged: boolean;
  reason?: string | null;
  updated_at: string;
}
export interface GateDecisionDto {
  decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL" | "ALLOW_WITH_REDACTION";
  policy_version: string;
  reason?: string;
  matched_rule_ids?: string[];
  redact_fields?: string[];
}
export interface UsageRowDto {
  meter: string;
  quantity: number;
  unit: string;
  group?: string;
}
export interface Page<T> {
  items: T[];
  /** Opaque position token the PORT understands; the gateway wraps it into a signed cursor. */
  next?: string | undefined;
}

/** Thrown by a port for "this tenant has no such thing"; the gateway turns it into 404 (same as a foreign id). */
export class PortNotFound extends Error {}
/** Thrown by a port for a state conflict (duplicate version, illegal signal, already decided). */
export class PortConflict extends Error {}
/** Thrown by a port for a refusal the caller can fix (bad input the schema cannot see). */
export class PortInvalid extends Error {
  constructor(
    message: string,
    readonly issues: { path: string; message: string; keyword?: string }[] = [],
  ) {
    super(message);
  }
}
/** Thrown by a port when a dependency is down: the gateway answers 503 and the caller retries. */
export class PortUnavailable extends Error {}
/** Thrown by a port when the operation is not permitted for this caller for reasons the role matrix cannot see. */
export class PortForbidden extends Error {}

// ---- authentication ------------------------------------------------------------------------------------------------

export interface Authenticator {
  /** The principal for a presented credential, or undefined. Throws only when a dependency is down (-> 503). */
  authenticate(c: { bearer?: string; apiKey?: string }): Promise<Principal | undefined>;
}

// ---- authorization -------------------------------------------------------------------------------------------------

export interface AuthzDecisionLike {
  allowed: boolean;
  reason: string;
  policyVersion: string;
}
export interface Authz {
  decide(p: Principal, action: string): Promise<AuthzDecisionLike>;
}

/** Audit of API mutations and denials (the control plane's `AdminAudit`). Throws when the chain cannot be appended. */
export interface ApiAudit {
  record(e: {
    tenantId: string;
    actor: { type: "human" | "system"; id: string };
    action: string;
    decision: "ALLOW" | "DENY";
    policyVersion: string;
    reason: string;
    inputs: unknown;
    outputs: unknown;
    traceId: string;
  }): Promise<unknown>;
}

// ---- domain ports ----------------------------------------------------------------------------------------------------

export interface BlueprintStore {
  /** Immutable once published; duplicate name@version throws PortConflict. */
  publish(tenantId: string, v: BlueprintVersionDto): Promise<BlueprintVersionDto>;
  list(tenantId: string, q: { limit: number; after?: string }): Promise<Page<BlueprintVersionDto>>;
  get(tenantId: string, name: string, version: string): Promise<BlueprintVersionDto | undefined>;
}

export interface StartRun {
  tenantId: string;
  runId: string;
  traceId: string;
  blueprint: { name: string; version: string };
  /** The compiled RuntimeManifest (ABL -> manifest happens in the gateway with the TS compiler). */
  manifest: unknown;
  input: Record<string, unknown>;
  principal: { memberId: string; role: string };
}

export interface RunsPort {
  start(r: StartRun): Promise<RunDto>;
  get(tenantId: string, runId: string): Promise<RunDto | undefined>;
  list(
    tenantId: string,
    q: { limit: number; after?: string; state?: string; blueprint?: string },
  ): Promise<Page<RunDto>>;
  signal(
    tenantId: string,
    runId: string,
    s: { pid?: string; signal: string; reason?: string },
  ): Promise<{ pid: string; state: string }>;
  events(
    tenantId: string,
    runId: string,
    q: { afterSequence: number; limit: number },
  ): Promise<RunEventDto[] | undefined>;
  /** Live feed after `afterSequence`; ends when the run is terminal and drained, or when `signal` aborts. */
  stream(
    tenantId: string,
    runId: string,
    afterSequence: number,
    signal: AbortSignal,
  ): AsyncIterable<RunEventDto>;
}

export interface ApprovalsPort {
  get(p: Principal, id: string): Promise<ApprovalDto>;
  list(
    p: Principal,
    q: { status?: ApprovalDto["status"]; limit: number; after?: string },
  ): Promise<Page<ApprovalDto>>;
  decide(
    p: Principal,
    id: string,
    d: { decision: "approve" | "reject"; comment?: string },
  ): Promise<ApprovalDto>;
}

export interface PolicyPort {
  list(p: Principal, q: { limit: number; after?: string }): Promise<Page<PolicyPackDto>>;
  publish(p: Principal, doc: unknown): Promise<PolicyPackDto>;
  /** Makes a published version the tenant's active version of its pack (the kernel enforces it from then on). */
  activate(p: Principal, versionId: string): Promise<PolicyPackDto>;
  test(
    p: Principal,
    q: {
      policy: unknown;
      request: { enforcement_point: string; action?: string; context: Record<string, unknown> };
    },
  ): Promise<GateDecisionDto>;
}

export interface AuditPort {
  list(
    tenantId: string,
    q: { fromSeq?: number; traceId?: string; limit: number },
  ): Promise<AuditEvent[]>;
  /** Highest seq in the tenant's chain (0 when empty). */
  head(tenantId: string): Promise<number>;
  verify(tenantId: string, range: { fromSeq?: number; toSeq?: number }): Promise<ChainVerdict>;
}

export interface KillSwitchPort {
  list(tenantId: string): Promise<KillSwitchDto[]>;
  set(
    p: Principal,
    r: { scope: "tenant" | "agent" | "tool"; target?: string; engaged: boolean; reason?: string },
  ): Promise<KillSwitchDto>;
}

export interface UsagePort {
  query(
    tenantId: string,
    q: { from: Date; to: Date; groupBy?: "meter" | "model" | "blueprint" | "day" },
  ): Promise<UsageRowDto[]>;
}

export interface IdentityPort {
  me(p: Principal): Promise<IdentityDto>;
}

export interface RegistryPort {
  listNamespaces(p: Principal): Promise<RegistryNamespaceDto[]>;
  claim(p: Principal, namespace: string): Promise<RegistryNamespaceDto>;
  listKeys(p: Principal, namespace: string): Promise<RegistryKeyDto[]>;
  addKey(p: Principal, namespace: string, publicKey: string): Promise<RegistryKeyDto>;
  publish(
    p: Principal,
    namespace: string,
    input: {
      abl: unknown;
      signature: { key_id: string; signed_at: string; sig: string };
      provenance: unknown;
    },
  ): Promise<RegistryVersionDto>;
  listVersions(p: Principal, namespace: string, name: string): Promise<RegistryVersionDto[]>;
  yank(
    p: Principal,
    namespace: string,
    name: string,
    version: string,
    reason: string,
  ): Promise<void>;
  /** Resolves AND verifies (hash, signature, provenance); a failure is a PortInvalid carrying the failed check codes. */
  resolve(p: Principal, ref: string): Promise<ResolvedBlueprintDto>;
  /** The eval-result attestations of one version, each re-verified on this read. Unknown or invisible version: PortNotFound. */
  evalAttestations(
    p: Principal,
    namespace: string,
    name: string,
    version: string,
  ): Promise<RegistryEvalAttestationDto[]>;
}

export interface MarketplacePort {
  listings(q: { text?: string; category?: string }): Promise<MarketplaceListingDto[]>;
  listing(namespace: string, name: string): Promise<MarketplaceListingDto>;
  preview(
    p: Principal,
    q: { namespace: string; name: string; range: string },
  ): Promise<InstallPreviewDto>;
  install(
    p: Principal,
    q: {
      namespace: string;
      name: string;
      version: string;
      content_hash: string;
      consent_digest: string;
    },
  ): Promise<MarketplaceInstallDto>;
  installs(p: Principal): Promise<MarketplaceInstallDto[]>;
  uninstall(p: Principal, namespace: string, name: string): Promise<void>;
}

export interface ExplainPort {
  explainRun(tenantId: string, q: { traceId: string; runEvents: RunEventDto[] }): Promise<unknown>;
  explainEvent(tenantId: string, seq: number): Promise<unknown | undefined>;
}

// ---- cross-cutting -----------------------------------------------------------------------------------------------------

export interface IdempotencyEntry {
  fingerprint: string;
  state: "in_progress" | "done";
  response?: StoredResponse;
  expiresAt: number;
}
export interface StoredResponse {
  status: number;
  body: unknown;
  headers: Record<string, string>;
}
export type IdemBegin =
  | { kind: "new" }
  | { kind: "replay"; response: StoredResponse }
  | { kind: "mismatch" }
  | { kind: "in_progress" };

export interface IdempotencyStore {
  /** Atomically: absent -> reserve (`new`); present with another fingerprint -> `mismatch`; in flight -> `in_progress`; done -> `replay`. */
  begin(scope: string, key: string, fingerprint: string, ttlMs: number): Promise<IdemBegin>;
  complete(scope: string, key: string, response: StoredResponse): Promise<void>;
  /** Releases a reservation (the request failed in a way that must be retryable). */
  abort(scope: string, key: string): Promise<void>;
}

export interface RateLimiter {
  /** Takes `cost` tokens from the bucket of `key`. */
  take(
    key: string,
    cost: number,
  ): { ok: boolean; limit: number; remaining: number; retryAfterSec: number };
}

// ---- evals --------------------------------------------------------------------------------------------------------------

/** The Eval Hub as the tenant side of the public API sees it (wire shapes = OpenAPI 1.3.0; the tenant and role come from the principal). */
export interface EvalsPort {
  start(
    p: Principal,
    q: {
      suite: string;
      mode?: "ci" | "manual";
      blueprint: { namespace?: string; name: string; version: string; content_hash: string };
    },
  ): Promise<EvalRunDto>;
  listRuns(
    p: Principal,
    q: {
      limit: number;
      cursor?: string;
      suite?: string;
      blueprint?: string;
      content_hash?: string;
      status?: string;
    },
  ): Promise<{ items: EvalRunDto[]; next?: string }>;
  getRun(p: Principal, id: string): Promise<EvalRunDetailDto>;
  comparison(p: Principal, id: string): Promise<Record<string, unknown> | undefined>;
  gate(
    p: Principal,
    body: { blueprint: unknown; suites?: unknown },
  ): Promise<Record<string, unknown>>;
  listDatasets(p: Principal, name?: string): Promise<Record<string, unknown>[]>;
  createDataset(p: Principal, body: Record<string, unknown>): Promise<Record<string, unknown>>;
  getDataset(p: Principal, name: string, version: string): Promise<Record<string, unknown>>;
  listSuites(p: Principal): Promise<Record<string, unknown>[]>;
  createSuite(p: Principal, body: Record<string, unknown>): Promise<Record<string, unknown>>;
  getSuite(p: Principal, ref: string): Promise<Record<string, unknown>>;
  listBaselines(p: Principal, blueprint: string, suite: string): Promise<Record<string, unknown>[]>;
  setBaseline(p: Principal, runId: string): Promise<Record<string, unknown>>;
  listTasks(
    p: Principal,
    q: { state?: string; run_id?: string },
  ): Promise<Record<string, unknown>[]>;
  claimTask(p: Principal, id: string): Promise<Record<string, unknown>>;
  gradeTask(
    p: Principal,
    id: string,
    body: { score: number; comment: string },
  ): Promise<Record<string, unknown>>;
  skipTask(p: Principal, id: string, reason: string): Promise<Record<string, unknown>>;
  listSampling(p: Principal): Promise<Record<string, unknown>[]>;
  putSampling(
    p: Principal,
    id: string,
    body: Record<string, unknown>,
  ): Promise<Record<string, unknown>>;
  onlineSummary(
    p: Principal,
    q: { blueprint?: string; suite?: string },
  ): Promise<Record<string, unknown>[]>;
  listRunners(p: Principal): Promise<Record<string, unknown>[]>;
  registerRunner(p: Principal, id: string, description?: string): Promise<Record<string, unknown>>;
  revokeRunner(p: Principal, id: string): Promise<Record<string, unknown>>;
}
export type EvalRunDto = { id: string; suite: string; status: string } & Record<string, unknown>;
export type EvalRunDetailDto = EvalRunDto & { case_results: unknown[] };

// ---- compliance -----------------------------------------------------------------------------------------------------------

type Rec = Record<string, unknown>;

/**
 * AI system inventory, AI impact assessments and sealed technical documentation (wire shapes = OpenAPI 1.5.0). The tenant, the member
 * and the role come from the principal and nothing else.
 */
export interface CompliancePort {
  listSystems(p: Principal, q: { risk_level?: string; lifecycle_stage?: string }): Promise<Rec[]>;
  createSystem(p: Principal, body: Rec): Promise<Rec>;
  getSystem(p: Principal, id: string, version?: number): Promise<Rec>;
  updateSystem(p: Principal, id: string, expectedVersion: number, body: Rec): Promise<Rec>;
  listAssessments(
    p: Principal,
    q: { system_id?: string; state?: string; overdue?: boolean },
  ): Promise<Rec[]>;
  createAssessment(p: Principal, body: Rec): Promise<Rec>;
  getAssessment(p: Principal, id: string, version?: number): Promise<Rec>;
  reviseAssessment(p: Principal, id: string, expectedVersion: number, body: Rec): Promise<Rec>;
  submitAssessment(p: Principal, id: string, expectedVersion: number): Promise<Rec>;
  withdrawAssessment(p: Principal, id: string, expectedVersion: number): Promise<Rec>;
  reviewAssessment(
    p: Principal,
    id: string,
    r: { expected_version: number; decision: "approve" | "reject"; comment?: string },
  ): Promise<Rec>;
  generateDocument(
    p: Principal,
    blueprint: { name: string; version: string },
  ): Promise<{ document: Rec; created: boolean }>;
  listDocuments(
    p: Principal,
    q: { blueprint_name?: string; blueprint_version?: string },
  ): Promise<Rec[]>;
  getDocument(p: Principal, id: string): Promise<{ document: Rec; verification: Rec }>;
}
