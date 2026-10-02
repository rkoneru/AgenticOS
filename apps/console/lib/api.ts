/**
 * The console's one data layer. Every network call the UI makes goes through this module, so the
 * typed SDK can replace it later without touching pages. Types mirror
 * `packages/contracts/openapi/axis-v1.yaml` (frozen /v1). Anything marked ADDITIVE is not in the
 * frozen spec (see docs/NEEDS.md #1300 block) and degrades gracefully when the server says 404/501.
 *
 * The browser talks to the console's own origin (`/api/axis/...`, the BFF route), never to the
 * control plane directly, so cookies stay same-site and CSRF is enforced in one place.
 */

// ---------------------------------------------------------------- types (frozen /v1)

export type ProcessState = "spawn" | "ready" | "running" | "waiting" | "suspended" | "terminated";
export type Signal = "PAUSE" | "RESUME" | "TERM" | "KILL" | "INTERRUPT";
export type Decision = "ALLOW" | "DENY" | "REQUIRE_APPROVAL" | "ALLOW_WITH_REDACTION";
export type ApprovalStatus = "pending" | "approved" | "rejected" | "expired" | "escalated";
export type Meter =
  | "tokens"
  | "runtime_seconds"
  | "tool_executions"
  | "voice_minutes"
  | "storage_gb_hours"
  | "marketplace_installs";

export interface Page<T> {
  items: T[];
  next_cursor?: string | null;
}

export interface BlueprintVersion {
  name: string;
  version: string;
  risk_level: "minimal" | "limited" | "high";
  content_hash?: string;
  signature?: string | null;
  created_at: string;
  abl: Record<string, unknown>;
}

export interface Run {
  id: string;
  init_pid?: string;
  blueprint: { name: string; version: string };
  state: ProcessState;
  exit_reason?: string | null;
  trace_id?: string;
  created_at: string;
  finished_at?: string | null;
}

export interface RunEvent {
  sequence: number;
  type: string;
  pid: string;
  at: string;
  audit_event_id?: string;
  data?: Record<string, unknown>;
}

export interface GateDecision {
  decision: Decision;
  policy_version: string;
  reason?: string;
  matched_rule_ids?: string[];
  redact_fields?: string[];
}

export interface Approval {
  id: string;
  status: ApprovalStatus;
  run_id: string;
  pid?: string;
  action?: string;
  roles?: string[];
  requested_at: string;
  sla_deadline: string;
  decided_by?: string | null;
  decided_at?: string | null;
  comment?: string | null;
  /** ADDITIVE: member id of whoever the approval's run acts for; used to disable self-approval in the UI. */
  requested_by?: string | null;
  /** ADDITIVE: hash of the canonical tool arguments (the arguments themselves are never shown). */
  args_hash?: string;
  /** ADDITIVE: the policy reason that produced REQUIRE_APPROVAL. */
  policy_reason?: string;
  matched_rule_ids?: string[];
}

export interface PolicyPack {
  name: string;
  version: string;
  content_hash?: string;
  created_at: string;
  /** ADDITIVE: the policy document, so activation can show a diff against the active version. */
  policy?: Record<string, unknown>;
  /** ADDITIVE */
  active?: boolean;
  /** ADDITIVE: admin activation id (`POST /admin/v1/policies/{versionId}/activate`). */
  version_id?: string;
}

export interface AuditEvent {
  schema_version: 1;
  id: string;
  tenant_id: string;
  seq: number;
  ts: string;
  trace_id: string;
  actor: { type: "human" | "agent" | "system"; id: string; pid?: string };
  blueprint: { name: string; version: string };
  policy_version: string;
  enforcement_point: string;
  action: string;
  decision: Decision;
  reason?: string;
  inputs_hash: string;
  outputs_hash: string;
  prev_hash: string;
  hash: string;
}

export interface AuditVerdict {
  ok: boolean;
  verified: number;
  broken_at_seq?: number;
  reason?: string;
}

export interface UsageRow {
  meter: Meter;
  quantity: number;
  unit: string;
  group?: string;
}

export interface KillSwitch {
  scope: "global" | "tenant" | "agent" | "tool";
  target?: string | null;
  engaged: boolean;
  reason?: string | null;
  updated_at: string;
}

export interface EvalRun {
  id: string;
  suite: string;
  status: "queued" | "running" | "passed" | "failed" | "errored";
  score?: number | null;
  threshold?: number | null;
}

export interface ProblemBody {
  type?: string;
  title: string;
  status: number;
  code?: string;
  detail?: string;
  trace_id?: string;
  errors?: Array<{ path: string; keyword?: string; message: string }>;
}

// ---------------------------------------------------------------- types (ADDITIVE)

/** AGIL explanation. The console renders exactly these fields and never composes explanation text itself. */
export interface Explanation {
  summary: string;
  steps: string[];
  decision_refs: Array<{ audit_event_id: string; seq?: number }>;
  remediation: string[];
}

export interface AblDiagnostic {
  line: number;
  column: number;
  severity: "error" | "warning";
  message: string;
  code: string;
  path: string;
}

export interface AblCheckResult {
  ok: boolean;
  diagnostics: AblDiagnostic[];
  doc?: Record<string, unknown>;
  riskLevel?: string;
  name?: string;
  version?: string;
}

export type Role = "owner" | "admin" | "builder" | "operator" | "auditor" | "billing" | "viewer";

export interface Session {
  member: { id: string; email: string; role: Role; display_name?: string };
  tenant: { id: string; name: string; region: string };
}

export interface Member {
  id: string;
  email: string;
  role: Role;
  status: "active" | "deprovisioned";
  display_name?: string;
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  environment: "dev" | "staging" | "prod";
  created_at: string;
  expires_at?: string | null;
  revoked_at?: string | null;
  last_used_at?: string | null;
  /** Present exactly once, in the create/rotate response. */
  secret?: string;
}

export interface ModelKey {
  provider: string;
  label: string;
  updated_at?: string;
}

export interface Budget {
  id: string;
  scope: "tenant" | "agent" | "run";
  target?: string;
  metric: "tokens" | "cost_usd" | "runtime_seconds" | "tool_calls";
  period: "run" | "day" | "month";
  soft?: number;
  hard?: number;
}

export interface TenantInfo {
  id: string;
  name: string;
  region: string;
  slug?: string;
}

export interface SsoSettings {
  connection_type?: "saml" | "oidc";
  organization_id?: string;
  jit_enabled?: boolean;
  jit_default_role?: Role;
}

export interface Directory {
  id: string;
  name: string;
  status: "active" | "revoked";
  default_role: Role;
  token_prefix: string;
}

export interface Listing {
  id: string;
  name: string;
  publisher: string;
  version: string;
  summary: string;
  installed?: boolean;
}

export interface PermissionSet {
  tools: string[];
  data_classes: string[];
  egress_hosts: string[];
  max_risk_level: "minimal" | "limited" | "high";
}

export interface ListingDetail extends Listing {
  /** Permissions the listing requests now. */
  permissions: PermissionSet;
  /** Permissions the installed version already holds (absent when not installed). */
  installed_permissions?: PermissionSet | null;
}

// ---------------------------------------------------------------- errors

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly detail: string | undefined;
  readonly traceId: string | undefined;
  readonly errors: NonNullable<ProblemBody["errors"]>;

  constructor(status: number, body: Partial<ProblemBody> | undefined, fallback: string) {
    super(body?.title ?? fallback);
    this.name = "ApiError";
    this.status = status;
    this.code = body?.code ?? defaultCode(status);
    this.detail = body?.detail;
    this.traceId = body?.trace_id;
    this.errors = body?.errors ?? [];
  }

  /** The endpoint (or the whole feature) is not served by this deployment. */
  get notAvailable(): boolean {
    return this.status === 404 || this.status === 405 || this.status === 501;
  }
}

function defaultCode(status: number): string {
  if (status === 401) return "unauthenticated";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status === 409) return "conflict";
  if (status === 422) return "validation_failed";
  if (status === 429) return "rate_limited";
  return "internal";
}

// ---------------------------------------------------------------- client

export const CSRF_COOKIE = "__Host-axis_csrf";
export const CSRF_HEADER = "x-axis-csrf";

export interface ClientOptions {
  /** Same-origin BFF prefix. */
  base?: string;
  fetchImpl?: typeof fetch;
  /** Returns the CSRF token for unsafe methods (default: reads the readable double-submit cookie). */
  csrf?: () => string | undefined;
  idempotencyKey?: () => string;
  /** Called on 401 so the shell can send the user to sign-in. */
  onUnauthenticated?: () => void;
}

export function readCookie(name: string, source?: string): string | undefined {
  const jar = source ?? (typeof document === "undefined" ? "" : document.cookie);
  for (const part of jar.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name)
      return decodeURIComponent(part.slice(i + 1).trim());
  }
  return undefined;
}

export function newIdempotencyKey(): string {
  return `console-${globalThis.crypto.randomUUID()}`;
}

type Query = Record<string, string | number | boolean | undefined | null>;

export function withQuery(path: string, query?: Query): string {
  if (!query) return path;
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(query))
    if (v !== undefined && v !== null && v !== "") sp.set(k, String(v));
  const s = sp.toString();
  return s ? `${path}?${s}` : path;
}

export interface Api {
  // identity
  session(): Promise<Session>;
  logout(): Promise<void>;
  // blueprints
  /** Live ABL check (console server route running the real compiler/linter); not a control-plane endpoint. */
  validateAbl(text: string, signal?: AbortSignal): Promise<AblCheckResult>;
  listBlueprints(q?: { limit?: number; cursor?: string }): Promise<Page<BlueprintVersion>>;
  getBlueprintVersion(name: string, version: string): Promise<BlueprintVersion>;
  publishBlueprint(abl: Record<string, unknown>): Promise<BlueprintVersion>;
  // runs
  listRuns(q?: {
    limit?: number;
    cursor?: string;
    state?: ProcessState;
    blueprint?: string;
  }): Promise<Page<Run>>;
  getRun(id: string): Promise<Run>;
  startRun(
    blueprint: { name: string; version: string },
    input?: Record<string, unknown>,
  ): Promise<Run>;
  signalRun(
    id: string,
    signal: Signal,
    reason?: string,
  ): Promise<{ pid: string; state: ProcessState }>;
  listRunEvents(
    id: string,
    q?: { after_sequence?: number; limit?: number },
  ): Promise<Page<RunEvent>>;
  streamRunEvents(
    id: string,
    afterSequence: number,
    signal: AbortSignal,
  ): Promise<ReadableStream<Uint8Array>>;
  // approvals
  listApprovals(q?: {
    status?: ApprovalStatus;
    limit?: number;
    cursor?: string;
  }): Promise<Page<Approval>>;
  decideApproval(id: string, decision: "approve" | "reject", comment?: string): Promise<Approval>;
  // policies
  listPolicyPacks(): Promise<Page<PolicyPack>>;
  publishPolicyPack(policy: Record<string, unknown>): Promise<PolicyPack>;
  testPolicy(
    policy: Record<string, unknown>,
    request: { enforcement_point: string; action?: string; context: Record<string, unknown> },
  ): Promise<GateDecision>;
  activatePolicy(versionId: string): Promise<unknown>;
  // audit
  listAuditEvents(q?: {
    limit?: number;
    cursor?: string;
    trace_id?: string;
    decision?: Decision;
    from_seq?: number;
  }): Promise<Page<AuditEvent>>;
  verifyAudit(range?: { from_seq?: number; to_seq?: number }): Promise<AuditVerdict>;
  // kill switches
  listKillSwitches(): Promise<{ items: KillSwitch[] }>;
  setKillSwitch(req: {
    scope: "tenant" | "agent" | "tool";
    target?: string;
    engaged: boolean;
    reason?: string;
  }): Promise<KillSwitch>;
  // usage
  getUsage(q: {
    from: string;
    to: string;
    group_by?: "meter" | "model" | "blueprint" | "day";
  }): Promise<{ items: UsageRow[] }>;
  // evals
  listEvalRuns(): Promise<Page<EvalRun>>;
  startEvalRun(suite: string, blueprint: { name: string; version: string }): Promise<EvalRun>;
  // AGIL (ADDITIVE)
  explainRun(id: string): Promise<Explanation>;
  explainApproval(id: string): Promise<Explanation>;
  explainAuditEvent(id: string): Promise<Explanation>;
  // admin
  tenant(): Promise<TenantInfo>;
  listMembers(): Promise<Page<Member>>;
  inviteMember(email: string, role: Role): Promise<Member>;
  updateMemberRole(id: string, role: Role): Promise<Member>;
  removeMember(id: string): Promise<void>;
  listApiKeys(): Promise<Page<ApiKey>>;
  createApiKey(input: {
    name: string;
    scopes: string[];
    environment?: string;
    expires_in_days?: number;
  }): Promise<ApiKey>;
  rotateApiKey(id: string): Promise<ApiKey>;
  revokeApiKey(id: string): Promise<unknown>;
  listModelKeys(): Promise<{ items: ModelKey[] }>;
  putModelKey(provider: string, label: string, value: string): Promise<ModelKey>;
  deleteModelKey(provider: string, label: string): Promise<void>;
  listBudgets(): Promise<{ items: Budget[] }>;
  putBudgets(items: Array<Omit<Budget, "id">>): Promise<{ items: Budget[] }>;
  deleteBudget(id: string): Promise<void>;
  getSso(): Promise<SsoSettings>;
  putSso(s: SsoSettings): Promise<SsoSettings>;
  listDirectories(): Promise<{ items: Directory[] }>;
  // marketplace (ADDITIVE, feature-flagged)
  listListings(q?: { q?: string }): Promise<Page<Listing>>;
  getListing(id: string): Promise<ListingDetail>;
  installListing(id: string, acceptedPermissions: PermissionSet): Promise<{ installed: true }>;
}

export function createApi(opts: ClientOptions = {}): Api {
  const base = opts.base ?? "/api/axis";
  const doFetch: typeof fetch = opts.fetchImpl ?? ((i, init) => fetch(i, init));
  const csrf = opts.csrf ?? (() => readCookie(CSRF_COOKIE));
  const idem = opts.idempotencyKey ?? newIdempotencyKey;

  async function raw(
    method: string,
    path: string,
    init: {
      body?: unknown;
      query?: Query;
      idempotent?: boolean;
      accept?: string;
      signal?: AbortSignal;
      absolute?: boolean;
    } = {},
  ): Promise<Response> {
    const headers: Record<string, string> = { accept: init.accept ?? "application/json" };
    if (init.body !== undefined) headers["content-type"] = "application/json";
    if (method !== "GET" && method !== "HEAD") {
      const t = csrf();
      if (t) headers[CSRF_HEADER] = t;
    }
    if (init.idempotent) headers["idempotency-key"] = idem();
    const res = await doFetch(`${init.absolute ? "" : base}${withQuery(path, init.query)}`, {
      method,
      headers,
      credentials: "same-origin",
      cache: "no-store",
      ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
      ...(init.signal ? { signal: init.signal } : {}),
    });
    if (!res.ok) {
      let body: Partial<ProblemBody> | undefined;
      try {
        body = (await res.json()) as Partial<ProblemBody>;
      } catch {
        body = undefined;
      }
      if (res.status === 401) opts.onUnauthenticated?.();
      throw new ApiError(res.status, body, `Request failed (${res.status})`);
    }
    return res;
  }

  async function json<T>(
    method: string,
    path: string,
    init?: Parameters<typeof raw>[2],
  ): Promise<T> {
    const res = await raw(method, path, init);
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  }
  const enc = encodeURIComponent;

  return {
    session: () => json("GET", "/auth/me"),
    validateAbl: (text, signal) =>
      json("POST", "/api/abl/validate", {
        body: { text },
        absolute: true,
        ...(signal ? { signal } : {}),
      }),
    logout: () => json("POST", "/auth/logout"),
    listBlueprints: (q) => json("GET", "/v1/blueprints", { query: q ?? {} }),
    getBlueprintVersion: (n, v) => json("GET", `/v1/blueprints/${enc(n)}/versions/${enc(v)}`),
    publishBlueprint: (abl) => json("POST", "/v1/blueprints", { body: { abl }, idempotent: true }),
    listRuns: (q) => json("GET", "/v1/runs", { query: q ?? {} }),
    getRun: (id) => json("GET", `/v1/runs/${enc(id)}`),
    startRun: (blueprint, input) =>
      json("POST", "/v1/runs", {
        body: { blueprint, ...(input ? { input } : {}) },
        idempotent: true,
      }),
    signalRun: (id, signal, reason) =>
      json("POST", `/v1/runs/${enc(id)}/signals`, {
        body: { signal, ...(reason ? { reason } : {}) },
        idempotent: true,
      }),
    listRunEvents: (id, q) => json("GET", `/v1/runs/${enc(id)}/events`, { query: q ?? {} }),
    async streamRunEvents(id, afterSequence, signal) {
      const res = await raw("GET", `/v1/runs/${enc(id)}/events`, {
        query: { after_sequence: afterSequence },
        accept: "text/event-stream",
        signal,
      });
      if (!res.body)
        throw new ApiError(502, { title: "No stream body", status: 502 }, "No stream body");
      return res.body;
    },
    listApprovals: (q) => json("GET", "/v1/approvals", { query: q ?? {} }),
    decideApproval: (id, decision, comment) =>
      json("POST", `/v1/approvals/${enc(id)}/decision`, {
        body: { decision, ...(comment ? { comment } : {}) },
        idempotent: true,
      }),
    listPolicyPacks: () => json("GET", "/v1/policies"),
    publishPolicyPack: (policy) => json("POST", "/v1/policies", { body: { policy } }),
    // The path contains a colon (`/policies:test`); it is part of the contract, not an escape.
    testPolicy: (policy, request) =>
      json("POST", "/v1/policies:test", { body: { policy, request } }),
    activatePolicy: (versionId) => json("POST", `/admin/v1/policies/${enc(versionId)}/activate`),
    listAuditEvents: (q) => json("GET", "/v1/audit/events", { query: q ?? {} }),
    verifyAudit: (range) => json("POST", "/v1/audit/verify", { body: range ?? {} }),
    listKillSwitches: () => json("GET", "/v1/kill-switches"),
    setKillSwitch: (req) => json("PUT", "/v1/kill-switches", { body: req }),
    getUsage: (q) => json("GET", "/v1/usage", { query: q }),
    listEvalRuns: () => json("GET", "/v1/evals/runs"),
    startEvalRun: (suite, blueprint) =>
      json("POST", "/v1/evals/runs", { body: { suite, blueprint }, idempotent: true }),
    explainRun: (id) => json("GET", `/v1/runs/${enc(id)}/explanation`),
    explainApproval: (id) => json("GET", `/v1/approvals/${enc(id)}/explanation`),
    explainAuditEvent: (id) => json("GET", `/v1/audit/events/${enc(id)}/explanation`),
    tenant: () => json("GET", "/admin/v1/tenant"),
    listMembers: () => json("GET", "/admin/v1/members"),
    inviteMember: (email, role) => json("POST", "/admin/v1/members", { body: { email, role } }),
    updateMemberRole: (id, role) =>
      json("PATCH", `/admin/v1/members/${enc(id)}`, { body: { role } }),
    removeMember: (id) => json("DELETE", `/admin/v1/members/${enc(id)}`),
    listApiKeys: () => json("GET", "/admin/v1/api-keys"),
    createApiKey: (input) => json("POST", "/admin/v1/api-keys", { body: input }),
    rotateApiKey: (id) => json("POST", `/admin/v1/api-keys/${enc(id)}/rotate`),
    revokeApiKey: (id) => json("DELETE", `/admin/v1/api-keys/${enc(id)}`),
    listModelKeys: () => json("GET", "/admin/v1/model-keys"),
    putModelKey: (p, l, value) =>
      json("PUT", `/admin/v1/model-keys/${enc(p)}/${enc(l)}`, { body: { value } }),
    deleteModelKey: (p, l) => json("DELETE", `/admin/v1/model-keys/${enc(p)}/${enc(l)}`),
    listBudgets: () => json("GET", "/admin/v1/budgets"),
    putBudgets: (items) => json("PUT", "/admin/v1/budgets", { body: { items } }),
    deleteBudget: (id) => json("DELETE", `/admin/v1/budgets/${enc(id)}`),
    getSso: () => json("GET", "/admin/v1/sso/connection"),
    putSso: (s) => json("PUT", "/admin/v1/sso/connection", { body: s }),
    listDirectories: () => json("GET", "/admin/v1/directories"),
    listListings: (q) => json("GET", "/v1/marketplace/listings", { query: q ?? {} }),
    getListing: (id) => json("GET", `/v1/marketplace/listings/${enc(id)}`),
    installListing: (id, accepted) =>
      json("POST", `/v1/marketplace/listings/${enc(id)}/install`, {
        body: { accepted_permissions: accepted },
        idempotent: true,
      }),
  };
}

/** Browser singleton; pages import this. Tests inject their own via `createApi({ fetchImpl })`. */
export const api: Api = createApi({
  onUnauthenticated: () => {
    if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
      window.location.assign(`/login?return_to=${encodeURIComponent(window.location.pathname)}`);
    }
  },
});
