import { randomBytes, randomUUID } from "node:crypto";
import { HmacSigner, ApprovalService, MemoryApprovalStore } from "@axis/approvals";
import { MemoryAuditLog } from "@axis/audit";
import { HmacSealSigner, MemoryUsageLedger } from "@axis/billing";
import {
  Authorizer,
  FakeDnsResolver,
  FakeIdentityProvider,
  LocalKms,
  MemoryControlPlaneStore,
  compileValidator,
  wireControlPlane,
  AdminAudit,
  type ControlPlane,
  type PackValidator,
  type Principal,
  type Role,
} from "@axis/control-plane";
import {
  AgilExplain,
  ApprovalsAdapter,
  AuditAdapter,
  ControlPlaneApiAudit,
  ControlPlaneAuthenticator,
  ControlPlaneAuthz,
  ControlPlanePolicies,
  KillSwitchService,
  LedgerUsage,
  MemoryBlueprintStore,
  MemoryIdempotencyStore,
  MemoryKillSwitchRecords,
  OpaCliPolicyTester,
  StorePolicyMetadata,
  createGateway,
  type Gateway,
  type GatewayDeps,
  type GatewayOptions,
} from "../src/index.js";
import { FakeKernel, FakeRuns } from "./fakes.js";

let authz: Promise<Authorizer> | undefined;
const sharedAuthorizer = (): Promise<Authorizer> => (authz ??= Authorizer.fromPackFile());
const cache = new Map<string, ReturnType<PackValidator>>();
const cachedValidator: PackValidator = (docs) => {
  const k = JSON.stringify(docs);
  let r = cache.get(k);
  if (!r) {
    r = compileValidator(docs);
    cache.set(k, r);
  }
  return r;
};

export interface Cred {
  tenantId: string;
  memberId: string;
  role: Role;
  /** Session access token. */
  token: string;
}

export interface World {
  gw: Gateway;
  base: string;
  cp: ControlPlane;
  store: MemoryControlPlaneStore;
  audit: MemoryAuditLog;
  runs: FakeRuns;
  kernel: FakeKernel;
  approvals: ApprovalService;
  ledger: MemoryUsageLedger;
  idem: MemoryIdempotencyStore;
  deps: GatewayDeps;
  logs: { level: string; msg: string; fields?: Record<string, unknown> | undefined }[];
  /** Provision a tenant; returns its owner credential. */
  tenant(slug?: string): Promise<Cred>;
  /** Add a member with `role` and log them in. */
  member(tenantId: string, role: Role): Promise<Cred>;
  apiKey(c: Cred, scopes: string[]): Promise<string>;
  close(): Promise<void>;
}

export async function makeWorld(opts: GatewayOptions = {}, over: Partial<GatewayDeps> = {}): Promise<World> {
  const store = new MemoryControlPlaneStore();
  const audit = new MemoryAuditLog();
  const cp = wireControlPlane({
    store,
    auditSink: audit,
    auditReader: audit,
    authorizer: await sharedAuthorizer(),
    idp: new FakeIdentityProvider(),
    kms: new LocalKms({ "kms-1": randomBytes(32) }, "kms-1"),
    dns: new FakeDnsResolver(),
    region: "us-east-1",
    regions: ["us-east-1"],
    secrets: { pepper: randomBytes(32), cookieKey: randomBytes(32), signingKeys: [{ kid: "k1", key: randomBytes(32) }] },
    redirectUri: "https://cp.example.test/cb",
    allowedReturnOrigins: [],
    validator: cachedValidator,
    secureCookies: true,
  });
  const approvals = new ApprovalService({ store: new MemoryApprovalStore(), audit, signer: new HmacSigner(randomBytes(32)) });
  const ledger = new MemoryUsageLedger({ signer: new HmacSealSigner(randomBytes(32)) });
  const runs = new FakeRuns();
  const kernel = new FakeKernel();
  const idem = new MemoryIdempotencyStore();
  const logs: World["logs"] = [];
  const deps: GatewayDeps = {
    auth: new ControlPlaneAuthenticator({ apiKeys: cp.apiKeys, sessions: cp.sessions }),
    authz: new ControlPlaneAuthz(await sharedAuthorizer()),
    audit: new ControlPlaneApiAudit(new AdminAudit(audit)),
    blueprints: new MemoryBlueprintStore(),
    runs,
    approvals: new ApprovalsAdapter(approvals),
    policies: new ControlPlanePolicies({ packs: cp.policies, tester: new OpaCliPolicyTester() }),
    auditLog: new AuditAdapter(audit),
    killSwitches: new KillSwitchService(kernel, new MemoryKillSwitchRecords()),
    usage: new LedgerUsage(ledger),
    explain: new AgilExplain(audit, new StorePolicyMetadata(store)),
    idempotency: idem,
    ...over,
  };
  const gw = createGateway(deps, {
    validateResponses: true,
    allowedOrigins: ["https://console.example.test"],
    log: (level, msg, fields) => logs.push({ level, msg, fields }),
    ...opts,
  });
  const port = await gw.listen(0);
  const w: World = {
    gw,
    base: `http://127.0.0.1:${port}/v1`,
    cp,
    store,
    audit,
    runs,
    kernel,
    approvals,
    ledger,
    idem,
    deps,
    logs,
    async tenant(slug = `t-${randomUUID().slice(0, 10)}`) {
      const r = await cp.provisioner.signup({ slug, name: `Tenant ${slug}`, ownerEmail: `owner@${slug}.test`, region: "us-east-1" });
      return login(r.tenantId, r.ownerMemberId, "owner");
    },
    async member(tenantId, role) {
      const id = randomUUID();
      await store.insertMember({ tenantId, id, userRef: `test:${id}`, email: `${role}-${id.slice(0, 6)}@x.test`, role, status: "active" });
      return login(tenantId, id, role);
    },
    async apiKey(c, scopes) {
      const p = await cp.sessions.authenticate(c.token);
      if (!p) throw new Error("no session");
      return (await cp.apiKeys.create(p as Principal, { name: "test key", scopes })).secret;
    },
    close: () => gw.close(),
  };
  async function login(tenantId: string, memberId: string, role: Role): Promise<Cred> {
    const m = await store.getMember(tenantId, memberId);
    if (!m) throw new Error("no member");
    const s = await cp.sessions.issue(m, "dev");
    return { tenantId, memberId, role, token: s.accessToken };
  }
  return w;
}

// ---- HTTP helper -------------------------------------------------------------------------------------------------------------

export interface Res {
  status: number;
  headers: Headers;
  body: any; // eslint-disable-line @typescript-eslint/no-explicit-any
  text: string;
}

export async function call(
  w: World,
  method: string,
  path: string,
  o: { token?: string; key?: string; body?: unknown; raw?: string; headers?: Record<string, string>; contentType?: string } = {},
): Promise<Res> {
  const headers: Record<string, string> = { ...(o.headers ?? {}) };
  if (o.token) headers["authorization"] = `Bearer ${o.token}`;
  if (o.key) headers["x-axis-api-key"] = o.key;
  const payload = o.raw ?? (o.body !== undefined ? JSON.stringify(o.body) : undefined);
  if (payload !== undefined) headers["content-type"] = o.contentType ?? "application/json";
  const r = await fetch(w.base + path, { method, headers, ...(payload !== undefined ? { body: payload } : {}) });
  const text = await r.text();
  let body: unknown;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    body = undefined;
  }
  return { status: r.status, headers: r.headers, body, text };
}

export const ABL = (name: string, version = "1.0.0"): Record<string, unknown> => ({
  apiVersion: "abl.axis.dev/v1",
  kind: "Agent",
  metadata: { name, version, description: "test agent" },
  spec: {
    riskClassification: { level: "limited", rationale: "Reads claim records; nothing leaves the tenant.", transparencyNotice: "You are talking to an AI." },
    model: { primary: { provider: "openai", model: "gpt-4o", params: { maxOutputTokens: 128 } } },
    instructions: { system: "You help." },
    tools: [{ name: "lookup-claim", kind: "function", sideEffects: "read" }],
    budgets: { tokens: { soft: 1000, hard: 2000 } },
  },
});

export const POLICY = (name = "tenant-acme", version = "1.0.0"): Record<string, unknown> => ({
  apiVersion: "policy.axis.dev/v1",
  kind: "PolicyPack",
  metadata: { name, version },
  spec: {
    defaultDecision: "DENY",
    rules: [
      { id: "allow-reads", enforcementPoints: ["tool_call"], when: { field: "tool.side_effects", op: "eq", value: "read" }, decision: "ALLOW" },
      { id: "deny-big", priority: 500, enforcementPoints: ["tool_call"], when: { field: "args.amount", op: "gt", value: 100 }, decision: "DENY" },
    ],
  },
});

// ---- seeding ----------------------------------------------------------------------------------------------------------------

export interface Seed {
  owner: Cred;
  runId: string;
  traceId: string;
  approvalId: string;
  denySeq: number;
  blueprint: { name: string; version: string };
}

export const hex32 = (): string => randomBytes(16).toString("hex");
const h64 = (): string => randomBytes(32).toString("hex");

/** A tenant with a published blueprint, a started run with audited decisions on its trace, an open approval and some usage. */
export async function seed(w: World, owner?: Cred): Promise<Seed> {
  const o = owner ?? (await w.tenant());
  const blueprint = { name: "claims", version: "1.0.0" };
  const pub = await call(w, "POST", "/blueprints", { token: o.token, body: { abl: ABL(blueprint.name, blueprint.version) } });
  if (pub.status !== 201) throw new Error(`seed blueprint: ${pub.text}`);
  const run = await call(w, "POST", "/runs", { token: o.token, body: { blueprint, input: { prompt: "review claim 42" } } });
  if (run.status !== 202) throw new Error(`seed run: ${run.text}`);
  const traceId = run.body.trace_id as string;
  const mk = (over: Record<string, unknown>) =>
    w.audit.append({
      schema_version: 1,
      tenant_id: o.tenantId,
      trace_id: traceId,
      actor: { type: "agent", id: "claims", pid: "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV" },
      blueprint,
      policy_version: "tenant-acme@1.0.0",
      enforcement_point: "tool_call",
      action: "lookup-claim",
      decision: "ALLOW",
      reason: "tenant-acme/allow-reads",
      inputs_hash: h64(),
      outputs_hash: h64(),
      ...over,
    } as never);
  await mk({});
  const denied = await mk({ action: "lookup-restricted", decision: "DENY", reason: "tenant-acme/deny-restricted" });
  const approval = await w.approvals.create({
    tenant_id: o.tenantId,
    run_id: run.body.id,
    trace_id: traceId,
    agent: { name: "claims", version: "1.0.0", pid: "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV" },
    tool: "send-report",
    args_hash: h64(),
    risk_level: "high",
    requester: { type: "agent", id: "claims", pid: "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV" },
    approval: { roles: ["admin", "owner"], sla_seconds: 3600, escalate_to: [], on_timeout: "DENY" },
  });
  await w.ledger.append({
    tenantId: o.tenantId,
    idempotencyKey: `seed-${randomBytes(4).toString("hex")}`,
    meter: "tokens_in",
    quantity: 120n,
    eventTime: new Date(),
    dimensions: { model_class: "standard", agent: "claims" },
    source: "test",
  });
  return { owner: o, runId: run.body.id as string, traceId, approvalId: approval.id, denySeq: denied.seq, blueprint };
}
