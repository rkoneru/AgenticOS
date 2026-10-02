import { randomBytes, randomUUID } from "node:crypto";
import { HmacSigner, ApprovalService, MemoryApprovalStore } from "@axis/approvals";
import { MemoryAuditLog } from "@axis/audit";
import { HmacSealSigner, MemoryUsageLedger } from "@axis/billing";
import {
  FakeDomainProver,
  FakeIdentityProver as FakeMpIdentityProver,
  MemoryDocStore,
  createMarketplace,
  type Marketplace,
} from "@axis/marketplace";
import {
  MemoryRegistryStore,
  RegistryService,
  ServiceAudit,
  ablContentHash,
  buildStatement,
  generatePublisherKey,
  signBlueprint,
  signStatement,
  type PublisherKeyPair,
} from "@axis/registry";
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
  ControlPlaneIdentity,
  ControlPlanePolicies,
  KillSwitchService,
  MarketplaceAdapter,
  RegistryAdapter,
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
  registry: RegistryService;
  marketplace: Marketplace;
  mpDomain: FakeDomainProver;
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

export async function makeWorld(
  opts: GatewayOptions = {},
  over: Partial<GatewayDeps> = {},
): Promise<World> {
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
    secrets: {
      pepper: randomBytes(32),
      cookieKey: randomBytes(32),
      signingKeys: [{ kid: "k1", key: randomBytes(32) }],
    },
    redirectUri: "https://cp.example.test/cb",
    allowedReturnOrigins: [],
    validator: cachedValidator,
    secureCookies: true,
  });
  const approvals = new ApprovalService({
    store: new MemoryApprovalStore(),
    audit,
    signer: new HmacSigner(randomBytes(32)),
  });
  const ledger = new MemoryUsageLedger({ signer: new HmacSealSigner(randomBytes(32)) });
  const registry = new RegistryService({
    store: new MemoryRegistryStore(),
    audit: new ServiceAudit(audit, "registry"),
  });
  const mpDomain = new FakeDomainProver();
  const marketplace = createMarketplace({
    docs: new MemoryDocStore(),
    registry,
    audit: new ServiceAudit(audit, "marketplace"),
    domain: mpDomain,
    identity: new FakeMpIdentityProver(),
  });
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
    policies: new ControlPlanePolicies({
      packs: cp.policies,
      tester: new OpaCliPolicyTester(),
      admin: cp.admin,
    }),
    auditLog: new AuditAdapter(audit),
    killSwitches: new KillSwitchService(kernel, new MemoryKillSwitchRecords()),
    usage: new LedgerUsage(ledger),
    explain: new AgilExplain(audit, new StorePolicyMetadata(store)),
    identity: new ControlPlaneIdentity(store),
    registry: new RegistryAdapter(registry),
    marketplace: new MarketplaceAdapter(marketplace),
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
    registry,
    marketplace,
    mpDomain,
    ledger,
    idem,
    deps,
    logs,
    async tenant(slug = `t-${randomUUID().slice(0, 10)}`) {
      const r = await cp.provisioner.signup({
        slug,
        name: `Tenant ${slug}`,
        ownerEmail: `owner@${slug}.test`,
        region: "us-east-1",
      });
      return login(r.tenantId, r.ownerMemberId, "owner");
    },
    async member(tenantId, role) {
      const id = randomUUID();
      await store.insertMember({
        tenantId,
        id,
        userRef: `test:${id}`,
        email: `${role}-${id.slice(0, 6)}@x.test`,
        role,
        status: "active",
      });
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
  o: {
    token?: string;
    key?: string;
    body?: unknown;
    raw?: string;
    headers?: Record<string, string>;
    contentType?: string;
  } = {},
): Promise<Res> {
  const headers: Record<string, string> = { ...(o.headers ?? {}) };
  if (o.token) headers["authorization"] = `Bearer ${o.token}`;
  if (o.key) headers["x-axis-api-key"] = o.key;
  const payload = o.raw ?? (o.body !== undefined ? JSON.stringify(o.body) : undefined);
  if (payload !== undefined) headers["content-type"] = o.contentType ?? "application/json";
  const r = await fetch(w.base + path, {
    method,
    headers,
    ...(payload !== undefined ? { body: payload } : {}),
  });
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
    riskClassification: {
      level: "limited",
      rationale: "Reads claim records; nothing leaves the tenant.",
      transparencyNotice: "You are talking to an AI.",
    },
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
      {
        id: "allow-reads",
        enforcementPoints: ["tool_call"],
        when: { field: "tool.side_effects", op: "eq", value: "read" },
        decision: "ALLOW",
      },
      {
        id: "deny-big",
        priority: 500,
        enforcementPoints: ["tool_call"],
        when: { field: "args.amount", op: "gt", value: 100 },
        decision: "DENY",
      },
    ],
  },
});

// ---- seeding ----------------------------------------------------------------------------------------------------------------

export interface Seed {
  owner: Cred;
  /** A listed marketplace entry published by ANOTHER tenant (the install target) with the consent the owner would give. */
  listing: { namespace: string; name: string; version: string };
  install: { content_hash: string; consent_digest: string };
  /** The owner's own registry namespace, its signing key and published blueprints (1.0.0 stays active, 1.1.0 is for yanking). */
  own: { namespace: string; name: string; key: PublisherKeyPair };
  /** A published policy pack version of the owner's tenant. */
  policyVersionId: string;
  runId: string;
  traceId: string;
  approvalId: string;
  denySeq: number;
  blueprint: { name: string; version: string };
}

export const hex32 = (): string => randomBytes(16).toString("hex");
const h64 = (): string => randomBytes(32).toString("hex");

export interface Publisher {
  tenantId: string;
  namespace: string;
  key: PublisherKeyPair;
  admin: { kind: "tenant"; tenantId: string; subject: string; role: "admin" };
}

const rid = (n = 6): string => Array.from(randomBytes(n), (b) => "cdfghjkpquxyz"[b % 13]).join("");

/** The ABL a publisher signs: a minimal, low-risk assistant (no tools: nothing to widen the installer's baseline but the model). */
export const LISTED_ABL = (name: string, version = "1.0.0"): Record<string, unknown> => ({
  apiVersion: "abl.axis.dev/v1",
  kind: "Agent",
  metadata: { name, version },
  spec: {
    riskClassification: {
      level: "minimal",
      rationale: "Answers general product questions; no decisions about people.",
    },
    model: { primary: { provider: "anthropic", model: "claude-sonnet-5-5" } },
    instructions: { system: "You are a helpful assistant." },
    budgets: { costUsd: { hard: 5 }, toolCalls: { hard: 20 } },
    policy: { packs: ["baseline-deny@^1.0.0"] },
  },
});

/** Signs `abl` the way publisher tooling does (detached signature + DSSE provenance), for registry publish tests. */
export function signedBundle(
  pub: Pick<Publisher, "namespace" | "key">,
  abl: Record<string, unknown>,
  at = new Date(),
): { abl: Record<string, unknown>; signature: unknown; provenance: unknown } {
  const meta = abl["metadata"] as { name: string; version: string };
  const level = (abl["spec"] as { riskClassification: { level: string } }).riskClassification.level;
  const hash = ablContentHash(abl);
  const signature = signBlueprint(
    {
      namespace: pub.namespace,
      name: meta.name,
      version: meta.version,
      riskLevel: level,
      contentHash: hash,
    },
    pub.key,
    at,
  );
  const provenance = signStatement(
    buildStatement(
      {
        namespace: pub.namespace,
        name: meta.name,
        version: meta.version,
        abl,
        builderId: "ci.example.com",
        sourceRef: "git+https://example.com/r@main",
        now: at,
      },
      hash,
    ),
    pub.key,
  );
  return {
    abl,
    signature: { key_id: signature.keyId, signed_at: signature.signedAt, sig: signature.sig },
    provenance,
  };
}

/** A verified publisher (another tenant) with one reviewed, listed blueprint: the install target of the marketplace tests. */
export async function seedListing(
  w: World,
  name = `helper-${rid(4)}`,
  version = "1.0.0",
): Promise<{ publisher: Publisher; namespace: string; name: string; version: string }> {
  const tenantId = randomUUID();
  const namespace = `pub-${rid(6)}`;
  const admin = {
    kind: "tenant" as const,
    tenantId,
    subject: `admin-${namespace}`,
    role: "admin" as const,
  };
  const key = generatePublisherKey();
  await w.registry.claimNamespace(admin, namespace);
  await w.registry.addKey(admin, namespace, {
    publicKey: key.publicKey,
    validFrom: new Date(Date.now() - 60_000),
  });
  const domain = `${namespace}.example.com`;
  const rec = await w.marketplace.publishers.start(admin, {
    legalName: `${namespace} Inc`,
    domain,
    contactEmail: `ops@${domain}`,
  });
  w.mpDomain.records.set(domain, [`axis-verify=${rec.challenge}`]);
  await w.marketplace.publishers.submitEvidence(admin);
  await w.marketplace.publishers.decide({ kind: "reviewer", subject: "rev-1" }, tenantId, {
    decision: "approve",
    reason: "evidence checked",
  });
  const publisher: Publisher = { tenantId, namespace, key, admin };
  const b = signedBundle(publisher, LISTED_ABL(name, version));
  await w.registry.publish(admin, namespace, {
    abl: b.abl,
    signature: {
      keyId: (b.signature as { key_id: string }).key_id,
      signedAt: (b.signature as { signed_at: string }).signed_at,
      sig: (b.signature as { sig: string }).sig,
    },
    provenance: b.provenance as never,
  });
  const review = await w.marketplace.reviews.submit(admin, { namespace, name, version });
  if (review.state === "in_review")
    await w.marketplace.reviews.decide(
      { kind: "reviewer", subject: "rev-2" },
      `${tenantId}|${namespace}/${name}@${version}`,
      { decision: "approve", note: "reviewed, fine to list", acknowledged: [] },
    );
  await w.marketplace.listings.create(admin, {
    namespace,
    name,
    title: `${name} title`,
    summary: "A helpful assistant",
    categories: ["support"],
  });
  return { publisher, namespace, name, version };
}

/** A tenant with a published blueprint, a started run with audited decisions on its trace, an open approval and some usage. */
export async function seed(w: World, owner?: Cred): Promise<Seed> {
  const o = owner ?? (await w.tenant());
  const blueprint = { name: "claims", version: "1.0.0" };
  const pub = await call(w, "POST", "/blueprints", {
    token: o.token,
    body: { abl: ABL(blueprint.name, blueprint.version) },
  });
  if (pub.status !== 201) throw new Error(`seed blueprint: ${pub.text}`);
  const run = await call(w, "POST", "/runs", {
    token: o.token,
    body: { blueprint, input: { prompt: "review claim 42" } },
  });
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
  const denied = await mk({
    action: "lookup-restricted",
    decision: "DENY",
    reason: "tenant-acme/deny-restricted",
  });
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
  const listed = await seedListing(w);
  const ownerP = {
    kind: "tenant" as const,
    tenantId: o.tenantId,
    subject: o.memberId,
    role: "admin" as const,
  };
  const preview = await w.marketplace.installs.preview(
    ownerP,
    listed.namespace,
    listed.name,
    listed.version,
  );
  const ownNs = `own-${rid(6)}`;
  const ownKey = generatePublisherKey();
  await w.registry.claimNamespace(ownerP, ownNs);
  await w.registry.addKey(ownerP, ownNs, {
    publicKey: ownKey.publicKey,
    validFrom: new Date(Date.now() - 60_000),
  });
  for (const v of ["1.0.0", "1.1.0"]) {
    const b = signedBundle({ namespace: ownNs, key: ownKey }, LISTED_ABL("own-agent", v));
    const sig = b.signature as { key_id: string; signed_at: string; sig: string };
    await w.registry.publish(ownerP, ownNs, {
      abl: b.abl,
      signature: { keyId: sig.key_id, signedAt: sig.signed_at, sig: sig.sig },
      provenance: b.provenance as never,
    });
  }
  const pol = await call(w, "POST", "/policies", {
    token: o.token,
    body: { policy: POLICY("seeded-pack", "1.0.0") },
  });
  if (pol.status !== 201) throw new Error(`seed policy: ${pol.text}`);
  return {
    owner: o,
    listing: { namespace: listed.namespace, name: listed.name, version: listed.version },
    install: { content_hash: preview.contentHash, consent_digest: preview.consentDigest },
    own: { namespace: ownNs, name: "own-agent", key: ownKey },
    policyVersionId: pol.body.version_id as string,
    runId: run.body.id as string,
    traceId,
    approvalId: approval.id,
    denySeq: denied.seq,
    blueprint,
  };
}
