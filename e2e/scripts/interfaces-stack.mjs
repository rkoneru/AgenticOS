// E2E harness (NOT production) for Phase 7: the "hands" and the shared services around the REAL API gateway process.
//   control plane : HTTP (/auth, /admin/v1, /platform/v1, /internal/v1) over the Postgres store, the real authorization pack on OPA Wasm,
//                   FAKE IdP (an authorize page that "logs the user in" so a real browser can complete the SSO redirect dance), FAKE KMS/DNS.
//                   Active policy packs are compiled to <bundle_dir>/<tenant>.tar.gz for the Risk Kernel process.
//   billing       : the usage ledger (Postgres) and the loopback ingest server the run service posts usage to.
//   marketplace   : the publisher and staff side (verification, security review, listing). The public API has no publisher/staff
//                   operations (ADR 0053): this is where a person at the marketplace would act. The tenant side (preview, consent, install)
//                   is served by the gateway process, over the same Postgres.
//   ops           : the test's hands: provision a tenant (signup, SSO link, per-tenant service tokens, BYO model key, optionally a policy
//                   pack), members and sessions, API keys, the fake IdP's next user, ledger reads. Every call goes through the same service
//                   classes the HTTP surfaces use; ops never writes a table directly.
// The API gateway is NOT here: it is its own process (apps/api-gateway/dist/main.js), started by the orchestrator (e2e/interfaces_stack.py).
// usage: node interfaces-stack.mjs <config.json>   (prints one JSON line: {"event":"stack", cp, billing, ops, idp})
import http from "node:http";
import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import pg from "pg";
import { PgAuditLog } from "@axis/audit";
import {
  Authorizer,
  FakeDnsResolver,
  FakeIdentityProvider,
  FileBundleSink,
  LocalKms,
  PgControlPlaneStore,
  createControlPlaneServer,
  listenLoopback as cpListen,
  wireControlPlane,
} from "@axis/control-plane";
import {
  AdjustmentApi,
  DEV_PRICE_BOOK,
  HmacSealSigner,
  PgInvoiceStore,
  PgUsageLedger,
  createDevServer,
  listenLoopback as billingListen,
} from "@axis/billing";
import {
  FakeDomainProver,
  FakeIdentityProver,
  PgDocStore,
  createMarketplace,
} from "@axis/marketplace";
import { PgRegistryStore, RegistryService, ServiceAudit } from "@axis/registry";

const cfg = JSON.parse(readFileSync(process.argv[2], "utf8"));
const hex = (s) => Buffer.from(s, "hex");

// ---- database, audit, control plane -------------------------------------------------------------------------------
const pool = new pg.Pool({ connectionString: cfg.db_url, max: 12 });
const store = new PgControlPlaneStore({ pool, role: cfg.role });
const audit = new PgAuditLog({ pool, role: cfg.role });

// The fake IdP's authorize page: the "user" authenticates instantly as the profile queued for the organization (default: its owner).
const idpNext = new Map(); // org -> [email]
const orgs = new Map(); // org -> {slug, ownerEmail}
let idp;
const idpServer = http.createServer((req, res) => {
  const u = new URL(req.url ?? "/", "http://idp.local");
  if (u.pathname !== "/authorize") {
    res.writeHead(404).end();
    return;
  }
  const state = u.searchParams.get("state") ?? "";
  const org = u.searchParams.get("organization") ?? "";
  const redirect = u.searchParams.get("redirect_uri") ?? "";
  const known = orgs.get(org);
  if (!known) {
    res.writeHead(400, { "content-type": "text/plain" }).end("unknown organization");
    return;
  }
  const email = idpNext.get(org)?.shift() ?? known.ownerEmail;
  try {
    const code = idp.complete(state, {
      id: `idp-${email}`,
      email,
      emailVerified: true,
      organizationId: org,
      connectionType: "oidc",
      firstName: email.split("@")[0],
    });
    const back = new URL(redirect);
    back.searchParams.set("code", code);
    back.searchParams.set("state", state);
    res.writeHead(302, { location: back.toString(), "cache-control": "no-store" }).end();
  } catch {
    res.writeHead(400, { "content-type": "text/plain" }).end("unknown login");
  }
});
const idpPort = await cpListen(idpServer, 0);
idp = new FakeIdentityProvider(`http://127.0.0.1:${idpPort}`);

const runtimeTokens = new Map(); // CP runtime-bridge token -> tenant
const cp = wireControlPlane({
  store,
  auditSink: audit,
  auditReader: audit,
  authorizer: await Authorizer.fromPackFile(),
  idp,
  kms: new LocalKms({ "e2e-1": randomBytes(32) }, "e2e-1"),
  dns: new FakeDnsResolver(),
  region: cfg.region,
  regions: [cfg.region],
  secrets: {
    pepper: hex(cfg.secrets.pepper),
    cookieKey: hex(cfg.secrets.cookie_key),
    signingKeys: [{ kid: "k1", key: hex(cfg.secrets.signing_key) }],
  },
  redirectUri: cfg.redirect_uri,
  allowedReturnOrigins: cfg.return_origins ?? [],
  platformToken: cfg.platform_token,
  runtimeAuth: (authorization) => {
    const m = /^Bearer (\S+)$/.exec(authorization ?? "");
    return m ? runtimeTokens.get(m[1]) : undefined;
  },
  secureCookies: true, // a real browser: Secure + __Host- cookies (Chromium accepts them from http://localhost)
  bundleSink: new FileBundleSink(cfg.bundle_dir),
});
const cpServer = createControlPlaneServer(cp.deps);
const cpPort = await cpListen(cpServer, 0);

// ---- billing ------------------------------------------------------------------------------------------------------
const ledger = new PgUsageLedger({
  pool,
  signer: new HmacSealSigner(Buffer.from(cfg.seal_key, "utf8")),
  role: cfg.role,
});
const billingTokens = new Map();
const billingServer = createDevServer({
  ledger,
  invoices: new PgInvoiceStore({ pool, role: cfg.role }),
  adjustments: new AdjustmentApi({ ledger, audit, now: () => new Date() }),
  authenticate: async (authorization) => {
    const m = /^Bearer (\S+)$/.exec(authorization ?? "");
    return m ? billingTokens.get(m[1]) : undefined;
  },
  classifyRules: DEV_PRICE_BOOK.modelClasses,
  now: () => new Date(),
});
const billingPort = await billingListen(billingServer, 0);

// ---- marketplace (publisher and staff side) -------------------------------------------------------------------------
const mpDomain = new FakeDomainProver();
const registry = new RegistryService({
  store: new PgRegistryStore({ pool, role: cfg.role }),
  audit: new ServiceAudit(audit, "registry"),
});
const mp = createMarketplace({
  docs: new PgDocStore({ pool, role: cfg.role }),
  registry,
  audit: new ServiceAudit(audit, "marketplace"),
  domain: mpDomain,
  identity: new FakeIdentityProver(),
});
const reviewer = (subject) => ({ kind: "reviewer", subject });
const tenantAdmin = (tenantId, role = "admin") => ({
  kind: "tenant",
  tenantId,
  subject: `ops-${role}-${tenantId.slice(0, 8)}`,
  role,
});

// ---- tenants and token files -----------------------------------------------------------------------------------------
const tenants = new Map(); // id -> record
const writeJson = (path, obj) => {
  const tmp = `${path}.${randomBytes(4).toString("hex")}.tmp`;
  writeFileSync(tmp, JSON.stringify(obj), { mode: 0o600 });
  renameSync(tmp, path);
};
function flushTokenFiles() {
  const f = cfg.files;
  const all = [...tenants.values()];
  const byTenant = (pick) => Object.fromEntries(all.map((t) => [t.id, pick(t)]));
  const byToken = (pick) => Object.fromEntries(all.map((t) => [pick(t), t.id]));
  writeJson(f.kernel_principals, Object.fromEntries(all.map((t) => [t.kernelToken, { tenantId: t.id, subject: `svc-${t.slug}`, platformOperator: false }])));
  writeJson(f.gw_run, byTenant((t) => t.runToken));
  writeJson(f.run_tokens, byToken((t) => t.runToken));
  writeJson(f.gw_kernel, byTenant((t) => t.kernelToken));
  writeJson(f.run_kernel, byTenant((t) => t.kernelToken));
  writeJson(f.run_runtime, byTenant((t) => t.runtimeToken));
  writeJson(f.run_ingest, byTenant((t) => t.ingestToken));
}

const token = (p) => `${p}-${randomBytes(12).toString("hex")}`;
const sessionOf = async (tenantId, memberId) => {
  const m = await store.getMember(tenantId, memberId);
  if (!m) throw new Error("no such member");
  return (await cp.sessions.issue(m, "dev")).accessToken;
};
const principalOf = async (accessToken) => {
  const p = await cp.sessions.authenticate(accessToken);
  if (!p) throw new Error("no such session");
  return p;
};

async function provision(b) {
  const slug = String(b.slug);
  const out = await cp.provisioner.signup({
    slug,
    name: `Tenant ${slug}`,
    ownerEmail: `owner@${slug}.example`,
    region: cfg.region,
  });
  const org = `org_${slug}`;
  await store.upsertConnection({
    tenantId: out.tenantId,
    id: randomUUID(),
    idpOrgId: org,
    connectionType: "oidc",
    jitEnabled: false,
    jitDefaultRole: "viewer",
  });
  const t = {
    id: out.tenantId,
    slug,
    org,
    ownerEmail: `owner@${slug}.example`,
    ownerMemberId: out.ownerMemberId,
    kernelToken: token("rk"),
    runToken: token("rn"),
    runtimeToken: token("rt"),
    ingestToken: token("bi"),
  };
  orgs.set(org, { slug, ownerEmail: t.ownerEmail });
  tenants.set(t.id, t);
  runtimeTokens.set(t.runtimeToken, t.id);
  billingTokens.set(t.ingestToken, { tenantId: t.id, scopes: ["ingest"], subject: `rt-${slug}` });
  flushTokenFiles();
  const ownerToken = await sessionOf(t.id, t.ownerMemberId);
  const owner = await principalOf(ownerToken);
  if (b.byo_key) {
    // the tenant's BYO model key, stored through the control plane's own admin API (envelope-encrypted by the fake KMS)
    const r = await fetch(`http://127.0.0.1:${cpPort}/admin/v1/model-keys/openai/default`, {
      method: "PUT",
      headers: { authorization: `Bearer ${ownerToken}`, "content-type": "application/json" },
      body: JSON.stringify({ value: b.byo_key }),
    });
    if (!r.ok) throw new Error(`BYO key: ${r.status} ${await r.text()}`);
  }
  let activated = null;
  if (b.pack) {
    const v = await cp.policies.publish(owner, b.pack);
    await cp.admin.activatePolicy(owner, v.versionId);
    activated = `${v.pack}@${v.version}`;
  }
  return {
    tenant_id: t.id,
    slug,
    org,
    owner_email: t.ownerEmail,
    owner_member_id: t.ownerMemberId,
    owner_session: ownerToken,
    activated_pack: activated,
  };
}

const ops = {
  "provision-tenant": provision,
  member: async (b) => {
    const id = randomUUID();
    const email = b.email ?? `${b.role}-${id.slice(0, 6)}@${tenants.get(b.tenant_id)?.slug ?? "x"}.example`;
    await store.insertMember({
      tenantId: b.tenant_id,
      id,
      userRef: `ops:${id}`,
      email,
      role: b.role,
      status: "active",
    });
    return { member_id: id, email, session: await sessionOf(b.tenant_id, id) };
  },
  session: async (b) => ({ session: await sessionOf(b.tenant_id, b.member_id) }),
  "api-key": async (b) => {
    const p = await principalOf(await sessionOf(b.tenant_id, b.member_id));
    const k = await cp.apiKeys.create(p, { name: b.name ?? "e2e key", scopes: b.scopes ?? ["*"] });
    return { secret: k.secret, id: k.id ?? k.apiKeyId ?? null };
  },
  "idp/next": async (b) => {
    const q = idpNext.get(b.org) ?? [];
    q.push(b.email);
    idpNext.set(b.org, q);
    return { ok: true };
  },
  "mp/publisher-verify": async (b) => {
    const t = tenants.get(b.tenant_id);
    const admin = tenantAdmin(b.tenant_id);
    const domain = `${t.slug}.example.com`;
    const rec = await mp.publishers.start(admin, { legalName: `${t.slug} Inc`, domain, contactEmail: `ops@${domain}` });
    mpDomain.records.set(domain, [`axis-verify=${rec.challenge}`]);
    await mp.publishers.submitEvidence(admin);
    await mp.publishers.decide(reviewer("rev-verify"), b.tenant_id, { decision: "approve", reason: "evidence checked" });
    return { ok: true };
  },
  "mp/review-and-list": async (b) => {
    const builder = tenantAdmin(b.tenant_id, "builder");
    const rv = await mp.reviews.submit(builder, { namespace: b.namespace, name: b.name, version: b.version });
    if (rv.state === "in_review")
      await mp.reviews.decide(reviewer("rev-approve"), `${b.tenant_id}|${b.namespace}/${b.name}@${b.version}`, {
        decision: "approve",
        note: "reviewed by the e2e harness, fine to list",
        acknowledged: rv.findings.filter((f) => f.severity === "high").map((f) => f.id),
      });
    await mp.listings
      .create(builder, {
        namespace: b.namespace,
        name: b.name,
        title: b.title ?? `${b.name}`,
        summary: b.summary ?? "A listing from the e2e harness",
        categories: b.categories ?? ["support"],
      })
      .catch((e) => {
        if (e.code !== "conflict") throw e;
      });
    return { state: rv.state, findings: rv.findings.map((f) => f.id) };
  },
  "mp/takedown": async (b) => {
    await mp.listings.takedown({ kind: "moderator", subject: "mod-1" }, {
      namespace: b.namespace,
      name: b.name,
      ...(b.version ? { version: b.version } : {}),
      reason: b.reason ?? "e2e takedown",
    });
    return { ok: true };
  },
  "billing/totals": async (b) => ({
    totals: (await ledger.totals(b.tenant_id, b.period)).map((t) => ({ ...t })),
  }),
  "billing/entries": async (b) => ({
    entries: (await ledger.entries(b.tenant_id, { periodId: b.period })).map((e) => ({
      key: e.idempotencyKey,
      meter: e.meter,
      quantity: e.quantity,
      type: e.entryType,
      dimensions: e.dimensions,
    })),
  }),
};

const json = (x) => JSON.stringify(x, (_k, v) => (typeof v === "bigint" ? v.toString() : v));
const opsServer = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const send = (status, body) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(json(body));
    };
    if (req.headers.authorization !== `Bearer ${cfg.ops_token}`) return send(401, { error: "unauthorized" });
    const name = (req.url ?? "").replace(/^\/ops\//, "");
    const op = ops[name];
    if (!op || req.method !== "POST") return send(404, { error: "no such op" });
    try {
      send(200, await op(JSON.parse(Buffer.concat(chunks).toString() || "{}")));
    } catch (e) {
      send(500, { error: String(e?.message ?? e), code: e?.code });
    }
  });
});
const opsPort = await cpListen(opsServer, 0);

console.log(JSON.stringify({ event: "stack", cp: cpPort, billing: billingPort, ops: opsPort, idp: idpPort }));
process.on("SIGTERM", () => {
  cpServer.close();
  billingServer.close();
  opsServer.close();
  idpServer.close();
  void pool.end().finally(() => process.exit(0));
});
