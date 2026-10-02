// E2E harness (NOT production) for Phase 6: the SaaS control plane and the billing service on REAL Postgres, in one process.
//   control plane  : HTTP (/auth, /admin/v1, /scim/v2, /platform/v1, /internal/v1) over the Postgres store, the real authorization
//                    pack on OPA Wasm, the real policy toolchain; FAKE IdP, FAKE KMS, FAKE DNS (docs/NEEDS.md #179-#195).
//                    Tenant admin audit goes through RoutedAuditLog: a `dedicated_db` tenant's chain lands in the SECOND database.
//                    Active policy packs are compiled and written to <bundle_dir>/<tenant>.tar.gz for the Risk Kernel (dev mechanism).
//   billing        : the usage ledger (Postgres, forced RLS), invoices, the price book, the Stripe FAKE (FakePaymentProvider, test
//                    mode) and the loopback dev server the runtime posts usage to.
//   ops (loopback) : the test's hands where a real deployment has a human or another system: the fake IdP user, the platform
//                    operator linking an SSO organization, token registration, a controllable billing clock, period close,
//                    invoice push, reconciliation, provider fault injection. It never bypasses a service: every call goes
//                    through the same classes the HTTP surfaces use.
// usage: node saas-stack.mjs <config.json>   (prints `listening <cp-port> <billing-port> <ops-port>`)
import http from "node:http";
import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import pg from "pg";
import { PgAuditLog } from "@axis/audit";
import {
  Authorizer,
  FakeDnsResolver,
  FakeIdentityProvider,
  FileBundleSink,
  LocalKms,
  PgControlPlaneStore,
  RoutedAuditLog,
  TenantRouter,
  createControlPlaneServer,
  listenLoopback as cpListen,
  wireControlPlane,
} from "@axis/control-plane";
import {
  AdjustmentApi,
  BillingService,
  DEV_PRICE_BOOK,
  FakePaymentProvider,
  HmacSealSigner,
  PgInvoiceStore,
  PgUsageLedger,
  StripePaymentProvider,
  createDevServer,
  invoiceToJson,
  listenLoopback as billingListen,
} from "@axis/billing";

const cfg = JSON.parse(readFileSync(process.argv[2], "utf8"));
const M = 1_000_000n;

// ---- databases and the placement router ---------------------------------------------------------------------------
const pool = new pg.Pool({ connectionString: cfg.db_url, max: 10 });
const pool2 = new pg.Pool({ connectionString: cfg.db2_url, max: 4 });
const admin2 = new pg.Client({ connectionString: cfg.db2_url });
await admin2.connect();
const store = new PgControlPlaneStore({ pool, role: cfg.role });
const router = new TenantRouter({
  placements: store,
  shared: pool,
  dedicated: { "ded-1": pool2 },
});
const audit = new RoutedAuditLog({
  router,
  open: (p) => new PgAuditLog({ pool: p, role: cfg.role }),
});

// ---- control plane ------------------------------------------------------------------------------------------------
const idp = new FakeIdentityProvider();
const dns = new FakeDnsResolver();
const runtimeTokens = new Map(); // token -> tenant (the control plane's per-tenant runtime bridge credential)
const cp = wireControlPlane({
  store,
  auditSink: audit,
  auditReader: audit,
  authorizer: await Authorizer.fromPackFile(),
  idp,
  kms: new LocalKms({ "e2e-1": randomBytes(32) }, "e2e-1"),
  dns,
  region: cfg.region,
  regions: [cfg.region, cfg.other_region],
  secrets: {
    pepper: randomBytes(32),
    cookieKey: randomBytes(32),
    signingKeys: [{ kid: "k1", key: randomBytes(32) }],
  },
  redirectUri: "http://127.0.0.1/auth/sso/callback",
  allowedReturnOrigins: [],
  platformToken: cfg.platform_token,
  devToken: cfg.dev_token,
  runtimeAuth: (authorization) => {
    const m = /^Bearer (\S+)$/.exec(authorization ?? "");
    return m ? runtimeTokens.get(m[1]) : undefined;
  },
  secureCookies: false,
  bundleSink: new FileBundleSink(cfg.bundle_dir),
});
const cpServer = createControlPlaneServer(cp.deps);
const cpPort = await cpListen(cpServer, 0);

// ---- billing ------------------------------------------------------------------------------------------------------
const clock = { override: null };
const now = () => (clock.override ? new Date(clock.override) : new Date());
const ledger = new PgUsageLedger({
  pool,
  signer: new HmacSealSigner(Buffer.from(cfg.seal_key, "utf8")),
  role: cfg.role,
  now,
});
const invoices = new PgInvoiceStore({ pool, role: cfg.role });
const provider = new FakePaymentProvider(); // the Stripe FAKE (test mode); the live-key refusal is exercised on the real adapter below
const PLAN = {
  id: "e2e",
  name: "E2E",
  priceBook: { id: DEV_PRICE_BOOK.id, version: DEV_PRICE_BOOK.version },
  baseFeeMicro: 10n * M,
  included: {},
  commitMicro: 0n,
};
const billing = new BillingService({
  ledger,
  invoices,
  provider,
  priceBook: DEV_PRICE_BOOK,
  config: { config: async () => ({ plan: PLAN }) },
});
const billingTokens = new Map(); // token -> {tenantId, scopes, subject}
const billingServer = createDevServer({
  ledger,
  invoices,
  adjustments: new AdjustmentApi({ ledger, audit, now }),
  authenticate: async (authorization) => {
    const m = /^Bearer (\S+)$/.exec(authorization ?? "");
    return m ? billingTokens.get(m[1]) : undefined;
  },
  classifyRules: DEV_PRICE_BOOK.modelClasses,
  now,
});
const billingPort = await billingListen(billingServer, 0);

// ---- ops ----------------------------------------------------------------------------------------------------------
const customers = new Map(); // tenant -> provider customer id
const json = (x) => JSON.stringify(x, (_k, v) => (typeof v === "bigint" ? v.toString() : v));
const sealJson = (s) => ({ ...s, closedAt: s.closedAt.toISOString() });

async function customerOf(tenantId) {
  let id = customers.get(tenantId);
  if (!id) {
    id = (await provider.createCustomer({ tenantId, name: `e2e-${tenantId}` }, `cus:${tenantId}`))
      .id;
    customers.set(tenantId, id);
  }
  return id;
}

const ops = {
  "idp/complete": async (b) => ({ code: idp.complete(b.state, b.profile) }),
  "sso-connection": async (b) => {
    // The platform operator links the tenant's IdP organization (WorkOS organization created at signup). The OWNER can then log in
    // through SSO; the owner session in the scenario comes from the IdP, not from the dev session bridge.
    await store.upsertConnection({
      tenantId: b.tenant_id,
      id: randomUUID(),
      idpOrgId: b.idp_org_id,
      connectionType: b.connection_type ?? "oidc",
      jitEnabled: b.jit_enabled ?? false,
      jitDefaultRole: b.jit_default_role ?? "viewer",
    });
    return { ok: true };
  },
  "runtime-token": async (b) => {
    runtimeTokens.set(b.token, b.tenant_id);
    return { ok: true };
  },
  "billing-token": async (b) => {
    billingTokens.set(b.token, { tenantId: b.tenant_id, scopes: b.scopes, subject: b.subject });
    return { ok: true };
  },
  placement: async (b) => {
    // Move a tenant to its own database: the dedicated database gets the tenant row (its own RLS root), the placement is recorded
    // in the control database. Provisioning the database itself is Phase 10 (NEEDS #188).
    const t = await store.getTenant(b.tenant_id);
    await admin2.query(
      "INSERT INTO tenants (id, slug, name, region) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
      [t.id, t.slug, t.name, t.region],
    );
    await store.putPlacement({
      tenantId: b.tenant_id,
      isolationTier: b.tier,
      ...(b.pool_key ? { poolKey: b.pool_key } : {}),
    });
    return { ok: true };
  },
  clock: async (b) => {
    clock.override = b.iso ?? null;
    return { now: now().toISOString() };
  },
  "billing/close": async (b) => {
    const r = await billing.closeAndRate(b.tenant_id, b.period);
    return {
      seal: sealJson(r.seal),
      invoice: {
        id: r.invoice.id,
        revision: r.invoice.revision,
        ...invoiceToJson(r.invoice.invoice),
      },
    };
  },
  "billing/verify-seal": async (b) => ({ verdict: await ledger.verifySeal(b.tenant_id, b.period) }),
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
  "billing/push": async (b) => {
    const customer = await customerOf(b.tenant_id);
    const usage = await billing.pushUsage(b.tenant_id, b.period, customer);
    const latest = (await invoices.list(b.tenant_id, b.period)).at(-1);
    const invoice = latest
      ? (latest.providerInvoiceId ?? (await billing.pushInvoice(b.tenant_id, latest, customer)))
      : null;
    return { customer, usage_events: usage, provider_invoice: invoice };
  },
  "billing/reconcile": async (b) => ({
    report: await billing.reconcile(b.tenant_id, b.period, await customerOf(b.tenant_id)),
  }),
  "billing/provider-state": async (b) => ({
    usage: provider.usage
      .filter((u) => u.customerId === customers.get(b.tenant_id))
      .map((u) => ({ identifier: u.identifier, meter: u.meter, quantity: u.quantity })),
    invoices: [...provider.invoices.values()].filter(
      (i) => i.customerId === customers.get(b.tenant_id),
    ),
  }),
  "billing/inject": async (b) => {
    // Provider-side faults AFTER a clean push, as a flaky provider would produce them. Nothing here touches the ledger.
    const id = `axis:${b.tenant_id}:${b.period}:${b.meter}`;
    const rec = provider.usage.find((u) => u.identifier === id);
    if (!rec) throw new Error(`no provider record ${id}`);
    if (b.kind === "duplicate") provider.usage.push({ ...rec, id: `${rec.id}_dup` });
    else if (b.kind === "drop") provider.usage.splice(provider.usage.indexOf(rec), 1);
    else if (b.kind === "alter") rec.quantity += 1n;
    else throw new Error("unknown fault");
    return { ok: true };
  },
  "billing/live-key": async (b) => {
    try {
      new StripePaymentProvider({
        apiKey: b.key,
        transport: { request: async () => ({ status: 500, body: "{}" }) },
      });
      return { refused: false };
    } catch (e) {
      return { refused: true, code: e.code, echoed: String(e.message).includes(b.key) };
    }
  },
  "billing/conflicts": async (b) => ({ conflicts: await ledger.conflicts(b.tenant_id) }),
  "cp/effective-policy": async (b) => ({
    ...(await cp.policies.effective(b.tenant_id)),
    rego: undefined,
  }),
};

const opsServer = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const send = (status, body) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(json(body));
    };
    if (req.headers.authorization !== `Bearer ${cfg.ops_token}`)
      return send(401, { error: "unauthorized" });
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

console.log(`listening ${cpPort} ${billingPort} ${opsPort}`);
process.on("SIGTERM", () => {
  cpServer.close();
  billingServer.close();
  opsServer.close();
  void Promise.all([pool.end(), pool2.end(), admin2.end()]).finally(() => process.exit(0));
});
