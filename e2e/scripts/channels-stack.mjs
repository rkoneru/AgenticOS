// E2E harness (NOT production): the channels service on real Postgres (conversations, identities, audit chain) with FAKE provider
// transports. Everything between the provider webhook and the transport is real code: signature verification, tenant routing,
// replay protection, identity linking, the audit chain, the inbox bridge, the gated send, the web hub.
// usage: node channels-stack.mjs <config.json>   (prints `listening <port> <fake-port>`)
//   config: { db_url, role, tokens: {token: {tenantId}}, routes: [RouteConfig], system_tenant }
// The fake-provider port (separate listener, loopback) lets the test see what "left" the platform:
//   GET /sent -> {http: [HttpCall], email: [EmailCall]}   POST /reset   POST /mode {"slack_ok": bool}
import http from "node:http";
import { readFileSync } from "node:fs";
import pg from "pg";
import { PgAuditLog } from "@axis/audit";
import {
  ChannelGateway,
  EmailAdapter,
  IdentityService,
  InboxQueue,
  MemoryIdempotencyStore,
  MemoryRateLimiter,
  PgConversationStore,
  SlackAdapter,
  SmsAdapter,
  StaticRoutingTable,
  WebAdapter,
  WebHub,
  createDevServer,
  listenLoopback,
  staticTokenAuthenticator,
} from "@axis/channels";

const cfg = JSON.parse(readFileSync(process.argv[2], "utf8"));
const pool = new pg.Pool({ connectionString: cfg.db_url });
const store = new PgConversationStore({ pool, role: cfg.role });
const audit = new PgAuditLog({ pool, role: cfg.role });
const routes = new StaticRoutingTable(cfg.routes);
const limiter = new MemoryRateLimiter();
const hub = new WebHub();
const inbox = new InboxQueue();
const identity = new IdentityService({ store, limiter });

const sent = { http: [], email: [] };
const mode = { slack_ok: true };
const fakeHttp = {
  async request(call) {
    sent.http.push({ url: call.url, body: call.body, headers: call.headers });
    if (call.url.includes("slack.com")) return { status: 200, body: JSON.stringify({ ok: mode.slack_ok }) };
    return { status: 201, body: "{}" };
  },
};
const fakeEmail = {
  async send(call) {
    sent.email.push({ raw: call.raw, envelope_from: call.envelope_from, envelope_to: call.envelope_to });
  },
};

const gateway = new ChannelGateway({
  adapters: [new WebAdapter(), new SlackAdapter(), new EmailAdapter(), new SmsAdapter()],
  routes,
  store,
  identity,
  audit,
  idempotency: new MemoryIdempotencyStore(),
  limiter,
  hub,
  http: fakeHttp,
  email: fakeEmail,
  onMessage: inbox.handler,
  // A request that names NO known route is audited under the platform tenant.
  systemAudit: { sink: audit, tenant_id: cfg.system_tenant },
});
const server = createDevServer({
  gateway,
  routes,
  store,
  identity,
  hub,
  inbox,
  authenticate: staticTokenAuthenticator(cfg.tokens),
});
const port = await listenLoopback(server, 0);

const fake = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(chunks).toString() || "{}";
    if (req.method === "POST" && req.url === "/reset") {
      sent.http.length = 0;
      sent.email.length = 0;
    } else if (req.method === "POST" && req.url === "/mode") Object.assign(mode, JSON.parse(body));
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(req.method === "GET" ? sent : { ok: true }));
  });
});
const fakePort = await listenLoopback(fake, 0);
console.log(`listening ${port} ${fakePort}`);
process.on("SIGTERM", () => {
  server.close();
  fake.close();
  void pool.end();
  process.exit(0);
});
