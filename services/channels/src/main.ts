/* Dev/e2e entry point (NOT production; docs/NEEDS.md). Environment:
   AXIS_CHANNELS_DATABASE_URL  Postgres URL (omit for the in-memory store)
   AXIS_CHANNELS_ROLE          e.g. axis_app when connecting as a superuser in dev
   AXIS_CHANNELS_TOKENS        JSON {"<token>": {"tenantId": "<uuid>"}} for the runtime's outbound client
   AXIS_CHANNELS_ROUTES        JSON array of RouteConfig (secrets inline: dev only)
   Audit: PgAuditLog on the same pool when a database URL is set, otherwise an in-memory log.
   AXIS_CHANNELS_PORT          listen port (default random). Prints `listening <port>` on stdout.
   Real HTTP/SMTP egress is NOT wired: outbound uses an HTTP transport that REFUSES every call until a provider transport is
   configured (NEEDS). */
import pg from "pg";
import { MemoryAuditLog, PgAuditLog } from "@axis/audit";
import {
  ChannelGateway,
  EmailAdapter,
  GuardedHttpTransport,
  FetchTransport,
  IdentityService,
  MemoryConversationStore,
  MemoryIdempotencyStore,
  MemoryRateLimiter,
  PgConversationStore,
  SlackAdapter,
  SmsAdapter,
  StaticRoutingTable,
  WebAdapter,
  WebHub,
  WhatsAppAdapter,
  PROVIDER_HOSTS,
  createDevServer,
  listenLoopback,
  staticTokenAuthenticator,
  type RouteConfig,
  type ServiceAuth,
} from "./index.js";

const tokens = process.env["AXIS_CHANNELS_TOKENS"];
const routesJson = process.env["AXIS_CHANNELS_ROUTES"];
if (!tokens || !routesJson) {
  console.error("AXIS_CHANNELS_TOKENS and AXIS_CHANNELS_ROUTES are required");
  process.exit(2);
}
const url = process.env["AXIS_CHANNELS_DATABASE_URL"];
const role = process.env["AXIS_CHANNELS_ROLE"];
const pool = url ? new pg.Pool({ connectionString: url }) : undefined;
const store = pool
  ? new PgConversationStore({ pool, ...(role ? { role } : {}) })
  : new MemoryConversationStore();
const routes = new StaticRoutingTable(JSON.parse(routesJson) as RouteConfig[]);
const limiter = new MemoryRateLimiter();
const hub = new WebHub();
const gateway = new ChannelGateway({
  adapters: [
    new WebAdapter(),
    new SlackAdapter(),
    new EmailAdapter(),
    new SmsAdapter(),
    new WhatsAppAdapter(),
  ],
  routes,
  store,
  identity: new IdentityService({ store, limiter }),
  audit: pool ? new PgAuditLog({ pool, ...(role ? { role } : {}) }) : new MemoryAuditLog(),
  idempotency: new MemoryIdempotencyStore(),
  limiter,
  hub,
  http: new GuardedHttpTransport(new FetchTransport(), [
    ...PROVIDER_HOSTS.slack,
    ...PROVIDER_HOSTS.twilio,
    ...PROVIDER_HOSTS.meta,
  ]),
});
const server = createDevServer({
  gateway,
  routes,
  store,
  identity: new IdentityService({ store, limiter }),
  hub,
  authenticate: staticTokenAuthenticator(JSON.parse(tokens) as Record<string, ServiceAuth>),
});
const port = await listenLoopback(server, Number(process.env["AXIS_CHANNELS_PORT"] ?? 0));
console.log(`listening ${port}`);
process.on("SIGTERM", () => {
  server.close();
  void pool?.end();
});
