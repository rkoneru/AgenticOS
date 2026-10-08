/* Dev/e2e entry point (INTERNAL admin surface, not the public API; NEEDS 370):
   AXIS_GOV_DATABASE_URL=... AXIS_GOV_TOKENS='{"tok":{"tenantId":"<uuid>","id":"officer","roles":["privacy_officer"]}}' AXIS_GOV_MASTER_KEY=<64 hex> node dist/main.js
   Providers: every Postgres-backed store. The master key is a dev stand-in for a KMS (NEEDS 365). Refuses NODE_ENV=production. */
import { MemoryAuditLog } from "@axis/audit";
import pg from "pg";
import { GovernanceAudit } from "./audit.js";
import { ManifestSigner } from "./bundle.js";
import { createAdminServer, listenLoopback, staticTokenAuthenticator } from "./dev-server.js";
import { DsarEngine } from "./dsar.js";
import { MasterKeyProvider, Pseudonymiser, Sealer } from "./keys.js";
import { ApprovalsProvider } from "./providers/approvals.js";
import { BillingProvider } from "./providers/billing.js";
import { ChannelsProvider } from "./providers/channels.js";
import { EvalHubProvider } from "./providers/evalhub.js";
import { MembersProvider } from "./providers/members.js";
import { MemoryProvider } from "./providers/memory.js";
import { RunLogsProvider } from "./providers/runlogs.js";
import { HoldRegistry } from "./registry.js";
import { ResidencyPolicy } from "./residency.js";
import { RetentionEngine } from "./retention.js";
import { PgGovernanceStore } from "./store.js";
import type { Principal } from "./types.js";

if (process.env["NODE_ENV"] === "production") {
  console.error("data-governance dev server refuses NODE_ENV=production");
  process.exit(2);
}
const url = process.env["AXIS_GOV_DATABASE_URL"];
const tokens = process.env["AXIS_GOV_TOKENS"];
const key = process.env["AXIS_GOV_MASTER_KEY"];
const region = process.env["AXIS_GOV_REGION"];
if (!url || !tokens || !key || !region) {
  console.error(
    "AXIS_GOV_DATABASE_URL, AXIS_GOV_TOKENS, AXIS_GOV_MASTER_KEY and AXIS_GOV_REGION are required",
  );
  process.exit(2);
}
const pool = new pg.Pool({ connectionString: url });
const o = { pool, role: process.env["AXIS_GOV_ROLE"] ?? "axis_governance" };
const store = new PgGovernanceStore(o);
const providers = [
  new ChannelsProvider(o, true),
  new ChannelsProvider(o),
  new MemoryProvider(o),
  new MembersProvider(o),
  new BillingProvider(o),
  new EvalHubProvider(o),
  new RunLogsProvider(o),
  new ApprovalsProvider({ pg: o }),
];
const keys = new MasterKeyProvider(Buffer.from(key, "hex"));
const pseudo = new Pseudonymiser(keys);
const sealer = new Sealer(keys);
// Dev: audit events go to an in-process chain (NEEDS 371: wire the shared audit service sink).
const audit = new GovernanceAudit(new MemoryAuditLog());
const holds = new HoldRegistry({ store, pseudo, sealer, audit, now: () => new Date() });
const residency = new ResidencyPolicy({
  resolve: async (t) => {
    const c = await pool.connect();
    try {
      const r = await c.query("SELECT region FROM tenants WHERE id = $1", [t]);
      return r.rows[0] ? { homeRegion: r.rows[0].region as string } : undefined;
    } finally {
      c.release();
    }
  },
});
const verifier = { verify: async () => ({ ok: false, method: "none-configured" }) }; // fail closed until a real verifier is wired
const dsar = new DsarEngine({
  store,
  pseudo,
  sealer,
  providers,
  audit,
  verifier,
  residency,
  holds,
  signer: new ManifestSigner(),
  serviceRegion: region,
});
const retention = new RetentionEngine({
  store,
  providers,
  holds,
  audit,
  settings: { get: async () => undefined }, // fail closed until the control-plane port is wired (NEEDS 369)
});
const server = createAdminServer({
  dsar,
  holds,
  retention,
  authenticate: staticTokenAuthenticator(JSON.parse(tokens) as Record<string, Principal>),
});
const port = await listenLoopback(server, Number(process.env["AXIS_GOV_PORT"] ?? 0));
console.log(`listening ${port}`);
process.on("SIGTERM", () => {
  server.close();
  void pool.end();
});
