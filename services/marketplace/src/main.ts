/* Dev/e2e entry point (loopback, static tokens, NOT production). Registry and marketplace share one Postgres:
   AXIS_MARKETPLACE_DATABASE_URL=... AXIS_MARKETPLACE_TOKENS='{"tok":{"kind":"tenant","tenantId":"<uuid>","subject":"u1","role":"admin"}}' node dist/main.js
   Domain/identity proofs are FAKES; audit is an in-memory chain; no usage hook unless a billing endpoint is wired (NEEDS 260+). */
import { MemoryAuditLog } from "@axis/audit";
import { PgRegistryStore, RegistryService, ServiceAudit, listenLoopback } from "@axis/registry";
import pg from "pg";
import { PgDocStore } from "./docstore.js";
import { createMarketplaceDevServer, type DevAuth } from "./dev-server.js";
import { FakeDomainProver, FakeIdentityProver } from "./publishers.js";
import { createMarketplace } from "./service.js";

const url = process.env["AXIS_MARKETPLACE_DATABASE_URL"];
const tokens = process.env["AXIS_MARKETPLACE_TOKENS"];
if (!url || !tokens) {
  console.error("AXIS_MARKETPLACE_DATABASE_URL and AXIS_MARKETPLACE_TOKENS are required");
  process.exit(2);
}
const role = process.env["AXIS_MARKETPLACE_ROLE"];
const pool = new pg.Pool({ connectionString: url });
const audit = new MemoryAuditLog();
const registry = new RegistryService({
  store: new PgRegistryStore({ pool, ...(role ? { role } : {}) }),
  audit: new ServiceAudit(audit, "registry"),
});
const marketplace = createMarketplace({
  docs: new PgDocStore({ pool, ...(role ? { role } : {}) }),
  registry,
  audit: new ServiceAudit(audit, "marketplace"),
  domain: new FakeDomainProver(),
  identity: new FakeIdentityProver(),
});
const server = createMarketplaceDevServer({
  marketplace,
  tokens: JSON.parse(tokens) as Record<string, DevAuth>,
});
const port = await listenLoopback(server, Number(process.env["AXIS_MARKETPLACE_PORT"] ?? 0));
console.log(`listening ${port}`);
process.on("SIGTERM", () => {
  server.close();
  void pool.end();
});
