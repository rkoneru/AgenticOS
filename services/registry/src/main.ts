/* Dev/e2e entry point (loopback, static tokens, NOT production):
   AXIS_REGISTRY_DATABASE_URL=... AXIS_REGISTRY_TOKENS='{"tok":{"tenantId":"<uuid>","subject":"u1","role":"admin"}}' node dist/main.js
   Prints `listening <port>` on stdout. Audit goes to an in-memory chain (the tenant audit service has no network surface yet: NEEDS). */
import { MemoryAuditLog } from "@axis/audit";
import pg from "pg";
import { ServiceAudit } from "./audit.js";
import { createRegistryDevServer, type DevTenantAuth } from "./dev-server.js";
import { listenLoopback } from "./http-kit.js";
import { PgRegistryStore } from "./pg-store.js";
import { RegistryService } from "./service.js";

const url = process.env["AXIS_REGISTRY_DATABASE_URL"];
const tokens = process.env["AXIS_REGISTRY_TOKENS"];
if (!url || !tokens) {
  console.error("AXIS_REGISTRY_DATABASE_URL and AXIS_REGISTRY_TOKENS are required");
  process.exit(2);
}
const role = process.env["AXIS_REGISTRY_ROLE"]; // e.g. axis_app when connecting as a superuser in dev
const pool = new pg.Pool({ connectionString: url });
pool.on("error", (e) =>
  console.error(
    JSON.stringify({
      level: "error",
      msg: "idle postgres client error (connection lost; the pool reconnects on next use)",
      error: e.message,
    }),
  ),
);
const registry = new RegistryService({
  store: new PgRegistryStore({ pool, ...(role ? { role } : {}) }),
  audit: new ServiceAudit(new MemoryAuditLog(), "registry"),
});
const server = createRegistryDevServer({
  registry,
  tokens: JSON.parse(tokens) as Record<string, DevTenantAuth>,
});
const port = await listenLoopback(server, Number(process.env["AXIS_REGISTRY_PORT"] ?? 0));
console.log(`listening ${port}`);
process.on("SIGTERM", () => {
  server.close();
  void pool.end();
});
