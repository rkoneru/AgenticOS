/* Dev/e2e entry point (loopback, static tokens, NOT production):
   AXIS_EVALHUB_DATABASE_URL=... AXIS_EVALHUB_TOKENS='{"tok":{"kind":"tenant","tenantId":"<uuid>","subject":"u1","role":"admin"},
     "rtok":{"kind":"runner","tenantId":"<uuid>","runnerId":"runner-1"}}' node dist/main.js
   Prints `listening <port>` on stdout. Audit goes to an in-memory chain (the tenant audit service has no network surface yet: NEEDS). */
import { MemoryAuditLog } from "@axis/audit";
import { ServiceAudit, listenLoopback } from "@axis/registry";
import pg from "pg";
import { createHubDevServer, type DevAuth } from "./dev-server.js";
import { PgDocStore } from "./docstore.js";
import { createEvalHub } from "./hub.js";

const url = process.env["AXIS_EVALHUB_DATABASE_URL"];
const tokens = process.env["AXIS_EVALHUB_TOKENS"];
if (!url || !tokens) {
  console.error("AXIS_EVALHUB_DATABASE_URL and AXIS_EVALHUB_TOKENS are required");
  process.exit(2);
}
const role = process.env["AXIS_EVALHUB_ROLE"]; // e.g. axis_app when connecting as a superuser in dev
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
const hub = createEvalHub({
  docs: new PgDocStore({ pool, ...(role ? { role } : {}) }),
  audit: new ServiceAudit(new MemoryAuditLog(), "eval-hub"),
});
const server = createHubDevServer({ hub, tokens: JSON.parse(tokens) as Record<string, DevAuth> });
const port = await listenLoopback(server, Number(process.env["AXIS_EVALHUB_PORT"] ?? 0));
console.log(`listening ${port}`);
process.on("SIGTERM", () => {
  server.close();
  void pool.end();
});
