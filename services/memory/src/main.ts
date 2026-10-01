/* Dev/e2e entry point: `AXIS_MEMORY_DATABASE_URL=... AXIS_MEMORY_TOKENS='{"tok":{"tenantId":"<uuid>","admin":false}}' node dist/main.js`.
   Uses the deterministic HashEmbedder (no provider is called; docs/NEEDS.md). Prints `listening <port>` on stdout. */
import pg from "pg";
import {
  createDevServer,
  listenLoopback,
  staticTokenAuthenticator,
  type DevAuth,
} from "./dev-server.js";
import { HashEmbedder } from "./embedder.js";
import { PgMemoryService } from "./store.js";

const url = process.env["AXIS_MEMORY_DATABASE_URL"];
const tokens = process.env["AXIS_MEMORY_TOKENS"];
if (!url || !tokens) {
  console.error("AXIS_MEMORY_DATABASE_URL and AXIS_MEMORY_TOKENS are required");
  process.exit(2);
}
const role = process.env["AXIS_MEMORY_ROLE"]; // e.g. axis_app when connecting as a superuser in dev
const pool = new pg.Pool({ connectionString: url });
const service = new PgMemoryService({
  pool,
  embedder: new HashEmbedder(),
  ...(role ? { role } : {}),
});
const server = createDevServer({
  service,
  authenticate: staticTokenAuthenticator(JSON.parse(tokens) as Record<string, DevAuth>),
});
const port = await listenLoopback(server, Number(process.env["AXIS_MEMORY_PORT"] ?? 0));
console.log(`listening ${port}`);
process.on("SIGTERM", () => {
  server.close();
  void pool.end();
});
