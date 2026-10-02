/* Dev/e2e entry point (loopback, static tokens, NOT production):
   AXIS_BILLING_DATABASE_URL=... AXIS_BILLING_TOKENS='{"tok":{"tenantId":"<uuid>","scopes":["read"],"subject":"svc"}}'
   AXIS_BILLING_SEAL_KEY=<32+ chars> node dist/main.js     Prints `listening <port>` on stdout. */
import { MemoryAuditLog } from "@axis/audit";
import pg from "pg";
import { AdjustmentApi } from "./adjustments.js";
import {
  createDevServer,
  listenLoopback,
  staticTokenAuthenticator,
  type DevAuth,
} from "./dev-server.js";
import { PgInvoiceStore } from "./invoices.js";
import { PgUsageLedger } from "./pg-ledger.js";
import { DEV_PRICE_BOOK } from "./pricebook.js";
import { HmacSealSigner } from "./seal.js";

const url = process.env["AXIS_BILLING_DATABASE_URL"];
const tokens = process.env["AXIS_BILLING_TOKENS"];
const sealKey = process.env["AXIS_BILLING_SEAL_KEY"];
if (!url || !tokens || !sealKey) {
  console.error(
    "AXIS_BILLING_DATABASE_URL, AXIS_BILLING_TOKENS and AXIS_BILLING_SEAL_KEY are required",
  );
  process.exit(2);
}
const role = process.env["AXIS_BILLING_ROLE"]; // e.g. axis_app when connecting as a superuser in dev
const pool = new pg.Pool({ connectionString: url });
const ledger = new PgUsageLedger({
  pool,
  signer: new HmacSealSigner(Buffer.from(sealKey, "utf8")),
  ...(role ? { role } : {}),
});
const server = createDevServer({
  ledger,
  invoices: new PgInvoiceStore({ pool, ...(role ? { role } : {}) }),
  // Dev only: adjustments are audited into an in-memory chain. The tenant audit service has no network surface yet (NEEDS).
  adjustments: new AdjustmentApi({ ledger, audit: new MemoryAuditLog() }),
  authenticate: staticTokenAuthenticator(JSON.parse(tokens) as Record<string, DevAuth>),
  classifyRules: DEV_PRICE_BOOK.modelClasses,
});
const port = await listenLoopback(server, Number(process.env["AXIS_BILLING_PORT"] ?? 0));
console.log(`listening ${port}`);
process.on("SIGTERM", () => {
  server.close();
  void pool.end();
});
