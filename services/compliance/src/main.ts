/* Dev/e2e entry point (loopback, static tokens, NOT production):
   AXIS_COMPLIANCE_DATABASE_URL=... AXIS_COMPLIANCE_TOKENS='{"tok":{"tenantId":"<uuid>","subject":"u1","role":"admin"}}' node dist/main.js
   Prints `listening <port>` on stdout. Document sources are NOT wired in this process (every source is reported as a gap); audit goes to
   an in-memory chain (the tenant audit service has no network surface yet: NEEDS). */
import { MemoryAuditLog } from "@axis/audit";
import pg from "pg";
import { ComplianceAudit } from "./audit.js";
import { createComplianceDevServer, listenLoopback, type DevAuth } from "./dev-server.js";
import { PgDocStore } from "./docstore.js";
import { missing } from "./docgen/ports.js";
import { HmacSealer } from "./docgen/seal.js";
import { createCompliance } from "./hub.js";

const url = process.env["AXIS_COMPLIANCE_DATABASE_URL"];
const tokens = process.env["AXIS_COMPLIANCE_TOKENS"];
const seal = process.env["AXIS_COMPLIANCE_SEAL_SECRET"];
if (!url || !tokens || !seal || seal.length < 16) {
  console.error(
    "AXIS_COMPLIANCE_DATABASE_URL, AXIS_COMPLIANCE_TOKENS and AXIS_COMPLIANCE_SEAL_SECRET (>= 16 chars) are required",
  );
  process.exit(2);
}
const role = process.env["AXIS_COMPLIANCE_ROLE"];
const pool = new pg.Pool({ connectionString: url });
const none = (): Promise<ReturnType<typeof missing<never>>> =>
  Promise.resolve(missing<never>("source not wired in the standalone dev process"));
const compliance = createCompliance({
  docs: new PgDocStore({ pool, ...(role ? { role } : {}) }),
  audit: new ComplianceAudit(new MemoryAuditLog()),
  sealer: new HmacSealer(Buffer.from(seal, "utf8"), "dev-seal"),
  sources: {
    blueprints: { get: none },
    evals: { evidence: none },
    policies: { activePacks: none },
    audit: { statistics: none },
    limitations: { list: none },
  },
});
const server = createComplianceDevServer({
  compliance,
  tokens: JSON.parse(tokens) as Record<string, DevAuth>,
});
const port = await listenLoopback(server, Number(process.env["AXIS_COMPLIANCE_PORT"] ?? 0));
console.log(`listening ${port}`);
process.on("SIGTERM", () => {
  server.close();
  void pool.end();
});
