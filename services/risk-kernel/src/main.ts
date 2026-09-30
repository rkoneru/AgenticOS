/* Process entry point (dev/e2e): env-configured kernel with in-memory stores and audit. Excluded from coverage. */
import { readFileSync } from "node:fs";
import { PgAuditLog } from "@axis/audit";
import type { AuditSink } from "@axis/contracts";
import pg from "pg";
import { createGateServer, listen, staticTokenAuthenticator, type Principal } from "./grpc.js";
import { WasmPolicyEngine } from "./engine.js";
import { RiskKernel } from "./kernel.js";
import { MemoryAuditSink } from "./memory-sink.js";
import { MemoryCounterStore, MemoryKillSwitchStore } from "./stores.js";

const bundle = process.env["AXIS_POLICY_BUNDLE"];
const tokens = process.env["AXIS_RK_TOKENS"];
if (!bundle || !tokens) {
  console.error(
    "AXIS_POLICY_BUNDLE (wasm bundle .tar.gz) and AXIS_RK_TOKENS (json file: token -> principal) are required",
  );
  process.exit(1);
}
const engine = await WasmPolicyEngine.fromBundle(readFileSync(bundle));
// AXIS_AUDIT_PG_URL: durable hash-chained audit in Postgres (connect as the axis_app role). Otherwise in-memory (dev only).
const pgUrl = process.env["AXIS_AUDIT_PG_URL"];
const audit: AuditSink = pgUrl
  ? new PgAuditLog({
      pool: new pg.Pool({ connectionString: pgUrl }),
      ...(process.env["AXIS_AUDIT_PG_ROLE"] ? { role: process.env["AXIS_AUDIT_PG_ROLE"] } : {}),
    })
  : new MemoryAuditSink();
const killSwitches = new MemoryKillSwitchStore();
const counters = new MemoryCounterStore();
const kernel = new RiskKernel({
  engine,
  audit,
  killSwitches,
  counters,
  logger: {
    warn: (m, f) => console.error(JSON.stringify({ level: "warn", m, ...f })),
    error: (m, f) => console.error(JSON.stringify({ level: "error", m, ...f })),
  },
});
const authenticate = staticTokenAuthenticator(
  JSON.parse(readFileSync(tokens, "utf8")) as Record<string, Principal>,
);
const server = createGateServer({ kernel, audit, killSwitches, authenticate });
const port = await listen(server, `127.0.0.1:${process.env["AXIS_RK_PORT"] ?? "0"}`);
console.log(JSON.stringify({ event: "listening", port }));
for (const sig of ["SIGINT", "SIGTERM"] as const)
  process.on(sig, () => server.tryShutdown(() => process.exit(0)));
