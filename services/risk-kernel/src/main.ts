/* Process entry point (dev/e2e): env-configured kernel with in-memory stores and audit. Excluded from coverage. */
import { readFileSync } from "node:fs";
import {
  ApprovalResolver,
  ApprovalService,
  HmacSigner,
  MemoryApprovalStore,
  createDevBridge,
  kernelApprovalPorts,
  listenLoopback,
  staticTenantAuthenticator,
} from "@axis/approvals";
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
// AXIS_APPROVALS_HMAC_KEY (hex, >= 32 bytes): wires an in-process approvals service (in-memory store, same audit chain) into the
// kernel's requester/verifier ports. Without it REQUIRE_APPROVAL yields an empty approval_id (clients DENY).
// AXIS_APPROVALS_DEV_BRIDGE=1 additionally serves the loopback dev bridge (docs/NEEDS.md #62): e2e/dev only, NOT an approver API.
const tokenTable = JSON.parse(readFileSync(tokens, "utf8")) as Record<string, Principal>;
const hmacKey = process.env["AXIS_APPROVALS_HMAC_KEY"];
const approvals = hmacKey
  ? (() => {
      // Buffer.from(x, "hex") silently truncates at the first bad character, which would quietly weaken the key.
      if (!/^(?:[0-9a-fA-F]{2}){32,}$/.test(hmacKey))
        throw new Error("AXIS_APPROVALS_HMAC_KEY must be hex, at least 32 bytes (64 hex chars)");
      const signer = new HmacSigner(Buffer.from(hmacKey, "hex"));
      const service = new ApprovalService({
        store: new MemoryApprovalStore(),
        audit,
        signer,
        logger: {
          info: () => undefined,
          warn: (m, f) => console.error(JSON.stringify({ level: "warn", m, ...f })),
          error: (m, f) => console.error(JSON.stringify({ level: "error", m, ...f })),
        },
      });
      service.startSweeper(1000);
      return { service, ports: kernelApprovalPorts(service, signer) };
    })()
  : undefined;
const kernel = new RiskKernel({
  engine,
  audit,
  killSwitches,
  counters,
  ...(approvals
    ? {
        approvalRequester: approvals.ports.requester,
        approvalVerifier: approvals.ports.verifier,
      }
    : {}),
  logger: {
    warn: (m, f) => console.error(JSON.stringify({ level: "warn", m, ...f })),
    error: (m, f) => console.error(JSON.stringify({ level: "error", m, ...f })),
  },
});
const authenticate = staticTokenAuthenticator(tokenTable);
const server = createGateServer({ kernel, audit, killSwitches, authenticate });
const port = await listen(server, `127.0.0.1:${process.env["AXIS_RK_PORT"] ?? "0"}`);
let approvalsPort: number | undefined;
if (approvals && process.env["AXIS_APPROVALS_DEV_BRIDGE"] === "1") {
  const tenants: Record<string, string> = {};
  for (const [token, p] of Object.entries(tokenTable)) if (p.tenantId) tenants[token] = p.tenantId;
  approvalsPort = await listenLoopback(
    createDevBridge({
      service: approvals.service,
      resolver: new ApprovalResolver(approvals.service),
      authenticate: staticTenantAuthenticator(tenants),
    }),
    Number(process.env["AXIS_APPROVALS_PORT"] ?? "0"),
  );
}
console.log(JSON.stringify({ event: "listening", port, approvals_port: approvalsPort ?? null }));
for (const sig of ["SIGINT", "SIGTERM"] as const)
  process.on(sig, () => server.tryShutdown(() => process.exit(0)));
