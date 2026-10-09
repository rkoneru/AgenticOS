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
import {
  createGateServer,
  listen,
  staticTokenAuthenticator,
  type Authenticator,
  type Principal,
} from "./grpc.js";
import { WasmPolicyEngine } from "./engine.js";
import { ReloadingTokenTable, TenantBundleEngine } from "./tenant-engine.js";
import { RiskKernel } from "./kernel.js";
import { MemoryAuditSink } from "./memory-sink.js";
import { FileKillSwitchStore } from "./file-kill-switch.js";
import { FileToolCatalog } from "./capability.js";
import { MemoryCounterStore, MemoryKillSwitchStore } from "./stores.js";

// AXIS_POLICY_BUNDLE (one wasm bundle for every tenant) XOR AXIS_POLICY_BUNDLE_DIR (DEV, Phase 6: `<tenant uuid>.tar.gz` per tenant,
// written by the control plane when a tenant activates a pack; a tenant without a bundle is DENIED). With the directory form the token
// file is re-read when it changes (AXIS_RK_TOKENS_RELOAD is implied) so tenants created after start can be given a token.
const bundle = process.env["AXIS_POLICY_BUNDLE"];
const bundleDir = process.env["AXIS_POLICY_BUNDLE_DIR"];
const tokens = process.env["AXIS_RK_TOKENS"];
if ((!bundle && !bundleDir) || (bundle && bundleDir) || !tokens) {
  console.error(
    "exactly one of AXIS_POLICY_BUNDLE (wasm bundle .tar.gz) or AXIS_POLICY_BUNDLE_DIR (per-tenant bundles), and AXIS_RK_TOKENS (json file: token -> principal), are required",
  );
  process.exit(1);
}
const engine = bundleDir
  ? new TenantBundleEngine(bundleDir)
  : await WasmPolicyEngine.fromBundle(readFileSync(bundle as string));
// AXIS_AUDIT_PG_URL: durable hash-chained audit in Postgres (connect as the axis_app role). Otherwise in-memory (dev only).
const pgUrl = process.env["AXIS_AUDIT_PG_URL"];
// An idle pooled connection that Postgres drops (failover, restart, network cut) emits "error" on the POOL; unhandled it would crash the
// kernel (found by the Phase 9 chaos suite). The next use reconnects; meanwhile every decision is DENIED "audit unavailable".
const auditPool = pgUrl ? new pg.Pool({ connectionString: pgUrl }) : undefined;
auditPool?.on("error", (e) =>
  console.error(
    JSON.stringify({ level: "error", msg: "idle postgres client error", error: e.message }),
  ),
);
const audit: AuditSink = auditPool
  ? new PgAuditLog({
      pool: auditPool,
      ...(process.env["AXIS_AUDIT_PG_ROLE"] ? { role: process.env["AXIS_AUDIT_PG_ROLE"] } : {}),
    })
  : new MemoryAuditSink();
// AXIS_RK_KILL_STATE_FILE: engaged kill-switches survive a restart (single instance; Redis is the multi-instance answer, docs/NEEDS.md).
// Without it the state is in memory and a restart RELEASES every switch (dev only).
const killStateFile = process.env["AXIS_RK_KILL_STATE_FILE"];
const killSwitches = killStateFile
  ? new FileKillSwitchStore(killStateFile)
  : new MemoryKillSwitchStore();
const counters = new MemoryCounterStore();
// AXIS_APPROVALS_HMAC_KEY (hex, >= 32 bytes): wires an in-process approvals service (in-memory store, same audit chain) into the
// kernel's requester/verifier ports. Without it REQUIRE_APPROVAL yields an empty approval_id (clients DENY).
// AXIS_APPROVALS_DEV_BRIDGE=1 additionally serves the loopback dev bridge (docs/NEEDS.md #62): e2e/dev only, NOT an approver API.
const reloading = bundleDir ? new ReloadingTokenTable<Principal>(tokens) : undefined;
const tokenTable = reloading
  ? {}
  : (JSON.parse(readFileSync(tokens, "utf8")) as Record<string, Principal>);
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
// AXIS_RK_TOOL_CATALOG_FILE: JSON {"<tenant uuid>": {"<tool name>": "none|read|write|external"}}, the tenants' pre-registered tool
// side-effects (authoritative over a blueprint's label, ADR 0110). Without it the kernel classifies from name, kind and argument keys.
const catalogFile = process.env["AXIS_RK_TOOL_CATALOG_FILE"];
const toolCatalog = catalogFile
  ? new FileToolCatalog(catalogFile) // re-read when the file changes; a bad file denies tool calls (fail closed)
  : undefined;
const kernel = new RiskKernel({
  engine,
  ...(toolCatalog ? { toolCatalog } : {}),
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
const authenticate: Authenticator = reloading
  ? (md) => {
      const h = md.get("authorization")[0];
      const token = typeof h === "string" && h.startsWith("Bearer ") ? h.slice(7) : undefined;
      return Promise.resolve(token === undefined ? undefined : reloading.get(token));
    }
  : staticTokenAuthenticator(tokenTable);
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
      // With the reloading token table (per-tenant bundles, Phase 6/7) tenants created after start get their bridge access from the same
      // token file the gate uses; the static table is read once.
      authenticate: reloading
        ? (authorization) => {
            const token = authorization?.startsWith("Bearer ") ? authorization.slice(7) : undefined;
            return Promise.resolve(
              token === undefined ? undefined : (reloading.get(token)?.tenantId ?? undefined),
            );
          }
        : staticTenantAuthenticator(tenants),
    }),
    Number(process.env["AXIS_APPROVALS_PORT"] ?? "0"),
  );
}
console.log(JSON.stringify({ event: "listening", port, approvals_port: approvalsPort ?? null }));
for (const sig of ["SIGINT", "SIGTERM"] as const)
  process.on(sig, () => server.tryShutdown(() => process.exit(0)));
