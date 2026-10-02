import type { ApprovalService } from "@axis/approvals";
import type { UsageLedger } from "@axis/billing";
import {
  AdminAudit,
  type Authorizer,
  type ControlPlane,
  type ControlPlaneStore,
} from "@axis/control-plane";
import type { GatewayDeps, GatewayOptions } from "./context.js";
import { MemoryIdempotencyStore } from "./limits.js";
import { MemoryBlueprintStore } from "./memory.js";
import { AgilExplain, AuditAdapter, type AuditStoreLike } from "./adapters/audit.js";
import { ApprovalsAdapter } from "./adapters/approvals.js";
import {
  ControlPlaneApiAudit,
  ControlPlaneAuthenticator,
  ControlPlaneAuthz,
  ControlPlanePolicies,
  OpaCliPolicyTester,
  StorePolicyMetadata,
} from "./adapters/control-plane.js";
import {
  GrpcKernelKillApplier,
  KillSwitchService,
  MemoryKillSwitchRecords,
  type KernelKillApplier,
} from "./adapters/kernel.js";
import { HttpRunsPort } from "./adapters/runs-http.js";
import { LedgerUsage } from "./adapters/usage.js";
import type { BlueprintStore, RunsPort } from "./ports.js";
import { createGateway, type Gateway } from "./server.js";

export interface DevWiring {
  controlPlane: ControlPlane;
  authorizer: Pick<Authorizer, "decide">;
  store: Pick<ControlPlaneStore, "listPackVersions">;
  /** The tenant's audit store (gateway events are appended here, AGIL reads it through a frozen reader). */
  audit: AuditStoreLike & { append(e: never): Promise<unknown> };
  approvals: Pick<ApprovalService, "list" | "approve" | "deny">;
  ledger: Pick<UsageLedger, "entries">;
  /** Run service base URL and the per-tenant bearer table (tenant id -> token). */
  runs: { url: string; tokens: Readonly<Record<string, string>> } | RunsPort;
  /** Kernel gRPC target and per-tenant kernel credentials, or an applier of your own. */
  kernel: { target: string; tokens: Readonly<Record<string, string>> } | KernelKillApplier;
  blueprints?: BlueprintStore;
}

/** Composition root of the DEV gateway: real control-plane/approvals/audit/billing classes in-process, the run service over HTTP, the kernel over gRPC. */
export function wireGateway(
  w: DevWiring,
  options: GatewayOptions = {},
): { gateway: Gateway; deps: GatewayDeps } {
  const runs: RunsPort =
    "start" in w.runs
      ? w.runs
      : new HttpRunsPort(w.runs.url, (t) =>
          w.runs && "tokens" in w.runs ? w.runs.tokens[t] : undefined,
        );
  const kernel: KernelKillApplier =
    "apply" in w.kernel
      ? w.kernel
      : new GrpcKernelKillApplier(
          w.kernel.target,
          (t) => (w.kernel as { tokens: Record<string, string> }).tokens[t],
        );
  const deps: GatewayDeps = {
    auth: new ControlPlaneAuthenticator({
      apiKeys: w.controlPlane.apiKeys,
      sessions: w.controlPlane.sessions,
    }),
    authz: new ControlPlaneAuthz(w.authorizer),
    audit: new ControlPlaneApiAudit(new AdminAudit(w.audit as never)),
    blueprints: w.blueprints ?? new MemoryBlueprintStore(),
    runs,
    approvals: new ApprovalsAdapter(w.approvals),
    policies: new ControlPlanePolicies({
      packs: w.controlPlane.policies,
      tester: new OpaCliPolicyTester(),
    }),
    auditLog: new AuditAdapter(w.audit),
    killSwitches: new KillSwitchService(kernel, new MemoryKillSwitchRecords()),
    usage: new LedgerUsage(w.ledger),
    explain: new AgilExplain(w.audit, new StorePolicyMetadata(w.store)),
    idempotency: new MemoryIdempotencyStore(),
  };
  return { gateway: createGateway(deps, { validateResponses: true, ...options }), deps };
}
