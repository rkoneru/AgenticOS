import type { ApprovalService } from "@axis/approvals";
import type { UsageLedger } from "@axis/billing";
import {
  AdminAudit,
  type Authorizer,
  type ControlPlane,
  type ControlPlaneStore,
} from "@axis/control-plane";
import {
  ComplianceAudit,
  createCompliance,
  type Compliance,
  type DocSealer,
  type DocStore,
  type LimitationsSourcePort,
} from "@axis/compliance";
import type { EvalHub } from "@axis/eval-hub";
import type { Marketplace } from "@axis/marketplace";
import type { RegistryService } from "@axis/registry";
import type { GatewayDeps, GatewayOptions } from "./context.js";
import { MemoryIdempotencyStore } from "./limits.js";
import { MemoryBlueprintStore } from "./memory.js";
import { AgilExplain, AuditAdapter, type AuditStoreLike } from "./adapters/audit.js";
import { ApprovalsAdapter } from "./adapters/approvals.js";
import {
  ControlPlaneApiAudit,
  ControlPlaneAuthenticator,
  ControlPlaneAuthz,
  ControlPlaneIdentity,
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
import { ComplianceAdapter, UnavailableCompliance } from "./adapters/compliance.js";
import { gatewayComplianceSources } from "./adapters/compliance-sources.js";
import { EvalsAdapter, UnavailableEvals } from "./adapters/evals.js";
import { MarketplaceAdapter } from "./adapters/marketplace.js";
import { RegistryAdapter } from "./adapters/registry.js";
import { HttpRunsPort } from "./adapters/runs-http.js";
import { LedgerUsage } from "./adapters/usage.js";
import type { BlueprintStore, RunsPort } from "./ports.js";
import { createGateway, type Gateway } from "./server.js";

export interface DevWiring {
  controlPlane: Pick<ControlPlane, "apiKeys" | "sessions" | "policies" | "admin">;
  authorizer: Pick<Authorizer, "decide">;
  store: Pick<ControlPlaneStore, "listPackVersions" | "getTenant" | "getMember">;
  registry: RegistryService;
  marketplace: Marketplace;
  /** The Eval Hub. Without one every evals operation answers 503 (fail-closed); wire the SAME hub into the registry's `evalGate`. */
  evals?: EvalHub;
  /** The tenant's audit store (gateway events are appended here, AGIL reads it through a frozen reader). */
  audit: AuditStoreLike & { append(e: never): Promise<unknown> };
  approvals: Pick<ApprovalService, "list" | "approve" | "deny" | "get">;
  ledger: Pick<UsageLedger, "entries">;
  /** Run service base URL and the per-tenant bearer table (tenant id -> token). */
  runs: { url: string; tokens: Readonly<Record<string, string>> } | RunsPort;
  /** Kernel gRPC target and per-tenant kernel credentials, or an applier of your own. */
  kernel: { target: string; tokens: Readonly<Record<string, string>> } | KernelKillApplier;
  blueprints?: BlueprintStore;
  /**
   * The compliance service: a ready `Compliance`, or `{ docs, sealer, limitations }` to build one whose document sources are this
   * gateway's own ports (same tenant scoping, same roles). Without it every compliance operation answers 503 (fail-closed).
   */
  compliance?:
    | Compliance
    | {
        docs: DocStore;
        sealer: DocSealer;
        trustedSealers?: readonly DocSealer[];
        limitations: LimitationsSourcePort;
        maxAuditEvents?: number;
      };
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
  const blueprints = w.blueprints ?? new MemoryBlueprintStore();
  const registryPort = new RegistryAdapter(w.registry);
  const evalsPort = w.evals ? new EvalsAdapter(w.evals) : new UnavailableEvals();
  const policiesPort = new ControlPlanePolicies({
    packs: w.controlPlane.policies,
    tester: new OpaCliPolicyTester(),
    admin: w.controlPlane.admin,
  });
  const auditPort = new AuditAdapter(w.audit);
  const compliance = ((): ComplianceAdapter | UnavailableCompliance => {
    const c = w.compliance;
    if (!c) return new UnavailableCompliance();
    if ("documents" in c) return new ComplianceAdapter(c);
    return new ComplianceAdapter(
      createCompliance({
        docs: c.docs,
        audit: new ComplianceAudit(w.audit as never),
        sealer: c.sealer,
        ...(c.trustedSealers ? { trustedSealers: c.trustedSealers } : {}),
        sources: gatewayComplianceSources({
          blueprints,
          registry: registryPort,
          evals: evalsPort,
          policies: policiesPort,
          auditLog: auditPort,
          limitations: c.limitations,
          ...(c.maxAuditEvents !== undefined ? { maxAuditEvents: c.maxAuditEvents } : {}),
        }),
      }),
    );
  })();
  const deps: GatewayDeps = {
    auth: new ControlPlaneAuthenticator({
      apiKeys: w.controlPlane.apiKeys,
      sessions: w.controlPlane.sessions,
    }),
    authz: new ControlPlaneAuthz(w.authorizer),
    audit: new ControlPlaneApiAudit(new AdminAudit(w.audit as never)),
    blueprints,
    runs,
    approvals: new ApprovalsAdapter(w.approvals),
    policies: policiesPort,
    auditLog: auditPort,
    killSwitches: new KillSwitchService(kernel, new MemoryKillSwitchRecords()),
    usage: new LedgerUsage(w.ledger),
    explain: new AgilExplain(w.audit, new StorePolicyMetadata(w.store)),
    identity: new ControlPlaneIdentity(w.store),
    registry: registryPort,
    marketplace: new MarketplaceAdapter(w.marketplace),
    evals: evalsPort,
    compliance,
    idempotency: new MemoryIdempotencyStore(),
  };
  return { gateway: createGateway(deps, { validateResponses: true, ...options }), deps };
}
