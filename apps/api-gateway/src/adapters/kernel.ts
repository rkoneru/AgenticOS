import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { PortConflict, PortForbidden, PortUnavailable, type KillSwitchDto, type KillSwitchPort, type Principal } from "../ports.js";

export interface KillRequest {
  tenantId: string;
  scope: "tenant" | "agent" | "tool";
  target?: string;
  engaged: boolean;
  reason?: string;
}

/** Applies a kill-switch in the Risk Kernel. The tenant is the CREDENTIAL's tenant. Throws when the kernel did not apply it. */
export interface KernelKillApplier {
  apply(r: KillRequest): Promise<{ auditEventId: string }>;
}

export interface KillSwitchRecords {
  upsert(tenantId: string, rec: KillSwitchDto): Promise<void>;
  list(tenantId: string): Promise<KillSwitchDto[]>;
}

const PROTO_ROOT = fileURLToPath(new URL("../../../../proto/", import.meta.url));
const SCOPES = { tenant: "SCOPE_TENANT", agent: "SCOPE_AGENT", tool: "SCOPE_TOOL" } as const;

type GateClient = grpc.Client & {
  SetKillSwitch(
    req: Record<string, unknown>,
    md: grpc.Metadata,
    opts: { deadline: Date },
    cb: (err: grpc.ServiceError | null, res?: { engaged?: boolean; audit_event_id?: string }) => void,
  ): void;
};

/** gRPC client of `GateService.SetKillSwitch`. `tokenFor(tenant)` returns the kernel credential bound to that tenant (dev: static table). */
export class GrpcKernelKillApplier implements KernelKillApplier {
  private readonly client: GateClient;
  constructor(
    target: string,
    private readonly tokenFor: (tenantId: string) => string | undefined,
    private readonly timeoutMs = 5000,
  ) {
    const def = protoLoader.loadSync("axis/runtime/v1/gate.proto", { includeDirs: [PROTO_ROOT], keepCase: true, longs: String, enums: String, defaults: false, oneofs: true });
    const pkg = grpc.loadPackageDefinition(def) as unknown as { axis: { runtime: { v1: { GateService: new (t: string, c: grpc.ChannelCredentials) => GateClient } } } };
    this.client = new pkg.axis.runtime.v1.GateService(target, grpc.credentials.createInsecure());
  }

  apply(r: KillRequest): Promise<{ auditEventId: string }> {
    const token = this.tokenFor(r.tenantId);
    if (!token) return Promise.reject(new PortUnavailable("no kernel credential for this tenant"));
    const md = new grpc.Metadata();
    md.set("authorization", `Bearer ${token}`);
    return new Promise((resolve, reject) => {
      this.client.SetKillSwitch(
        { tenant_id: r.tenantId, scope: SCOPES[r.scope], target: r.target ?? "", engaged: r.engaged, reason: r.reason ?? "" },
        md,
        { deadline: new Date(Date.now() + this.timeoutMs) },
        (err, res) => {
          if (err) {
            if (err.code === grpc.status.PERMISSION_DENIED) return reject(new PortForbidden("the kernel refused the kill-switch change"));
            if (err.code === grpc.status.FAILED_PRECONDITION) return reject(new PortConflict("the kernel cannot record the release; try again later"));
            return reject(new PortUnavailable("the Risk Kernel is unavailable; the kill-switch was not changed"));
          }
          resolve({ auditEventId: res?.audit_event_id ?? "" });
        },
      );
    });
  }

  close(): void {
    this.client.close();
  }
}

export class MemoryKillSwitchRecords implements KillSwitchRecords {
  private readonly rows = new Map<string, Map<string, KillSwitchDto>>();
  async upsert(tenantId: string, rec: KillSwitchDto): Promise<void> {
    const t = this.rows.get(tenantId) ?? new Map<string, KillSwitchDto>();
    t.set(`${rec.scope}\u0000${rec.target ?? ""}`, { ...rec });
    this.rows.set(tenantId, t);
  }
  async list(tenantId: string): Promise<KillSwitchDto[]> {
    return [...(this.rows.get(tenantId)?.values() ?? [])].map((r) => ({ ...r }));
  }
}

/**
 * The kernel is the authority: the switch is applied THERE first (engaging is never blocked by the record store), and only a
 * confirmed application is recorded for listing. If the kernel cannot be reached, nothing is recorded and the caller gets a 503, so
 * the list never claims a state the kernel does not hold.
 */
export class KillSwitchService implements KillSwitchPort {
  constructor(
    private readonly kernel: KernelKillApplier,
    private readonly records: KillSwitchRecords,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async list(tenantId: string): Promise<KillSwitchDto[]> {
    return (await this.records.list(tenantId)).filter((r) => r.engaged).sort((a, b) => (a.scope + (a.target ?? "")).localeCompare(b.scope + (b.target ?? "")));
  }

  async set(p: Principal, r: { scope: "tenant" | "agent" | "tool"; target?: string; engaged: boolean; reason?: string }): Promise<KillSwitchDto> {
    await this.kernel.apply({ tenantId: p.tenantId, ...r });
    const rec: KillSwitchDto = {
      scope: r.scope,
      target: r.scope === "tenant" ? null : (r.target ?? null),
      engaged: r.engaged,
      reason: r.reason ?? null,
      updated_at: this.now().toISOString(),
    };
    try {
      await this.records.upsert(p.tenantId, rec);
    } catch {
      // The kernel already holds the new state; the listing will catch up on the next change. Never undo a safety action.
    }
    return rec;
  }
}
