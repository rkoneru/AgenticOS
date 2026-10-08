import { randomBytes, randomUUID } from "node:crypto";
import { MemoryAuditLog } from "@axis/audit";
import pg from "pg";
import { inject } from "vitest";
import {
  DsarEngine,
  GovernanceAudit,
  HoldRegistry,
  ManifestSigner,
  MasterKeyProvider,
  MemoryGovernanceStore,
  Pseudonymiser,
  ResidencyPolicy,
  RetentionEngine,
  Sealer,
  type CountResult,
  type DsarDeps,
  type EraseResult,
  type ExportCollection,
  type FindResult,
  type GovernanceStore,
  type Identifier,
  type Principal,
  type ProviderContext,
  type ProviderDeclaration,
  type PurgeRequest,
  type PurgeResult,
  type RequesterVerifier,
  type RetentionSettingsPort,
  type SubjectDataProvider,
  type TenantRetentionSettings,
} from "../src/index.js";

export const hex = (n: number): string => randomBytes(n / 2).toString("hex");
export const ROLE = "axis_governance";

export const officer = (tenantId: string, id = "officer-1"): Principal => ({
  tenantId,
  id,
  roles: ["privacy_officer"],
});
export const adminOnly = (tenantId: string): Principal => ({
  tenantId,
  id: "admin-1",
  roles: ["admin", "owner"],
});

export const email = (v = "Jane.Doe@Example.com"): Identifier => ({ kind: "email", value: v });

/** Fake store with rows owned by identifier values. `sticky` rows are never erased (a buggy provider). */
interface Row {
  id: string;
  owner: string;
  payload: string;
  sticky?: boolean;
  createdAt?: Date;
}
export class FakeProvider implements SubjectDataProvider {
  rows = new Map<string, Row[]>();
  erasedCalls = 0;
  readonly declaration: ProviderDeclaration;
  constructor(
    readonly id: string,
    private readonly opts: {
      classes?: ProviderDeclaration["dataClasses"];
      retainAfter?: boolean;
      discover?: Identifier[];
    } = {},
  ) {
    this.declaration = {
      exports: ["fake rows"],
      erases: ["fake rows"],
      retains: opts.retainAfter ? [{ what: "ledger", legalBasis: "test" }] : [],
      pseudonymises: [],
      dataClasses: opts.classes ?? ["memory"],
    };
  }
  put(tenant: string, owner: string, payload = "secret", extra: Partial<Row> = {}): Row {
    const r: Row = { id: randomUUID(), owner, payload, ...extra };
    const list = this.rows.get(tenant) ?? [];
    list.push(r);
    this.rows.set(tenant, list);
    return r;
  }
  all(tenant: string): Row[] {
    return this.rows.get(tenant) ?? [];
  }
  private mine(tenant: string, ids: readonly Identifier[]): Row[] {
    const v = new Set(ids.map((i) => i.value));
    return this.all(tenant).filter((r) => v.has(r.owner));
  }
  async find(ctx: ProviderContext, ids: readonly Identifier[]): Promise<FindResult> {
    return {
      count: this.mine(ctx.tenantId, ids).length,
      ...(this.opts.discover ? { discovered: this.opts.discover } : {}),
    };
  }
  async export(ctx: ProviderContext, ids: readonly Identifier[]): Promise<ExportCollection[]> {
    return [
      {
        name: "rows",
        records: this.mine(ctx.tenantId, ids).map((r) => ({ id: r.id, payload: r.payload })),
      },
    ];
  }
  async erase(ctx: ProviderContext, ids: readonly Identifier[]): Promise<EraseResult> {
    this.erasedCalls++;
    const mine = this.mine(ctx.tenantId, ids).filter((r) => !r.sticky);
    const set = new Set(mine);
    this.rows.set(
      ctx.tenantId,
      this.all(ctx.tenantId).filter((r) => !set.has(r)),
    );
    return { erased: mine.length, pseudonymised: 0, retained: 0 };
  }
  async count(ctx: ProviderContext, ids: readonly Identifier[]): Promise<CountResult> {
    return { residual: this.mine(ctx.tenantId, ids).length, retained: 0, pseudonymised: 0 };
  }
  async purge(ctx: ProviderContext, req: PurgeRequest): Promise<PurgeResult> {
    const prot = new Set(req.protect.subjects.flat().map((i) => i.value));
    const old = this.all(ctx.tenantId).filter((r) => (r.createdAt ?? new Date(0)) < req.olderThan);
    const open = old.filter((r) => !prot.has(r.owner));
    if (!req.dryRun) {
      const set = new Set(open);
      this.rows.set(
        ctx.tenantId,
        this.all(ctx.tenantId).filter((r) => !set.has(r)),
      );
    }
    return {
      matched: old.length,
      purged: req.dryRun ? 0 : open.length,
      protectedByHold: old.length - open.length,
    };
  }
}

export class OkVerifier implements RequesterVerifier {
  calls = 0;
  constructor(private readonly ok = true) {}
  async verify(): Promise<{ ok: boolean; method: string }> {
    this.calls++;
    return { ok: this.ok, method: "test-evidence" };
  }
}

export const FIXED_NOW = new Date("2026-03-01T00:00:00.000Z");

export interface Rig {
  store: GovernanceStore;
  audit: MemoryAuditLog;
  deps: DsarDeps;
  engine: DsarEngine;
  holds: HoldRegistry;
  retention: RetentionEngine;
  signer: ManifestSigner;
  pseudo: Pseudonymiser;
  providers: SubjectDataProvider[];
  clock: { now: Date };
  settings: Map<string, TenantRetentionSettings>;
  regions: Record<string, { homeRegion: string; allowedRegions?: string[] }>;
  verifier: OkVerifier;
}

export function rig(
  providers: SubjectDataProvider[],
  over: {
    store?: GovernanceStore;
    checkpoint?: DsarDeps["checkpoint"];
    verifier?: OkVerifier;
    audit?: MemoryAuditLog;
    keys?: MasterKeyProvider;
  } = {},
): Rig {
  const clock = { now: new Date(FIXED_NOW) };
  const now = (): Date => new Date(clock.now);
  const store = over.store ?? new MemoryGovernanceStore();
  const audit = over.audit ?? new MemoryAuditLog({ now });
  const keys = over.keys ?? new MasterKeyProvider();
  const pseudo = new Pseudonymiser(keys);
  const sealer = new Sealer(keys);
  const gaudit = new GovernanceAudit(audit, now);
  const holds = new HoldRegistry({ store, pseudo, sealer, audit: gaudit, now });
  const regions: Rig["regions"] = {};
  const residency = new ResidencyPolicy({ resolve: async (t) => regions[t] });
  const signer = new ManifestSigner();
  const verifier = over.verifier ?? new OkVerifier();
  const deps: DsarDeps = {
    store,
    pseudo,
    sealer,
    providers,
    audit: gaudit,
    verifier,
    residency,
    holds,
    signer,
    now,
    serviceRegion: "eu-west-1",
    ...(over.checkpoint ? { checkpoint: over.checkpoint } : {}),
  };
  const settings = new Map<string, TenantRetentionSettings>();
  const port: RetentionSettingsPort = { get: async (t) => settings.get(t) };
  return {
    store,
    audit,
    deps,
    holds,
    signer,
    pseudo,
    providers,
    clock,
    settings,
    regions,
    verifier,
    engine: new DsarEngine(deps),
    retention: new RetentionEngine({ store, providers, settings: port, holds, audit: gaudit, now }),
  };
}

/** Register a tenant in the rig (region + retention settings). */
export function setupTenant(r: Rig, tenant = randomUUID(), region = "eu-west-1"): string {
  r.regions[tenant] = { homeRegion: region };
  r.settings.set(tenant, {
    retentionAuditDays: 2555,
    retentionTranscriptDays: 30,
    retentionMemoryDays: 365,
  });
  return tenant;
}

export async function verifiedErase(r: Rig, tenant: string, ids: Identifier[]): Promise<string> {
  const p = officer(tenant);
  const req = await r.engine.open(p, { kind: "erase", identifiers: ids });
  await r.engine.verify(p, req.id, {});
  return req.id;
}

// ---- Postgres -------------------------------------------------------------------------------------------------------------------
export const newPool = (max = 10): pg.Pool =>
  new pg.Pool({ connectionString: inject("dbUrl"), max });
export async function adminClient(): Promise<pg.Client> {
  const c = new pg.Client({ connectionString: inject("dbUrl") });
  await c.connect();
  return c;
}
export async function newTenant(
  admin: pg.Client,
  opts: { phi?: boolean; region?: string } = {},
): Promise<string> {
  const id = randomUUID();
  await admin.query(
    "INSERT INTO tenants (id, slug, name, region, phi_mode) VALUES ($1, $2, $2, $3, $4)",
    [id, `t-${hex(10)}`, opts.region ?? "eu-west-1", opts.phi ?? false],
  );
  return id;
}
