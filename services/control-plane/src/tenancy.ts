import type { PoolClient } from "pg";
import { CpError } from "./errors.js";
import type { ControlPlaneStore, IsolationTier, Placement } from "./types.js";

/** Anything that hands out connections (a pg.Pool). */
export interface PoolLike {
  connect(): Promise<PoolClient>;
  end?(): Promise<void>;
}

export interface PlacementSource {
  getPlacement(tenantId: string): Promise<Placement | undefined>;
}

export interface TierRoute {
  tier: IsolationTier;
  pool: PoolLike;
  /** The database role to SET LOCAL ROLE (tests) is the caller's concern; this says which pool, nothing else. */
  poolKey: string | undefined;
}

export interface TenantRouterOptions {
  placements: PlacementSource;
  /** The shared RLS pool. */
  shared: PoolLike;
  /** pool_key -> pool for `dedicated_db` and `single_tenant_vpc` tenants, built from configuration/secrets, never from the request. */
  dedicated?: Readonly<Record<string, PoolLike>>;
}

/**
 * Maps tenant -> connection pool by isolation tier: `shared_rls` -> the shared pool (isolation by forced RLS), `dedicated_db` /
 * `single_tenant_vpc` -> a separately configured pool. FAIL-CLOSED: no placement, a tier without a configured pool, or a dedicated
 * tenant is NEVER answered with the shared pool. The tenant id is the caller's authenticated tenant (the router does not parse input).
 * Deploying dedicated databases / VPCs is Phase 10 (NEEDS #709); this is the routing layer and its tests with two real databases.
 */
export class TenantRouter {
  constructor(private readonly o: TenantRouterOptions) {}

  async resolve(tenantId: string): Promise<TierRoute> {
    let placement: Placement | undefined;
    try {
      placement = await this.o.placements.getPlacement(tenantId);
    } catch {
      throw new CpError("unavailable", "tenant placement unavailable");
    }
    if (!placement) throw new CpError("unavailable", "tenant has no placement");
    if (placement.isolationTier === "shared_rls")
      return { tier: "shared_rls", pool: this.o.shared, poolKey: undefined };
    const pool = placement.poolKey ? this.o.dedicated?.[placement.poolKey] : undefined;
    if (!pool)
      throw new CpError(
        "unavailable",
        `no pool is configured for ${placement.isolationTier} tenant placement`,
      );
    if (pool === this.o.shared)
      throw new CpError("unavailable", "a dedicated placement must not resolve to the shared pool");
    return { tier: placement.isolationTier, pool, poolKey: placement.poolKey };
  }
}

export function routerFromStore(
  store: ControlPlaneStore,
  shared: PoolLike,
  dedicated?: Record<string, PoolLike>,
): TenantRouter {
  return new TenantRouter({ placements: store, shared, ...(dedicated ? { dedicated } : {}) });
}

/** Region pinning: a control plane instance refuses WRITES for tenants homed elsewhere (reads stay possible for support). */
export class RegionGuard {
  constructor(
    private readonly region: string,
    private readonly store: Pick<ControlPlaneStore, "getTenant">,
  ) {}
  async assertWritable(tenantId: string): Promise<void> {
    const t = await this.store.getTenant(tenantId);
    if (!t) throw new CpError("not_found", "tenant not found");
    if (t.region !== this.region)
      throw new CpError(
        "region_mismatch",
        `tenant is homed in ${t.region}; this endpoint serves ${this.region}`,
      );
  }
}
