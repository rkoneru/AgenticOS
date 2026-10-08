/**
 * Residency pinning (ADR-0083). Deliberately dependency-free: services import `@axis/data-governance/residency` for the guard.
 * Fail-closed: an unknown tenant, an unknown region, a resolver error, or an empty allow-list all REFUSE. There is no default-allow.
 * Limits: this repo has no real multi-region deployment; the guard enforces the *decision* at each write/egress boundary.
 */
export interface TenantRegions {
  homeRegion: string;
  /** Regions data may be written to / sent to. Defaults to [homeRegion]. */
  allowedRegions?: readonly string[];
}
export interface TenantRegionResolver {
  resolve(tenantId: string): Promise<TenantRegions | undefined>;
}

export class ResidencyError extends Error {
  readonly code = "region_mismatch";
  constructor(message: string) {
    super(message);
    this.name = "ResidencyError";
  }
}

/** Handed to a service so its write paths can call `assertWrite(tenantId)` without knowing the policy. */
export interface WriteGuard {
  assertWrite(tenantId: string): Promise<void>;
}

const canon = (r: string): string => r.trim().toLowerCase();

export class ResidencyPolicy {
  constructor(private readonly resolver: TenantRegionResolver) {}

  async allowedRegions(tenantId: string): Promise<string[]> {
    let t: TenantRegions | undefined;
    try {
      t = await this.resolver.resolve(tenantId);
    } catch {
      return []; // resolver failure => nothing is allowed
    }
    if (!t || canon(t.homeRegion) === "") return [];
    const set = new Set([canon(t.homeRegion), ...(t.allowedRegions ?? []).map(canon)]);
    set.delete("");
    return [...set].sort();
  }

  /** True only when `region` is non-empty and in the tenant's allowed set. */
  async permits(tenantId: string, region: string | undefined): Promise<boolean> {
    if (region === undefined || canon(region) === "") return false;
    return (await this.allowedRegions(tenantId)).includes(canon(region));
  }

  private async assert(tenantId: string, region: string | undefined, what: string): Promise<void> {
    if (!(await this.permits(tenantId, region)))
      throw new ResidencyError(
        `${what} to region "${region ?? ""}" is not permitted for this tenant`,
      );
  }

  /** A service instance running in `serviceRegion` may write this tenant's data only if that region is allowed. */
  assertWrite(tenantId: string, serviceRegion: string | undefined): Promise<void> {
    return this.assert(tenantId, serviceRegion, "write");
  }
  /** Data leaving the platform (DSAR bundle destination, outbound transfer). */
  assertEgress(tenantId: string, destinationRegion: string | undefined): Promise<void> {
    return this.assert(tenantId, destinationRegion, "egress");
  }
  /** A model provider endpoint in `providerRegion` may receive this tenant's prompts only if allowed. */
  assertModelRegion(tenantId: string, providerRegion: string | undefined): Promise<void> {
    return this.assert(tenantId, providerRegion, "model call");
  }

  forService(serviceRegion: string): WriteGuard {
    return { assertWrite: (tenantId) => this.assertWrite(tenantId, serviceRegion) };
  }
}

export class StaticRegionResolver implements TenantRegionResolver {
  constructor(private readonly map: Readonly<Record<string, TenantRegions>>) {}
  async resolve(tenantId: string): Promise<TenantRegions | undefined> {
    return this.map[tenantId];
  }
}
