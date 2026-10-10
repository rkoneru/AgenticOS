import type { AttesterDirectory } from "./verifier.js";
import type { RetentionSettingsPort, TenantRetentionSettings } from "./retention.js";
import type { TenantRegionResolver, TenantRegions } from "./residency.js";
import { governedTx, type PgGovOptions } from "./store.js";

/**
 * Postgres-backed ports onto what the control plane owns (ADR 0111). Every read runs in a tenant-scoped transaction under forced RLS
 * as the governance role, so a bug here can read the caller's own tenant and nothing else.
 */

/** `tenant_settings` (retention periods) and `tenants.phi_mode`. No settings row means "unknown": the retention engine then purges nothing. */
export class PgRetentionSettings implements RetentionSettingsPort {
  constructor(private readonly o: PgGovOptions) {}
  async get(tenantId: string): Promise<TenantRetentionSettings | undefined> {
    return governedTx(this.o, tenantId, async (c) => {
      const { rows } = await c.query(
        `SELECT s.retention_audit_days, s.retention_transcript_days, s.retention_memory_days, t.phi_mode
           FROM tenants t JOIN tenant_settings s ON s.tenant_id = t.id
          WHERE t.id = $1`,
        [tenantId],
      );
      const r = rows[0] as
        | {
            retention_audit_days: number;
            retention_transcript_days: number;
            retention_memory_days: number;
            phi_mode: boolean;
          }
        | undefined;
      return r
        ? {
            retentionAuditDays: r.retention_audit_days,
            retentionTranscriptDays: r.retention_transcript_days,
            retentionMemoryDays: r.retention_memory_days,
            phiMode: r.phi_mode === true,
          }
        : undefined;
    });
  }
}

/** The tenant's home region (`tenants.region`). The only region data may be written to today (ADR 0083). */
export class PgRegionResolver implements TenantRegionResolver {
  constructor(private readonly o: PgGovOptions) {}
  async resolve(tenantId: string): Promise<TenantRegions | undefined> {
    return governedTx(this.o, tenantId, async (c) => {
      const { rows } = await c.query("SELECT region FROM tenants WHERE id = $1", [tenantId]);
      const region = (rows[0] as { region?: string } | undefined)?.region;
      return typeof region === "string" && region !== "" ? { homeRegion: region } : undefined;
    });
  }
}

/** Active `owner` / `admin` members of the tenant: who may attest a requester's identity. */
export class PgAttesterDirectory implements AttesterDirectory {
  constructor(private readonly o: PgGovOptions) {}
  async isTenantAdmin(tenantId: string, memberId: string): Promise<boolean> {
    if (!/^[0-9a-f-]{36}$/i.test(memberId)) return false;
    return governedTx(this.o, tenantId, async (c) => {
      const { rowCount } = await c.query(
        "SELECT 1 FROM members WHERE id = $1 AND status = 'active' AND role IN ('owner', 'admin')",
        [memberId],
      );
      return (rowCount ?? 0) > 0;
    });
  }
}
