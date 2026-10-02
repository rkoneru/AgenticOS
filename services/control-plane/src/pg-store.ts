import { withTenant } from "@axis/db";
import type { ClientBase, PoolClient } from "pg";
import type { Role } from "./roles.js";
import {
  LastOwnerError,
  StoreConflict,
  type ApiKeyRecord,
  type Budget,
  type ControlPlaneStore,
  type DirectoryRecord,
  type IdentityConnection,
  type Member,
  type ModelCredentialRecord,
  type PackVersionRecord,
  type Page,
  type Placement,
  type PolicyAssignment,
  type ProvisionSpec,
  type ScimGroup,
  type SessionRecord,
  type TenantKeyRecord,
  type TenantRecord,
  type TenantSettings,
  type VerifiedDomain,
} from "./types.js";

export interface PgPoolLike {
  connect(): Promise<PoolClient>;
}
export interface PgStoreOptions {
  pool: PgPoolLike;
  /** Tests only: SET LOCAL ROLE for each transaction (production connects as axis_app). */
  role?: string;
}

type Row = Record<string, unknown>;
const UNIQUE = "23505";

/** Drops undefined keys so optional properties are absent (exactOptionalPropertyTypes). */
function clean<T extends object>(o: Record<string, unknown>): T {
  for (const key of Object.keys(o)) if (o[key] === undefined || o[key] === null) delete o[key];
  return o as T;
}
const d = (v: unknown): Date | undefined => (v instanceof Date ? v : undefined);
const num = (v: unknown): number | undefined =>
  v === null || v === undefined ? undefined : Number(v);

const memberOf = (r: Row): Member =>
  clean<Member>({
    tenantId: r["tenant_id"],
    id: r["id"],
    userRef: r["user_ref"],
    email: r["email"],
    role: r["role"],
    status: r["status"],
    displayName: r["display_name"],
    externalId: r["external_id"],
    directoryId: r["directory_id"],
    deprovisionedAt: d(r["deprovisioned_at"]),
    createdAt: r["created_at"],
    updatedAt: r["updated_at"],
  });

const keyOf = (r: Row): ApiKeyRecord =>
  clean<ApiKeyRecord>({
    tenantId: r["tenant_id"],
    id: r["id"],
    name: r["name"],
    prefix: r["prefix"],
    keyHash: r["key_hash"],
    scopes: r["scopes"],
    environment: r["environment"],
    ownerMemberId: r["owner_member_id"],
    createdBy: r["created_by"],
    createdAt: r["created_at"],
    expiresAt: d(r["expires_at"]),
    revokedAt: d(r["revoked_at"]),
    lastUsedAt: d(r["last_used_at"]),
    rotatedFrom: r["rotated_from"],
  });

const sessionOf = (r: Row): SessionRecord =>
  clean<SessionRecord>({
    tenantId: r["tenant_id"],
    id: r["id"],
    memberId: r["member_id"],
    refreshHash: r["refresh_hash"],
    prevRefreshHash: r["prev_refresh_hash"],
    counter: r["counter"],
    authMethod: r["auth_method"],
    createdAt: r["created_at"],
    expiresAt: r["expires_at"],
    refreshedAt: r["refreshed_at"],
    revokedAt: d(r["revoked_at"]),
    revokedReason: r["revoked_reason"],
  });

const dirOf = (r: Row): DirectoryRecord =>
  clean<DirectoryRecord>({
    tenantId: r["tenant_id"],
    id: r["id"],
    name: r["name"],
    idpDirectoryId: r["idp_directory_id"],
    tokenPrefix: r["token_prefix"],
    tokenHash: r["token_hash"],
    defaultRole: r["default_role"],
    status: r["status"],
    createdAt: r["created_at"],
    revokedAt: d(r["revoked_at"]),
    lastUsedAt: d(r["last_used_at"]),
  });

const groupOf = (r: Row): ScimGroup =>
  clean<ScimGroup>({
    tenantId: r["tenant_id"],
    id: r["id"],
    directoryId: r["directory_id"],
    displayName: r["display_name"],
    externalId: r["external_id"],
    createdAt: r["created_at"],
  });

const connOf = (r: Row): IdentityConnection =>
  clean<IdentityConnection>({
    tenantId: r["tenant_id"],
    id: r["id"],
    idpOrgId: r["idp_org_id"],
    idpConnectionId: r["idp_connection_id"],
    connectionType: r["connection_type"],
    jitEnabled: r["jit_enabled"],
    jitDefaultRole: r["jit_default_role"],
  });

const domainOf = (r: Row): VerifiedDomain =>
  clean<VerifiedDomain>({
    tenantId: r["tenant_id"],
    domain: r["domain"],
    status: r["status"],
    challengeHash: r["challenge_hash"],
    verifiedAt: d(r["verified_at"]),
  });

const tkeyOf = (r: Row): TenantKeyRecord =>
  clean<TenantKeyRecord>({
    tenantId: r["tenant_id"],
    version: r["version"],
    kmsKeyId: r["kms_key_id"],
    wrappedDek: r["wrapped_dek"],
    retiredAt: d(r["retired_at"]),
  });

const credOf = (r: Row): ModelCredentialRecord =>
  clean<ModelCredentialRecord>({
    tenantId: r["tenant_id"],
    id: r["id"],
    provider: r["provider"],
    label: r["label"],
    keyVersion: r["key_version"],
    nonceAndCiphertext: Buffer.concat([r["nonce"] as Buffer, r["ciphertext"] as Buffer]),
    createdBy: r["created_by"],
    createdAt: r["created_at"],
    rotatedAt: d(r["rotated_at"]),
  });

const versionOf = (r: Row): PackVersionRecord =>
  ({
    tenantId: r["tenant_id"],
    packId: r["pack_id"],
    packName: r["pack_name"],
    versionId: r["id"],
    version: r["version"],
    source: r["source"],
    rego: r["rego"],
    contentHash: r["content_hash"],
    createdAt: r["created_at"],
  }) as PackVersionRecord;

const assignOf = (r: Row): PolicyAssignment =>
  clean<PolicyAssignment>({
    tenantId: r["tenant_id"],
    id: r["id"],
    packId: r["pack_id"],
    versionId: r["version_id"],
    active: r["active"],
    activatedBy: r["activated_by"],
    activatedAt: r["activated_at"],
    deactivatedAt: d(r["deactivated_at"]),
  });

const budgetOf = (r: Row): Budget =>
  clean<Budget>({
    tenantId: r["tenant_id"],
    id: r["id"],
    scope: r["scope"],
    target: r["target"],
    metric: r["metric"],
    period: r["period"],
    soft: num(r["soft"]),
    hard: num(r["hard"]),
  });

const settingsOf = (r: Row): TenantSettings =>
  clean<TenantSettings>({
    tenantId: r["tenant_id"],
    retentionAuditDays: r["retention_audit_days"],
    retentionTranscriptDays: r["retention_transcript_days"],
    retentionMemoryDays: r["retention_memory_days"],
    updatedBy: r["updated_by"],
  });

const SPLIT_NONCE = 12;

function pageOf<T extends { id: string }>(rows: T[], limit: number): Page<T> {
  const items = rows.slice(0, limit);
  const last = items[items.length - 1];
  return rows.length > limit && last ? { items, nextCursor: last.id } : { items };
}

/**
 * Postgres implementation. Every method runs in `withTenant` (FORCED RLS for the tenant) and also names tenant_id in its WHERE
 * clause. The three pre-tenant lookups set the transaction-local lookup settings that the 0009 policies match on.
 */
export class PgControlPlaneStore implements ControlPlaneStore {
  constructor(private readonly o: PgStoreOptions) {}

  private async tx<T>(tenantId: string, fn: (c: ClientBase) => Promise<T>): Promise<T> {
    const client = await this.o.pool.connect();
    try {
      return await withTenant(client, tenantId, fn, this.o.role ? { role: this.o.role } : {});
    } catch (err) {
      if ((err as { code?: string }).code === UNIQUE) throw new StoreConflict("already exists");
      throw err;
    } finally {
      client.release();
    }
  }

  /** A transaction with no tenant, only lookup settings. */
  private async lookup<T>(
    settings: Record<string, string>,
    fn: (c: ClientBase) => Promise<T>,
  ): Promise<T> {
    const client = await this.o.pool.connect();
    try {
      await client.query("BEGIN");
      try {
        if (this.o.role)
          await client.query(`SET LOCAL ROLE ${client.escapeIdentifier(this.o.role)}`);
        for (const [key, v] of Object.entries(settings))
          await client.query("SELECT set_config($1, $2, true)", [key, v]);
        const out = await fn(client);
        await client.query("COMMIT");
        return out;
      } catch (err) {
        await client.query("ROLLBACK");
        throw err;
      }
    } finally {
      client.release();
    }
  }

  async provisionTenant(s: ProvisionSpec): Promise<void> {
    const client = await this.o.pool.connect();
    try {
      await client.query("BEGIN");
      try {
        if (this.o.role)
          await client.query(`SET LOCAL ROLE ${client.escapeIdentifier(this.o.role)}`);
        await client.query("SELECT axis.provision_tenant($1, $2, $3, $4, $5)", [
          s.tenantId,
          s.slug,
          s.name,
          s.region,
          s.phiMode,
        ]);
        await client.query("SELECT axis.set_tenant($1::uuid)", [s.tenantId]);
        await client.query(
          "INSERT INTO members (tenant_id, id, user_ref, email, role, display_name) VALUES ($1,$2,$3,$4,'owner',$5)",
          [s.tenantId, s.owner.id, s.owner.userRef, s.owner.email, s.owner.displayName ?? null],
        );
        for (const p of s.packs) {
          await client.query("INSERT INTO policy_packs (tenant_id, id, name) VALUES ($1,$2,$3)", [
            s.tenantId,
            p.packId,
            p.name,
          ]);
          await client.query(
            "INSERT INTO policy_pack_versions (tenant_id, id, pack_id, version, source, rego, content_hash) VALUES ($1,$2,$3,$4,$5,$6,$7)",
            [
              s.tenantId,
              p.versionId,
              p.packId,
              p.version,
              JSON.stringify(p.source),
              p.rego,
              p.contentHash,
            ],
          );
          await client.query(
            "INSERT INTO policy_assignments (tenant_id, pack_id, version_id, activated_by) VALUES ($1,$2,$3,$4)",
            [s.tenantId, p.packId, p.versionId, s.owner.id],
          );
        }
        for (const b of s.budgets)
          await client.query(
            "INSERT INTO budgets (tenant_id, scope, target, metric, period, soft, hard) VALUES ($1,$2,$3,$4,$5,$6,$7)",
            [s.tenantId, b.scope, b.target, b.metric, b.period, b.soft ?? null, b.hard ?? null],
          );
        await client.query(
          "INSERT INTO tenant_settings (tenant_id, retention_audit_days, retention_transcript_days, retention_memory_days) VALUES ($1,$2,$3,$4)",
          [
            s.tenantId,
            s.settings.retentionAuditDays,
            s.settings.retentionTranscriptDays,
            s.settings.retentionMemoryDays,
          ],
        );
        await client.query(
          "INSERT INTO tenant_placements (tenant_id, isolation_tier, pool_key) VALUES ($1,$2,$3)",
          [s.tenantId, s.placement.isolationTier, s.placement.poolKey ?? null],
        );
        await client.query("COMMIT");
      } catch (err) {
        await client.query("ROLLBACK");
        if ((err as { code?: string }).code === UNIQUE)
          throw new StoreConflict("slug already in use");
        throw err;
      }
    } finally {
      client.release();
    }
  }

  getTenant(t: string): Promise<TenantRecord | undefined> {
    return this.tx(t, async (c) => {
      const r = await c.query(
        "SELECT id, slug, name, region, phi_mode, status FROM tenants WHERE id = $1",
        [t],
      );
      const x = r.rows[0] as Row | undefined;
      return (
        x &&
        ({
          id: x["id"],
          slug: x["slug"],
          name: x["name"],
          region: x["region"],
          phiMode: x["phi_mode"],
          status: x["status"],
        } as TenantRecord)
      );
    });
  }

  // members
  insertMember(m: Omit<Member, "createdAt" | "updatedAt">): Promise<Member> {
    return this.tx(m.tenantId, async (c) => {
      const r = await c.query(
        `INSERT INTO members (tenant_id, id, user_ref, email, role, status, display_name, external_id, directory_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
        [
          m.tenantId,
          m.id,
          m.userRef,
          m.email,
          m.role,
          m.status,
          m.displayName ?? null,
          m.externalId ?? null,
          m.directoryId ?? null,
        ],
      );
      return memberOf(r.rows[0] as Row);
    });
  }
  getMember(t: string, id: string): Promise<Member | undefined> {
    return this.tx(t, async (c) => {
      const r = await c.query("SELECT * FROM members WHERE tenant_id = $1 AND id = $2", [t, id]);
      return r.rows[0] ? memberOf(r.rows[0] as Row) : undefined;
    });
  }
  private findMember(t: string, where: string, params: unknown[]): Promise<Member | undefined> {
    return this.tx(t, async (c) => {
      const r = await c.query(`SELECT * FROM members WHERE tenant_id = $1 AND ${where} LIMIT 1`, [
        t,
        ...params,
      ]);
      return r.rows[0] ? memberOf(r.rows[0] as Row) : undefined;
    });
  }
  findMemberByUserRef(t: string, userRef: string): Promise<Member | undefined> {
    return this.findMember(t, "user_ref = $2", [userRef]);
  }
  findMemberByEmail(t: string, email: string): Promise<Member | undefined> {
    return this.findMember(t, "lower(email) = lower($2)", [email]);
  }
  findMemberByExternalId(t: string, dir: string, ext: string): Promise<Member | undefined> {
    return this.findMember(t, "directory_id = $2 AND external_id = $3", [dir, ext]);
  }
  listMembers(t: string, limit: number, after?: string): Promise<Page<Member>> {
    return this.tx(t, async (c) => {
      const r = await c.query(
        "SELECT * FROM members WHERE tenant_id = $1 AND ($2::uuid IS NULL OR id > $2) ORDER BY id LIMIT $3",
        [t, after ?? null, limit + 1],
      );
      return pageOf((r.rows as Row[]).map(memberOf), limit);
    });
  }
  updateMember(
    t: string,
    id: string,
    patch: Partial<Pick<Member, "role" | "status" | "displayName" | "email">>,
    now: Date,
  ): Promise<Member | undefined> {
    return this.tx(t, async (c) => {
      // Serialise every owner-affecting change of this tenant, then count owners under the lock.
      await c.query("SELECT pg_advisory_xact_lock(727281, hashtext($1))", [t]);
      const cur = await c.query(
        "SELECT * FROM members WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        [t, id],
      );
      const m = cur.rows[0] as Row | undefined;
      if (!m) return undefined;
      const next = {
        role: patch.role ?? (m["role"] as string),
        status: patch.status ?? (m["status"] as string),
      };
      if (
        m["role"] === "owner" &&
        m["status"] === "active" &&
        (next.role !== "owner" || next.status !== "active")
      ) {
        const o = await c.query(
          "SELECT count(*)::int AS n FROM members WHERE tenant_id = $1 AND id <> $2 AND role = 'owner' AND status = 'active'",
          [t, id],
        );
        if ((o.rows[0] as { n: number }).n === 0) throw new LastOwnerError();
      }
      const r = await c.query(
        `UPDATE members SET role = $3, status = $4, display_name = COALESCE($5, display_name), email = COALESCE($6, email),
           deprovisioned_at = CASE WHEN $4 = 'deprovisioned' AND status <> 'deprovisioned' THEN $7 ELSE deprovisioned_at END,
           updated_at = $7 WHERE tenant_id = $1 AND id = $2 RETURNING *`,
        [t, id, next.role, next.status, patch.displayName ?? null, patch.email ?? null, now],
      );
      return memberOf(r.rows[0] as Row);
    });
  }

  // api keys
  insertApiKey(k: ApiKeyRecord): Promise<ApiKeyRecord> {
    return this.tx(k.tenantId, async (c) => {
      const r = await c.query(
        `INSERT INTO api_keys (tenant_id, id, name, prefix, key_hash, scopes, environment, owner_member_id, created_by, created_at, expires_at, rotated_from)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
        [
          k.tenantId,
          k.id,
          k.name,
          k.prefix,
          k.keyHash,
          k.scopes,
          k.environment,
          k.ownerMemberId,
          k.createdBy,
          k.createdAt,
          k.expiresAt ?? null,
          k.rotatedFrom ?? null,
        ],
      );
      return keyOf(r.rows[0] as Row);
    });
  }
  getApiKey(t: string, id: string): Promise<ApiKeyRecord | undefined> {
    return this.tx(t, async (c) => {
      const r = await c.query("SELECT * FROM api_keys WHERE tenant_id = $1 AND id = $2", [t, id]);
      return r.rows[0] ? keyOf(r.rows[0] as Row) : undefined;
    });
  }
  listApiKeys(t: string, limit: number, after?: string): Promise<Page<ApiKeyRecord>> {
    return this.tx(t, async (c) => {
      const r = await c.query(
        "SELECT * FROM api_keys WHERE tenant_id = $1 AND ($2::uuid IS NULL OR id > $2) ORDER BY id LIMIT $3",
        [t, after ?? null, limit + 1],
      );
      return pageOf((r.rows as Row[]).map(keyOf), limit);
    });
  }
  findApiKeyByLookup(prefix: string, keyHash: Buffer): Promise<ApiKeyRecord | undefined> {
    return this.lookup(
      { "axis.lookup_prefix": prefix, "axis.lookup_hash": keyHash.toString("hex") },
      async (c) => {
        const r = await c.query("SELECT * FROM api_keys WHERE prefix = $1 LIMIT 1", [prefix]);
        return r.rows[0] ? keyOf(r.rows[0] as Row) : undefined;
      },
    );
  }
  updateApiKey(
    t: string,
    id: string,
    patch: { revokedAt?: Date; lastUsedAt?: Date },
  ): Promise<ApiKeyRecord | undefined> {
    return this.tx(t, async (c) => {
      const r = await c.query(
        `UPDATE api_keys SET revoked_at = COALESCE(revoked_at, $3), last_used_at = COALESCE($4, last_used_at)
         WHERE tenant_id = $1 AND id = $2 RETURNING *`,
        [t, id, patch.revokedAt ?? null, patch.lastUsedAt ?? null],
      );
      return r.rows[0] ? keyOf(r.rows[0] as Row) : undefined;
    });
  }
  revokeApiKeysOfMember(t: string, memberId: string, at: Date): Promise<number> {
    return this.tx(t, async (c) => {
      const r = await c.query(
        "UPDATE api_keys SET revoked_at = $3 WHERE tenant_id = $1 AND owner_member_id = $2 AND revoked_at IS NULL",
        [t, memberId, at],
      );
      return r.rowCount ?? 0;
    });
  }

  // sessions
  insertSession(s: SessionRecord): Promise<void> {
    return this.tx(s.tenantId, async (c) => {
      await c.query(
        `INSERT INTO sessions (tenant_id, id, member_id, refresh_hash, counter, auth_method, created_at, expires_at, refreshed_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [
          s.tenantId,
          s.id,
          s.memberId,
          s.refreshHash,
          s.counter,
          s.authMethod,
          s.createdAt,
          s.expiresAt,
          s.refreshedAt,
        ],
      );
    });
  }
  getSession(t: string, id: string): Promise<SessionRecord | undefined> {
    return this.tx(t, async (c) => {
      const r = await c.query("SELECT * FROM sessions WHERE tenant_id = $1 AND id = $2", [t, id]);
      return r.rows[0] ? sessionOf(r.rows[0] as Row) : undefined;
    });
  }
  rotateRefresh(
    t: string,
    id: string,
    expected: Buffer,
    next: Buffer,
    now: Date,
  ): Promise<boolean> {
    return this.tx(t, async (c) => {
      const r = await c.query(
        `UPDATE sessions SET prev_refresh_hash = refresh_hash, refresh_hash = $4, counter = counter + 1, refreshed_at = $5
         WHERE tenant_id = $1 AND id = $2 AND refresh_hash = $3 AND revoked_at IS NULL`,
        [t, id, expected, next, now],
      );
      return (r.rowCount ?? 0) === 1;
    });
  }
  revokeSession(t: string, id: string, at: Date, reason: string): Promise<boolean> {
    return this.tx(t, async (c) => {
      const r = await c.query(
        "UPDATE sessions SET revoked_at = $3, revoked_reason = $4 WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL",
        [t, id, at, reason],
      );
      return (r.rowCount ?? 0) === 1;
    });
  }
  revokeSessionsOfMember(t: string, memberId: string, at: Date, reason: string): Promise<number> {
    return this.tx(t, async (c) => {
      const r = await c.query(
        "UPDATE sessions SET revoked_at = $3, revoked_reason = $4 WHERE tenant_id = $1 AND member_id = $2 AND revoked_at IS NULL",
        [t, memberId, at, reason],
      );
      return r.rowCount ?? 0;
    });
  }

  // directories
  insertDirectory(x: DirectoryRecord): Promise<void> {
    return this.tx(x.tenantId, async (c) => {
      await c.query(
        `INSERT INTO directories (tenant_id, id, name, idp_directory_id, token_prefix, token_hash, default_role, status, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [
          x.tenantId,
          x.id,
          x.name,
          x.idpDirectoryId ?? null,
          x.tokenPrefix,
          x.tokenHash,
          x.defaultRole,
          x.status,
          x.createdAt,
        ],
      );
    });
  }
  getDirectory(t: string, id: string): Promise<DirectoryRecord | undefined> {
    return this.tx(t, async (c) => {
      const r = await c.query("SELECT * FROM directories WHERE tenant_id = $1 AND id = $2", [
        t,
        id,
      ]);
      return r.rows[0] ? dirOf(r.rows[0] as Row) : undefined;
    });
  }
  listDirectories(t: string): Promise<DirectoryRecord[]> {
    return this.tx(t, async (c) =>
      (await c.query("SELECT * FROM directories WHERE tenant_id = $1 ORDER BY id", [t])).rows.map(
        (r) => dirOf(r as Row),
      ),
    );
  }
  findDirectoryByLookup(prefix: string, tokenHash: Buffer): Promise<DirectoryRecord | undefined> {
    return this.lookup(
      { "axis.lookup_prefix": prefix, "axis.lookup_hash": tokenHash.toString("hex") },
      async (c) => {
        const r = await c.query("SELECT * FROM directories WHERE token_prefix = $1 LIMIT 1", [
          prefix,
        ]);
        return r.rows[0] ? dirOf(r.rows[0] as Row) : undefined;
      },
    );
  }
  updateDirectory(
    t: string,
    id: string,
    p: { revokedAt?: Date; lastUsedAt?: Date; tokenPrefix?: string; tokenHash?: Buffer },
  ): Promise<void> {
    return this.tx(t, async (c) => {
      await c.query(
        `UPDATE directories SET revoked_at = COALESCE($3, revoked_at), status = CASE WHEN $3::timestamptz IS NOT NULL THEN 'revoked' ELSE status END,
           last_used_at = COALESCE($4, last_used_at), token_prefix = COALESCE($5, token_prefix), token_hash = COALESCE($6, token_hash)
         WHERE tenant_id = $1 AND id = $2`,
        [
          t,
          id,
          p.revokedAt ?? null,
          p.lastUsedAt ?? null,
          p.tokenPrefix ?? null,
          p.tokenHash ?? null,
        ],
      );
    });
  }
  setRoleMapping(t: string, dir: string, name: string, role: Role | undefined): Promise<void> {
    return this.tx(t, async (c) => {
      if (role === undefined)
        await c.query(
          "DELETE FROM directory_role_mappings WHERE tenant_id = $1 AND directory_id = $2 AND group_name = $3",
          [t, dir, name],
        );
      else
        await c.query(
          `INSERT INTO directory_role_mappings (tenant_id, directory_id, group_name, role) VALUES ($1,$2,$3,$4)
           ON CONFLICT (tenant_id, directory_id, group_name) DO UPDATE SET role = EXCLUDED.role`,
          [t, dir, name, role],
        );
    });
  }
  listRoleMappings(t: string, dir: string): Promise<Record<string, Role>> {
    return this.tx(t, async (c) => {
      const r = await c.query(
        "SELECT group_name, role FROM directory_role_mappings WHERE tenant_id = $1 AND directory_id = $2",
        [t, dir],
      );
      return Object.fromEntries(
        (r.rows as Row[]).map((x) => [x["group_name"] as string, x["role"] as Role]),
      );
    });
  }
  insertGroup(g: Omit<ScimGroup, "createdAt">): Promise<ScimGroup> {
    return this.tx(g.tenantId, async (c) => {
      const r = await c.query(
        "INSERT INTO scim_groups (tenant_id, id, directory_id, display_name, external_id) VALUES ($1,$2,$3,$4,$5) RETURNING *",
        [g.tenantId, g.id, g.directoryId, g.displayName, g.externalId ?? null],
      );
      return groupOf(r.rows[0] as Row);
    });
  }
  getGroup(t: string, dir: string, id: string): Promise<ScimGroup | undefined> {
    return this.tx(t, async (c) => {
      const r = await c.query(
        "SELECT * FROM scim_groups WHERE tenant_id = $1 AND directory_id = $2 AND id = $3",
        [t, dir, id],
      );
      return r.rows[0] ? groupOf(r.rows[0] as Row) : undefined;
    });
  }
  listGroups(t: string, dir: string): Promise<ScimGroup[]> {
    return this.tx(t, async (c) =>
      (
        await c.query(
          "SELECT * FROM scim_groups WHERE tenant_id = $1 AND directory_id = $2 ORDER BY id",
          [t, dir],
        )
      ).rows.map((r) => groupOf(r as Row)),
    );
  }
  updateGroup(
    t: string,
    dir: string,
    id: string,
    p: { displayName?: string; externalId?: string },
  ): Promise<ScimGroup | undefined> {
    return this.tx(t, async (c) => {
      const r = await c.query(
        "UPDATE scim_groups SET display_name = COALESCE($4, display_name), external_id = COALESCE($5, external_id) WHERE tenant_id = $1 AND directory_id = $2 AND id = $3 RETURNING *",
        [t, dir, id, p.displayName ?? null, p.externalId ?? null],
      );
      return r.rows[0] ? groupOf(r.rows[0] as Row) : undefined;
    });
  }
  deleteGroup(t: string, dir: string, id: string): Promise<boolean> {
    return this.tx(t, async (c) => {
      const r = await c.query(
        "DELETE FROM scim_groups WHERE tenant_id = $1 AND directory_id = $2 AND id = $3",
        [t, dir, id],
      );
      return (r.rowCount ?? 0) === 1;
    });
  }
  groupMembers(t: string, groupId: string): Promise<string[]> {
    return this.tx(t, async (c) =>
      (
        await c.query(
          "SELECT member_id FROM scim_group_members WHERE tenant_id = $1 AND group_id = $2",
          [t, groupId],
        )
      ).rows.map((r) => (r as Row)["member_id"] as string),
    );
  }
  setGroupMembers(t: string, groupId: string, ids: string[]): Promise<void> {
    return this.tx(t, async (c) => {
      await c.query("DELETE FROM scim_group_members WHERE tenant_id = $1 AND group_id = $2", [
        t,
        groupId,
      ]);
      if (ids.length > 0)
        await c.query(
          `INSERT INTO scim_group_members (tenant_id, group_id, member_id)
           SELECT $1, $2, m.id FROM members m WHERE m.tenant_id = $1 AND m.id = ANY($3::uuid[])`,
          [t, groupId, ids],
        );
    });
  }
  groupsOfMember(t: string, dir: string, memberId: string): Promise<ScimGroup[]> {
    return this.tx(t, async (c) =>
      (
        await c.query(
          `SELECT g.* FROM scim_groups g JOIN scim_group_members m ON m.tenant_id = g.tenant_id AND m.group_id = g.id
           WHERE g.tenant_id = $1 AND g.directory_id = $2 AND m.member_id = $3`,
          [t, dir, memberId],
        )
      ).rows.map((r) => groupOf(r as Row)),
    );
  }

  // identity
  upsertConnection(x: IdentityConnection): Promise<void> {
    return this.tx(x.tenantId, async (c) => {
      await c.query(
        `INSERT INTO identity_connections (tenant_id, id, idp_org_id, idp_connection_id, connection_type, jit_enabled, jit_default_role)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (tenant_id, id) DO UPDATE SET idp_connection_id = EXCLUDED.idp_connection_id, connection_type = EXCLUDED.connection_type,
           jit_enabled = EXCLUDED.jit_enabled, jit_default_role = EXCLUDED.jit_default_role`,
        [
          x.tenantId,
          x.id,
          x.idpOrgId,
          x.idpConnectionId ?? null,
          x.connectionType,
          x.jitEnabled,
          x.jitDefaultRole,
        ],
      );
    });
  }
  findConnectionByOrg(org: string): Promise<IdentityConnection | undefined> {
    return this.lookup({ "axis.lookup_idp_org": org }, async (c) => {
      const r = await c.query("SELECT * FROM identity_connections WHERE idp_org_id = $1 LIMIT 1", [
        org,
      ]);
      return r.rows[0] ? connOf(r.rows[0] as Row) : undefined;
    });
  }
  listConnections(t: string): Promise<IdentityConnection[]> {
    return this.tx(t, async (c) =>
      (
        await c.query("SELECT * FROM identity_connections WHERE tenant_id = $1 ORDER BY id", [t])
      ).rows.map((r) => connOf(r as Row)),
    );
  }
  upsertDomain(x: VerifiedDomain): Promise<void> {
    return this.tx(x.tenantId, async (c) => {
      await c.query(
        `INSERT INTO verified_domains (tenant_id, domain, status, challenge_hash, verified_at) VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (tenant_id, domain) DO UPDATE SET status = EXCLUDED.status, challenge_hash = EXCLUDED.challenge_hash, verified_at = EXCLUDED.verified_at`,
        [x.tenantId, x.domain, x.status, x.challengeHash ?? null, x.verifiedAt ?? null],
      );
    });
  }
  getDomain(t: string, domain: string): Promise<VerifiedDomain | undefined> {
    return this.tx(t, async (c) => {
      const r = await c.query(
        "SELECT * FROM verified_domains WHERE tenant_id = $1 AND domain = $2",
        [t, domain],
      );
      return r.rows[0] ? domainOf(r.rows[0] as Row) : undefined;
    });
  }
  listDomains(t: string): Promise<VerifiedDomain[]> {
    return this.tx(t, async (c) =>
      (
        await c.query("SELECT * FROM verified_domains WHERE tenant_id = $1 ORDER BY domain", [t])
      ).rows.map((r) => domainOf(r as Row)),
    );
  }

  // BYO
  getActiveTenantKey(t: string): Promise<TenantKeyRecord | undefined> {
    return this.tx(t, async (c) => {
      const r = await c.query(
        "SELECT * FROM tenant_keys WHERE tenant_id = $1 AND retired_at IS NULL ORDER BY version DESC LIMIT 1",
        [t],
      );
      return r.rows[0] ? tkeyOf(r.rows[0] as Row) : undefined;
    });
  }
  getTenantKey(t: string, version: number): Promise<TenantKeyRecord | undefined> {
    return this.tx(t, async (c) => {
      const r = await c.query("SELECT * FROM tenant_keys WHERE tenant_id = $1 AND version = $2", [
        t,
        version,
      ]);
      return r.rows[0] ? tkeyOf(r.rows[0] as Row) : undefined;
    });
  }
  insertTenantKey(x: TenantKeyRecord): Promise<void> {
    return this.tx(x.tenantId, async (c) => {
      await c.query(
        "INSERT INTO tenant_keys (tenant_id, version, kms_key_id, wrapped_dek) VALUES ($1,$2,$3,$4)",
        [x.tenantId, x.version, x.kmsKeyId, x.wrappedDek],
      );
    });
  }
  putModelCredential(x: ModelCredentialRecord): Promise<ModelCredentialRecord> {
    return this.tx(x.tenantId, async (c) => {
      const nonce = x.nonceAndCiphertext.subarray(0, SPLIT_NONCE);
      const ct = x.nonceAndCiphertext.subarray(SPLIT_NONCE);
      const r = await c.query(
        `INSERT INTO model_credentials (tenant_id, id, provider, label, secret_ref, key_version, nonce, ciphertext, created_by, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (tenant_id, provider, label) DO UPDATE SET key_version = EXCLUDED.key_version, nonce = EXCLUDED.nonce,
           ciphertext = EXCLUDED.ciphertext, rotated_at = EXCLUDED.created_at, created_by = EXCLUDED.created_by
         RETURNING *`,
        [
          x.tenantId,
          x.id,
          x.provider,
          x.label,
          `cp:${x.id}`,
          x.keyVersion,
          nonce,
          ct,
          x.createdBy,
          x.createdAt,
        ],
      );
      return credOf(r.rows[0] as Row);
    });
  }
  getModelCredential(
    t: string,
    provider: string,
    label: string,
  ): Promise<ModelCredentialRecord | undefined> {
    return this.tx(t, async (c) => {
      const r = await c.query(
        "SELECT * FROM model_credentials WHERE tenant_id = $1 AND provider = $2 AND label = $3 AND ciphertext IS NOT NULL",
        [t, provider, label],
      );
      return r.rows[0] ? credOf(r.rows[0] as Row) : undefined;
    });
  }
  listModelCredentials(t: string): Promise<ModelCredentialRecord[]> {
    return this.tx(t, async (c) =>
      (
        await c.query(
          "SELECT * FROM model_credentials WHERE tenant_id = $1 AND ciphertext IS NOT NULL ORDER BY provider, label",
          [t],
        )
      ).rows.map((r) => credOf(r as Row)),
    );
  }
  deleteModelCredential(t: string, provider: string, label: string): Promise<boolean> {
    return this.tx(t, async (c) => {
      const r = await c.query(
        "DELETE FROM model_credentials WHERE tenant_id = $1 AND provider = $2 AND label = $3",
        [t, provider, label],
      );
      return (r.rowCount ?? 0) === 1;
    });
  }

  // policies
  insertPackVersion(v: Omit<PackVersionRecord, "createdAt">): Promise<PackVersionRecord> {
    return this.tx(v.tenantId, async (c) => {
      const ex = await c.query("SELECT id FROM policy_packs WHERE tenant_id = $1 AND name = $2", [
        v.tenantId,
        v.packName,
      ]);
      let packId = (ex.rows[0] as Row | undefined)?.["id"] as string | undefined;
      if (!packId) {
        await c.query("INSERT INTO policy_packs (tenant_id, id, name) VALUES ($1,$2,$3)", [
          v.tenantId,
          v.packId,
          v.packName,
        ]);
        packId = v.packId;
      }
      const r = await c.query(
        `INSERT INTO policy_pack_versions (tenant_id, id, pack_id, version, source, rego, content_hash) VALUES ($1,$2,$3,$4,$5,$6,$7)
         RETURNING *, $8::text AS pack_name`,
        [
          v.tenantId,
          v.versionId,
          packId,
          v.version,
          JSON.stringify(v.source),
          v.rego,
          v.contentHash,
          v.packName,
        ],
      );
      return versionOf(r.rows[0] as Row);
    });
  }
  getPackVersion(t: string, id: string): Promise<PackVersionRecord | undefined> {
    return this.tx(t, async (c) => {
      const r = await c.query(
        "SELECT v.*, p.name AS pack_name FROM policy_pack_versions v JOIN policy_packs p ON p.tenant_id = v.tenant_id AND p.id = v.pack_id WHERE v.tenant_id = $1 AND v.id = $2",
        [t, id],
      );
      return r.rows[0] ? versionOf(r.rows[0] as Row) : undefined;
    });
  }
  listPackVersions(t: string): Promise<PackVersionRecord[]> {
    return this.tx(t, async (c) =>
      (
        await c.query(
          "SELECT v.*, p.name AS pack_name FROM policy_pack_versions v JOIN policy_packs p ON p.tenant_id = v.tenant_id AND p.id = v.pack_id WHERE v.tenant_id = $1 ORDER BY p.name, v.created_at, v.id",
          [t],
        )
      ).rows.map((r) => versionOf(r as Row)),
    );
  }
  activatePackVersion(
    t: string,
    versionId: string,
    by: string,
    now: Date,
  ): Promise<PolicyAssignment> {
    return this.tx(t, async (c) => {
      const v = await c.query(
        "SELECT pack_id FROM policy_pack_versions WHERE tenant_id = $1 AND id = $2",
        [t, versionId],
      );
      const packId = (v.rows[0] as Row | undefined)?.["pack_id"];
      if (!packId) throw new StoreConflict("unknown version");
      await c.query(
        "UPDATE policy_assignments SET active = false, deactivated_at = $3 WHERE tenant_id = $1 AND pack_id = $2 AND active",
        [t, packId, now],
      );
      const r = await c.query(
        "INSERT INTO policy_assignments (tenant_id, pack_id, version_id, activated_by, activated_at) VALUES ($1,$2,$3,$4,$5) RETURNING *",
        [t, packId, versionId, by, now],
      );
      return assignOf(r.rows[0] as Row);
    });
  }
  deactivatePack(t: string, packId: string, now: Date): Promise<boolean> {
    return this.tx(t, async (c) => {
      const r = await c.query(
        "UPDATE policy_assignments SET active = false, deactivated_at = $3 WHERE tenant_id = $1 AND pack_id = $2 AND active",
        [t, packId, now],
      );
      return (r.rowCount ?? 0) > 0;
    });
  }
  listActiveAssignments(t: string): Promise<PolicyAssignment[]> {
    return this.tx(t, async (c) =>
      (
        await c.query(
          "SELECT * FROM policy_assignments WHERE tenant_id = $1 AND active ORDER BY id",
          [t],
        )
      ).rows.map((r) => assignOf(r as Row)),
    );
  }

  // budgets etc
  upsertBudget(b: Budget): Promise<Budget> {
    return this.tx(b.tenantId, async (c) => {
      const r = await c.query(
        `INSERT INTO budgets (tenant_id, id, scope, target, metric, period, soft, hard) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (tenant_id, scope, target, metric, period) DO UPDATE SET soft = EXCLUDED.soft, hard = EXCLUDED.hard RETURNING *`,
        [b.tenantId, b.id, b.scope, b.target, b.metric, b.period, b.soft ?? null, b.hard ?? null],
      );
      return budgetOf(r.rows[0] as Row);
    });
  }
  listBudgets(t: string): Promise<Budget[]> {
    return this.tx(t, async (c) =>
      (await c.query("SELECT * FROM budgets WHERE tenant_id = $1 ORDER BY id", [t])).rows.map((r) =>
        budgetOf(r as Row),
      ),
    );
  }
  deleteBudget(t: string, id: string): Promise<boolean> {
    return this.tx(
      t,
      async (c) =>
        ((await c.query("DELETE FROM budgets WHERE tenant_id = $1 AND id = $2", [t, id]))
          .rowCount ?? 0) === 1,
    );
  }
  getSettings(t: string): Promise<TenantSettings | undefined> {
    return this.tx(t, async (c) => {
      const r = await c.query("SELECT * FROM tenant_settings WHERE tenant_id = $1", [t]);
      return r.rows[0] ? settingsOf(r.rows[0] as Row) : undefined;
    });
  }
  putSettings(s: TenantSettings): Promise<void> {
    return this.tx(s.tenantId, async (c) => {
      await c.query(
        `INSERT INTO tenant_settings (tenant_id, retention_audit_days, retention_transcript_days, retention_memory_days, updated_by) VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (tenant_id) DO UPDATE SET retention_audit_days = EXCLUDED.retention_audit_days, retention_transcript_days = EXCLUDED.retention_transcript_days,
           retention_memory_days = EXCLUDED.retention_memory_days, updated_by = EXCLUDED.updated_by, updated_at = now()`,
        [
          s.tenantId,
          s.retentionAuditDays,
          s.retentionTranscriptDays,
          s.retentionMemoryDays,
          s.updatedBy ?? null,
        ],
      );
    });
  }
  getPlacement(t: string): Promise<Placement | undefined> {
    return this.tx(t, async (c) => {
      const r = await c.query("SELECT * FROM tenant_placements WHERE tenant_id = $1", [t]);
      const x = r.rows[0] as Row | undefined;
      return (
        x &&
        clean<Placement>({
          tenantId: x["tenant_id"],
          isolationTier: x["isolation_tier"],
          poolKey: x["pool_key"],
        })
      );
    });
  }
  putPlacement(p: Placement): Promise<void> {
    return this.tx(p.tenantId, async (c) => {
      await c.query(
        `INSERT INTO tenant_placements (tenant_id, isolation_tier, pool_key) VALUES ($1,$2,$3)
         ON CONFLICT (tenant_id) DO UPDATE SET isolation_tier = EXCLUDED.isolation_tier, pool_key = EXCLUDED.pool_key, updated_at = now()`,
        [p.tenantId, p.isolationTier, p.poolKey ?? null],
      );
    });
  }
}
