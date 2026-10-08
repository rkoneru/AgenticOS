import type { ClientBase } from "pg";
import { inTx, pgCode, pgConstraint, type PgPoolLike } from "./pg-util.js";
import { StoreConflict, StoreForbidden, type RegistryStore } from "./store.js";
import {
  statusOf,
  type EvalAttestationRecord,
  type NamespaceRecord,
  type PublisherKey,
  type RevokeReason,
  type VersionEvent,
  type VersionRecord,
  type VersionRow,
  type Viewer,
} from "./types.js";

export interface PgRegistryOptions {
  /** Residency guard (`@axis/data-governance/residency`): when set, every write for a tenant is refused unless this instance's region is allowed. */
  residency?: { assertWrite(tenantId: string): Promise<void> };
  pool: PgPoolLike;
  /** Tests only: connect as a superuser and SET LOCAL ROLE axis_app per transaction. */
  role?: string;
}

interface NsRow {
  namespace: string;
  tenant_id: string;
  normalized: string;
  created_at: Date;
  created_by: string;
  is_public: boolean;
}
interface KeyRow {
  namespace: string;
  key_id: string;
  tenant_id: string;
  public_key: string;
  valid_from: Date;
  valid_until: Date | null;
  revoked_at: Date | null;
  revoke_reason: RevokeReason | null;
  created_at: Date;
  created_by: string;
}
interface VerRow {
  namespace: string;
  name: string;
  version: string;
  tenant_id: string;
  abl: string;
  content_hash: string;
  risk_level: VersionRecord["riskLevel"];
  signature: VersionRecord["signature"];
  provenance: VersionRecord["provenance"];
  published_at: Date;
  published_by: string;
}
interface EvRow {
  tenant_id: string;
  namespace: string;
  name: string;
  version: string;
  kind: VersionEvent["kind"];
  reason: string;
  actor: string;
  at: Date;
}

const toNs = (r: NsRow): NamespaceRecord => ({
  namespace: r.namespace,
  tenantId: r.tenant_id,
  normalized: r.normalized,
  createdAt: r.created_at,
  createdBy: r.created_by,
  public: r.is_public,
});
const toKey = (r: KeyRow): PublisherKey => ({
  namespace: r.namespace,
  keyId: r.key_id,
  tenantId: r.tenant_id,
  publicKey: r.public_key,
  validFrom: r.valid_from,
  validUntil: r.valid_until,
  revokedAt: r.revoked_at,
  revokeReason: r.revoke_reason,
  createdAt: r.created_at,
  createdBy: r.created_by,
});
const toVer = (r: VerRow): VersionRecord => ({
  namespace: r.namespace,
  name: r.name,
  version: r.version,
  tenantId: r.tenant_id,
  abl: r.abl,
  contentHash: r.content_hash,
  riskLevel: r.risk_level,
  signature: r.signature,
  provenance: r.provenance,
  publishedAt: r.published_at,
  publishedBy: r.published_by,
});
const toEv = (r: EvRow): VersionEvent => ({
  namespace: r.namespace,
  name: r.name,
  version: r.version,
  tenantId: r.tenant_id,
  kind: r.kind,
  reason: r.reason,
  actor: r.actor,
  at: r.at,
});

const NS_SELECT = `SELECT n.*, EXISTS (SELECT 1 FROM registry_public_namespaces p WHERE p.namespace = n.namespace) AS is_public
                   FROM registry_namespaces n`;

/** Postgres store. Tenant isolation is the database's job (forced RLS, migration 0015); this code never filters by tenant itself for reads. */
export class PgRegistryStore implements RegistryStore {
  constructor(private readonly o: PgRegistryOptions) {}

  private tx<T>(tenantId: string | null, fn: (c: ClientBase) => Promise<T>): Promise<T> {
    return inTx(this.o.pool, { tenantId, ...(this.o.role ? { role: this.o.role } : {}) }, fn);
  }
  private static rls(err: unknown): never {
    // 42501 = RLS WITH CHECK violation / insufficient privilege.
    if (pgCode(err) === "42501") throw new StoreForbidden("not the owner");
    throw err;
  }

  async claimNamespace(n: Omit<NamespaceRecord, "public">): Promise<NamespaceRecord> {
    try {
      await this.tx(n.tenantId, (c) =>
        c.query(
          "INSERT INTO registry_namespaces (namespace, tenant_id, normalized, created_at, created_by) VALUES ($1,$2,$3,$4,$5)",
          [n.namespace, n.tenantId, n.normalized, n.createdAt, n.createdBy],
        ),
      );
    } catch (err) {
      if (pgCode(err) === "23505")
        throw new StoreConflict(
          pgConstraint(err).includes("normalized") ? "namespace_confusable" : "namespace",
          "namespace taken",
        );
      return PgRegistryStore.rls(err);
    }
    return { ...n, public: false };
  }
  async getNamespace(viewer: Viewer, namespace: string): Promise<NamespaceRecord | undefined> {
    const r = await this.tx(viewer.tenantId, (c) =>
      c.query<NsRow>(`${NS_SELECT} WHERE n.namespace = $1`, [namespace]),
    );
    const row = r.rows[0];
    // Namespace names are readable by everyone (global uniqueness); hide the record unless the viewer may see the namespace.
    return row && (row.is_public || row.tenant_id === viewer.tenantId) ? toNs(row) : undefined;
  }
  /** Platform path (marketplace moderation needs the owner of any namespace); the namespace name is not secret but its row is RLS-protected. */
  async ownerOf(namespace: string): Promise<string | undefined> {
    const r = await inTx(
      this.o.pool,
      { tenantId: null, platform: true, ...(this.o.role ? { role: this.o.role } : {}) },
      (c) =>
        c.query<{ tenant_id: string }>(
          "SELECT tenant_id FROM registry_namespaces WHERE namespace = $1",
          [namespace],
        ),
    );
    return r.rows[0]?.tenant_id;
  }
  async listNamespaces(tenantId: string): Promise<NamespaceRecord[]> {
    const r = await this.tx(tenantId, (c) =>
      c.query<NsRow>(`${NS_SELECT} WHERE n.tenant_id = $1 ORDER BY n.namespace`, [tenantId]),
    );
    return r.rows.map(toNs);
  }
  async setPublic(tenantId: string, namespace: string, listedBy: string, at: Date): Promise<void> {
    try {
      await this.tx(tenantId, async (c) => {
        const own = await c.query(
          "SELECT 1 FROM registry_namespaces WHERE namespace = $1 AND tenant_id = $2",
          [namespace, tenantId],
        );
        if (own.rowCount === 0) throw new StoreForbidden("not the namespace owner");
        await c.query(
          "INSERT INTO registry_public_namespaces (namespace, tenant_id, listed_at, listed_by) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
          [namespace, tenantId, at, listedBy],
        );
      });
    } catch (err) {
      if (err instanceof StoreForbidden) throw err;
      PgRegistryStore.rls(err);
    }
  }
  async setVersionPublic(
    tenantId: string,
    namespace: string,
    name: string,
    version: string,
    listedBy: string,
    at: Date,
  ): Promise<void> {
    try {
      await this.tx(tenantId, async (c) => {
        const own = await c.query(
          "SELECT 1 FROM registry_versions WHERE namespace = $1 AND name = $2 AND version = $3 AND tenant_id = $4",
          [namespace, name, version, tenantId],
        );
        if (own.rowCount === 0) throw new StoreForbidden("not the version owner");
        await c.query(
          "INSERT INTO registry_public_versions (namespace, name, version, tenant_id, listed_at, listed_by) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
          [namespace, name, version, tenantId, at, listedBy],
        );
      });
    } catch (err) {
      if (err instanceof StoreForbidden) throw err;
      PgRegistryStore.rls(err);
    }
  }
  async listPublicNamespaces(): Promise<NamespaceRecord[]> {
    const r = await this.tx(null, (c) =>
      c.query<NsRow>(
        `${NS_SELECT} WHERE EXISTS (SELECT 1 FROM registry_public_namespaces p WHERE p.namespace = n.namespace) ORDER BY n.namespace`,
      ),
    );
    return r.rows.map(toNs);
  }

  async addKey(key: PublisherKey): Promise<void> {
    try {
      await this.tx(key.tenantId, (c) =>
        c.query(
          `INSERT INTO registry_keys (namespace, key_id, tenant_id, public_key, valid_from, valid_until, revoked_at, revoke_reason, created_at, created_by)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [
            key.namespace,
            key.keyId,
            key.tenantId,
            key.publicKey,
            key.validFrom,
            key.validUntil,
            key.revokedAt,
            key.revokeReason,
            key.createdAt,
            key.createdBy,
          ],
        ),
      );
    } catch (err) {
      if (pgCode(err) === "23505") throw new StoreConflict("key", "key already registered");
      if (pgCode(err) === "23503") throw new StoreForbidden("no such namespace");
      PgRegistryStore.rls(err);
    }
  }
  async getKeys(viewer: Viewer, namespace: string): Promise<PublisherKey[]> {
    const r = await this.tx(viewer.tenantId, (c) =>
      c.query<KeyRow>(
        "SELECT * FROM registry_keys WHERE namespace = $1 ORDER BY created_at, key_id",
        [namespace],
      ),
    );
    return r.rows.map(toKey);
  }
  async updateKey(
    tenantId: string,
    namespace: string,
    keyId: string,
    patch: { validUntil?: Date; revoke?: { at: Date; reason: RevokeReason } },
  ): Promise<PublisherKey> {
    try {
      return await this.tx(tenantId, async (c) => {
        const cur = await c.query<KeyRow>(
          "SELECT * FROM registry_keys WHERE namespace = $1 AND key_id = $2 AND tenant_id = $3 FOR UPDATE",
          [namespace, keyId, tenantId],
        );
        const row = cur.rows[0];
        if (!row) throw new StoreForbidden("not the key owner");
        if (patch.validUntil) {
          if (row.valid_until)
            throw new StoreConflict("key_state", "key validity end is already set");
          if (patch.validUntil.getTime() <= row.valid_from.getTime())
            throw new StoreConflict("key_state", "validity end must follow its start");
        }
        if (patch.revoke && row.revoked_at)
          throw new StoreConflict("key_state", "key is already revoked");
        const up = await c.query<KeyRow>(
          `UPDATE registry_keys SET valid_until = COALESCE($4, valid_until), revoked_at = COALESCE($5, revoked_at),
                  revoke_reason = COALESCE($6, revoke_reason)
           WHERE namespace = $1 AND key_id = $2 AND tenant_id = $3 RETURNING *`,
          [
            namespace,
            keyId,
            tenantId,
            patch.validUntil ?? null,
            patch.revoke?.at ?? null,
            patch.revoke?.reason ?? null,
          ],
        );
        return toKey(up.rows[0] as KeyRow);
      });
    } catch (err) {
      if (err instanceof StoreConflict || err instanceof StoreForbidden) throw err;
      return PgRegistryStore.rls(err);
    }
  }

  async insertVersion(rec: VersionRecord, normalizedName: string): Promise<void> {
    await this.o.residency?.assertWrite(rec.tenantId);
    try {
      await this.tx(rec.tenantId, async (c) => {
        const own = await c.query(
          "SELECT 1 FROM registry_namespaces WHERE namespace = $1 AND tenant_id = $2",
          [rec.namespace, rec.tenantId],
        );
        if (own.rowCount === 0) throw new StoreForbidden("not the namespace owner");
        await c.query("SAVEPOINT nm");
        try {
          await c.query(
            "INSERT INTO registry_names (namespace, name, tenant_id, normalized, created_at) VALUES ($1,$2,$3,$4,$5)",
            [rec.namespace, rec.name, rec.tenantId, normalizedName, rec.publishedAt],
          );
        } catch (err) {
          if (pgCode(err) !== "23505") throw err;
          await c.query("ROLLBACK TO SAVEPOINT nm");
          // PK clash = the name exists (fine); the normalized UNIQUE = a different, confusable name.
          if (pgConstraint(err).endsWith("normalized_key"))
            throw new StoreConflict(
              "name_confusable",
              "name is confusable with an existing blueprint",
            );
        }
        await c.query(
          `INSERT INTO registry_versions (namespace, name, version, tenant_id, abl, content_hash, risk_level, signature, provenance, published_at, published_by)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10,$11)`,
          [
            rec.namespace,
            rec.name,
            rec.version,
            rec.tenantId,
            rec.abl,
            rec.contentHash,
            rec.riskLevel,
            JSON.stringify(rec.signature),
            JSON.stringify(rec.provenance),
            rec.publishedAt,
            rec.publishedBy,
          ],
        );
      });
    } catch (err) {
      if (err instanceof StoreConflict || err instanceof StoreForbidden) throw err;
      if (pgCode(err) === "23505") throw new StoreConflict("version", "version already published");
      PgRegistryStore.rls(err);
    }
  }

  private async rows(c: ClientBase, where: string, params: unknown[]): Promise<VersionRow[]> {
    const v = await c.query<VerRow>(
      `SELECT * FROM registry_versions WHERE ${where} ORDER BY published_at, version`,
      params,
    );
    if (v.rows.length === 0) return [];
    const ev = await c.query<EvRow>(
      `SELECT * FROM registry_version_events WHERE (namespace, name) IN (SELECT namespace, name FROM registry_versions WHERE ${where}) ORDER BY seq`,
      params,
    );
    return v.rows.map((r) => ({
      record: toVer(r),
      status: statusOf(
        ev.rows
          .filter(
            (e) => e.namespace === r.namespace && e.name === r.name && e.version === r.version,
          )
          .map(toEv),
      ),
    }));
  }
  async getVersion(
    viewer: Viewer,
    ns: string,
    name: string,
    version: string,
  ): Promise<VersionRow | undefined> {
    const r = await this.tx(viewer.tenantId, (c) =>
      this.rows(c, "namespace = $1 AND name = $2 AND version = $3", [ns, name, version]),
    );
    return r[0];
  }
  listVersions(viewer: Viewer, ns: string, name: string): Promise<VersionRow[]> {
    return this.tx(viewer.tenantId, (c) =>
      this.rows(c, "namespace = $1 AND name = $2", [ns, name]),
    );
  }
  async listNames(viewer: Viewer, ns: string): Promise<string[]> {
    const r = await this.tx(viewer.tenantId, (c) =>
      c.query<{ name: string }>(
        "SELECT name FROM registry_names WHERE namespace = $1 ORDER BY name",
        [ns],
      ),
    );
    return r.rows.map((x) => x.name);
  }
  async addAttestation(a: EvalAttestationRecord): Promise<void> {
    try {
      await this.tx(a.tenantId, async (c) => {
        const own = await c.query(
          "SELECT 1 FROM registry_versions WHERE namespace = $1 AND name = $2 AND version = $3 AND tenant_id = $4",
          [a.namespace, a.name, a.version, a.tenantId],
        );
        if (own.rowCount === 0) throw new StoreForbidden("not the version owner");
        await c.query(
          "INSERT INTO registry_eval_attestations (tenant_id, namespace, name, version, run_id, suite_ref, content_hash, overall, envelope, attached_at, attached_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11)",
          [
            a.tenantId,
            a.namespace,
            a.name,
            a.version,
            a.runId,
            a.suiteRef,
            a.contentHash,
            a.overall,
            JSON.stringify(a.envelope),
            a.attachedAt,
            a.attachedBy,
          ],
        );
      });
    } catch (err) {
      if (err instanceof StoreForbidden) throw err;
      if (pgCode(err) === "23505")
        throw new StoreConflict("version", "attestation exists for this run");
      PgRegistryStore.rls(err);
    }
  }
  async attestations(
    viewer: Viewer,
    ns: string,
    name: string,
    version: string,
  ): Promise<EvalAttestationRecord[]> {
    const r = await this.tx(viewer.tenantId, (c) =>
      c.query<{
        tenant_id: string;
        namespace: string;
        name: string;
        version: string;
        run_id: string;
        suite_ref: string;
        content_hash: string;
        overall: number;
        envelope: EvalAttestationRecord["envelope"];
        attached_at: Date;
        attached_by: string;
      }>(
        "SELECT * FROM registry_eval_attestations WHERE namespace = $1 AND name = $2 AND version = $3 ORDER BY seq",
        [ns, name, version],
      ),
    );
    return r.rows.map((x) => ({
      tenantId: x.tenant_id,
      namespace: x.namespace,
      name: x.name,
      version: x.version,
      runId: x.run_id,
      suiteRef: x.suite_ref,
      contentHash: x.content_hash,
      overall: x.overall,
      envelope: x.envelope,
      attachedAt: x.attached_at,
      attachedBy: x.attached_by,
    }));
  }
  async appendEvent(e: VersionEvent): Promise<void> {
    try {
      await this.tx(e.tenantId, async (c) => {
        const own = await c.query(
          "SELECT 1 FROM registry_versions WHERE namespace = $1 AND name = $2 AND version = $3 AND tenant_id = $4",
          [e.namespace, e.name, e.version, e.tenantId],
        );
        if (own.rowCount === 0) throw new StoreForbidden("not the version owner");
        await c.query(
          "INSERT INTO registry_version_events (tenant_id, namespace, name, version, kind, reason, actor, at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
          [e.tenantId, e.namespace, e.name, e.version, e.kind, e.reason, e.actor, e.at],
        );
      });
    } catch (err) {
      if (err instanceof StoreForbidden) throw err;
      PgRegistryStore.rls(err);
    }
  }
  async events(viewer: Viewer, ns: string, name: string, version: string): Promise<VersionEvent[]> {
    const r = await this.tx(viewer.tenantId, (c) =>
      c.query<EvRow>(
        "SELECT * FROM registry_version_events WHERE namespace = $1 AND name = $2 AND version = $3 ORDER BY seq",
        [ns, name, version],
      ),
    );
    return r.rows.map(toEv);
  }
}
