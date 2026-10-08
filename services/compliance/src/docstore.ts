import { inTx, pgCode, type PgPoolLike } from "@axis/registry";
import type { ClientBase } from "pg";

/**
 * Document persistence (one table, forced RLS: migration 0014). Every call names the tenant, which the service takes from the
 * CREDENTIAL; the database refuses anything else. Nothing is ever deleted. The memory store is the reference; both run one contract suite.
 *
 *  systems         : the inventory head of each AI system (optimistic revisions)
 *  system_versions : append-only snapshot of every version of a system
 *  assessments     : one document per assessment VERSION (`<id>@<n>`); updatable until approved / rejected, then frozen
 *  documents       : generated technical documentation, append-only
 */
export const APPEND_ONLY = new Set(["system_versions", "documents"]);
export const COLLECTIONS = new Set(["systems", "system_versions", "assessments", "documents"]);

export interface Doc<T = Record<string, unknown>> {
  tenantId: string;
  coll: string;
  key: string;
  rev: number;
  data: T;
}

export type Filter = Readonly<Record<string, string | number | boolean>>;

export class DocConflict extends Error {}
export class DocForbidden extends Error {}

export interface DocStore {
  get<T = Record<string, unknown>>(
    tenantId: string,
    coll: string,
    key: string,
  ): Promise<Doc<T> | undefined>;
  /** Fails with DocConflict when the key exists. */
  insert<T = Record<string, unknown>>(
    tenantId: string,
    coll: string,
    key: string,
    data: T,
  ): Promise<Doc<T>>;
  /** Optimistic: `expectRev` must be the current revision, else DocConflict; DocForbidden for immutable documents. */
  update<T = Record<string, unknown>>(
    tenantId: string,
    coll: string,
    key: string,
    expectRev: number,
    data: T,
  ): Promise<Doc<T>>;
  /** Top-level equality filter over the document body, ordered by key. */
  find<T = Record<string, unknown>>(
    tenantId: string,
    coll: string,
    filter?: Filter,
  ): Promise<Doc<T>[]>;
}

const matches = (data: Record<string, unknown>, f: Filter): boolean =>
  Object.entries(f).every(([k, v]) => data[k] === v);

/** The immutability rules of migration 0014 (the database trigger is the enforcement; this mirrors it for the memory store). */
function frozen(coll: string, data: Record<string, unknown>): boolean {
  if (APPEND_ONLY.has(coll)) return true;
  if (coll === "assessments") return data["state"] === "approved" || data["state"] === "rejected";
  return false;
}

/** The independence rule of migration 0014: an approving or rejecting reviewer is never the author or a contributor. */
export function reviewerIndependent(data: Record<string, unknown>): boolean {
  const state = data["state"];
  if (state !== "approved" && state !== "rejected") return true;
  const reviewer = data["reviewed_by"];
  if (typeof reviewer !== "string" || reviewer === "") return false;
  if (data["author"] === reviewer) return false;
  const contributors = data["contributors"];
  return !(Array.isArray(contributors) && contributors.includes(reviewer));
}

export class MemoryDocStore implements DocStore {
  private rows = new Map<string, Doc>();
  private k = (t: string, c: string, key: string): string => [t, c, key].join("\u0000");

  get<T>(tenantId: string, coll: string, key: string): Promise<Doc<T> | undefined> {
    const d = this.rows.get(this.k(tenantId, coll, key));
    return Promise.resolve(d ? (structuredClone(d) as Doc<T>) : undefined);
  }
  insert<T>(tenantId: string, coll: string, key: string, data: T): Promise<Doc<T>> {
    if (!COLLECTIONS.has(coll)) return Promise.reject(new DocForbidden("unknown collection"));
    if (coll === "assessments" && !reviewerIndependent(data as Record<string, unknown>))
      return Promise.reject(new DocForbidden("reviewer must differ from the author"));
    const id = this.k(tenantId, coll, key);
    if (this.rows.has(id)) return Promise.reject(new DocConflict("document exists"));
    const d: Doc = {
      tenantId,
      coll,
      key,
      rev: 1,
      data: structuredClone(data) as Record<string, unknown>,
    };
    this.rows.set(id, d);
    return Promise.resolve(structuredClone(d) as Doc<T>);
  }
  update<T>(
    tenantId: string,
    coll: string,
    key: string,
    expectRev: number,
    data: T,
  ): Promise<Doc<T>> {
    const cur = this.rows.get(this.k(tenantId, coll, key));
    if (!cur) return Promise.reject(new DocForbidden("no such document"));
    if (frozen(coll, cur.data))
      return Promise.reject(new DocForbidden(`${coll} document is immutable`));
    if (coll === "assessments" && !reviewerIndependent(data as Record<string, unknown>))
      return Promise.reject(new DocForbidden("reviewer must differ from the author"));
    if (cur.rev !== expectRev) return Promise.reject(new DocConflict("stale revision"));
    cur.rev++;
    cur.data = structuredClone(data) as Record<string, unknown>;
    return Promise.resolve(structuredClone(cur) as Doc<T>);
  }
  find<T>(tenantId: string, coll: string, filter: Filter = {}): Promise<Doc<T>[]> {
    const out = [...this.rows.values()].filter(
      (d) => d.tenantId === tenantId && d.coll === coll && matches(d.data, filter),
    );
    return Promise.resolve(
      out.sort((a, b) => (a.key < b.key ? -1 : 1)).map((d) => structuredClone(d) as Doc<T>),
    );
  }
}

interface Row {
  tenant_id: string;
  coll: string;
  key: string;
  rev: number;
  data: Record<string, unknown>;
}
const toDoc = <T>(r: Row): Doc<T> => ({
  tenantId: r.tenant_id,
  coll: r.coll,
  key: r.key,
  rev: r.rev,
  data: r.data as T,
});

export interface PgDocOptions {
  pool: PgPoolLike;
  /** Tests only: `SET LOCAL ROLE` (production connects as axis_app). */
  role?: string;
}

export class PgDocStore implements DocStore {
  constructor(private readonly o: PgDocOptions) {}
  private tx<T>(tenantId: string, fn: (c: ClientBase) => Promise<T>): Promise<T> {
    return inTx(this.o.pool, { tenantId, ...(this.o.role ? { role: this.o.role } : {}) }, fn);
  }
  async get<T>(tenantId: string, coll: string, key: string): Promise<Doc<T> | undefined> {
    const r = await this.tx(tenantId, (c) =>
      c.query<Row>(
        "SELECT * FROM compliance_docs WHERE tenant_id = $1 AND coll = $2 AND key = $3",
        [tenantId, coll, key],
      ),
    );
    return r.rows[0] ? toDoc<T>(r.rows[0]) : undefined;
  }
  async insert<T>(tenantId: string, coll: string, key: string, data: T): Promise<Doc<T>> {
    try {
      const r = await this.tx(tenantId, (c) =>
        c.query<Row>(
          "INSERT INTO compliance_docs (tenant_id, coll, key, rev, data) VALUES ($1,$2,$3,1,$4::jsonb) RETURNING *",
          [tenantId, coll, key, JSON.stringify(data)],
        ),
      );
      return toDoc<T>(r.rows[0] as Row);
    } catch (err) {
      if (pgCode(err) === "23505") throw new DocConflict("document exists");
      if (pgCode(err) === "42501" || pgCode(err) === "23514")
        throw new DocForbidden("not permitted for this tenant");
      throw err;
    }
  }
  async update<T>(
    tenantId: string,
    coll: string,
    key: string,
    expectRev: number,
    data: T,
  ): Promise<Doc<T>> {
    try {
      const r = await this.tx(tenantId, (c) =>
        c.query<Row>(
          "UPDATE compliance_docs SET rev = rev + 1, data = $5::jsonb, updated_at = now() WHERE tenant_id = $1 AND coll = $2 AND key = $3 AND rev = $4 RETURNING *",
          [tenantId, coll, key, expectRev, JSON.stringify(data)],
        ),
      );
      if (r.rows[0]) return toDoc<T>(r.rows[0]);
    } catch (err) {
      if (pgCode(err) === "42501") throw new DocForbidden(`${coll} document is immutable`);
      if (pgCode(err) === "23514") throw new DocForbidden("reviewer must differ from the author");
      throw err;
    }
    const exists = await this.get(tenantId, coll, key);
    if (!exists) throw new DocForbidden("no such document");
    throw new DocConflict("stale revision");
  }
  async find<T>(tenantId: string, coll: string, filter: Filter = {}): Promise<Doc<T>[]> {
    const r = await this.tx(tenantId, (c) =>
      c.query<Row>(
        "SELECT * FROM compliance_docs WHERE tenant_id = $1 AND coll = $2 AND data @> $3::jsonb ORDER BY key",
        [tenantId, coll, JSON.stringify(filter)],
      ),
    );
    return r.rows.map((x) => toDoc<T>(x));
  }
}
