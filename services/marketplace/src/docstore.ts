import { inTx, pgCode, type PgPoolLike } from "@axis/registry";
import type { ClientBase } from "pg";

/**
 * Document persistence for the marketplace (one table, forced RLS: migration 0011). Three scopes, mirroring the database policies:
 *  - tenant   : only rows of that tenant (credential-derived)
 *  - platform : every row (reviewer / moderator / service code paths only)
 *  - catalog  : read-only, only `listings` whose status is `listed` (anonymous catalog reads)
 * Append-only collections (`events`, `evidence`, `takedowns`) reject updates. Nothing is ever deleted.
 */
export type Scope =
  { kind: "tenant"; tenantId: string } | { kind: "platform" } | { kind: "catalog" };
export const tenantScope = (tenantId: string): Scope => ({ kind: "tenant", tenantId });
export const PLATFORM: Scope = { kind: "platform" };
export const CATALOG: Scope = { kind: "catalog" };

export const APPEND_ONLY = new Set(["events", "evidence", "takedowns"]);

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
    scope: Scope,
    tenantId: string,
    coll: string,
    key: string,
  ): Promise<Doc<T> | undefined>;
  /** Fails with DocConflict when the key exists, DocForbidden when the scope may not write that tenant. */
  insert<T = Record<string, unknown>>(
    scope: Scope,
    tenantId: string,
    coll: string,
    key: string,
    data: T,
  ): Promise<Doc<T>>;
  /** Optimistic: `expectRev` must be the current revision, else DocConflict. */
  update<T = Record<string, unknown>>(
    scope: Scope,
    tenantId: string,
    coll: string,
    key: string,
    expectRev: number,
    data: T,
  ): Promise<Doc<T>>;
  /** Top-level equality filter over the document body. `tenantId` narrows (platform/catalog); tenant scope is always its own tenant. */
  find<T = Record<string, unknown>>(
    scope: Scope,
    coll: string,
    filter?: Filter,
    tenantId?: string,
  ): Promise<Doc<T>[]>;
}

const matches = (data: Record<string, unknown>, f: Filter): boolean =>
  Object.entries(f).every(([k, v]) => data[k] === v);

const catalogVisible = (coll: string, data: Record<string, unknown>): boolean =>
  coll === "listings" && data["status"] === "listed";

/** Reference implementation: same scope rules as the RLS policies of migration 0011. */
export class MemoryDocStore implements DocStore {
  private rows = new Map<string, Doc>();
  private k = (t: string, c: string, key: string): string => [t, c, key].join("\u0000");
  private visible(scope: Scope, d: Doc): boolean {
    if (scope.kind === "platform") return true;
    if (scope.kind === "tenant" && scope.tenantId === d.tenantId) return true;
    return catalogVisible(d.coll, d.data);
  }
  private writable(scope: Scope, tenantId: string): boolean {
    return scope.kind === "platform" || (scope.kind === "tenant" && scope.tenantId === tenantId);
  }

  get<T>(scope: Scope, tenantId: string, coll: string, key: string): Promise<Doc<T> | undefined> {
    const d = this.rows.get(this.k(tenantId, coll, key));
    return Promise.resolve(
      d && this.visible(scope, d) ? (structuredClone(d) as Doc<T>) : undefined,
    );
  }
  insert<T>(scope: Scope, tenantId: string, coll: string, key: string, data: T): Promise<Doc<T>> {
    if (!this.writable(scope, tenantId))
      return Promise.reject(new DocForbidden("scope may not write this tenant"));
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
    scope: Scope,
    tenantId: string,
    coll: string,
    key: string,
    expectRev: number,
    data: T,
  ): Promise<Doc<T>> {
    if (!this.writable(scope, tenantId))
      return Promise.reject(new DocForbidden("scope may not write this tenant"));
    if (APPEND_ONLY.has(coll))
      return Promise.reject(new DocForbidden(`collection ${coll} is append-only`));
    const cur = this.rows.get(this.k(tenantId, coll, key));
    if (!cur) return Promise.reject(new DocForbidden("no such document"));
    if (cur.rev !== expectRev) return Promise.reject(new DocConflict("stale revision"));
    cur.rev++;
    cur.data = structuredClone(data) as Record<string, unknown>;
    return Promise.resolve(structuredClone(cur) as Doc<T>);
  }
  find<T>(scope: Scope, coll: string, filter: Filter = {}, tenantId?: string): Promise<Doc<T>[]> {
    const out = [...this.rows.values()].filter(
      (d) =>
        d.coll === coll &&
        this.visible(scope, d) &&
        (tenantId === undefined || d.tenantId === tenantId) &&
        matches(d.data, filter),
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
  role?: string;
}

export class PgDocStore implements DocStore {
  constructor(private readonly o: PgDocOptions) {}
  private tx<T>(scope: Scope, fn: (c: ClientBase) => Promise<T>): Promise<T> {
    return inTx(
      this.o.pool,
      {
        tenantId: scope.kind === "tenant" ? scope.tenantId : null,
        platform: scope.kind === "platform",
        ...(this.o.role ? { role: this.o.role } : {}),
      },
      fn,
    );
  }
  async get<T>(
    scope: Scope,
    tenantId: string,
    coll: string,
    key: string,
  ): Promise<Doc<T> | undefined> {
    const r = await this.tx(scope, (c) =>
      c.query<Row>(
        "SELECT * FROM marketplace_docs WHERE tenant_id = $1 AND coll = $2 AND key = $3",
        [tenantId, coll, key],
      ),
    );
    return r.rows[0] ? toDoc<T>(r.rows[0]) : undefined;
  }
  async insert<T>(
    scope: Scope,
    tenantId: string,
    coll: string,
    key: string,
    data: T,
  ): Promise<Doc<T>> {
    try {
      const r = await this.tx(scope, (c) =>
        c.query<Row>(
          "INSERT INTO marketplace_docs (tenant_id, coll, key, rev, data) VALUES ($1,$2,$3,1,$4::jsonb) RETURNING *",
          [tenantId, coll, key, JSON.stringify(data)],
        ),
      );
      return toDoc<T>(r.rows[0] as Row);
    } catch (err) {
      if (pgCode(err) === "23505") throw new DocConflict("document exists");
      if (pgCode(err) === "42501") throw new DocForbidden("scope may not write this tenant");
      throw err;
    }
  }
  async update<T>(
    scope: Scope,
    tenantId: string,
    coll: string,
    key: string,
    expectRev: number,
    data: T,
  ): Promise<Doc<T>> {
    try {
      const r = await this.tx(scope, (c) =>
        c.query<Row>(
          "UPDATE marketplace_docs SET rev = rev + 1, data = $5::jsonb, updated_at = now() WHERE tenant_id = $1 AND coll = $2 AND key = $3 AND rev = $4 RETURNING *",
          [tenantId, coll, key, expectRev, JSON.stringify(data)],
        ),
      );
      if (r.rows[0]) return toDoc<T>(r.rows[0]);
    } catch (err) {
      if (pgCode(err) === "42501") throw new DocForbidden(`collection ${coll} is append-only`);
      throw err;
    }
    const exists = await this.get(scope, tenantId, coll, key);
    if (!exists) throw new DocForbidden("no such document");
    throw new DocConflict("stale revision");
  }
  async find<T>(
    scope: Scope,
    coll: string,
    filter: Filter = {},
    tenantId?: string,
  ): Promise<Doc<T>[]> {
    const r = await this.tx(scope, (c) =>
      c.query<Row>(
        "SELECT * FROM marketplace_docs WHERE coll = $1 AND data @> $2::jsonb AND ($3::uuid IS NULL OR tenant_id = $3::uuid) ORDER BY key",
        [coll, JSON.stringify(filter), tenantId ?? null],
      ),
    );
    return r.rows.map((x) => toDoc<T>(x));
  }
}
