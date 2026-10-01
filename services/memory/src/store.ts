import { withTenant } from "@axis/db";
import type { ClientBase, PoolClient } from "pg";
import {
  aclKey,
  aclSql,
  canonicalAcl,
  hashContent,
  validatePrincipal,
  type CanonicalAcl,
} from "./acl.js";
import { chunkText, type ChunkOptions } from "./chunk.js";
import { EMBEDDING_DIMENSIONS, vectorLiteral } from "./embedder.js";
import { redactForPhi } from "./redact.js";
import {
  ENTRY_SCOPES,
  MemoryError,
  SCOPES,
  type Embedder,
  type Entry,
  type IngestRequest,
  type IngestResult,
  type Metadata,
  type Principal,
  type RecallQuery,
  type Scope,
  type SearchHit,
  type SearchQuery,
  type WriteRequest,
  type WriteResult,
} from "./types.js";

export interface PgPoolLike {
  connect(): Promise<PoolClient>;
}

export interface PgMemoryOptions {
  pool: PgPoolLike;
  embedder: Embedder;
  /** Tests only: `SET LOCAL ROLE` for each transaction (production connects as axis_app). */
  role?: string;
  now?: () => Date;
  chunking?: ChunkOptions;
}

export const MAX_CONTENT_CHARS = 1_000_000;
export const MAX_CHUNKS_PER_DOCUMENT = 2000;
const MAX_ENTRY_CHARS = 32_000;
const MAX_TTL_SECONDS = 10 * 365 * 24 * 3600;
const NAME_RE = /^[a-z][a-z0-9-]{1,62}$/;
// pgvector's hnsw.ef_search bounds the candidate list: a filtered (ACL / metadata) search returns at most that many candidates
// before the filter, so keep it high. Fewer than `limit` readable rows can be returned only if fewer readable rows exist in the
// candidates; this affects recall, never confidentiality.
const EF_SEARCH = 400;

function assertText(s: unknown, what: string, max: number): asserts s is string {
  if (typeof s !== "string" || s.trim() === "")
    throw new MemoryError("INVALID", `${what} must be a non-empty string`);
  if (s.length > max) throw new MemoryError("INVALID", `${what} exceeds ${max} characters`);
  if (s.includes("\u0000")) throw new MemoryError("INVALID", `${what} must not contain NUL`);
}

function assertMetadata(m: unknown): Metadata {
  if (m === undefined) return {};
  if (typeof m !== "object" || m === null || Array.isArray(m))
    throw new MemoryError("INVALID", "metadata must be an object");
  const text = JSON.stringify(m);
  if (text.length > 16_000) throw new MemoryError("INVALID", "metadata exceeds 16000 characters");
  if (text.includes("\\u0000")) throw new MemoryError("INVALID", "metadata must not contain NUL");
  return m as Metadata;
}

function optionalName(v: string | undefined, what: string): string | undefined {
  if (v === undefined) return undefined;
  assertText(v, what, 256);
  return v;
}

function ttlToExpiry(now: Date, ttl: number | undefined): Date | null {
  if (ttl === undefined) return null;
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > MAX_TTL_SECONDS)
    throw new MemoryError("INVALID", "ttlSeconds must be a positive integer (at most ten years)");
  return new Date(now.getTime() + ttl * 1000);
}

interface Prepared {
  content: string;
  metadata: Metadata;
  phi: boolean;
}

function toVectorLiterals(vectors: number[][], expected: number): string[] {
  if (vectors.length !== expected)
    throw new MemoryError("EMBEDDER", "embedder returned the wrong number of vectors");
  return vectors.map((v) => {
    if (v.length !== EMBEDDING_DIMENSIONS || !v.every(Number.isFinite))
      throw new MemoryError(
        "EMBEDDER",
        `embedder must return finite ${EMBEDDING_DIMENSIONS}-dimensional vectors`,
      );
    return vectorLiteral(v);
  });
}

/**
 * Run, session, long-term and knowledge-base memory on Postgres + pgvector.
 *
 * Tenancy: every method runs in a transaction that sets the tenant (`withTenant` / `axis.set_tenant`), so FORCED row-level
 * security applies, and every statement also names `tenant_id` explicitly (defence in depth, and index use).
 * ACL: reads select rows through `aclSql` in the same WHERE as the similarity ORDER BY / LIMIT; unreadable rows are never
 * fetched, scored, counted, or distinguishable from absent ones. No method returns a total or a "hidden results" count.
 * PHI: when the tenant is in `phi_mode` or the request sets `phi`, redaction runs before embedding, hashing and persistence.
 */
export class PgMemoryService {
  private readonly now: () => Date;

  constructor(private readonly o: PgMemoryOptions) {
    if (o.embedder.dimensions !== EMBEDDING_DIMENSIONS)
      throw new MemoryError("EMBEDDER", `embedder dimensions must be ${EMBEDDING_DIMENSIONS}`);
    this.now = o.now ?? (() => new Date());
  }

  private async inTenant<T>(tenantId: string, fn: (c: ClientBase) => Promise<T>): Promise<T> {
    const client = await this.o.pool.connect();
    try {
      return await withTenant(client, tenantId, fn, this.o.role ? { role: this.o.role } : {});
    } finally {
      client.release();
    }
  }

  private async embed(texts: string[]): Promise<string[]> {
    let vectors: number[][];
    try {
      vectors = await this.o.embedder.embed(texts);
    } catch {
      throw new MemoryError("EMBEDDER", "embedding failed");
    }
    return toVectorLiterals(vectors, texts.length);
  }

  private async prepare(
    c: ClientBase,
    tenantId: string,
    req: {
      content: string;
      metadata?: Metadata | undefined;
      phi?: boolean | undefined;
      redact?: readonly string[] | undefined;
    },
    maxChars: number,
  ): Promise<Prepared> {
    assertText(req.content, "content", maxChars);
    const metadata = assertMetadata(req.metadata);
    const tenant = await c.query<{ phi_mode: boolean }>(
      "SELECT phi_mode FROM tenants WHERE id = $1",
      [tenantId],
    );
    if (tenant.rowCount === 0) throw new MemoryError("NOT_FOUND", "tenant not found");
    const phi = req.phi === true || tenant.rows[0]?.phi_mode === true;
    if (!phi) return { content: req.content, metadata, phi };
    const red = redactForPhi({ content: req.content, metadata }, req.redact ?? []);
    return { content: red.content, metadata: red.metadata, phi };
  }

  // ---------------------------------------------------------------- knowledge bases

  async ensureKnowledgeBase(tenantId: string, name: string): Promise<string> {
    if (!NAME_RE.test(name))
      throw new MemoryError("INVALID", "knowledge base name must match ^[a-z][a-z0-9-]{1,62}$");
    return this.inTenant(tenantId, (c) => this.kbId(c, tenantId, name));
  }

  private async kbId(c: ClientBase, tenantId: string, name: string): Promise<string> {
    const r = await c.query<{ id: string }>(
      `INSERT INTO knowledge_bases (tenant_id, name) VALUES ($1, $2)
       ON CONFLICT (tenant_id, name) DO UPDATE SET name = EXCLUDED.name RETURNING id`,
      [tenantId, name],
    );
    return (r.rows[0] as { id: string }).id;
  }

  // ---------------------------------------------------------------- writes

  /** Write one run / session / agent (long-term) / tenant memory entry. Authorisation is the caller's gate decision. */
  async write(tenantId: string, req: WriteRequest): Promise<WriteResult> {
    if (!(ENTRY_SCOPES as readonly string[]).includes(req.scope))
      throw new MemoryError("INVALID", `scope must be one of ${ENTRY_SCOPES.join(", ")}`);
    const principal = validatePrincipal(req.principal);
    const owner = optionalName(req.ownerRef, "ownerRef");
    if (req.scope === "tenant" ? owner !== undefined : owner === undefined)
      throw new MemoryError(
        "INVALID",
        req.scope === "tenant"
          ? "tenant scope takes no ownerRef"
          : `${req.scope} scope needs an ownerRef`,
      );
    const acl = canonicalAcl(req.acl ?? { users: [principal.id] });
    const subject = optionalName(req.subject, "subject");
    const expires = ttlToExpiry(this.now(), req.ttlSeconds);
    return this.inTenant(tenantId, async (c) => {
      const p = await this.prepare(c, tenantId, req, MAX_ENTRY_CHARS);
      const [vec] = await this.embed([p.content]);
      const r = await c.query<{ id: string; inserted: boolean }>(
        `INSERT INTO memory_chunks (tenant_id, scope, owner_ref, content, embedding, acl, acl_key, metadata, content_hash,
                                    subject, phi, embedding_model, expires_at, created_by)
         VALUES ($1, $2, $3, $4, $5::vector, $6::jsonb, $7, $8::jsonb, $9, $10, $11, $12, $13, $14)
         ON CONFLICT (tenant_id, scope, COALESCE(owner_ref, ''), content_hash, acl_key) WHERE document_id IS NULL
         DO UPDATE SET expires_at = EXCLUDED.expires_at, metadata = EXCLUDED.metadata, subject = EXCLUDED.subject
         RETURNING id, (xmax = 0) AS inserted`,
        [
          tenantId,
          req.scope,
          owner ?? null,
          p.content,
          vec,
          JSON.stringify(acl),
          aclKey(acl),
          JSON.stringify(p.metadata),
          hashContent(p.content),
          subject ?? null,
          p.phi,
          this.o.embedder.id,
          expires,
          principal.id,
        ],
      );
      const row = r.rows[0] as { id: string; inserted: boolean };
      return {
        id: row.id,
        deduped: !row.inserted,
        phi: p.phi,
        expiresAt: expires ? expires.toISOString() : null,
      };
    });
  }

  /** Ingest a knowledge-base document: chunk, embed, label with the ACL, dedupe by content hash. */
  async ingestDocument(tenantId: string, req: IngestRequest): Promise<IngestResult> {
    if (!NAME_RE.test(req.kb))
      throw new MemoryError("INVALID", "knowledge base name must match ^[a-z][a-z0-9-]{1,62}$");
    const principal = validatePrincipal(req.principal);
    if (req.acl === undefined) throw new MemoryError("INVALID", "acl is required for a document");
    const acl = canonicalAcl(req.acl);
    const source = optionalName(req.source, "source");
    const title = optionalName(req.title, "title");
    const subject = optionalName(req.subject, "subject");
    const expires = ttlToExpiry(this.now(), req.ttlSeconds);
    return this.inTenant(tenantId, async (c) => {
      const p = await this.prepare(c, tenantId, req, MAX_CONTENT_CHARS);
      const chunks = chunkText(p.content, this.o.chunking);
      if (chunks.length > MAX_CHUNKS_PER_DOCUMENT)
        throw new MemoryError("INVALID", `document exceeds ${MAX_CHUNKS_PER_DOCUMENT} chunks`);
      const kbId = await this.kbId(c, tenantId, req.kb);
      const hash = hashContent(p.content);
      const key = aclKey(acl);
      const doc = await c.query<{ id: string }>(
        `INSERT INTO memory_documents (tenant_id, kb_id, source, title, content_hash, acl, acl_key, metadata, subject, phi,
                                       expires_at, created_by)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8::jsonb, $9, $10, $11, $12)
         ON CONFLICT (tenant_id, kb_id, content_hash, acl_key) DO NOTHING RETURNING id`,
        [
          tenantId,
          kbId,
          source ?? null,
          title ?? null,
          hash,
          JSON.stringify(acl),
          key,
          JSON.stringify(p.metadata),
          subject ?? null,
          p.phi,
          expires,
          principal.id,
        ],
      );
      if (doc.rowCount === 0) {
        const existing = await c.query<{ id: string }>(
          `SELECT id FROM memory_documents WHERE tenant_id = $1 AND kb_id = $2 AND content_hash = $3 AND acl_key = $4`,
          [tenantId, kbId, hash, key],
        );
        return {
          documentId: (existing.rows[0] as { id: string }).id,
          chunks: 0,
          deduped: true,
          phi: p.phi,
        };
      }
      const documentId = (doc.rows[0] as { id: string }).id;
      const vectors = await this.embed(chunks.map((k) => k.text));
      for (const k of chunks) {
        await c.query(
          `INSERT INTO memory_chunks (tenant_id, kb_id, scope, document_id, ordinal, content, embedding, acl, acl_key,
                                      metadata, content_hash, subject, phi, embedding_model, expires_at, created_by)
           VALUES ($1, $2, 'kb', $3, $4, $5, $6::vector, $7::jsonb, $8, $9::jsonb, $10, $11, $12, $13, $14, $15)`,
          [
            tenantId,
            kbId,
            documentId,
            k.ordinal,
            k.text,
            vectors[k.ordinal],
            JSON.stringify(acl),
            key,
            JSON.stringify({
              ...p.metadata,
              ...(title ? { title } : {}),
              ...(source ? { source } : {}),
            }),
            hashContent(k.text),
            subject ?? null,
            p.phi,
            this.o.embedder.id,
            expires,
            principal.id,
          ],
        );
      }
      return { documentId, chunks: chunks.length, deduped: false, phi: p.phi };
    });
  }

  // ---------------------------------------------------------------- reads (ACL-filtered)

  async search(tenantId: string, who: Principal, q: SearchQuery): Promise<SearchHit[]> {
    const principal = validatePrincipal(who);
    assertText(q.query, "query", 8000);
    const limit = q.limit ?? 5;
    if (!Number.isInteger(limit) || limit < 1 || limit > 50)
      throw new MemoryError("INVALID", "limit must be 1..50");
    const scopes = q.scopes ?? [];
    for (const s of scopes)
      if (!(SCOPES as readonly string[]).includes(s))
        throw new MemoryError("INVALID", "unknown scope");
    const metadata = q.metadata === undefined ? undefined : assertMetadata(q.metadata);
    if (
      q.minScore !== undefined &&
      (typeof q.minScore !== "number" || !(q.minScore >= -1 && q.minScore <= 1))
    )
      throw new MemoryError("INVALID", "minScore must be in [-1, 1]");
    const owner = optionalName(q.ownerRef, "ownerRef");
    const kbs = q.kbs ?? [];
    for (const k of kbs)
      if (!NAME_RE.test(k)) throw new MemoryError("INVALID", "bad knowledge base name");
    const [vec] = await this.embed([q.query]);
    const now = this.now();
    return this.inTenant(tenantId, async (c) => {
      await c.query(`SET LOCAL hnsw.ef_search = ${EF_SEARCH}`);
      const params: unknown[] = [
        tenantId,
        this.o.embedder.id,
        now,
        principal.id,
        principal.groups,
        vec,
      ];
      const where = [
        "c.tenant_id = $1",
        "c.embedding_model = $2",
        "(c.expires_at IS NULL OR c.expires_at > $3)",
        aclSql("c", 4, 5),
      ];
      const add = (sql: (n: number) => string, v: unknown): void => {
        params.push(v);
        where.push(sql(params.length));
      };
      if (scopes.length > 0) add((n) => `c.scope = ANY($${n}::text[])`, scopes);
      if (owner !== undefined) add((n) => `c.owner_ref = $${n}`, owner);
      if (kbs.length > 0)
        add(
          (n) =>
            `c.kb_id IN (SELECT id FROM knowledge_bases WHERE tenant_id = $1 AND name = ANY($${n}::text[]))`,
          kbs,
        );
      if (metadata !== undefined)
        add((n) => `c.metadata @> $${n}::jsonb`, JSON.stringify(metadata));
      if (q.minScore !== undefined)
        add((n) => `1 - (c.embedding <=> $6::vector) >= $${n}`, q.minScore);
      params.push(limit);
      const r = await c.query<HitRow>(
        `SELECT c.id, c.document_id, c.scope, c.owner_ref, k.name AS kb, c.content, c.metadata,
                1 - (c.embedding <=> $6::vector) AS score
           FROM memory_chunks c LEFT JOIN knowledge_bases k ON k.tenant_id = c.tenant_id AND k.id = c.kb_id
          WHERE ${where.join(" AND ")}
          ORDER BY c.embedding <=> $6::vector, c.id
          LIMIT $${params.length}`,
        params,
      );
      return r.rows.map((x) => ({
        id: x.id,
        documentId: x.document_id,
        scope: x.scope,
        ownerRef: x.owner_ref,
        kb: x.kb,
        content: x.content,
        metadata: x.metadata,
        score: Number(x.score),
      }));
    });
  }

  /** Most recent readable entries of one scope/owner (e.g. a run's scratchpad), newest first. */
  async recall(tenantId: string, who: Principal, q: RecallQuery): Promise<Entry[]> {
    const principal = validatePrincipal(who);
    if (!(SCOPES as readonly string[]).includes(q.scope))
      throw new MemoryError("INVALID", "unknown scope");
    const limit = q.limit ?? 20;
    if (!Number.isInteger(limit) || limit < 1 || limit > 200)
      throw new MemoryError("INVALID", "limit must be 1..200");
    const owner = optionalName(q.ownerRef, "ownerRef");
    const now = this.now();
    return this.inTenant(tenantId, async (c) => {
      const params: unknown[] = [tenantId, q.scope, now, principal.id, principal.groups];
      let ownerSql = "";
      if (owner !== undefined) {
        params.push(owner);
        ownerSql = `AND c.owner_ref = $${params.length}`;
      }
      params.push(limit);
      const r = await c.query<EntryRow>(
        `SELECT c.id, c.scope, c.owner_ref, c.content, c.metadata, c.created_at FROM memory_chunks c
          WHERE c.tenant_id = $1 AND c.scope = $2 AND (c.expires_at IS NULL OR c.expires_at > $3) AND ${aclSql("c", 4, 5)} ${ownerSql}
          ORDER BY c.created_at DESC, c.id LIMIT $${params.length}`,
        params,
      );
      return r.rows.map((x) => ({
        id: x.id,
        scope: x.scope,
        ownerRef: x.owner_ref,
        content: x.content,
        metadata: x.metadata,
        createdAt: x.created_at.toISOString(),
      }));
    });
  }

  // ---------------------------------------------------------------- administration

  /** Replace a document's ACL (and its chunks') atomically. Unknown id and other tenants' ids look the same: NOT_FOUND. */
  async setDocumentAcl(
    tenantId: string,
    documentId: string,
    acl: CanonicalAcl | import("./types.js").Acl,
  ): Promise<void> {
    const canon = canonicalAcl(acl);
    await this.inTenant(tenantId, async (c) => {
      const d = await c.query(
        `UPDATE memory_documents SET acl = $3::jsonb, acl_key = $4 WHERE tenant_id = $1 AND id = $2`,
        [tenantId, documentId, JSON.stringify(canon), aclKey(canon)],
      );
      if (d.rowCount === 0) throw new MemoryError("NOT_FOUND", "document not found");
      await c.query(
        `UPDATE memory_chunks SET acl = $3::jsonb, acl_key = $4 WHERE tenant_id = $1 AND document_id = $2`,
        [tenantId, documentId, JSON.stringify(canon), aclKey(canon)],
      );
    });
  }

  async deleteDocument(tenantId: string, documentId: string): Promise<void> {
    await this.inTenant(tenantId, async (c) => {
      const d = await c.query(`DELETE FROM memory_documents WHERE tenant_id = $1 AND id = $2`, [
        tenantId,
        documentId,
      ]);
      if (d.rowCount === 0) throw new MemoryError("NOT_FOUND", "document not found");
    });
  }

  /** DSAR hook: hard-delete everything held about a data subject (entries, documents, chunks). */
  async forgetSubject(
    tenantId: string,
    subject: string,
  ): Promise<{ chunks: number; documents: number }> {
    assertText(subject, "subject", 256);
    return this.inTenant(tenantId, async (c) => {
      const ch = await c.query(`DELETE FROM memory_chunks WHERE tenant_id = $1 AND subject = $2`, [
        tenantId,
        subject,
      ]);
      const dc = await c.query(
        `DELETE FROM memory_documents WHERE tenant_id = $1 AND subject = $2`,
        [tenantId, subject],
      );
      return { chunks: ch.rowCount ?? 0, documents: dc.rowCount ?? 0 };
    });
  }

  /** Physically delete expired rows (reads already ignore them). Run periodically per tenant. */
  async purgeExpired(tenantId: string): Promise<{ chunks: number; documents: number }> {
    const now = this.now();
    return this.inTenant(tenantId, async (c) => {
      const ch = await c.query(
        `DELETE FROM memory_chunks WHERE tenant_id = $1 AND expires_at IS NOT NULL AND expires_at <= $2`,
        [tenantId, now],
      );
      const dc = await c.query(
        `DELETE FROM memory_documents WHERE tenant_id = $1 AND expires_at IS NOT NULL AND expires_at <= $2`,
        [tenantId, now],
      );
      return { chunks: ch.rowCount ?? 0, documents: dc.rowCount ?? 0 };
    });
  }
}

interface HitRow {
  id: string;
  document_id: string | null;
  scope: Scope;
  owner_ref: string | null;
  kb: string | null;
  content: string;
  metadata: Metadata;
  score: string | number;
}
interface EntryRow {
  id: string;
  scope: Scope;
  owner_ref: string | null;
  content: string;
  metadata: Metadata;
  created_at: Date;
}
