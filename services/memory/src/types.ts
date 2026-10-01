export const SCOPES = ["run", "session", "agent", "tenant", "kb"] as const;
export type Scope = (typeof SCOPES)[number];
/** Scopes writable through `write` (kb content goes through `ingestDocument`). */
export const ENTRY_SCOPES = ["run", "session", "agent", "tenant"] as const;
export type EntryScope = (typeof ENTRY_SCOPES)[number];

/** Who is asking. `groups` match `acl.roles`. */
export interface Principal {
  id: string;
  groups: readonly string[];
}

/** Access label on a document or entry. Empty (no users, no roles, tenant not true) means nobody: fail closed. */
export interface Acl {
  users?: readonly string[];
  roles?: readonly string[];
  tenant?: boolean;
}

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
export type Metadata = { [k: string]: Json };

export interface WriteRequest {
  scope: EntryScope;
  /** run id / session id / agent name. Required for run, session and agent; forbidden for tenant. */
  ownerRef?: string;
  content: string;
  metadata?: Metadata;
  /** Default: only the writer. */
  acl?: Acl;
  /** Data subject (DSAR forget key). In PHI mode this must be an opaque id, never PHI itself. */
  subject?: string;
  ttlSeconds?: number;
  /** Request PHI mode (the tenant's `phi_mode` also turns it on; it can never be turned off per request). */
  phi?: boolean;
  /** Extra redaction paths over `{content, metadata}` (e.g. from an ALLOW_WITH_REDACTION decision). PHI mode only. */
  redact?: readonly string[];
  principal: Principal;
}

export interface WriteResult {
  id: string;
  /** True if an identical entry (same scope, owner, content, ACL) existed: it was refreshed, not duplicated. */
  deduped: boolean;
  phi: boolean;
  expiresAt: string | null;
}

export interface IngestRequest {
  kb: string;
  content: string;
  /** Required: documents are never implicitly readable. */
  acl: Acl;
  source?: string;
  title?: string;
  metadata?: Metadata;
  subject?: string;
  ttlSeconds?: number;
  phi?: boolean;
  redact?: readonly string[];
  principal: Principal;
}

export interface IngestResult {
  documentId: string;
  chunks: number;
  deduped: boolean;
  phi: boolean;
}

export interface SearchQuery {
  query: string;
  /** 1..50, default 5. */
  limit?: number;
  scopes?: readonly Scope[];
  ownerRef?: string;
  kbs?: readonly string[];
  /** JSON containment filter on chunk metadata. Applied only to rows the principal can read. */
  metadata?: Metadata;
  /** Cosine similarity floor in [-1, 1]. */
  minScore?: number;
}

export interface SearchHit {
  id: string;
  documentId: string | null;
  scope: Scope;
  ownerRef: string | null;
  kb: string | null;
  content: string;
  metadata: Metadata;
  /** Cosine similarity, higher is closer. Computed only over rows the principal may read. */
  score: number;
}

export interface RecallQuery {
  scope: Scope;
  ownerRef?: string;
  limit?: number;
}

export interface Entry {
  id: string;
  scope: Scope;
  ownerRef: string | null;
  content: string;
  metadata: Metadata;
  createdAt: string;
}

export type MemoryErrorCode = "INVALID" | "NOT_FOUND" | "EMBEDDER";

export class MemoryError extends Error {
  constructor(
    readonly code: MemoryErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "MemoryError";
  }
}

/**
 * Turns text into vectors. The memory table is `vector(1536)`: `dimensions` must be 1536 (project if a provider differs).
 * Real providers go through the ModelGateway (docs/NEEDS.md); tests use `HashEmbedder`.
 */
export interface Embedder {
  /** Identifies the model; vectors of different ids are never compared. */
  readonly id: string;
  readonly dimensions: number;
  embed(texts: readonly string[]): Promise<number[][]>;
}
