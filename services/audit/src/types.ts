import type { AuditEvent, AuditSink, ChainVerdict, UnsealedEvent } from "@axis/contracts";

/** What a caller supplies. `id` and `ts` are assigned when absent; chain fields are never accepted. */
export type AuditInput = Omit<UnsealedEvent, "id" | "ts"> & { id?: string; ts?: string };

export interface ReadRange {
  /** Inclusive, default 1. */
  fromSeq?: number;
  /** Inclusive, default unbounded. */
  toSeq?: number;
  /** Maximum events returned (ascending by seq), default unbounded. */
  limit?: number;
}

export interface ListQuery {
  traceId?: string;
  fromSeq?: number;
  /** Required: readers must always bound their result. 1..10000. */
  limit: number;
}

/** Read-only view for AGIL and other observers. Deliberately has no write method. */
export interface AuditReader {
  listEvents(tenantId: string, query: ListQuery): Promise<AuditEvent[]>;
}

/** Low-level chain access shared by verification, checkpoints and export. */
export interface ChainSource {
  head(tenantId: string): Promise<AuditEvent | undefined>;
  /** Events in ascending seq order. */
  read(tenantId: string, range: ReadRange): Promise<AuditEvent[]>;
}

export interface VerifyRange {
  fromSeq?: number;
  toSeq?: number;
}

export interface AuditStore extends AuditSink, ChainSource, AuditReader {
  append(event: AuditInput): Promise<AuditEvent>;
  verify(tenantId: string, range?: VerifyRange): Promise<ChainVerdict>;
}

export interface Checkpoint {
  tenant_id: string;
  seq: number;
  hash: string;
  /** UTC, millisecond precision, trailing Z. */
  ts: string;
  /** Base64 Ed25519 signature over the checkpoint message (see checkpoint.ts). */
  signature: string;
}

export interface Signer {
  /** Signs `message`. Implementations: node:crypto Ed25519 (here); KMS is planned (docs/NEEDS.md). */
  sign(message: Uint8Array): Promise<Uint8Array>;
}

export interface CheckpointStore {
  save(checkpoint: Checkpoint): Promise<void>;
  /** Highest seq (then most recent) checkpoint for the tenant. */
  latest(tenantId: string): Promise<Checkpoint | undefined>;
  list(tenantId: string): Promise<Checkpoint[]>;
}

/** Write-once object storage for exports. put() must never overwrite an existing object. */
export interface WormSink {
  put(name: string, data: Uint8Array): Promise<void>;
  get(name: string): Promise<Uint8Array>;
  list(): Promise<string[]>;
}
