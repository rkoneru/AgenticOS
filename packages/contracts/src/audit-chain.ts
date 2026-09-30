import { canonicalize, sha256Hex } from "./canonical.js";

export const GENESIS_HASH = "0".repeat(64);

export interface AuditEvent {
  schema_version: 1;
  id: string;
  tenant_id: string;
  seq: number;
  ts: string;
  trace_id: string;
  actor: { type: "human" | "agent" | "system"; id: string; pid?: string };
  blueprint: { name: string; version: string };
  policy_version: string;
  enforcement_point: string;
  action: string;
  decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL" | "ALLOW_WITH_REDACTION";
  reason?: string;
  inputs_hash: string;
  outputs_hash: string;
  prev_hash: string;
  hash: string;
}

export type UnsealedEvent = Omit<AuditEvent, "hash" | "prev_hash" | "seq">;

/** hash = SHA-256(canonical JSON of the event without its own `hash` field). `prev_hash` is included. */
export function computeEventHash(event: Omit<AuditEvent, "hash">): string {
  return sha256Hex(canonicalize(event));
}

/** Seal the next event in a tenant's chain. `prev` is the last sealed event, or undefined for genesis. */
export function sealEvent(event: UnsealedEvent, prev: AuditEvent | undefined): AuditEvent {
  const unhashed = {
    ...event,
    seq: prev ? prev.seq + 1 : 1,
    prev_hash: prev ? prev.hash : GENESIS_HASH,
  };
  return { ...unhashed, hash: computeEventHash(unhashed) };
}

export type ChainVerdict =
  | { ok: true; length: number }
  | {
      ok: false;
      brokenAtSeq: number;
      reason: "tenant_mismatch" | "seq_gap" | "prev_hash_mismatch" | "hash_mismatch";
    };

/**
 * Verify a contiguous run of one tenant's events. `prevOfFirst` is the event before the slice
 * (undefined when the slice starts at genesis, seq 1).
 */
export function verifyChain(events: readonly AuditEvent[], prevOfFirst?: AuditEvent): ChainVerdict {
  let prev = prevOfFirst;
  const tenant = events[0]?.tenant_id;
  for (const e of events) {
    if (e.tenant_id !== tenant || (prev && e.tenant_id !== prev.tenant_id)) {
      return { ok: false, brokenAtSeq: e.seq, reason: "tenant_mismatch" };
    }
    if (e.seq !== (prev ? prev.seq + 1 : 1))
      return { ok: false, brokenAtSeq: e.seq, reason: "seq_gap" };
    if (e.prev_hash !== (prev ? prev.hash : GENESIS_HASH)) {
      return { ok: false, brokenAtSeq: e.seq, reason: "prev_hash_mismatch" };
    }
    const { hash, ...rest } = e;
    if (computeEventHash(rest) !== hash)
      return { ok: false, brokenAtSeq: e.seq, reason: "hash_mismatch" };
    prev = e;
  }
  return { ok: true, length: events.length };
}
