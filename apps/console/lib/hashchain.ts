import type { AuditEvent } from "./api";

export const GENESIS_HASH = "0".repeat(64);

/** Canonical JSON identical to `@axis/contracts` `canonicalize` (sorted keys, safe integers only). */
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
    case "boolean":
      return JSON.stringify(value);
    case "number":
      if (!Number.isSafeInteger(value))
        throw new TypeError("canonicalize: only safe integers allowed");
      return String(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(",")}}`;
    }
    default:
      throw new TypeError(`canonicalize: unsupported type ${typeof value}`);
  }
}

export async function sha256Hex(text: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export type LocalVerdict =
  | { ok: true; length: number; firstSeq?: number; lastSeq?: number }
  | {
      ok: false;
      brokenAtSeq: number;
      reason: "tenant_mismatch" | "seq_gap" | "prev_hash_mismatch" | "hash_mismatch" | "malformed";
    };

/**
 * Re-verify a contiguous slice in the browser (SHA-256 over canonical JSON). This is a second opinion
 * next to the server's `/audit/verify`: it proves the page's own events are internally consistent;
 * it cannot prove the slice is the whole log (that is the server's anchored verdict).
 * `anchor` is the hash of the event just before the slice (omit when the slice starts at seq 1).
 */
export async function verifyChainLocal(
  events: readonly AuditEvent[],
  anchor?: { seq: number; hash: string },
): Promise<LocalVerdict> {
  if (events.length === 0) return { ok: true, length: 0 };
  const first = events[0]!;
  let prevHash = anchor ? anchor.hash : GENESIS_HASH;
  let prevSeq = anchor ? anchor.seq : 0;
  const tenant = first.tenant_id;
  for (const e of events) {
    if (e.tenant_id !== tenant) return { ok: false, brokenAtSeq: e.seq, reason: "tenant_mismatch" };
    if (e.seq !== prevSeq + 1) return { ok: false, brokenAtSeq: e.seq, reason: "seq_gap" };
    if (e.prev_hash !== prevHash)
      return { ok: false, brokenAtSeq: e.seq, reason: "prev_hash_mismatch" };
    const { hash, ...rest } = e;
    let computed: string;
    try {
      computed = await sha256Hex(canonicalize(rest));
    } catch {
      return { ok: false, brokenAtSeq: e.seq, reason: "malformed" };
    }
    if (computed !== hash) return { ok: false, brokenAtSeq: e.seq, reason: "hash_mismatch" };
    prevHash = hash;
    prevSeq = e.seq;
  }
  return {
    ok: true,
    length: events.length,
    firstSeq: first.seq,
    lastSeq: events[events.length - 1]!.seq,
  };
}

export function sortBySeq(events: readonly AuditEvent[]): AuditEvent[] {
  return [...events].sort((a, b) => a.seq - b.seq);
}

export function reasonText(r: string): string {
  switch (r) {
    case "tenant_mismatch":
      return "an event belongs to a different tenant";
    case "seq_gap":
      return "a sequence number is missing";
    case "prev_hash_mismatch":
      return "an event does not point at the hash of the one before it";
    case "hash_mismatch":
      return "an event's content does not match its hash";
    case "malformed":
      return "an event could not be canonicalised";
    default:
      return r;
  }
}
