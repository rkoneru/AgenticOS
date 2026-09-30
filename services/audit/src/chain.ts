import { computeEventHash, verifyChain, type AuditEvent, type ChainVerdict } from "@axis/contracts";
import type { ChainSource, VerifyRange } from "./types.js";

export const DEFAULT_PAGE = 500;

export function assertSeq(name: string, v: number | undefined): void {
  if (v !== undefined && (!Number.isSafeInteger(v) || v < 1)) {
    throw new RangeError(`${name} must be a positive integer`);
  }
}

/** True when the stored hash of `e` matches its content. */
export function selfHashOk(e: AuditEvent): boolean {
  const { hash, ...rest } = e;
  return computeEventHash(rest) === hash;
}

/**
 * Verify a (slice of a) tenant chain, reading in pages. For a slice starting after seq 1 the preceding event is read
 * and used as the anchor (its own hash is checked too). A missing anchor with later rows present is a `seq_gap`.
 * NOTE: a truncated tail is not detectable here (nothing follows it); use a signed checkpoint.
 */
export async function verifyRange(
  src: ChainSource,
  tenantId: string,
  range: VerifyRange = {},
  pageSize: number = DEFAULT_PAGE,
): Promise<ChainVerdict> {
  const fromSeq = range.fromSeq ?? 1;
  const toSeq = range.toSeq;
  assertSeq("fromSeq", fromSeq);
  assertSeq("toSeq", toSeq);
  if (toSeq !== undefined && toSeq < fromSeq) throw new RangeError("toSeq must be >= fromSeq");

  let prev: AuditEvent | undefined;
  let length = 0;
  let cursor = fromSeq > 1 ? fromSeq - 1 : 1;
  let first = true;
  for (;;) {
    const readTo = toSeq;
    const page = await src.read(tenantId, {
      fromSeq: cursor,
      ...(readTo !== undefined ? { toSeq: readTo } : {}),
      limit: pageSize + (first && fromSeq > 1 ? 1 : 0),
    });
    if (page.length === 0) return { ok: true, length };
    for (const e of page) {
      if (e.tenant_id !== tenantId) {
        return { ok: false, brokenAtSeq: e.seq, reason: "tenant_mismatch" };
      }
    }
    let events = page;
    if (first && fromSeq > 1) {
      const anchor = page[0] as AuditEvent;
      if (anchor.seq !== fromSeq - 1)
        return { ok: false, brokenAtSeq: anchor.seq, reason: "seq_gap" };
      if (!selfHashOk(anchor))
        return { ok: false, brokenAtSeq: anchor.seq, reason: "hash_mismatch" };
      prev = anchor;
      events = page.slice(1);
    }
    first = false;
    const verdict = verifyChain(events, prev);
    if (!verdict.ok) return verdict;
    length += events.length;
    const last = events.at(-1);
    if (last === undefined) return { ok: true, length };
    prev = last;
    cursor = last.seq + 1;
    if (events.length < pageSize) return { ok: true, length };
  }
}

/** Read the event before `fromSeq` (the chain anchor) for slices; undefined when fromSeq is 1. */
export async function readAnchor(
  src: ChainSource,
  tenantId: string,
  fromSeq: number,
): Promise<AuditEvent | "missing" | "corrupt" | undefined> {
  if (fromSeq <= 1) return undefined;
  const [a] = await src.read(tenantId, { fromSeq: fromSeq - 1, toSeq: fromSeq - 1, limit: 1 });
  if (a === undefined || a.seq !== fromSeq - 1) return "missing";
  return selfHashOk(a) ? a : "corrupt";
}
