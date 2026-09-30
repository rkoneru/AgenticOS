import { createHash } from "node:crypto";
import {
  canonicalize,
  GENESIS_HASH,
  validateAuditEvent,
  verifyChain,
  type AuditEvent,
} from "@axis/contracts";
import { assertSeq, readAnchor } from "./chain.js";
import { AuditExportError } from "./errors.js";
import type { ChainSource, WormSink } from "./types.js";

export const MANIFEST_NAME = "manifest.json";
export const EXPORT_FORMAT = "axis-audit-export-v1";
const SEGMENT_RE = /^segment-\d{6}\.ndjson$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HASH_RE = /^[0-9a-f]{64}$/;

export interface SegmentInfo {
  name: string;
  first_seq: number;
  last_seq: number;
  count: number;
  sha256: string;
}

export interface ExportManifest {
  format: typeof EXPORT_FORMAT;
  tenant_id: string;
  first_seq: number;
  last_seq: number;
  count: number;
  segment_size: number;
  /** `prev_hash` of the first exported event: genesis zeros for a full export, the anchor hash for a slice. */
  first_prev_hash: string;
  /** Hash of the last exported event (the chain head at export time, for a full-to-head export). */
  head_hash: string;
  exported_at: string;
  segments: SegmentInfo[];
}

const sha256 = (b: Uint8Array): string => createHash("sha256").update(b).digest("hex");
const enc = (s: string): Uint8Array => Buffer.from(s, "utf8");
const segName = (i: number): string => `segment-${String(i).padStart(6, "0")}.ndjson`;

/**
 * Export events [from, to] (clamped to the head) as NDJSON segments of `segmentSize` events plus a manifest, written
 * to a write-once sink. The chain is verified while reading: a broken chain is never exported as if it were good.
 * Segments go first and the manifest last; a sink without a manifest holds an incomplete export and must not be reused
 * (use a fresh sink per export).
 */
export async function exportRange(
  src: ChainSource,
  tenantId: string,
  from: number,
  to: number,
  sink: WormSink,
  opts: { segmentSize?: number; now?: () => Date } = {},
): Promise<ExportManifest> {
  assertSeq("from", from);
  assertSeq("to", to);
  if (to < from) throw new RangeError("to must be >= from");
  const segmentSize = opts.segmentSize ?? 1000;
  if (!Number.isSafeInteger(segmentSize) || segmentSize < 1)
    throw new RangeError("segmentSize must be >= 1");

  const anchor = await readAnchor(src, tenantId, from);
  if (anchor === "missing" || anchor === "corrupt") {
    throw new AuditExportError(`cannot anchor export at seq ${from}: preceding event is ${anchor}`);
  }
  let prev: AuditEvent | undefined = anchor;
  let cursor = from;
  const segments: SegmentInfo[] = [];
  let firstPrevHash = GENESIS_HASH;
  let head: AuditEvent | undefined;

  while (cursor <= to) {
    const events = await src.read(tenantId, {
      fromSeq: cursor,
      toSeq: Math.min(to, cursor + segmentSize - 1),
      limit: segmentSize,
    });
    const first = events[0];
    if (!first) break;
    if (events.some((e) => e.tenant_id !== tenantId)) {
      throw new AuditExportError("export aborted: event from another tenant in range");
    }
    const verdict = verifyChain(events, prev);
    if (!verdict.ok) {
      throw new AuditExportError(
        `export aborted: chain broken at seq ${verdict.brokenAtSeq} (${verdict.reason})`,
      );
    }
    if (segments.length === 0) firstPrevHash = first.prev_hash;
    const bytes = enc(events.map((e) => canonicalize(e) + "\n").join(""));
    const name = segName(segments.length + 1);
    await sink.put(name, bytes);
    head = events[events.length - 1] as AuditEvent;
    segments.push({
      name,
      first_seq: first.seq,
      last_seq: head.seq,
      count: events.length,
      sha256: sha256(bytes),
    });
    prev = head;
    cursor = head.seq + 1;
  }
  if (!head || segments.length === 0) {
    throw new AuditExportError(`nothing to export for tenant ${tenantId} in seq ${from}..${to}`);
  }
  const manifest: ExportManifest = {
    format: EXPORT_FORMAT,
    tenant_id: tenantId,
    first_seq: (segments[0] as SegmentInfo).first_seq,
    last_seq: head.seq,
    count: segments.reduce((n, s) => n + s.count, 0),
    segment_size: segmentSize,
    first_prev_hash: firstPrevHash,
    head_hash: head.hash,
    exported_at: (opts.now ?? (() => new Date()))().toISOString(),
    segments,
  };
  await sink.put(MANIFEST_NAME, enc(JSON.stringify(manifest, null, 2) + "\n"));
  return manifest;
}

export type ExportVerdict =
  | {
      ok: true;
      tenant_id: string;
      first_seq: number;
      last_seq: number;
      head_hash: string;
      count: number;
    }
  | {
      ok: false;
      reason:
        | "manifest_missing"
        | "manifest_invalid"
        | "segment_missing"
        | "segment_hash_mismatch"
        | "segment_malformed"
        | "segment_range_mismatch"
        | "unexpected_segment"
        | "chain_broken"
        | "head_mismatch";
      detail: string;
      brokenAtSeq?: number;
    };

const fail = (
  reason: Extract<ExportVerdict, { ok: false }>["reason"],
  detail: string,
  brokenAtSeq?: number,
): ExportVerdict => ({
  ok: false,
  reason,
  detail,
  ...(brokenAtSeq === undefined ? {} : { brokenAtSeq }),
});

const isInt = (v: unknown): v is number =>
  typeof v === "number" && Number.isSafeInteger(v) && v >= 1;

function parseManifest(raw: Uint8Array): ExportManifest | undefined {
  let m: unknown;
  try {
    m = JSON.parse(Buffer.from(raw).toString("utf8"));
  } catch {
    return undefined;
  }
  if (typeof m !== "object" || m === null) return undefined;
  const o = m as Record<string, unknown>;
  if (
    o["format"] !== EXPORT_FORMAT ||
    typeof o["tenant_id"] !== "string" ||
    !UUID_RE.test(o["tenant_id"]) ||
    !isInt(o["first_seq"]) ||
    !isInt(o["last_seq"]) ||
    !isInt(o["count"]) ||
    typeof o["first_prev_hash"] !== "string" ||
    !HASH_RE.test(o["first_prev_hash"]) ||
    typeof o["head_hash"] !== "string" ||
    !HASH_RE.test(o["head_hash"]) ||
    !Array.isArray(o["segments"]) ||
    o["segments"].length === 0
  ) {
    return undefined;
  }
  for (const s of o["segments"] as unknown[]) {
    const x = s as Record<string, unknown> | null;
    if (
      typeof x !== "object" ||
      x === null ||
      typeof x["name"] !== "string" ||
      !SEGMENT_RE.test(x["name"]) ||
      !isInt(x["first_seq"]) ||
      !isInt(x["last_seq"]) ||
      !isInt(x["count"]) ||
      typeof x["sha256"] !== "string" ||
      !HASH_RE.test(x["sha256"])
    ) {
      return undefined;
    }
  }
  return m as ExportManifest;
}

/**
 * Re-verify an export offline (no database): manifest shape, every segment's SHA-256, every event against the audit
 * schema, the hash chain across segments, the segment/manifest ranges, and the head hash. The manifest itself is
 * trusted to be what the WORM store preserved; compare `head_hash`/`last_seq` with a signed checkpoint to bind it.
 */
export async function verifyExport(sink: WormSink): Promise<ExportVerdict> {
  const names = await sink.list();
  if (!names.includes(MANIFEST_NAME)) return fail("manifest_missing", "manifest.json not found");
  const manifest = parseManifest(await sink.get(MANIFEST_NAME));
  if (!manifest) return fail("manifest_invalid", "manifest.json is not a valid export manifest");
  if (manifest.first_seq === 1 && manifest.first_prev_hash !== GENESIS_HASH) {
    return fail("manifest_invalid", "a chain starting at seq 1 must have the genesis prev_hash");
  }

  const declared = new Set(manifest.segments.map((s) => s.name));
  const stray = names.find((n) => SEGMENT_RE.test(n) && !declared.has(n));
  if (stray) return fail("unexpected_segment", `segment ${stray} is not listed in the manifest`);

  let prev =
    manifest.first_seq === 1
      ? undefined
      : ({
          seq: manifest.first_seq - 1,
          hash: manifest.first_prev_hash,
          tenant_id: manifest.tenant_id,
        } as AuditEvent);
  let expectedSeq = manifest.first_seq;
  let total = 0;
  let lastHash = "";
  for (const seg of manifest.segments) {
    if (!names.includes(seg.name)) return fail("segment_missing", `${seg.name} is missing`);
    const bytes = await sink.get(seg.name);
    if (sha256(bytes) !== seg.sha256)
      return fail("segment_hash_mismatch", `${seg.name} content does not match the manifest`);
    const text = Buffer.from(bytes).toString("utf8");
    const lines = text.split("\n");
    if (lines.pop() !== "")
      return fail("segment_malformed", `${seg.name} does not end with a newline`);
    const events: AuditEvent[] = [];
    for (const line of lines) {
      let e: unknown;
      try {
        e = JSON.parse(line);
      } catch {
        return fail("segment_malformed", `${seg.name} contains a line that is not JSON`);
      }
      if (!validateAuditEvent(e))
        return fail(
          "segment_malformed",
          `${seg.name} contains an event that fails the audit schema`,
        );
      events.push(e as AuditEvent);
    }
    const first = events[0];
    const last = events[events.length - 1];
    if (
      !first ||
      !last ||
      events.length !== seg.count ||
      first.seq !== seg.first_seq ||
      last.seq !== seg.last_seq ||
      seg.first_seq !== expectedSeq
    ) {
      return fail(
        "segment_range_mismatch",
        `${seg.name} does not cover the range the manifest declares`,
      );
    }
    if (events.some((e) => e.tenant_id !== manifest.tenant_id)) {
      return fail("chain_broken", `${seg.name} contains an event of another tenant`, first.seq);
    }
    const verdict = verifyChain(events, prev);
    if (!verdict.ok)
      return fail("chain_broken", `${verdict.reason} in ${seg.name}`, verdict.brokenAtSeq);
    prev = last;
    lastHash = last.hash;
    expectedSeq = last.seq + 1;
    total += events.length;
  }
  if (expectedSeq - 1 !== manifest.last_seq || total !== manifest.count) {
    return fail("segment_range_mismatch", "segments do not add up to the manifest range");
  }
  if (lastHash !== manifest.head_hash)
    return fail("head_mismatch", "last event hash differs from manifest head_hash");
  return {
    ok: true,
    tenant_id: manifest.tenant_id,
    first_seq: manifest.first_seq,
    last_seq: manifest.last_seq,
    head_hash: manifest.head_hash,
    count: total,
  };
}
