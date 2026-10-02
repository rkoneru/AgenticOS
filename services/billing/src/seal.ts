import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { canonicalize } from "@axis/contracts";
import { METERS, type Meter } from "./types.js";

export const GENESIS_SEAL = "0".repeat(64);

export interface SealSigner {
  readonly keyId: string;
  sign(hashHex: string): string;
  verify(hashHex: string, signature: string): boolean;
}

/** HMAC-SHA256 seal signer. A KMS-held asymmetric key replaces it in production (docs/NEEDS.md 8xx). */
export class HmacSealSigner implements SealSigner {
  constructor(
    private readonly key: Buffer,
    readonly keyId = "hmac-dev-1",
  ) {
    if (key.length < 32) throw new Error("seal key must be at least 32 bytes");
  }
  sign(hashHex: string): string {
    return createHmac("sha256", this.key).update(hashHex, "utf8").digest("hex");
  }
  verify(hashHex: string, signature: string): boolean {
    const a = Buffer.from(this.sign(hashHex), "utf8");
    const b = Buffer.from(signature, "utf8");
    return a.length === b.length && timingSafeEqual(a, b);
  }
}

export interface SealRow {
  idempotencyKey: string;
  payloadHash: string;
  meter: Meter;
  quantity: bigint;
}

export interface PeriodSeal {
  tenantId: string;
  periodId: string;
  seq: number;
  prevSealHash: string;
  sealHash: string;
  signature: string;
  keyId: string;
  eventCount: number;
  rowsDigest: string;
  totals: Readonly<Record<string, string>>;
  closedAt: Date;
}

export type SealVerdict = { ok: true } | { ok: false; reason: string };

/** Digest over the (key, payload hash) pairs, order independent. */
export function rowsDigest(rows: readonly SealRow[]): string {
  const lines = rows.map((r) => `${r.idempotencyKey}\u0000${r.payloadHash}`).sort();
  return createHash("sha256").update(canonicalize(lines), "utf8").digest("hex");
}

export function sealTotals(rows: readonly SealRow[]): Record<string, string> {
  const t = new Map<Meter, bigint>();
  for (const r of rows) t.set(r.meter, (t.get(r.meter) ?? 0n) + r.quantity);
  const out: Record<string, string> = {};
  for (const m of METERS) if (t.has(m)) out[m] = (t.get(m) as bigint).toString();
  return out;
}

export function sealHashOf(b: {
  tenantId: string;
  periodId: string;
  seq: number;
  prevSealHash: string;
  eventCount: number;
  rowsDigest: string;
  totals: Readonly<Record<string, string>>;
  closedAt: Date;
  keyId: string;
}): string {
  return createHash("sha256")
    .update(
      canonicalize({
        tenant: b.tenantId,
        period: b.periodId,
        seq: b.seq,
        prev: b.prevSealHash,
        count: b.eventCount,
        rows: b.rowsDigest,
        totals: b.totals,
        closed_at: b.closedAt.toISOString(),
        key: b.keyId,
      }),
      "utf8",
    )
    .digest("hex");
}

export function buildSeal(args: {
  tenantId: string;
  periodId: string;
  seq: number;
  prevSealHash: string;
  rows: readonly SealRow[];
  closedAt: Date;
  signer: SealSigner;
}): PeriodSeal {
  const digest = rowsDigest(args.rows);
  const totals = sealTotals(args.rows);
  const base = {
    tenantId: args.tenantId,
    periodId: args.periodId,
    seq: args.seq,
    prevSealHash: args.prevSealHash,
    eventCount: args.rows.length,
    rowsDigest: digest,
    totals,
    closedAt: args.closedAt,
    keyId: args.signer.keyId,
  };
  const sealHash = sealHashOf(base);
  return { ...base, sealHash, signature: args.signer.sign(sealHash) };
}

/** Recomputes a seal from the rows currently stored for its period and checks hash, signature and totals. */
export function verifySeal(seal: PeriodSeal, rows: readonly SealRow[], signer: SealSigner): SealVerdict {
  if (rows.length !== seal.eventCount) return { ok: false, reason: "event count differs from the seal" };
  if (rowsDigest(rows) !== seal.rowsDigest) return { ok: false, reason: "rows differ from the seal" };
  if (canonicalize(sealTotals(rows)) !== canonicalize(seal.totals))
    return { ok: false, reason: "totals differ from the seal" };
  if (sealHashOf(seal) !== seal.sealHash) return { ok: false, reason: "seal hash mismatch" };
  if (!signer.verify(seal.sealHash, seal.signature)) return { ok: false, reason: "bad signature" };
  return { ok: true };
}
