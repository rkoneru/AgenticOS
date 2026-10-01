import { createHmac, timingSafeEqual } from "node:crypto";
import { canonicalize } from "@axis/contracts";
import type { DecisionRecord } from "./types.js";

export interface DecisionSigner {
  readonly keyId: string;
  sign(message: Uint8Array): Promise<Uint8Array>;
  verify(message: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

/**
 * HMAC-SHA256 signer for decision records. Symmetric: the verifier (Risk Kernel / runtime) must hold the same key, so
 * this proves integrity between AXIS components, not non-repudiation to third parties. A KMS-backed asymmetric signer
 * is planned (docs/NEEDS.md #44).
 */
export class HmacSigner implements DecisionSigner {
  constructor(
    private readonly key: Uint8Array,
    readonly keyId = "hmac-1",
  ) {
    if (key.length < 32) throw new Error("HMAC key must be at least 32 bytes");
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    return createHmac("sha256", this.key).update(message).digest();
  }

  async verify(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    const want = createHmac("sha256", this.key).update(message).digest();
    return signature.length === want.length && timingSafeEqual(want, signature);
  }
}

export type UnsignedRecord = Omit<DecisionRecord, "signature">;

export function recordMessage(r: UnsignedRecord): Uint8Array {
  return new TextEncoder().encode(canonicalize(r));
}

export async function signRecord(
  r: UnsignedRecord,
  signer: DecisionSigner,
): Promise<DecisionRecord> {
  const sig = await signer.sign(recordMessage(r));
  return { ...r, signature: Buffer.from(sig).toString("base64") };
}

/** True only for a record whose signature verifies under `signer` and whose key id matches. Never throws. */
export async function verifyRecord(rec: DecisionRecord, signer: DecisionSigner): Promise<boolean> {
  try {
    const { signature, ...rest } = rec;
    if (rest.key_id !== signer.keyId || typeof signature !== "string") return false;
    return await signer.verify(recordMessage(rest), Buffer.from(signature, "base64"));
  } catch {
    return false;
  }
}

export interface ExpectedAction {
  tenant_id: string;
  run_id: string;
  tool: string;
  args_hash: string;
}

/**
 * The only function a caller needs to decide "may I run this action now?". True iff the record is a verified APPROVED
 * decision for exactly this tenant, run, tool and arguments hash. Anything else (denied, expired, forged, replayed for
 * different arguments or another tenant) is false. With `freshness`, a record decided more than `maxAgeMs` ago (or in
 * the future) is false too, so an approval that was never consumed cannot be replayed indefinitely.
 */
export async function isApprovalValidFor(
  rec: DecisionRecord,
  expected: ExpectedAction,
  signer: DecisionSigner,
  freshness?: { nowMs: number; maxAgeMs: number },
): Promise<boolean> {
  if (freshness !== undefined) {
    // `decided_at` is covered by the signature, so it is only trusted once that verifies (below); an
    // unparsable or future-dated value fails here as well.
    const age = freshness.nowMs - Date.parse(rec.decided_at);
    if (!(age >= 0 && age <= freshness.maxAgeMs)) return false;
  }
  return (
    rec.outcome === "APPROVED" &&
    rec.decision === "ALLOW" &&
    rec.tenant_id === expected.tenant_id &&
    rec.run_id === expected.run_id &&
    rec.tool === expected.tool &&
    rec.args_hash === expected.args_hash &&
    (await verifyRecord(rec, signer))
  );
}
