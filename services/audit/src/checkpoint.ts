import { canonicalize, type ChainVerdict } from "@axis/contracts";
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { verifyRange } from "./chain.js";
import type { ChainSource, Checkpoint, CheckpointStore, Signer } from "./types.js";

const DOMAIN = "axis-audit-checkpoint-v1\n";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HASH_RE = /^[0-9a-f]{64}$/;
const TS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

/** Bytes that are signed: a domain-separation prefix plus canonical JSON of the checkpoint body. */
export function checkpointMessage(
  c: Pick<Checkpoint, "tenant_id" | "seq" | "hash" | "ts">,
): Buffer {
  return Buffer.from(
    DOMAIN + canonicalize({ tenant_id: c.tenant_id, seq: c.seq, hash: c.hash, ts: c.ts }),
    "utf8",
  );
}

export function isWellFormedCheckpoint(c: unknown): c is Checkpoint {
  if (typeof c !== "object" || c === null) return false;
  const o = c as Record<string, unknown>;
  return (
    typeof o["tenant_id"] === "string" &&
    UUID_RE.test(o["tenant_id"]) &&
    typeof o["seq"] === "number" &&
    Number.isSafeInteger(o["seq"]) &&
    o["seq"] >= 1 &&
    typeof o["hash"] === "string" &&
    HASH_RE.test(o["hash"]) &&
    typeof o["ts"] === "string" &&
    TS_RE.test(o["ts"]) &&
    typeof o["signature"] === "string" &&
    B64_RE.test(o["signature"])
  );
}

/** Ed25519 signer backed by node:crypto. The KMS-backed signer is planned (docs/NEEDS.md). */
export class Ed25519Signer implements Signer {
  private readonly key: KeyObject;
  constructor(privateKey: KeyObject | string) {
    this.key = typeof privateKey === "string" ? createPrivateKey(privateKey) : privateKey;
    if (this.key.asymmetricKeyType !== "ed25519")
      throw new TypeError("Ed25519Signer needs an ed25519 key");
  }
  sign(message: Uint8Array): Promise<Uint8Array> {
    return Promise.resolve(sign(null, message, this.key));
  }
  get publicKey(): KeyObject {
    return createPublicKey(this.key);
  }
}

export function generateEd25519(): { signer: Ed25519Signer; publicKey: KeyObject } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { signer: new Ed25519Signer(privateKey), publicKey };
}

/** True iff `checkpoint.signature` is a valid Ed25519 signature over its body under `publicKey`. */
export function verifyCheckpointSignature(
  checkpoint: Checkpoint,
  publicKey: KeyObject | string,
): boolean {
  try {
    const key = typeof publicKey === "string" ? createPublicKey(publicKey) : publicKey;
    return verify(
      null,
      checkpointMessage(checkpoint),
      key,
      Buffer.from(checkpoint.signature, "base64"),
    );
  } catch {
    return false;
  }
}

export type CheckpointVerdict =
  | { ok: true; checkpointSeq: number; headSeq: number }
  | {
      ok: false;
      reason:
        | "malformed"
        | "bad_signature"
        | "tenant_mismatch"
        | "truncated"
        | "hash_mismatch"
        | "chain_broken";
      detail?: string;
      chain?: ChainVerdict;
    };

export class AuditCheckpointer {
  private readonly now: () => Date;
  constructor(
    private readonly log: ChainSource,
    private readonly store: CheckpointStore,
    private readonly signer: Signer,
    opts: { now?: () => Date } = {},
  ) {
    this.now = opts.now ?? (() => new Date());
  }

  /**
   * Sign and persist the current head. Does NOT verify the chain: cadence jobs should run `verify` first (runbook),
   * because a checkpoint over an already-corrupt head would only pin the corruption.
   */
  async createCheckpoint(tenantId: string): Promise<Checkpoint> {
    const head = await this.log.head(tenantId);
    if (!head) throw new Error(`cannot checkpoint tenant ${tenantId}: audit log is empty`);
    const body = {
      tenant_id: tenantId,
      seq: head.seq,
      hash: head.hash,
      ts: this.now().toISOString(),
    };
    const sig = await this.signer.sign(checkpointMessage(body));
    const checkpoint: Checkpoint = { ...body, signature: Buffer.from(sig).toString("base64") };
    await this.store.save(checkpoint); // never hand back an unpersisted checkpoint
    return checkpoint;
  }

  /**
   * Checks, in order: shape, signature, tenant, head not behind the checkpoint (truncation), the hash at the
   * checkpoint seq (rewrite), and the chain from genesis to the checkpoint seq.
   */
  async verifyAgainstCheckpoint(
    tenantId: string,
    checkpoint: Checkpoint,
    publicKey: KeyObject | string,
  ): Promise<CheckpointVerdict> {
    if (!isWellFormedCheckpoint(checkpoint)) return { ok: false, reason: "malformed" };
    if (!verifyCheckpointSignature(checkpoint, publicKey))
      return { ok: false, reason: "bad_signature" };
    if (checkpoint.tenant_id !== tenantId) return { ok: false, reason: "tenant_mismatch" };
    const head = await this.log.head(tenantId);
    if (!head || head.seq < checkpoint.seq) {
      return {
        ok: false,
        reason: "truncated",
        detail: `log head is seq ${head?.seq ?? 0}, checkpoint is at seq ${checkpoint.seq}`,
      };
    }
    const [at] = await this.log.read(tenantId, {
      fromSeq: checkpoint.seq,
      toSeq: checkpoint.seq,
      limit: 1,
    });
    if (at?.hash !== checkpoint.hash) {
      return {
        ok: false,
        reason: "hash_mismatch",
        detail: at
          ? `hash at seq ${checkpoint.seq} differs from checkpoint`
          : `no event at seq ${checkpoint.seq}`,
      };
    }
    const chain = await verifyRange(this.log, tenantId, { toSeq: checkpoint.seq });
    if (!chain.ok) return { ok: false, reason: "chain_broken", chain };
    return { ok: true, checkpointSeq: checkpoint.seq, headSeq: head.seq };
  }
}

/** In-process checkpoint store (tests, local dev). */
export class MemoryCheckpointStore implements CheckpointStore {
  private readonly items: Checkpoint[] = [];
  save(c: Checkpoint): Promise<void> {
    this.items.push(structuredClone(c));
    return Promise.resolve();
  }
  latest(tenantId: string): Promise<Checkpoint | undefined> {
    const all = this.items.filter((c) => c.tenant_id === tenantId);
    // highest seq wins; later insert wins ties
    const best = all.reduce<Checkpoint | undefined>(
      (b, c) => (!b || c.seq >= b.seq ? c : b),
      undefined,
    );
    return Promise.resolve(best && structuredClone(best));
  }
  list(tenantId: string): Promise<Checkpoint[]> {
    return Promise.resolve(structuredClone(this.items.filter((c) => c.tenant_id === tenantId)));
  }
}
