import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";
import { canonicalizePayload, hashJson } from "@axis/contracts";
import type { DataClass, ProviderDeclaration } from "./types.js";

export interface ManifestStore {
  provider: string;
  declaration: ProviderDeclaration;
  collections: { name: string; count: number; sha256: string }[];
}
export interface ExportManifest {
  version: 1;
  request_id: string;
  tenant_id: string;
  subject_ref: string;
  generated_at: string;
  stores: ManifestStore[];
  total_records: number;
  records_sha256: string;
}
export interface ExportBundle {
  manifest: ExportManifest;
  /** provider -> collection -> records. Machine-readable JSON. */
  records: Record<string, Record<string, unknown[]>>;
  signature: { alg: "Ed25519"; key_id: string; value: string };
}

export class ManifestSigner {
  readonly keyId: string;
  private readonly priv: KeyObject;
  readonly publicKey: KeyObject;
  constructor(privateKeyPem?: string) {
    if (privateKeyPem) {
      this.priv = createPrivateKey(privateKeyPem);
      this.publicKey = createPublicKey(this.priv);
    } else {
      const kp = generateKeyPairSync("ed25519");
      this.priv = kp.privateKey;
      this.publicKey = kp.publicKey;
    }
    const der = this.publicKey.export({ type: "spki", format: "der" });
    this.keyId = hashJson({ spki: der.toString("base64") }).slice(0, 16);
  }
  sign(manifest: ExportManifest): ExportBundle["signature"] {
    return {
      alg: "Ed25519",
      key_id: this.keyId,
      value: sign(null, Buffer.from(canonicalizePayload(manifest)), this.priv).toString("base64"),
    };
  }
}

export type BundleVerdict = { ok: true } | { ok: false; reason: string };

/** Offline verification: signature, per-collection counts and hashes, totals and the overall records hash. */
export function verifyBundle(b: ExportBundle, publicKey: KeyObject): BundleVerdict {
  const okSig = verify(
    null,
    Buffer.from(canonicalizePayload(b.manifest)),
    publicKey,
    Buffer.from(b.signature.value, "base64"),
  );
  if (!okSig) return { ok: false, reason: "signature" };
  if (hashJson(b.records) !== b.manifest.records_sha256)
    return { ok: false, reason: "records_sha256" };
  let total = 0;
  for (const s of b.manifest.stores)
    for (const c of s.collections) {
      const recs = b.records[s.provider]?.[c.name];
      if (!recs || recs.length !== c.count)
        return { ok: false, reason: `count:${s.provider}.${c.name}` };
      if (hashJson(recs) !== c.sha256) return { ok: false, reason: `hash:${s.provider}.${c.name}` };
      total += c.count;
    }
  return total === b.manifest.total_records ? { ok: true } : { ok: false, reason: "total" };
}

export const classesOf = (d: ProviderDeclaration): DataClass[] => d.dataClasses;
