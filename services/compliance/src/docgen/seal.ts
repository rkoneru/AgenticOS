import {
  createHmac,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  timingSafeEqual,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";
import { sha256Hex } from "../canonical.js";

/** Seals a document. Signatures are deterministic (HMAC-SHA256, Ed25519 per RFC 8032) so regenerating a document gives the same bytes. */
export interface DocSealer {
  readonly alg: "ed25519" | "hmac-sha256";
  readonly keyId: string;
  sign(payload: string): string;
  verify(payload: string, sig: string): boolean;
}

export class HmacSealer implements DocSealer {
  readonly alg = "hmac-sha256" as const;
  readonly keyId: string;
  constructor(
    private readonly secret: Uint8Array,
    keyId?: string,
  ) {
    if (secret.length < 16) throw new Error("HMAC seal secret must be at least 16 bytes");
    this.keyId = keyId ?? `hmac:${sha256Hex(secret).slice(0, 16)}`;
  }
  sign(payload: string): string {
    return createHmac("sha256", this.secret).update(payload, "utf8").digest("base64url");
  }
  verify(payload: string, sig: string): boolean {
    const a = Buffer.from(this.sign(payload));
    const b = Buffer.from(typeof sig === "string" ? sig : "");
    return a.length === b.length && timingSafeEqual(a, b);
  }
}

export class Ed25519Sealer implements DocSealer {
  readonly alg = "ed25519" as const;
  readonly keyId: string;
  private readonly priv: KeyObject | null;
  private readonly pub: KeyObject;
  private constructor(priv: KeyObject | null, pub: KeyObject, keyId?: string) {
    this.priv = priv;
    this.pub = pub;
    const der = pub.export({ type: "spki", format: "der" });
    this.keyId = keyId ?? `ed25519:${sha256Hex(der).slice(0, 16)}`;
  }
  /** A fresh key pair (tests, dev). The key is in memory only. */
  static generate(keyId?: string): Ed25519Sealer {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    return new Ed25519Sealer(privateKey, publicKey, keyId);
  }
  static fromPrivatePem(pem: string, keyId?: string): Ed25519Sealer {
    const priv = createPrivateKey(pem);
    return new Ed25519Sealer(priv, createPublicKey(priv), keyId);
  }
  /** Verification only (a reader that cannot seal). */
  static fromPublicPem(pem: string, keyId?: string): Ed25519Sealer {
    return new Ed25519Sealer(null, createPublicKey(pem), keyId);
  }
  sign(payload: string): string {
    if (!this.priv) throw new Error("this seal key cannot sign");
    return edSign(null, Buffer.from(payload, "utf8"), this.priv).toString("base64url");
  }
  verify(payload: string, sig: string): boolean {
    if (typeof sig !== "string") return false;
    try {
      return edVerify(null, Buffer.from(payload, "utf8"), this.pub, Buffer.from(sig, "base64url"));
    } catch {
      return false;
    }
  }
}
