import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";
import { canonicalJson, contentHash } from "@axis/abl";
import type { BlueprintSignature, PublisherKey } from "./types.js";

/** DER prefix of an Ed25519 SubjectPublicKeyInfo; the raw 32-byte key follows. */
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
export const SIGNATURE_DOMAIN = "axis-registry/blueprint-signature/v1";
export const MAX_SKEW_MS = 5 * 60_000;

/** Strict base64url: canonical alphabet, no padding, and re-encoding must reproduce the input (rejects non-canonical trailing bits). */
export function decodeB64u(s: unknown, expectedLen?: number): Buffer | undefined {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) return undefined;
  const b = Buffer.from(s, "base64url");
  if (b.toString("base64url") !== s) return undefined;
  if (expectedLen !== undefined && b.length !== expectedLen) return undefined;
  return b;
}

/** Strict standard base64 (with padding), same canonical-form rule. */
export function decodeB64(s: unknown): Buffer | undefined {
  if (typeof s !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return undefined;
  const b = Buffer.from(s, "base64");
  return b.toString("base64") === s ? b : undefined;
}

export function keyIdOf(rawPublicKey: Uint8Array): string {
  return `k1-${createHash("sha256").update(rawPublicKey).digest("hex").slice(0, 32)}`;
}

export function publicKeyObject(publicKeyB64u: string): KeyObject | undefined {
  const raw = decodeB64u(publicKeyB64u, 32);
  if (!raw) return undefined;
  try {
    return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: "der", type: "spki" });
  } catch {
    /* v8 ignore next 2 -- defensive: OpenSSL accepts any 32 bytes here; point validity is checked at verify time */
    return undefined;
  }
}

export interface PublisherKeyPair {
  keyId: string;
  /** base64url raw public key, as registered. */
  publicKey: string;
  privateKey: KeyObject;
}

export function generatePublisherKey(): PublisherKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const raw = spki.subarray(spki.length - 32);
  return { keyId: keyIdOf(raw), publicKey: raw.toString("base64url"), privateKey };
}

export const privateKeyFromPem = (pem: string): KeyObject => createPrivateKey(pem);

export function signDetached(privateKey: KeyObject, message: Uint8Array): string {
  return edSign(null, message, privateKey).toString("base64url");
}

/** Never throws: any malformed key, signature or message is a plain `false`. */
export function verifyDetached(
  publicKeyB64u: string,
  message: Uint8Array,
  sigB64u: unknown,
): boolean {
  const key = publicKeyObject(publicKeyB64u);
  const sig = decodeB64u(sigB64u, 64);
  if (!key || !sig) return false;
  try {
    return edVerify(null, message, key, sig);
  } catch {
    return false;
  }
}

export type KeyTrust = { ok: true } | { ok: false; reason: string };

/**
 * Was `key` a key whose signatures are trusted at instant `at`?
 *  - not yet valid, or past `validUntil` (rotated out): no
 *  - revoked as `compromised`: NEVER (a stolen key can mint any timestamp, so nothing it signed is trustworthy, before or after)
 *  - revoked as `retired`: only before the revocation instant
 */
export function keyTrustedAt(key: PublisherKey, at: Date): KeyTrust {
  if (key.revokeReason === "compromised")
    return { ok: false, reason: "key revoked as compromised" };
  if (at.getTime() < key.validFrom.getTime()) return { ok: false, reason: "key not yet valid" };
  if (key.validUntil && at.getTime() >= key.validUntil.getTime())
    return { ok: false, reason: "key validity ended" };
  if (key.revokedAt && at.getTime() >= key.revokedAt.getTime())
    return { ok: false, reason: "key revoked" };
  return { ok: true };
}

export interface SignedStatement {
  v: 1;
  namespace: string;
  name: string;
  version: string;
  contentHash: string;
  riskLevel: string;
  keyId: string;
  signedAt: string;
}

/** The exact bytes a publisher signs. Rebuilt by the verifier from the stored record, never taken from the client. */
export function signedMessage(s: SignedStatement): Buffer {
  return Buffer.from(`${SIGNATURE_DOMAIN}\n${canonicalJson(s)}`, "utf8");
}

export interface BlueprintIdentity {
  namespace: string;
  name: string;
  version: string;
  riskLevel: string;
  contentHash: string;
}

export function signBlueprint(
  id: BlueprintIdentity,
  key: { keyId: string; privateKey: KeyObject },
  signedAt: Date = new Date(),
): BlueprintSignature {
  const iso = signedAt.toISOString();
  const msg = signedMessage({ v: 1, ...id, keyId: key.keyId, signedAt: iso });
  return { keyId: key.keyId, signedAt: iso, sig: signDetached(key.privateKey, msg) };
}

/** Content hash of an ABL document: the ABL compiler's canonical form (re-exported so publishers need one import). */
export const ablContentHash = (doc: unknown): string => contentHash(doc);
