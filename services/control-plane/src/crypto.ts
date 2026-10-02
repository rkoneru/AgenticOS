import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

export const b64u = (b: Uint8Array): string => Buffer.from(b).toString("base64url");
export const fromB64u = (s: string): Buffer => Buffer.from(s, "base64url");
export const sha256 = (data: string | Uint8Array): Buffer =>
  createHash("sha256").update(data).digest();
export const sha256Hex = (data: string | Uint8Array): string => sha256(data).toString("hex");
export const hmac = (key: Uint8Array, ...parts: (string | Uint8Array)[]): Buffer => {
  const h = createHmac("sha256", key);
  for (const p of parts) h.update(p);
  return h.digest();
};

/** Constant-time equality. Different lengths are unequal (length is not secret for fixed-size digests). */
export function safeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export const randomToken = (bytes = 32): string => b64u(randomBytes(bytes));
export const randomHex = (bytes: number): string => randomBytes(bytes).toString("hex");

/** AES-256-GCM. Output: nonce(12) || ciphertext || tag(16). `aad` binds the ciphertext to its context (tenant, purpose). */
export function seal(key: Uint8Array, plaintext: Uint8Array, aad: string): Buffer {
  if (key.length !== 32) throw new Error("seal: key must be 32 bytes");
  const nonce = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, nonce);
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([nonce, ct, c.getAuthTag()]);
}

/** Throws on any tampering, wrong key or wrong `aad`. */
export function open(key: Uint8Array, box: Uint8Array, aad: string): Buffer {
  if (key.length !== 32) throw new Error("open: key must be 32 bytes");
  if (box.length < 12 + 16) throw new Error("open: box too short");
  const b = Buffer.from(box);
  const d = createDecipheriv("aes-256-gcm", key, b.subarray(0, 12));
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(b.subarray(b.length - 16));
  return Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()]);
}

export interface SigningKey {
  kid: string;
  key: Uint8Array;
}

/** Compact signed token: `<kid>.<payload b64url>.<hmac b64url>`; the first key signs, any listed key verifies (rotation). */
export class TokenSigner {
  constructor(private readonly keys: readonly SigningKey[]) {
    if (keys.length === 0) throw new Error("at least one signing key is required");
    for (const k of keys)
      if (k.key.length < 32) throw new Error("signing keys must be >= 32 bytes");
  }

  sign(purpose: string, payload: Record<string, unknown>): string {
    const k = this.keys[0] as SigningKey;
    const body = b64u(Buffer.from(JSON.stringify(payload)));
    return `${k.kid}.${body}.${b64u(hmac(k.key, purpose, "\0", k.kid, ".", body))}`;
  }

  /** Returns the payload of a correctly signed token for `purpose`, else undefined. Never throws. */
  verify(purpose: string, token: string): Record<string, unknown> | undefined {
    const parts = token.split(".");
    if (parts.length !== 3) return undefined;
    const [kid, body, sig] = parts as [string, string, string];
    const k = this.keys.find((x) => x.kid === kid);
    if (!k) return undefined;
    const want = hmac(k.key, purpose, "\0", kid, ".", body);
    if (!safeEqual(want, fromB64u(sig))) return undefined;
    try {
      const v: unknown = JSON.parse(fromB64u(body).toString("utf8"));
      return typeof v === "object" && v !== null && !Array.isArray(v)
        ? (v as Record<string, unknown>)
        : undefined;
    } catch {
      return undefined;
    }
  }
}
