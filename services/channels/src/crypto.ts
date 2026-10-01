import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const sha256 = (b: Buffer | string): Buffer => createHash("sha256").update(b).digest();
const bytes = (v: string | Buffer): Buffer => (typeof v === "string" ? Buffer.from(v, "utf8") : v);

/**
 * Constant-time equality. Both sides are hashed first, so the comparison cost does not depend on where (or whether) the inputs
 * differ, and unequal lengths cannot be told apart by timing either.
 */
export function safeEqual(a: string | Buffer, b: string | Buffer): boolean {
  return timingSafeEqual(sha256(bytes(a)), sha256(bytes(b)));
}

export const hmacSha256Hex = (secret: string | Buffer, data: string | Buffer): string =>
  createHmac("sha256", secret).update(data).digest("hex");

export const hmacSha1Base64 = (secret: string | Buffer, data: string | Buffer): string =>
  createHmac("sha1", secret).update(data).digest("base64");

/** `expected` is the correctly computed signature; `provided` is the attacker-controlled header value. */
export const verifyHmacSha256Hex = (
  secret: string | Buffer,
  data: string | Buffer,
  provided: string | undefined,
): boolean => {
  if (!secret || provided === undefined || !/^[0-9a-f]{64}$/i.test(provided)) return false;
  return safeEqual(hmacSha256Hex(secret, data), provided.toLowerCase());
};

export const sha256Hex = (s: string | Buffer): string => sha256(s).toString("hex");

export const randomToken = (nBytes = 24): string => randomBytes(nBytes).toString("base64url");

const B64URL_RE = /^[A-Za-z0-9_-]*$/;
/** Strict base64url: rejects padding, whitespace and any other alphabet. */
export function b64urlDecode(s: string): Buffer | undefined {
  if (!B64URL_RE.test(s) || s.length % 4 === 1) return undefined;
  return Buffer.from(s, "base64url");
}
export const b64urlEncode = (b: Buffer | string): string => bytes(b).toString("base64url");

/**
 * Twilio signature: base64(HMAC-SHA1(authToken, url + for each POST parameter sorted by name: name + value)).
 * Parameters with several values contribute each value in order.
 */
export function twilioSignature(
  authToken: string,
  url: string,
  params: ReadonlyMap<string, readonly string[]> | Record<string, string>,
): string {
  const entries: [string, readonly string[]][] =
    params instanceof Map
      ? [...params.entries()]
      : Object.entries(params as Record<string, string>).map(([k, v]) => [k, [v]]);
  entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  let data = url;
  for (const [k, vs] of entries) for (const v of vs) data += k + v;
  return hmacSha1Base64(authToken, data);
}
