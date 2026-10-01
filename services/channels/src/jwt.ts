import { createPublicKey, verify as cryptoVerify, type JsonWebKey } from "node:crypto";
import { b64urlDecode } from "./crypto.js";

export interface Jwk extends JsonWebKey {
  kid?: string;
  use?: string;
  alg?: string;
}

/** Injected key source. Production fetches and caches the provider's OpenID JWKS (NEEDS); tests pass a static set. */
export interface JwksProvider {
  keys(): Promise<Jwk[]>;
}
export class StaticJwks implements JwksProvider {
  constructor(private readonly set: Jwk[]) {}
  async keys(): Promise<Jwk[]> {
    return this.set;
  }
}

export interface JwtOptions {
  jwks: JwksProvider;
  issuers: readonly string[];
  audience: string;
  nowMs: number;
  /** Clock skew tolerated on exp / nbf. Default 300 s. */
  skewSec?: number;
  maxTokenBytes?: number;
}

export type JwtResult =
  { ok: true; claims: Record<string, unknown> } | { ok: false; reason: string };

const fail = (reason: string): JwtResult => ({ ok: false, reason });

function parseJson(b: Buffer | undefined): Record<string, unknown> | undefined {
  if (!b) return undefined;
  try {
    const v: unknown = JSON.parse(b.toString("utf8"));
    return typeof v === "object" && v !== null && !Array.isArray(v)
      ? (v as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

/**
 * RS256 JWT verification with node:crypto. Only RS256 is accepted (`alg: none` and HMAC/EC confusion are rejected before any key is
 * touched), the key is chosen by `kid` from the injected JWKS, RSA keys under 2048 bits are refused, and `iss`, `aud`, `exp`
 * (required) and `nbf` are checked. Returns the claims only for a token that passed every check.
 */
export async function verifyRs256Jwt(token: string, o: JwtOptions): Promise<JwtResult> {
  if (token.length > (o.maxTokenBytes ?? 8192)) return fail("token too large");
  const parts = token.split(".");
  if (parts.length !== 3) return fail("not a compact JWS");
  const [h, p, s] = parts as [string, string, string];
  const header = parseJson(b64urlDecode(h));
  if (!header) return fail("bad header");
  if (header["alg"] !== "RS256") return fail("unsupported alg");
  if (header["crit"] !== undefined) return fail("unsupported crit");
  const kid = header["kid"];
  if (typeof kid !== "string" || kid === "") return fail("missing kid");
  const sig = b64urlDecode(s);
  if (!sig || sig.length === 0) return fail("bad signature encoding");

  let keys: Jwk[];
  try {
    keys = await o.jwks.keys();
  } catch {
    return fail("jwks unavailable");
  }
  const jwk = keys.find((k) => k.kid === kid);
  if (!jwk || jwk.kty !== "RSA" || (jwk.use !== undefined && jwk.use !== "sig"))
    return fail("unknown key");
  const modulus = typeof jwk.n === "string" ? b64urlDecode(jwk.n) : undefined;
  if (!modulus || modulus.length * 8 < 2048) return fail("weak key");
  let ok = false;
  try {
    const key = createPublicKey({ key: jwk, format: "jwk" });
    ok = cryptoVerify("RSA-SHA256", Buffer.from(`${h}.${p}`, "ascii"), key, sig);
  } catch {
    return fail("bad key");
  }
  if (!ok) return fail("signature mismatch");

  const claims = parseJson(b64urlDecode(p));
  if (!claims) return fail("bad claims");
  const skew = o.skewSec ?? 300;
  const nowSec = o.nowMs / 1000;
  const { iss, aud, exp, nbf } = claims;
  if (typeof iss !== "string" || !o.issuers.includes(iss)) return fail("bad issuer");
  const auds = Array.isArray(aud) ? aud : [aud];
  if (!auds.includes(o.audience)) return fail("bad audience");
  if (typeof exp !== "number" || !Number.isFinite(exp)) return fail("missing exp");
  if (exp + skew < nowSec) return fail("expired");
  if (nbf !== undefined && (typeof nbf !== "number" || nbf - skew > nowSec))
    return fail("not yet valid");
  return { ok: true, claims };
}
