import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { RequesterVerifier } from "./dsar.js";
import type { KeyProvider } from "./keys.js";

/**
 * The shipped requester verifier (ADR 0111). Identity of the data subject is proven by TWO signed tokens, both bound to this
 * tenant, this request and a short expiry, both HMAC-signed with a per-tenant key derived from the governance master key:
 *
 *   - `requester_token`: issued by the tenant's identity-proofing step once the data subject has been confirmed out of band
 *     (for example by a link sent to the address on file). It names the request and the opaque subject reference.
 *   - `admin_attestation`: a tenant `owner` or `admin` member attests that proofing took place. DUAL CONTROL: the attesting member
 *     must differ from the member who opened the request and from the member who submits the verification, and must be an active
 *     owner or admin of the tenant at the time of the check (looked up, never taken from the token).
 *
 * Fail-closed: a malformed, expired, mis-bound or badly signed token, an unknown attester, a directory error: all refuse.
 * The shape of the evidence is `{ requester_token: string, admin_attestation: string }`.
 */
export interface AttesterDirectory {
  /** Is `memberId` an active owner or admin of the tenant? */
  isTenantAdmin(tenantId: string, memberId: string): Promise<boolean>;
}

interface Claims {
  v: 1;
  typ: "requester" | "attestation";
  /** tenant */
  t: string;
  /** request */
  r: string;
  /** subject ref (requester token) */
  s?: string;
  /** attesting member (attestation) */
  m?: string;
  /** expiry, epoch seconds */
  exp: number;
  /** nonce */
  n: string;
}

const b64 = (b: Buffer): string => b.toString("base64url");
const MAX_TTL_SECONDS = 7 * 86_400;
const DOMAIN = "axis-gov-evidence.v1\u0000";

export class EvidenceVerifier implements RequesterVerifier {
  constructor(
    private readonly keys: KeyProvider,
    private readonly directory: AttesterDirectory,
    private readonly now: () => Date = () => new Date(),
  ) {}

  private async mac(tenantId: string, payload: string): Promise<Buffer> {
    return createHmac("sha256", await this.keys.tenantKey(tenantId, "evidence"))
      .update(DOMAIN)
      .update(payload)
      .digest();
  }

  private async issue(
    claims: Omit<Claims, "v" | "exp" | "n">,
    ttlSeconds: number,
  ): Promise<string> {
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > MAX_TTL_SECONDS)
      throw new RangeError(`ttlSeconds must be 1..${MAX_TTL_SECONDS}`);
    const full: Claims = {
      ...claims,
      v: 1,
      exp: Math.floor(this.now().getTime() / 1000) + ttlSeconds,
      n: randomBytes(9).toString("base64url"),
    };
    const payload = b64(Buffer.from(JSON.stringify(full), "utf8"));
    return `${payload}.${b64(await this.mac(claims.t, payload))}`;
  }

  /** Operator tooling: the proofing step hands the data subject's confirmation to the officer as this token. */
  issueRequesterToken(a: {
    tenantId: string;
    requestId: string;
    subjectRef: string;
    ttlSeconds?: number;
  }): Promise<string> {
    return this.issue(
      { typ: "requester", t: a.tenantId, r: a.requestId, s: a.subjectRef },
      a.ttlSeconds ?? 3600,
    );
  }

  /** Operator tooling: a tenant admin's attestation for one request. */
  issueAdminAttestation(a: {
    tenantId: string;
    requestId: string;
    memberId: string;
    ttlSeconds?: number;
  }): Promise<string> {
    return this.issue(
      { typ: "attestation", t: a.tenantId, r: a.requestId, m: a.memberId },
      a.ttlSeconds ?? 3600,
    );
  }

  private async open(
    tenantId: string,
    token: unknown,
    typ: Claims["typ"],
    requestId: string,
  ): Promise<Claims | undefined> {
    if (typeof token !== "string" || token.length > 2048) return undefined;
    const parts = token.split(".");
    if (parts.length !== 2) return undefined;
    const [payload, sig] = parts as [string, string];
    const want = await this.mac(tenantId, payload);
    const got = Buffer.from(sig, "base64url");
    if (got.length !== want.length || !timingSafeEqual(got, want)) return undefined;
    let c: Claims;
    try {
      c = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Claims;
    } catch {
      return undefined;
    }
    if (
      c.v !== 1 ||
      c.typ !== typ ||
      c.t !== tenantId ||
      c.r !== requestId ||
      typeof c.exp !== "number" ||
      c.exp * 1000 <= this.now().getTime()
    )
      return undefined;
    return c;
  }

  async verify(
    req: Parameters<RequesterVerifier["verify"]>[0],
    evidence: unknown,
  ): Promise<{ ok: boolean; method: string }> {
    const refuse = (why: string) => ({ ok: false, method: `refused:${why}` });
    try {
      if (typeof evidence !== "object" || evidence === null || Array.isArray(evidence))
        return refuse("evidence");
      const e = evidence as Record<string, unknown>;
      const requester = await this.open(
        req.tenantId,
        e["requester_token"],
        "requester",
        req.requestId,
      );
      if (!requester || requester.s !== req.subjectRef) return refuse("requester_token");
      const attest = await this.open(
        req.tenantId,
        e["admin_attestation"],
        "attestation",
        req.requestId,
      );
      if (!attest || typeof attest.m !== "string" || attest.m === "")
        return refuse("admin_attestation");
      // dual control: the attester is neither the member who opened the request nor the one submitting the verification
      if (attest.m === req.requestedBy || attest.m === req.verifiedBy)
        return refuse("dual_control");
      if (!(await this.directory.isTenantAdmin(req.tenantId, attest.m))) return refuse("attester");
      return { ok: true, method: "signed-token+admin-attestation" };
    } catch {
      return refuse("error");
    }
  }
}
