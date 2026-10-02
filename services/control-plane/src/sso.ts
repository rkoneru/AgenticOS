import { randomUUID } from "node:crypto";
import { b64u, fromB64u, open, randomToken, safeEqual, seal, sha256 } from "./crypto.js";
import { invalid, unauthenticated } from "./errors.js";
import type { AdminAudit } from "./audit.js";
import { pkceChallenge, type IdentityProvider, type IdpProfile } from "./idp.js";
import { isExternalRole, type Role } from "./roles.js";
import type { IssuedSession, SessionService } from "./sessions.js";
import type { ControlPlaneStore, Member } from "./types.js";

export interface SsoOptions {
  store: ControlPlaneStore;
  idp: IdentityProvider;
  sessions: SessionService;
  audit: AdminAudit;
  /** 32-byte key sealing the login cookie. */
  cookieKey: Uint8Array;
  /** Where the IdP sends the browser back: this service's callback URL (exact match enforced by the IdP). */
  redirectUri: string;
  /** Origins a `return_to` may point at (the console). Relative paths are always allowed. */
  allowedReturnOrigins: readonly string[];
  now?: () => Date;
  newId?: () => string;
  /** Login attempt lifetime. Default 600 s. */
  loginTtlSec?: number;
}

export interface LoginStart {
  redirectUrl: string;
  /** Set as `__Host-axis_login`; HttpOnly; Secure; SameSite=Lax (Strict would not survive the cross-site return); Path=/; Max-Age = ttl. */
  cookie: string;
  cookieMaxAgeSec: number;
}

export interface LoginResult {
  session: IssuedSession;
  returnTo: string;
  tenantId: string;
  memberId: string;
}

interface LoginCookie {
  s: string; // state
  n: string; // nonce
  v: string; // PKCE verifier
  o: string; // organization
  r: string; // sanitized return_to
  exp: number;
}

const COOKIE_AAD = "axis-login.v1";

/**
 * Open-redirect-safe return URL. Accepts a same-site path (`/x?y#z`) or an absolute URL whose origin is allow-listed. Rejects (and
 * falls back to `/`) protocol-relative `//host`, `/\host`, other schemes, embedded credentials and control characters.
 */
export function safeReturnTo(raw: string | undefined, allowedOrigins: readonly string[]): string {
  if (raw === undefined || raw.length === 0 || raw.length > 2048) return "/";
  // eslint-disable-next-line no-control-regex -- rejecting control characters is the point
  if (/[\u0000-\u001f\u007f\\]/.test(raw)) return "/";
  if (raw.startsWith("/")) return raw.startsWith("//") ? "/" : raw;
  try {
    const u = new URL(raw);
    if ((u.protocol !== "https:" && u.protocol !== "http:") || u.username || u.password) return "/";
    return allowedOrigins.includes(u.origin) ? u.toString() : "/";
  } catch {
    return "/";
  }
}

export class SsoService {
  private readonly now: () => Date;
  private readonly ttl: number;
  /** Spent login states (single use). In-process: NEEDS #187 (shared store). Entries expire with the login TTL. */
  private readonly spent = new Map<string, number>();
  constructor(private readonly o: SsoOptions) {
    if (o.cookieKey.length !== 32) throw new Error("cookieKey must be 32 bytes");
    this.now = o.now ?? (() => new Date());
    this.ttl = o.loginTtlSec ?? 600;
  }

  async begin(organizationId: string, returnTo?: string): Promise<LoginStart> {
    if (!/^[\w.-]{1,128}$/.test(organizationId)) throw invalid("invalid organization");
    const conn = await this.o.store.findConnectionByOrg(organizationId);
    if (!conn) throw invalid("unknown organization"); // not distinguishable from a misspelling
    const state = randomToken(32);
    const nonce = randomToken(24);
    const verifier = randomToken(48);
    const payload: LoginCookie = {
      s: state,
      n: nonce,
      v: verifier,
      o: organizationId,
      r: safeReturnTo(returnTo, this.o.allowedReturnOrigins),
      exp: Math.floor(this.now().getTime() / 1000) + this.ttl,
    };
    const cookie = b64u(seal(this.o.cookieKey, Buffer.from(JSON.stringify(payload)), COOKIE_AAD));
    return {
      redirectUrl: this.o.idp.authorizationUrl({
        organizationId,
        redirectUri: this.o.redirectUri,
        state,
        codeChallenge: pkceChallenge(verifier),
        nonce,
      }),
      cookie,
      cookieMaxAgeSec: this.ttl,
    };
  }

  private unseal(cookie: string | undefined): LoginCookie {
    if (!cookie) throw unauthenticated("login attempt not found");
    try {
      const v = JSON.parse(
        open(this.o.cookieKey, fromB64u(cookie), COOKIE_AAD).toString("utf8"),
      ) as LoginCookie;
      if (
        typeof v.s !== "string" ||
        typeof v.n !== "string" ||
        typeof v.v !== "string" ||
        typeof v.o !== "string" ||
        typeof v.r !== "string" ||
        typeof v.exp !== "number"
      )
        throw new Error("shape");
      return v;
    } catch {
      throw unauthenticated("login attempt not found");
    }
  }

  private async deny(tenantId: string | undefined, why: string, who: string): Promise<never> {
    if (tenantId)
      await this.o.audit
        .record({
          tenantId,
          actor: { type: "system", id: `idp:${who}`.slice(0, 120) },
          action: "auth.sso_login",
          decision: "DENY",
          policyVersion: "sso",
          reason: `why=${why}`,
          inputs: { why },
          outputs: {},
        })
        .catch(() => undefined);
    throw unauthenticated("sign-in failed");
  }

  async callback(
    q: { code?: string; state?: string; error?: string },
    cookie: string | undefined,
  ): Promise<LoginResult> {
    const c = this.unseal(cookie);
    const now = Math.floor(this.now().getTime() / 1000);
    if (c.exp <= now) throw unauthenticated("login attempt expired");
    if (!q.state || !q.code || q.error) throw unauthenticated("sign-in failed");
    if (!safeEqual(sha256(q.state), sha256(c.s))) throw unauthenticated("state mismatch"); // login CSRF
    for (const [k, e] of this.spent) if (e <= now) this.spent.delete(k);
    if (this.spent.has(c.s)) throw unauthenticated("login attempt already used");
    this.spent.set(c.s, c.exp);

    let profile: IdpProfile;
    try {
      profile = await this.o.idp.exchangeCode({
        code: q.code,
        codeVerifier: c.v,
        redirectUri: this.o.redirectUri,
      });
    } catch {
      throw unauthenticated("sign-in failed");
    }
    const conn = await this.o.store.findConnectionByOrg(profile.organizationId);
    if (!conn || profile.organizationId !== c.o) throw unauthenticated("sign-in failed"); // IdP asserted a different org than we asked for
    const tenantId = conn.tenantId;
    if (profile.nonce !== undefined) {
      if (!safeEqual(sha256(profile.nonce), sha256(c.n)))
        return this.deny(tenantId, "nonce_mismatch", profile.id);
    } else if (profile.connectionType === "oidc")
      return this.deny(tenantId, "nonce_missing", profile.id);
    if (conn.connectionType !== profile.connectionType)
      return this.deny(tenantId, "connection_type_mismatch", profile.id);

    const email = profile.email.toLowerCase();
    let member: Member | undefined = await this.o.store.findMemberByUserRef(
      tenantId,
      `idp:${profile.id}`,
    );
    if (!member && profile.emailVerified)
      member = await this.o.store.findMemberByEmail(tenantId, email);
    if (member) {
      if (member.status !== "active") return this.deny(tenantId, "member_deprovisioned", member.id);
    } else {
      member = await this.jit(tenantId, conn.jitEnabled, conn.jitDefaultRole, profile, email);
    }
    const session = await this.o.sessions.issue(member, "sso");
    await this.o.audit.record({
      tenantId,
      actor: { type: "human", id: member.id },
      action: "auth.sso_login",
      decision: "ALLOW",
      policyVersion: "sso",
      reason: `connection=${profile.connectionType} session=${session.sessionId}`,
      inputs: { org: profile.organizationId, connection: profile.connectionType },
      outputs: { session: session.sessionId },
    });
    return { session, returnTo: c.r, tenantId, memberId: member.id };
  }

  /** JIT provisioning only for a verified e-mail at a domain the tenant admin verified, never `owner`. */
  private async jit(
    tenantId: string,
    enabled: boolean,
    defaultRole: Role,
    p: IdpProfile,
    email: string,
  ): Promise<Member> {
    if (!enabled) return this.deny(tenantId, "jit_disabled", p.id);
    if (!p.emailVerified) return this.deny(tenantId, "email_unverified", p.id);
    const domain = email.split("@")[1] ?? "";
    const d = await this.o.store.getDomain(tenantId, domain);
    if (!d || d.status !== "verified") return this.deny(tenantId, "domain_not_verified", p.id);
    if (!isExternalRole(defaultRole)) return this.deny(tenantId, "jit_role_invalid", p.id);
    const m = await this.o.store.insertMember({
      tenantId,
      id: (this.o.newId ?? randomUUID)(),
      userRef: `idp:${p.id}`,
      email,
      role: defaultRole,
      status: "active",
      ...(p.firstName || p.lastName
        ? { displayName: [p.firstName, p.lastName].filter(Boolean).join(" ") }
        : {}),
    });
    await this.o.audit.record({
      tenantId,
      actor: { type: "system", id: `idp:${p.id}` },
      action: "members.jit_provision",
      decision: "ALLOW",
      policyVersion: "sso",
      reason: `member=${m.id} role=${defaultRole} domain=${domain}`,
      inputs: { domain },
      outputs: { member: m.id },
    });
    return m;
  }

  /** Test seam: forget spent states. */
  get spentCount(): number {
    return this.spent.size;
  }
}
