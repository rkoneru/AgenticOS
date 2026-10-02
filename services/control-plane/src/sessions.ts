import { randomUUID } from "node:crypto";
import { hmac, randomToken, safeEqual, TokenSigner } from "./crypto.js";
import { unauthenticated } from "./errors.js";
import type { Principal } from "./authz.js";
import type { ControlPlaneStore, Member, SessionRecord } from "./types.js";

export interface SessionOptions {
  store: ControlPlaneStore;
  signer: TokenSigner;
  /** Service secret (>= 32 bytes) keying the refresh-token hashes. */
  pepper: Uint8Array;
  now?: () => Date;
  newId?: () => string;
  /** Access token lifetime. Default 900 s. */
  accessTtlSec?: number;
  /** Absolute session lifetime (a refresh never extends it). Default 8 h. */
  absoluteTtlSec?: number;
}

export interface IssuedSession {
  sessionId: string;
  accessToken: string;
  refreshToken: string;
  accessExpiresAt: Date;
  sessionExpiresAt: Date;
}

const ACCESS = "axis-access.v1";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Short-lived signed access tokens backed by a server-side session row, and rotating refresh tokens.
 *  - Access token: `kid.payload.hmac`; payload {t: tenant, s: session, m: member, exp}. Validity needs the signature, `exp`, AND a live
 *    session row (the server-side revocation list) for an ACTIVE member. The role is read from the member NOW, never from the token.
 *  - Refresh token: `axr.<tenant>.<session>.<secret>`, stored only as HMAC(pepper, secret). Each use rotates it. Presenting a rotated
 *    (previous) token means it was stolen or replayed: the whole session is revoked.
 *  - Cookie flags (set by the HTTP layer): `__Host-axis_rt` HttpOnly; Secure; SameSite=Strict; Path=/ ; `__Host-axis_at` likewise.
 */
export class SessionService {
  private readonly now: () => Date;
  private readonly newId: () => string;
  private readonly accessTtl: number;
  private readonly absTtl: number;
  constructor(private readonly o: SessionOptions) {
    if (o.pepper.length < 32) throw new Error("pepper must be >= 32 bytes");
    this.now = o.now ?? (() => new Date());
    this.newId = o.newId ?? randomUUID;
    this.accessTtl = o.accessTtlSec ?? 900;
    this.absTtl = o.absoluteTtlSec ?? 8 * 3600;
  }

  private refreshHash(secret: string): Buffer {
    return hmac(this.o.pepper, "refresh\0", secret);
  }

  private mintAccess(
    s: { tenantId: string; id: string; memberId: string },
    expiresAt: Date,
  ): string {
    return this.o.signer.sign(ACCESS, {
      t: s.tenantId,
      s: s.id,
      m: s.memberId,
      exp: Math.floor(expiresAt.getTime() / 1000),
    });
  }

  async issue(member: Member, method: "sso" | "dev" = "sso"): Promise<IssuedSession> {
    if (member.status !== "active") throw unauthenticated("member is not active");
    const now = this.now();
    const id = this.newId();
    const secret = randomToken(32);
    const expiresAt = new Date(now.getTime() + this.absTtl * 1000);
    const rec: SessionRecord = {
      tenantId: member.tenantId,
      id,
      memberId: member.id,
      refreshHash: this.refreshHash(secret),
      counter: 0,
      authMethod: method,
      createdAt: now,
      expiresAt,
      refreshedAt: now,
    };
    await this.o.store.insertSession(rec);
    const accessExpiresAt = this.accessExpiry(now, expiresAt);
    return {
      sessionId: id,
      accessToken: this.mintAccess(rec, accessExpiresAt),
      refreshToken: `axr.${member.tenantId}.${id}.${secret}`,
      accessExpiresAt,
      sessionExpiresAt: expiresAt,
    };
  }

  private accessExpiry(now: Date, sessionExpiresAt: Date): Date {
    return new Date(Math.min(now.getTime() + this.accessTtl * 1000, sessionExpiresAt.getTime()));
  }

  /** Returns the principal for a valid access token, else undefined. Never throws for bad input. */
  async authenticate(token: string): Promise<Principal | undefined> {
    const p = this.o.signer.verify(ACCESS, token);
    if (!p) return undefined;
    const { t, s, m, exp } = p as { t?: unknown; s?: unknown; m?: unknown; exp?: unknown };
    if (
      typeof t !== "string" ||
      typeof s !== "string" ||
      typeof m !== "string" ||
      typeof exp !== "number"
    )
      return undefined;
    if (!UUID.test(t) || !UUID.test(s) || !UUID.test(m)) return undefined;
    const now = this.now();
    if (exp * 1000 <= now.getTime()) return undefined;
    const sess = await this.o.store.getSession(t, s);
    if (!sess || sess.memberId !== m || sess.revokedAt || sess.expiresAt.getTime() <= now.getTime())
      return undefined;
    const member = await this.o.store.getMember(t, m);
    if (!member || member.status !== "active") return undefined;
    return { tenantId: t, memberId: m, role: member.role, credential: "session", sessionId: s };
  }

  async refresh(refreshToken: string): Promise<IssuedSession> {
    const parts = refreshToken.split(".");
    if (parts.length !== 4 || parts[0] !== "axr") throw unauthenticated("invalid refresh token");
    const [, t, s, secret] = parts as [string, string, string, string];
    if (!UUID.test(t) || !UUID.test(s) || secret.length < 20)
      throw unauthenticated("invalid refresh token");
    const now = this.now();
    const sess = await this.o.store.getSession(t, s);
    if (!sess || sess.revokedAt || sess.expiresAt.getTime() <= now.getTime())
      throw unauthenticated("invalid refresh token");
    const presented = this.refreshHash(secret);
    if (sess.prevRefreshHash && safeEqual(sess.prevRefreshHash, presented)) {
      await this.o.store.revokeSession(t, s, now, "refresh_token_reuse");
      throw unauthenticated("refresh token reuse detected; session revoked");
    }
    const member = await this.o.store.getMember(t, sess.memberId);
    if (!member || member.status !== "active") {
      await this.o.store.revokeSession(t, s, now, "member_inactive");
      throw unauthenticated("invalid refresh token");
    }
    const next = randomToken(32);
    const ok = await this.o.store.rotateRefresh(t, s, presented, this.refreshHash(next), now);
    if (!ok) throw unauthenticated("invalid refresh token");
    const accessExpiresAt = this.accessExpiry(now, sess.expiresAt);
    return {
      sessionId: s,
      accessToken: this.mintAccess(
        { tenantId: t, id: s, memberId: sess.memberId },
        accessExpiresAt,
      ),
      refreshToken: `axr.${t}.${s}.${next}`,
      accessExpiresAt,
      sessionExpiresAt: sess.expiresAt,
    };
  }

  revoke(tenantId: string, sessionId: string, reason = "logout"): Promise<boolean> {
    return this.o.store.revokeSession(tenantId, sessionId, this.now(), reason);
  }

  /** Immediate effect: every session of the member dies (the next `authenticate` finds no live row). */
  revokeAllOfMember(tenantId: string, memberId: string, reason: string): Promise<number> {
    return this.o.store.revokeSessionsOfMember(tenantId, memberId, this.now(), reason);
  }
}
