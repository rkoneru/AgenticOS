import { randomInt } from "node:crypto";
import { sha256Hex } from "./crypto.js";
import type { RateLimiter } from "./replay.js";
import type { ConversationStore, Identity, RedeemResult } from "./store.js";
import { ChannelError, type ChannelId } from "./types.js";

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O/1/I
export const LINK_CODE_LENGTH = 10;
export const LINK_CODE_TTL_MS = 10 * 60_000;
const LINK_RE = /^\s*link\s+([A-Za-z0-9-]{10,12})\s*$/i;

export const hashLinkCode = (tenant: string, code: string): string =>
  sha256Hex(`axis-link.v1:${tenant}:${code.replace(/-/g, "").toUpperCase()}`);

/** `link ABCDE23456` as the whole message. Returns the code, or undefined for any other text. */
export const parseLinkCommand = (text: string): string | undefined => LINK_RE.exec(text)?.[1];

export interface IdentityServiceOptions {
  store: ConversationStore;
  now?: () => number;
  ttlMs?: number;
  /** Failed-redeem throttle per (tenant, channel, identity). */
  limiter: RateLimiter;
  maxAttemptsPerMinute?: number;
  /** Test seam. */
  randomChar?: () => string;
}

/**
 * Cross-channel identity. The ONLY ways two identifiers become one end user: (1) they are the same provider-verified identifier;
 * (2) a link code issued to an end user is redeemed from another provider-verified identifier of the SAME tenant. A claim in
 * message text ("I am alice@example.com") never reaches this class; there is no merge-by-email, merge-by-phone or merge-by-name.
 */
export class IdentityService {
  private readonly store: ConversationStore;
  private readonly now: () => number;
  private readonly ttlMs: number;
  private readonly limiter: RateLimiter;
  private readonly maxAttempts: number;
  private readonly char: () => string;

  constructor(o: IdentityServiceOptions) {
    this.store = o.store;
    this.now = o.now ?? Date.now;
    this.ttlMs = o.ttlMs ?? LINK_CODE_TTL_MS;
    this.limiter = o.limiter;
    this.maxAttempts = o.maxAttemptsPerMinute ?? 5;
    this.char = o.randomChar ?? ((): string => ALPHABET[randomInt(ALPHABET.length)]!);
  }

  /** Called with a channel/external id that a provider signature has just verified. */
  async resolve(tenant: string, channel: ChannelId, externalId: string): Promise<Identity> {
    return (await this.store.resolveIdentity(tenant, channel, externalId)).identity;
  }

  /** Issue a code to the end user behind an already-verified identity. The code is returned once; only its hash is stored. */
  async issueLinkCode(
    tenant: string,
    channel: ChannelId,
    externalId: string,
  ): Promise<{ code: string; expires_at_ms: number }> {
    const ident = await this.store.findIdentity(tenant, channel, externalId);
    if (!ident) throw new ChannelError("NOT_FOUND", "unknown identity");
    const code = Array.from({ length: LINK_CODE_LENGTH }, this.char).join("");
    const expires = this.now() + this.ttlMs;
    await this.store.createChallenge(
      tenant,
      ident.end_user_id,
      hashLinkCode(tenant, code),
      expires,
    );
    return { code, expires_at_ms: expires };
  }

  async redeem(
    tenant: string,
    channel: ChannelId,
    externalId: string,
    code: string,
  ): Promise<RedeemResult> {
    if (!this.limiter.take(`link:${tenant}:${channel}:${externalId}`, this.maxAttempts))
      return { ok: false, reason: "invalid" };
    return this.store.redeemChallenge(tenant, hashLinkCode(tenant, code), this.now(), {
      channel,
      externalId,
    });
  }
}
