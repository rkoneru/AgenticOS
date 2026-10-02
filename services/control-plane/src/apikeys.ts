import { randomUUID } from "node:crypto";
import { hmac, randomHex, randomToken, safeEqual } from "./crypto.js";
import { conflict, invalid, notFound } from "./errors.js";
import type { Principal } from "./authz.js";
import type { ApiKeyRecord, ControlPlaneStore, Environment } from "./types.js";

export interface ApiKeyOptions {
  store: ControlPlaneStore;
  /** Service secret (>= 32 bytes): keys are stored as HMAC-SHA256(pepper, key), so a database leak does not allow offline guessing. */
  pepper: Uint8Array;
  now?: () => Date;
  newId?: () => string;
  /** Minimum interval between `last_used_at` writes per key. Default 60 s. */
  lastUsedGranularityMs?: number;
}

export interface CreateKeyInput {
  name: string;
  scopes: string[];
  environment?: Environment;
  expiresInDays?: number;
}

export interface CreatedKey {
  /** The only time the secret exists outside the caller's hands. */
  secret: string;
  key: PublicApiKey;
}

export type PublicApiKey = Omit<ApiKeyRecord, "keyHash">;

const KEY_RE = /^axk_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$/;
const SCOPE_RE = /^(\*|[a-z]{2,24}:(read|write|\*))$/;
export const MAX_KEY_DAYS = 365;

const strip = (k: ApiKeyRecord): PublicApiKey => {
  const { keyHash: _h, ...rest } = k;
  void _h;
  return rest;
};

/** Random 256-bit keys, `axk_<16 hex prefix>_<43 char secret>`; only the HMAC is stored; the prefix is the lookup handle. */
export class ApiKeyService {
  private readonly now: () => Date;
  private readonly newId: () => string;
  private readonly granularity: number;
  constructor(private readonly o: ApiKeyOptions) {
    if (o.pepper.length < 32) throw new Error("pepper must be >= 32 bytes");
    this.now = o.now ?? (() => new Date());
    this.newId = o.newId ?? randomUUID;
    this.granularity = o.lastUsedGranularityMs ?? 60_000;
  }

  private hash(fullKey: string): Buffer {
    return hmac(this.o.pepper, "apikey\0", fullKey);
  }

  private async insert(
    p: Principal,
    i: CreateKeyInput,
    extra: { rotatedFrom?: string; ownerMemberId?: string },
  ): Promise<CreatedKey> {
    if (!/^[\w .:/-]{1,80}$/.test(i.name))
      throw invalid("name must be 1-80 characters of letters, digits, space and ._:/-");
    if (
      !Array.isArray(i.scopes) ||
      i.scopes.length === 0 ||
      i.scopes.length > 32 ||
      !i.scopes.every((s) => typeof s === "string" && SCOPE_RE.test(s))
    )
      throw invalid("scopes must be a non-empty list of '<resource>:read|write|*' or '*'");
    const days = i.expiresInDays ?? 90;
    if (!Number.isFinite(days) || days <= 0 || days > MAX_KEY_DAYS)
      throw invalid(`expiresInDays must be in (0, ${MAX_KEY_DAYS}]`);
    if (i.environment !== undefined && !["dev", "staging", "prod"].includes(i.environment))
      throw invalid("unknown environment");
    const prefix = randomHex(8);
    const full = `axk_${prefix}_${randomToken(32)}`;
    const now = this.now();
    const rec: ApiKeyRecord = {
      tenantId: p.tenantId,
      id: this.newId(),
      name: i.name,
      prefix,
      keyHash: this.hash(full),
      scopes: [...new Set(i.scopes)],
      environment: i.environment ?? "dev",
      ownerMemberId: extra.ownerMemberId ?? p.memberId,
      createdBy: p.memberId,
      createdAt: now,
      expiresAt: new Date(now.getTime() + days * 86_400_000),
      ...(extra.rotatedFrom ? { rotatedFrom: extra.rotatedFrom } : {}),
    };
    return { secret: full, key: strip(await this.o.store.insertApiKey(rec)) };
  }

  create(p: Principal, i: CreateKeyInput): Promise<CreatedKey> {
    return this.insert(p, i, {});
  }

  async get(p: Principal, id: string): Promise<ApiKeyRecord> {
    const k = await this.o.store.getApiKey(p.tenantId, id);
    if (!k) throw notFound("api key not found"); // another tenant's id looks exactly like a missing one
    return k;
  }

  async list(
    p: Principal,
    limit = 50,
    after?: string,
  ): Promise<{ items: PublicApiKey[]; nextCursor?: string }> {
    const r = await this.o.store.listApiKeys(p.tenantId, Math.min(Math.max(limit, 1), 200), after);
    return { items: r.items.map(strip), ...(r.nextCursor ? { nextCursor: r.nextCursor } : {}) };
  }

  /** New key with the same attributes; the old one is revoked in the same operation. */
  async rotate(p: Principal, id: string): Promise<CreatedKey> {
    const old = await this.get(p, id);
    if (old.revokedAt) throw conflict("key is already revoked");
    const created = await this.insert(
      p,
      {
        name: old.name,
        scopes: old.scopes,
        environment: old.environment,
        expiresInDays: old.expiresAt
          ? Math.max(
              1 / 24,
              Math.min(
                MAX_KEY_DAYS,
                (old.expiresAt.getTime() - old.createdAt.getTime()) / 86_400_000,
              ),
            )
          : 90,
      },
      { rotatedFrom: old.id, ownerMemberId: old.ownerMemberId },
    );
    await this.o.store.updateApiKey(p.tenantId, old.id, { revokedAt: this.now() });
    return created;
  }

  async revoke(p: Principal, id: string): Promise<PublicApiKey> {
    await this.get(p, id);
    const k = await this.o.store.updateApiKey(p.tenantId, id, { revokedAt: this.now() });
    return strip(k as ApiKeyRecord);
  }

  /**
   * Resolves a presented key to a principal. Format check, then an exact (prefix, HMAC) lookup, then a constant-time compare, then
   * revocation / expiry / owner-active checks. Every failure is the same `undefined`.
   */
  async verify(presented: string): Promise<Principal | undefined> {
    const m = KEY_RE.exec(presented);
    if (!m) return undefined;
    const hash = this.hash(presented);
    const rec = await this.o.store.findApiKeyByLookup(m[1] as string, hash);
    if (!rec || !safeEqual(rec.keyHash, hash)) return undefined;
    const now = this.now();
    if (rec.revokedAt) return undefined;
    if (rec.expiresAt && rec.expiresAt.getTime() <= now.getTime()) return undefined;
    const owner = await this.o.store.getMember(rec.tenantId, rec.ownerMemberId);
    if (!owner || owner.status !== "active") return undefined;
    if (!rec.lastUsedAt || now.getTime() - rec.lastUsedAt.getTime() >= this.granularity)
      await this.o.store.updateApiKey(rec.tenantId, rec.id, { lastUsedAt: now });
    return {
      tenantId: rec.tenantId,
      memberId: owner.id,
      role: owner.role,
      credential: "api_key",
      apiKeyId: rec.id,
      scopes: rec.scopes,
    };
  }
}
