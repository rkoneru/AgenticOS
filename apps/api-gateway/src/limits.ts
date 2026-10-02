import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { IdemBegin, IdempotencyStore, RateLimiter, StoredResponse } from "./ports.js";

// ---- token-bucket rate limiter ----------------------------------------------------------------------------------------------

export interface BucketConfig {
  /** Bucket size (the burst). */
  burst: number;
  /** Refill per second. */
  perSecond: number;
}

/**
 * Per-key token buckets with a bounded key table. Keys are tenant ids (authenticated) or remote addresses (failed authentication);
 * they are NEVER taken from a request header, so a caller cannot choose, split or reset its own bucket. When the table is full the
 * least recently used bucket is dropped (a dropped bucket restarts full, which only ever helps an idle key).
 */
export class TokenBuckets implements RateLimiter {
  private readonly buckets = new Map<string, { tokens: number; at: number }>();
  constructor(
    private readonly cfg: BucketConfig,
    private readonly now: () => number = Date.now,
    private readonly maxKeys = 50_000,
  ) {}

  take(key: string, cost = 1): { ok: boolean; limit: number; remaining: number; retryAfterSec: number } {
    const t = this.now();
    let b = this.buckets.get(key);
    if (b) {
      this.buckets.delete(key); // re-insert below: Map order = recency
      b.tokens = Math.min(this.cfg.burst, b.tokens + ((t - b.at) / 1000) * this.cfg.perSecond);
      b.at = t;
    } else {
      b = { tokens: this.cfg.burst, at: t };
      if (this.buckets.size >= this.maxKeys) {
        const oldest = this.buckets.keys().next().value;
        if (oldest !== undefined) this.buckets.delete(oldest);
      }
    }
    this.buckets.set(key, b);
    // A request that costs more than the bucket can ever hold is clamped, so it is not unservable.
    const need = Math.min(cost, this.cfg.burst);
    if (b.tokens >= need) {
      b.tokens -= need;
      return { ok: true, limit: this.cfg.burst, remaining: Math.floor(b.tokens), retryAfterSec: 0 };
    }
    const wait = (need - b.tokens) / this.cfg.perSecond;
    return { ok: false, limit: this.cfg.burst, remaining: Math.floor(b.tokens), retryAfterSec: wait };
  }

  get size(): number {
    return this.buckets.size;
  }
}

// ---- idempotency store ----------------------------------------------------------------------------------------------------------

interface Entry {
  fingerprint: string;
  state: "in_progress" | "done";
  response?: StoredResponse;
  expiresAt: number;
}

/** In-memory store (single instance; NEEDS #1006). `scope` already carries the tenant, so a key can never collide across tenants. */
export class MemoryIdempotencyStore implements IdempotencyStore {
  private readonly entries = new Map<string, Entry>();
  constructor(
    private readonly now: () => number = Date.now,
    private readonly maxEntries = 100_000,
  ) {}

  private k(scope: string, key: string): string {
    return `${scope}\u0000${key}`;
  }

  private sweep(): void {
    const t = this.now();
    for (const [k, e] of this.entries) {
      if (e.expiresAt <= t) this.entries.delete(k);
      else break; // insertion order is expiry order (single TTL)
    }
  }

  async begin(scope: string, key: string, fingerprint: string, ttlMs: number): Promise<IdemBegin> {
    this.sweep();
    const k = this.k(scope, key);
    const e = this.entries.get(k);
    if (e && e.expiresAt > this.now()) {
      if (e.fingerprint !== fingerprint) return { kind: "mismatch" };
      if (e.state === "in_progress" || !e.response) return { kind: "in_progress" };
      return { kind: "replay", response: structuredClone(e.response) };
    }
    if (this.entries.size >= this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (oldest !== undefined) this.entries.delete(oldest);
    }
    this.entries.set(k, { fingerprint, state: "in_progress", expiresAt: this.now() + ttlMs });
    return { kind: "new" };
  }

  async complete(scope: string, key: string, response: StoredResponse): Promise<void> {
    const e = this.entries.get(this.k(scope, key));
    if (e) {
      e.state = "done";
      e.response = structuredClone(response);
    }
  }

  async abort(scope: string, key: string): Promise<void> {
    this.entries.delete(this.k(scope, key));
  }

  get size(): number {
    return this.entries.size;
  }
}

// ---- fingerprints and cursors ----------------------------------------------------------------------------------------------------

/** Canonical JSON (sorted keys): the same logical body always hashes the same. */
export function canonical(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`)
    .join(",")}}`;
}

export function fingerprint(method: string, template: string, params: Record<string, string>, body: unknown): string {
  return createHash("sha256")
    .update(`${method} ${template}\n${canonical(params)}\n${canonical(body ?? null)}`)
    .digest("hex");
}

/**
 * Opaque, tamper-evident cursors bound to (tenant, resource). A cursor from tenant A presented by tenant B, or from `/runs` to
 * `/approvals`, fails the MAC and is a 422: cursors can never be a way to read another tenant's position or to forge one.
 */
export class CursorCodec {
  constructor(private readonly key: Buffer = randomBytes(32)) {}

  encode(tenantId: string, resource: string, position: string): string {
    const body = Buffer.from(JSON.stringify({ p: position }), "utf8").toString("base64url");
    return `${body}.${this.mac(tenantId, resource, body)}`;
  }

  /** The position, or undefined when the cursor is malformed, forged or belongs to another tenant/resource. */
  decode(tenantId: string, resource: string, cursor: string): string | undefined {
    const [body, mac, extra] = cursor.split(".");
    if (!body || !mac || extra !== undefined) return undefined;
    const want = Buffer.from(this.mac(tenantId, resource, body));
    const got = Buffer.from(mac);
    if (want.length !== got.length || !timingSafeEqual(want, got)) return undefined;
    try {
      const j = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as { p?: unknown };
      return typeof j.p === "string" ? j.p : undefined;
    } catch {
      return undefined;
    }
  }

  private mac(tenantId: string, resource: string, body: string): string {
    return createHmac("sha256", this.key).update(`${tenantId}\u0000${resource}\u0000${body}`).digest("base64url");
  }
}
