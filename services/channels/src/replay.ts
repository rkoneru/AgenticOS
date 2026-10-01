/** Replay protection: a timestamp window plus an idempotency store. Both are required; neither alone is enough. */

export function withinWindow(tsMs: number, nowMs: number, windowMs: number): boolean {
  return Number.isFinite(tsMs) && Math.abs(nowMs - tsMs) <= windowMs;
}

export interface IdempotencyStore {
  /** Atomically claim `key` for `ttlMs`. Returns false if it is already claimed (a duplicate or replay). */
  claim(key: string, ttlMs: number): Promise<boolean>;
  /** Give the claim back (processing failed before any effect, so the provider's retry must be accepted). */
  release(key: string): Promise<void>;
}

export class MemoryIdempotencyStore implements IdempotencyStore {
  private readonly seen = new Map<string, number>();
  constructor(private readonly now: () => number = Date.now) {}

  async claim(key: string, ttlMs: number): Promise<boolean> {
    const t = this.now();
    const until = this.seen.get(key);
    if (until !== undefined && until > t) return false;
    if (this.seen.size > 50_000) {
      for (const [k, u] of this.seen) if (u <= t) this.seen.delete(k);
    }
    this.seen.set(key, t + ttlMs);
    return true;
  }

  async release(key: string): Promise<void> {
    this.seen.delete(key);
  }
}

export interface RateLimiter {
  /** True if the call is within the limit (and is counted). */
  take(key: string, perMinute: number): boolean;
}

/** Fixed-window-per-minute token bucket with continuous refill. In-memory: per instance (NEEDS: shared limiter). */
export class MemoryRateLimiter implements RateLimiter {
  private readonly buckets = new Map<string, { tokens: number; at: number }>();
  constructor(private readonly now: () => number = Date.now) {}

  take(key: string, perMinute: number): boolean {
    const t = this.now();
    const b = this.buckets.get(key) ?? { tokens: perMinute, at: t };
    b.tokens = Math.min(perMinute, b.tokens + ((t - b.at) / 60_000) * perMinute);
    b.at = t;
    if (b.tokens < 1) {
      this.buckets.set(key, b);
      return false;
    }
    b.tokens -= 1;
    this.buckets.set(key, b);
    if (this.buckets.size > 50_000) {
      for (const [k, v] of this.buckets) if (t - v.at > 120_000) this.buckets.delete(k);
    }
    return true;
  }
}
