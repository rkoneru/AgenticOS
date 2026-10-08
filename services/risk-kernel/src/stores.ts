export type KillScope = "global" | "tenant" | "agent" | "tool";

export interface KillTarget {
  tenantId: string;
  agent: string;
  tool?: string | undefined;
}

/**
 * Kill-switch state. Reads are on the hot path of every decision; writes must become visible to every kernel
 * instance in < 1 s (Redis pub/sub in production; the in-memory store is single-process only).
 */
export interface KillSwitchStore {
  isEngaged(scope: KillScope, t: KillTarget): Promise<boolean>;
  set(
    scope: KillScope,
    t: { tenantId?: string | undefined; target?: string | undefined },
    engaged: boolean,
  ): Promise<void>;
}

export interface CounterStore {
  get(key: string): Promise<number>;
  add(key: string, n: number): Promise<number>;
  /**
   * ATOMIC check-and-add: adds `n` only if the result would stay <= `max`. Must be a single indivisible operation
   * (a Lua script / INCRBY-with-check in Redis); a separate get-then-add is a race that lets parallel requests
   * exceed a cap.
   */
  reserve(key: string, n: number, max: number): Promise<boolean>;
  /** Records one hit and returns the number of hits inside the trailing window (including this one). */
  hit(key: string, windowMs: number, nowMs: number): Promise<number>;
}

const killKey = (
  scope: KillScope,
  t: { tenantId?: string | undefined; target?: string | undefined },
): string => {
  switch (scope) {
    case "global":
      return "global";
    case "tenant":
      return `tenant:${t.tenantId}`;
    case "agent":
      return `agent:${t.tenantId}:${t.target}`;
    case "tool":
      return `tool:${t.tenantId}:${t.target}`;
  }
};

/** Single-process implementation (dev/test). NOT suitable for multi-instance deployments. */
export class MemoryKillSwitchStore implements KillSwitchStore {
  protected readonly engaged = new Set<string>();

  isEngaged(scope: KillScope, t: KillTarget): Promise<boolean> {
    const target = scope === "agent" ? t.agent : t.tool;
    if ((scope === "tool" && t.tool === undefined) || (scope !== "global" && !t.tenantId))
      return Promise.resolve(false);
    return Promise.resolve(this.engaged.has(killKey(scope, { tenantId: t.tenantId, target })));
  }

  set(
    scope: KillScope,
    t: { tenantId?: string | undefined; target?: string | undefined },
    engaged: boolean,
  ): Promise<void> {
    const k = killKey(scope, t);
    if (engaged) this.engaged.add(k);
    else this.engaged.delete(k);
    return Promise.resolve();
  }
}

/** Single-process implementation (dev/test). NOT suitable for multi-instance deployments. */
export class MemoryCounterStore implements CounterStore {
  private readonly values = new Map<string, number>();
  private readonly hits = new Map<string, number[]>();

  get(key: string): Promise<number> {
    return Promise.resolve(this.values.get(key) ?? 0);
  }

  add(key: string, n: number): Promise<number> {
    const v = (this.values.get(key) ?? 0) + n;
    this.values.set(key, v);
    return Promise.resolve(v);
  }

  reserve(key: string, n: number, max: number): Promise<boolean> {
    // No await between the read and the write: atomic within this single-threaded process.
    const next = (this.values.get(key) ?? 0) + n;
    if (next > max) return Promise.resolve(false);
    this.values.set(key, next);
    return Promise.resolve(true);
  }

  hit(key: string, windowMs: number, nowMs: number): Promise<number> {
    const live = (this.hits.get(key) ?? []).filter((t) => t > nowMs - windowMs);
    live.push(nowMs);
    this.hits.set(key, live);
    return Promise.resolve(live.length);
  }
}
