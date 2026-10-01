import type { ApprovalService } from "./service.js";
import type { DecisionRecord } from "./types.js";

export interface ResolverTimers {
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

/**
 * In-process interface the Risk Kernel / runtime calls to learn how a REQUIRE_APPROVAL ended.
 *
 * `resolve` waits until the request is terminal and returns a signed, audited `DecisionRecord`:
 * APPROVED (decision ALLOW) | DENIED | EXPIRED (both decision DENY). It re-checks SLA timers itself, so the answer does
 * not depend on the sweeper running. Callers MUST treat any rejection (unknown id, signing or audit failure, abort) as
 * DENY, and should gate the resumed action with `isApprovalValidFor`, which binds the approval to tenant, run, tool
 * and argument hash.
 */
export class ApprovalResolver {
  constructor(
    private readonly service: ApprovalService,
    private readonly timers: ResolverTimers = { setTimeout, clearTimeout },
  ) {}

  async resolve(
    tenantId: string,
    requestId: string,
    signal?: AbortSignal,
  ): Promise<DecisionRecord> {
    for (;;) {
      signal?.throwIfAborted();
      const r = await this.service.peek(tenantId, requestId);
      if (r.status !== "pending") return this.service.decisionRecord(r);
      await this.waitForChange(
        tenantId,
        requestId,
        Math.max(1, r.deadline_ms - this.service.now()),
        signal,
      );
    }
  }

  private waitForChange(
    tenantId: string,
    id: string,
    maxMs: number,
    signal: AbortSignal | undefined,
  ): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const cleanup = (): void => {
        off();
        this.timers.clearTimeout(handle);
        signal?.removeEventListener("abort", onAbort);
      };
      const onAbort = (): void => {
        cleanup();
        reject(signal?.reason as Error);
      };
      const off = this.service.onTerminal((t, i) => {
        if (t === tenantId && i === id) {
          cleanup();
          resolve();
        }
      });
      const handle = this.timers.setTimeout(() => {
        cleanup();
        resolve();
      }, maxMs);
      signal?.addEventListener("abort", onAbort, { once: true });
    });
  }
}
