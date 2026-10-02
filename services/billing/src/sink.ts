import type { UsageSink } from "./ledger.js";
import type { AdjustmentInput, AppendResult, UsageEntry, UsageInput } from "./types.js";

/** Analytics store (ClickHouse in production: real ClickHouse is NEEDS). NEVER authoritative: the Postgres ledger is. */
export interface AnalyticsSink {
  write(entries: readonly UsageEntry[]): Promise<void>;
}

/** In-memory stand-in for the ClickHouse sink. Like a ReplacingMergeTree keyed by (tenant, key), it keeps one row per key. */
export class FakeClickHouseSink implements AnalyticsSink {
  readonly rows = new Map<string, UsageEntry>();
  failNext = 0;
  async write(entries: readonly UsageEntry[]): Promise<void> {
    await Promise.resolve();
    if (this.failNext > 0) {
      this.failNext--;
      throw new Error("clickhouse unavailable");
    }
    for (const e of entries) this.rows.set(`${e.tenantId}\u0000${e.idempotencyKey}`, e);
  }
}

/**
 * Writes the authoritative ledger first; only entries that were actually inserted are forwarded to analytics. An analytics failure
 * never fails or reverts the ledger write (it is reported and the entry can be re-exported from Postgres).
 */
export class FanoutSink implements UsageSink {
  constructor(
    private readonly primary: UsageSink,
    private readonly analytics: readonly AnalyticsSink[],
    private readonly onAnalyticsError: (err: unknown, entry: UsageEntry) => void = () => undefined,
  ) {}
  async append(
    input: UsageInput | (AdjustmentInput & { entryType: "adjustment" }),
  ): Promise<AppendResult> {
    const r = await this.primary.append(input);
    if (r.status === "inserted") {
      for (const a of this.analytics) {
        try {
          await a.write([r.entry]);
        } catch (err) {
          this.onAnalyticsError(err, r.entry);
        }
      }
    }
    return r;
  }
}
