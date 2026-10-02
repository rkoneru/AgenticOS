import { periodBounds, periodIdOf, nextPeriod, type Meter, type UsageEntry, type UsageLedger } from "@axis/billing";
import { PortUnavailable, type UsagePort, type UsageRowDto } from "../ports.js";

/** API meter, its ledger meters, the divisor from ledger base units and the API unit. */
const API_METERS: Record<string, { from: readonly Meter[]; div: number; unit: string }> = {
  tokens: { from: ["tokens_in", "tokens_out"], div: 1, unit: "tokens" },
  runtime_seconds: { from: ["runtime_seconds"], div: 1000, unit: "seconds" },
  tool_executions: { from: ["tool_executions"], div: 1, unit: "executions" },
  voice_minutes: { from: ["voice_minutes"], div: 60_000, unit: "minutes" },
  storage_gb_hours: { from: ["storage_gb_hours"], div: 1000, unit: "gb_hours" },
  marketplace_installs: { from: ["marketplace_installs"], div: 1, unit: "installs" },
};
const LEDGER_TO_API = new Map<Meter, string>(Object.entries(API_METERS).flatMap(([api, m]) => m.from.map((l) => [l, api] as const)));

export class LedgerUsage implements UsagePort {
  constructor(private readonly ledger: Pick<UsageLedger, "entries">) {}

  async query(tenantId: string, q: { from: Date; to: Date; groupBy?: "meter" | "model" | "blueprint" | "day" }): Promise<UsageRowDto[]> {
    const rows: UsageEntry[] = [];
    try {
      for (let p = periodIdOf(q.from); periodBounds(p).start < q.to; p = nextPeriod(p))
        for (const e of await this.ledger.entries(tenantId, { periodId: p }))
          if (e.eventTime >= q.from && e.eventTime < q.to) rows.push(e);
    } catch {
      throw new PortUnavailable("the usage ledger is unavailable; retry");
    }
    const acc = new Map<string, { meter: string; group: string | undefined; q: bigint }>();
    for (const e of rows) {
      const meter = LEDGER_TO_API.get(e.meter);
      if (!meter) continue;
      const g = q.groupBy;
      const group =
        g === "day" ? e.eventTime.toISOString().slice(0, 10) : g === "model" ? (e.dimensions["model"] ?? e.dimensions["model_class"] ?? "unknown") : g === "blueprint" ? (e.dimensions["agent"] ?? "unknown") : undefined;
      const k = `${meter}\u0000${group ?? ""}`;
      const cur = acc.get(k);
      if (cur) cur.q += e.quantity;
      else acc.set(k, { meter, group, q: e.quantity });
    }
    return [...acc.values()]
      .sort((a, b) => (a.meter === b.meter ? (a.group ?? "").localeCompare(b.group ?? "") : METER_ORDER(a.meter) - METER_ORDER(b.meter)))
      .map((r) => {
        const m = API_METERS[r.meter] as { div: number; unit: string };
        return { meter: r.meter, quantity: Number(r.q) / m.div, unit: m.unit, ...(r.group !== undefined ? { group: r.group } : {}) };
      });
  }
}

const METER_ORDER = (m: string): number => Object.keys(API_METERS).indexOf(m);
