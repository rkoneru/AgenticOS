"use client";
import { useMemo, useState } from "react";
import { Input, Select } from "@axis/ui";
import { api, type Meter } from "@/lib/api";
import { totalsByMeter } from "@/lib/charts";
import { formatNumber } from "@/lib/format";
import { useResource } from "@/lib/hooks";
import { PageHeader, ResourceView } from "@/components/common";
import { UsageChart } from "@/components/usage-chart";

const day = (d: Date) => d.toISOString().slice(0, 10);

export default function UsagePage() {
  const [from, setFrom] = useState(() => day(new Date(Date.now() - 29 * 86_400_000)));
  const [to, setTo] = useState(() => day(new Date()));
  const [meter, setMeter] = useState<Meter>("tokens");
  const range = { from: `${from}T00:00:00Z`, to: `${to}T23:59:59Z` };
  const totals = useResource(() => api.getUsage({ ...range, group_by: "meter" }), [from, to]);
  const byDay = useResource(() => api.getUsage({ ...range, group_by: "day" }), [from, to]);
  const points = useMemo(
    () =>
      (byDay.data?.items ?? [])
        .filter((r) => r.meter === meter && r.group)
        .map((r) => ({ label: r.group!, value: r.quantity }))
        .sort((a, b) => a.label.localeCompare(b.label)),
    [byDay.data, meter],
  );
  const unit = byDay.data?.items.find((r) => r.meter === meter)?.unit ?? "";
  return (
    <>
      <title>Usage - AXIS Console</title>
      <PageHeader title="Usage" description="Metered usage that feeds billing." />
      <div className="mb-4 flex flex-wrap items-end gap-3">
        <Input
          label="From"
          type="date"
          value={from}
          max={to}
          onChange={(e) => setFrom(e.target.value)}
        />
        <Input
          label="To"
          type="date"
          value={to}
          min={from}
          onChange={(e) => setTo(e.target.value)}
        />
      </div>
      <ResourceView resource={totals}>
        {(t) => (
          <ul
            aria-label="Totals by meter"
            className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6"
          >
            {totalsByMeter(t.items).map((m) => (
              <li
                key={m.meter}
                className="rounded-md border border-[var(--axis-border)] bg-[var(--axis-surface)] p-3"
              >
                <div className="text-xs text-[var(--axis-muted)]">{m.meter}</div>
                <div className="text-xl font-semibold" data-testid={`total-${m.meter}`}>
                  {formatNumber(m.total)}
                </div>
                <div className="text-xs text-[var(--axis-muted)]">{m.unit}</div>
              </li>
            ))}
          </ul>
        )}
      </ResourceView>
      <div className="mb-3 max-w-xs">
        <Select
          label="Meter"
          value={meter}
          onChange={(e) => setMeter(e.target.value as Meter)}
          options={(
            [
              "tokens",
              "runtime_seconds",
              "tool_executions",
              "voice_minutes",
              "storage_gb_hours",
              "marketplace_installs",
            ] as const
          ).map((m) => ({ value: m, label: m }))}
        />
      </div>
      <ResourceView resource={byDay}>
        {() => <UsageChart title={`${meter} per day`} unit={unit} points={points} />}
      </ResourceView>
    </>
  );
}
