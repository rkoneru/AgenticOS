"use client";
import { useState } from "react";
import { barLayout, ticks } from "@/lib/charts";
import { formatNumber } from "@/lib/format";

export interface Point {
  label: string;
  value: number;
}

const W = 640;
const H = 220;

/**
 * Single-series bar chart in plain SVG. One hue (series slot 1), 2px rounded data ends, recessive grid,
 * hover/focus tooltip per bar, and a table view for non-visual access. Only attributes are used for
 * geometry (no inline styles) so the strict CSP holds.
 */
export function UsageChart({
  title,
  unit,
  points,
}: {
  title: string;
  unit: string;
  points: Point[];
}) {
  const [active, setActive] = useState<number | undefined>();
  const [table, setTable] = useState(false);
  const { bars, max } = barLayout(points, { width: W, height: H, padLeft: 48, padBottom: 28 });
  const ys = ticks(max, 4);
  const plotTop = 8;
  const plotH = H - 28 - plotTop;
  const yOf = (v: number) => plotTop + plotH - (v / max) * plotH;
  const a = active !== undefined ? bars[active] : undefined;
  return (
    <figure
      className="viz-root rounded-md border border-[var(--axis-border)] bg-[var(--axis-surface)] p-4"
      data-testid="usage-chart"
    >
      <figcaption className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <span className="text-sm font-medium">{title}</span>
        <button
          type="button"
          className="rounded-md border border-[var(--axis-border)] px-2 py-1 text-xs"
          aria-pressed={table}
          onClick={() => setTable((t) => !t)}
        >
          {table ? "Show chart" : "Show table"}
        </button>
      </figcaption>
      {table ? (
        <table className="w-full text-left text-sm">
          <caption className="sr-only">{title} data</caption>
          <thead>
            <tr>
              <th scope="col" className="py-1 pr-4">
                Period
              </th>
              <th scope="col" className="py-1">
                {unit}
              </th>
            </tr>
          </thead>
          <tbody>
            {points.map((p) => (
              <tr key={p.label}>
                <td className="py-0.5 pr-4">{p.label}</td>
                <td>{formatNumber(p.value)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : points.length === 0 ? (
        <p className="text-sm text-[var(--axis-muted)]">No usage in this period.</p>
      ) : (
        <div className="relative">
          <svg
            viewBox={`0 0 ${W} ${H}`}
            role="img"
            aria-label={`${title}: ${points.length} periods, peak ${formatNumber(Math.max(...points.map((p) => p.value)))} ${unit}`}
            className="h-auto w-full"
          >
            {ys.map((t) => (
              <g key={t}>
                <line
                  x1={48}
                  x2={W}
                  y1={yOf(t)}
                  y2={yOf(t)}
                  stroke="var(--axis-border)"
                  strokeWidth={t === 0 ? 1 : 0.5}
                />
                <text x={44} y={yOf(t) + 4} textAnchor="end" fontSize={11} fill="var(--axis-muted)">
                  {formatNumber(t)}
                </text>
              </g>
            ))}
            {bars.map((b, i) => (
              <g key={b.label}>
                <rect
                  x={b.x}
                  y={b.height > 4 ? b.y : b.y - (4 - b.height)}
                  width={b.width}
                  height={Math.max(b.height, 0)}
                  rx={4}
                  fill="var(--axis-viz-1)"
                  opacity={active === undefined || active === i ? 1 : 0.55}
                />
                {/* oversized transparent hit target */}
                <rect
                  x={b.x - 4}
                  y={0}
                  width={b.width + 8}
                  height={H - 28}
                  fill="transparent"
                  tabIndex={0}
                  role="img"
                  aria-label={`${b.label}: ${formatNumber(b.value)} ${unit}`}
                  onMouseEnter={() => setActive(i)}
                  onMouseLeave={() => setActive(undefined)}
                  onFocus={() => setActive(i)}
                  onBlur={() => setActive(undefined)}
                />
                {points.length <= 12 || i % Math.ceil(points.length / 12) === 0 ? (
                  <text
                    x={b.x + b.width / 2}
                    y={H - 10}
                    textAnchor="middle"
                    fontSize={11}
                    fill="var(--axis-muted)"
                  >
                    {b.label.slice(5)}
                  </text>
                ) : null}
              </g>
            ))}
          </svg>
          {a ? (
            <div
              role="status"
              className="pointer-events-none absolute right-2 top-0 rounded-md border border-[var(--axis-border)] bg-[var(--axis-surface-2)] px-2 py-1 text-xs"
            >
              {a.label}: <strong>{formatNumber(a.value)}</strong> {unit}
            </div>
          ) : null}
        </div>
      )}
    </figure>
  );
}
