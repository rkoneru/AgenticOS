"use client";
import { useState } from "react";
import { scoreBars, sparkPoints, type BarRow } from "@/lib/eval-charts";

const fmt = (v: number): string => v.toFixed(3);

/**
 * Per-grader (or per-case) scores on a FIXED 0..1 axis, optionally against a baseline. Plain SVG, attributes only (strict CSP).
 * Identity is never colour-alone: a legend names both series, every bar has a visible value, and a table view carries the same data.
 */
export function ScoreBars({
  title,
  rows,
  seriesName = "This run",
  otherName = "Baseline",
}: {
  title: string;
  rows: BarRow[];
  seriesName?: string;
  otherName?: string;
}) {
  const [table, setTable] = useState(false);
  const paired = rows.some((r) => r.other !== undefined);
  const W = 640;
  const labelW = 150;
  const valueW = 56;
  const plotW = W - labelW - valueW;
  const { bars, height } = scoreBars(rows, {
    plotWidth: plotW,
    rowHeight: paired ? 24 : 16,
    gap: 10,
    top: 4,
  });
  return (
    <figure
      className="viz-root rounded-md border border-[var(--axis-border)] bg-[var(--axis-surface)] p-4"
      data-testid="score-chart"
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
      {paired && !table ? (
        <ul className="mb-2 flex gap-4 text-xs" aria-label="Legend">
          <li className="flex items-center gap-1">
            <svg width="10" height="10" aria-hidden="true">
              <rect width="10" height="10" rx="2" fill="var(--axis-viz-1)" />
            </svg>
            {seriesName}
          </li>
          <li className="flex items-center gap-1">
            <svg width="10" height="10" aria-hidden="true">
              <rect width="10" height="10" rx="2" fill="var(--axis-viz-2)" />
            </svg>
            {otherName}
          </li>
        </ul>
      ) : null}
      {table ? (
        <table className="w-full text-left text-sm">
          <caption className="sr-only">{title} data</caption>
          <thead>
            <tr>
              <th scope="col" className="py-1 pr-4">
                Name
              </th>
              <th scope="col" className="py-1 pr-4">
                {seriesName}
              </th>
              {paired ? (
                <th scope="col" className="py-1">
                  {otherName}
                </th>
              ) : null}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.label}>
                <td className="py-0.5 pr-4">{r.label}</td>
                <td className="pr-4">{fmt(r.value)}</td>
                {paired ? <td>{r.other === undefined ? "-" : fmt(r.other)}</td> : null}
              </tr>
            ))}
          </tbody>
        </table>
      ) : rows.length === 0 ? (
        <p className="text-sm text-[var(--axis-muted)]">No scores yet.</p>
      ) : (
        <svg
          viewBox={`0 0 ${W} ${height}`}
          role="img"
          aria-label={`${title}: ${rows.map((r) => `${r.label} ${fmt(r.value)}`).join(", ")}`}
          className="h-auto w-full"
        >
          <line x1={labelW} x2={labelW} y1={0} y2={height} stroke="var(--axis-border)" />
          <line
            x1={labelW + plotW}
            x2={labelW + plotW}
            y1={0}
            y2={height}
            stroke="var(--axis-border)"
            strokeWidth={0.5}
          />
          {bars.map((b) => (
            <g key={b.label}>
              <text
                x={labelW - 8}
                y={b.y + b.height / 2 + 4}
                textAnchor="end"
                fontSize={12}
                fill="var(--axis-fg)"
              >
                {b.label.length > 22 ? `${b.label.slice(0, 21)}...` : b.label}
              </text>
              <rect
                x={labelW}
                y={b.y}
                width={Math.max(b.width, 2)}
                height={b.height}
                rx={3}
                fill="var(--axis-viz-1)"
              />
              <text
                x={labelW + plotW + 6}
                y={b.y + b.height / 2 + 4}
                fontSize={11}
                fill="var(--axis-fg)"
              >
                {fmt(b.value)}
              </text>
              {b.otherWidth !== undefined ? (
                <>
                  <rect
                    x={labelW}
                    y={b.y + b.height + 2}
                    width={Math.max(b.otherWidth, 2)}
                    height={b.height}
                    rx={3}
                    fill="var(--axis-viz-2)"
                  />
                  <text
                    x={labelW + plotW + 6}
                    y={b.y + b.height + 2 + b.height / 2 + 4}
                    fontSize={11}
                    fill="var(--axis-muted)"
                  >
                    {fmt(b.other as number)}
                  </text>
                </>
              ) : null}
            </g>
          ))}
        </svg>
      )}
    </figure>
  );
}

/** A score history, oldest first, on the fixed 0..1 axis: a line, a 2px-ringed marker per sample, and a table view. */
export function ScoreHistory({
  title,
  points,
}: {
  title: string;
  points: Array<{ label: string; value: number }>;
}) {
  const [table, setTable] = useState(false);
  const W = 640;
  const H = 120;
  const pts = sparkPoints(
    points.map((p) => p.value),
    { width: W, height: H, pad: 14 },
  );
  return (
    <figure
      className="viz-root rounded-md border border-[var(--axis-border)] bg-[var(--axis-surface)] p-4"
      data-testid="history-chart"
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
                Sample
              </th>
              <th scope="col" className="py-1">
                Score
              </th>
            </tr>
          </thead>
          <tbody>
            {points.map((p, i) => (
              <tr key={`${p.label}-${i}`}>
                <td className="py-0.5 pr-4">{p.label}</td>
                <td>{fmt(p.value)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : points.length === 0 ? (
        <p className="text-sm text-[var(--axis-muted)]">No samples yet.</p>
      ) : (
        <svg
          viewBox={`0 0 ${W} ${H}`}
          role="img"
          aria-label={`${title}: ${points.length} samples, latest ${fmt(points[points.length - 1]!.value)}`}
          className="h-auto w-full"
        >
          <line x1={14} x2={W - 14} y1={14} y2={14} stroke="var(--axis-border)" strokeWidth={0.5} />
          <line x1={14} x2={W - 14} y1={H - 14} y2={H - 14} stroke="var(--axis-border)" />
          <text x={W - 14} y={10} textAnchor="end" fontSize={10} fill="var(--axis-muted)">
            1.0
          </text>
          <text x={W - 14} y={H - 2} textAnchor="end" fontSize={10} fill="var(--axis-muted)">
            0.0
          </text>
          <polyline
            fill="none"
            stroke="var(--axis-viz-1)"
            strokeWidth={2}
            strokeLinejoin="round"
            points={pts.map((p) => `${p.x},${p.y}`).join(" ")}
          />
          {pts.map((p, i) => (
            <circle
              key={i}
              cx={p.x}
              cy={p.y}
              r={4}
              fill="var(--axis-viz-1)"
              stroke="var(--axis-surface)"
              strokeWidth={2}
            />
          ))}
        </svg>
      )}
    </figure>
  );
}
