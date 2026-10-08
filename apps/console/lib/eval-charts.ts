/** Pure geometry for the eval charts (plain SVG; no inline styles so the strict CSP holds). */

export interface BarRow {
  label: string;
  /** 0..1 */
  value: number;
  /** optional second series (the baseline), 0..1 */
  other?: number | undefined;
}

export interface BarGeom {
  label: string;
  y: number;
  height: number;
  width: number;
  otherWidth: number | undefined;
  value: number;
  other: number | undefined;
}

/** Horizontal bars on a fixed 0..1 axis: scores are bounded, so the scale is never auto-fitted to flatter a result. */
export function scoreBars(
  rows: BarRow[],
  o: { plotWidth: number; rowHeight: number; gap: number; top: number },
): { bars: BarGeom[]; height: number } {
  const paired = rows.some((r) => r.other !== undefined);
  const bh = paired ? Math.floor((o.rowHeight - 2) / 2) : o.rowHeight;
  const clamp = (v: number): number => Math.max(0, Math.min(1, Number.isFinite(v) ? v : 0));
  const bars = rows.map((r, i) => ({
    label: r.label,
    y: o.top + i * (o.rowHeight + o.gap),
    height: bh,
    width: clamp(r.value) * o.plotWidth,
    otherWidth: r.other === undefined ? undefined : clamp(r.other) * o.plotWidth,
    value: r.value,
    other: r.other,
  }));
  return { bars, height: o.top + rows.length * (o.rowHeight + o.gap) };
}

/** A polyline for a score history on a fixed 0..1 axis, oldest first. */
export function sparkPoints(
  values: number[],
  o: { width: number; height: number; pad: number },
): Array<{ x: number; y: number; v: number }> {
  const n = values.length;
  return values.map((v, i) => ({
    x: o.pad + (n === 1 ? (o.width - 2 * o.pad) / 2 : (i * (o.width - 2 * o.pad)) / (n - 1)),
    y: o.pad + (1 - Math.max(0, Math.min(1, v))) * (o.height - 2 * o.pad),
    v,
  }));
}
