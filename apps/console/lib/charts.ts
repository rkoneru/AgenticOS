/** Scale and tick helpers for the plain-SVG charts (no chart library). */

export function niceMax(v: number): number {
  if (!(v > 0) || !Number.isFinite(v)) return 1;
  const exp = Math.floor(Math.log10(v));
  const f = v / 10 ** exp;
  const nice = f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10;
  return nice * 10 ** exp;
}

export function ticks(max: number, count = 4): number[] {
  const m = niceMax(max);
  return Array.from({ length: count + 1 }, (_, i) => (m / count) * i);
}

export function scaleLinear(
  domain: [number, number],
  range: [number, number],
): (v: number) => number {
  const [d0, d1] = domain;
  const [r0, r1] = range;
  const span = d1 - d0;
  return (v) => (span === 0 ? r0 : r0 + ((v - d0) / span) * (r1 - r0));
}

export interface Bar {
  label: string;
  value: number;
  x: number;
  y: number;
  width: number;
  height: number;
}

export function barLayout(
  items: ReadonlyArray<{ label: string; value: number }>,
  box: { width: number; height: number; padLeft: number; padBottom: number; padTop?: number },
): { bars: Bar[]; max: number } {
  const padTop = box.padTop ?? 8;
  const max = niceMax(Math.max(0, ...items.map((i) => i.value)));
  const innerW = box.width - box.padLeft;
  const innerH = box.height - box.padBottom - padTop;
  const slot = items.length ? innerW / items.length : innerW;
  const width = Math.max(2, slot * 0.7);
  const y = scaleLinear([0, max], [padTop + innerH, padTop]);
  const bars = items.map((it, i) => {
    const top = y(it.value);
    return {
      label: it.label,
      value: it.value,
      x: box.padLeft + slot * i + (slot - width) / 2,
      y: top,
      width,
      height: padTop + innerH - top,
    };
  });
  return { bars, max };
}

/** Group usage rows by meter, summing quantities of the same group. */
export function totalsByMeter(
  rows: ReadonlyArray<{ meter: string; quantity: number; unit: string }>,
): Array<{ meter: string; unit: string; total: number }> {
  const m = new Map<string, { meter: string; unit: string; total: number }>();
  for (const r of rows) {
    const cur = m.get(r.meter) ?? { meter: r.meter, unit: r.unit, total: 0 };
    cur.total += r.quantity;
    m.set(r.meter, cur);
  }
  return [...m.values()].sort((a, b) => a.meter.localeCompare(b.meter));
}
