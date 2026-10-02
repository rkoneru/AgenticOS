export function shortId(id: string, n = 8): string {
  return id.length > n ? id.slice(0, n) : id;
}

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return "-";
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? "-"
    : d
        .toISOString()
        .replace("T", " ")
        .replace(/\.\d+Z$/, "Z");
}

export function formatNumber(n: number): string {
  if (!Number.isFinite(n)) return "-";
  if (Math.abs(n) >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (Math.abs(n) >= 10_000) return `${(n / 1000).toFixed(1)}k`;
  return Number.isInteger(n) ? String(n) : n.toFixed(2);
}

export function formatUsd(n: number): string {
  return `$${n.toFixed(n < 1 ? 4 : 2)}`;
}
