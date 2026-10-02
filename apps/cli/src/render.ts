import { stringify } from "yaml";

export type OutputFormat = "table" | "json" | "yaml";

export interface Column<T> {
  header: string;
  get: (row: T) => unknown;
}

export interface Style {
  color: boolean;
}

const ANSI = {
  bold: "\x1b[1m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  dim: "\x1b[2m",
  reset: "\x1b[0m",
};

export function paint(style: Style, kind: keyof Omit<typeof ANSI, "reset">, text: string): string {
  return style.color ? `${ANSI[kind]}${text}${ANSI.reset}` : text;
}

/** Cell text: scalars as-is, null as "-", objects as compact JSON. */
export function cell(v: unknown): string {
  if (v === null || v === undefined || v === "") return "-";
  if (typeof v === "string") return v.replace(/\s+/g, " ");
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return JSON.stringify(v);
}

/** Left-aligned columns separated by two spaces; no trailing whitespace. */
export function table<T>(rows: readonly T[], columns: readonly Column<T>[], style: Style): string {
  const cells = rows.map((r) => columns.map((c) => cell(c.get(r))));
  const widths = columns.map((c, i) =>
    Math.max(c.header.length, ...cells.map((row) => (row[i] as string).length)),
  );
  const line = (parts: string[]) =>
    parts
      .map((p, i) => p.padEnd(widths[i] as number))
      .join("  ")
      .trimEnd();
  const head = line(columns.map((c) => c.header.toUpperCase()));
  return [paint(style, "bold", head), ...cells.map(line)].join("\n");
}

/** Two-column key/value listing of one object. */
export function keyValues(pairs: ReadonlyArray<readonly [string, unknown]>, style: Style): string {
  const w = Math.max(...pairs.map(([k]) => k.length));
  return pairs.map(([k, v]) => `${paint(style, "bold", k.padEnd(w))}  ${cell(v)}`).join("\n");
}

export function asJson(data: unknown): string {
  return JSON.stringify(data, null, 2);
}

export function asYaml(data: unknown): string {
  return stringify(data).trimEnd();
}

/** Render structured data for json/yaml; tables are produced by the caller (they are command specific). */
export function structured(data: unknown, format: Exclude<OutputFormat, "table">): string {
  return format === "json" ? asJson(data) : asYaml(data);
}

export function shortId(id: string | undefined): string {
  return id ?? "-";
}
