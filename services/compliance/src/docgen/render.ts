import type { DocBody } from "./assemble.js";
import { SECTION_KEYS } from "./assemble.js";

const esc = (s: string): string =>
  s.replaceAll("|", "\\|").replaceAll("\n", " ").replaceAll("\r", " ");

const isPrim = (v: unknown): v is string | number | boolean | null =>
  v === null || ["string", "number", "boolean"].includes(typeof v);

const cell = (v: unknown): string => (v === null ? "-" : esc(String(v)));

const isFlatRows = (v: unknown): v is Record<string, string | number | boolean | null>[] =>
  Array.isArray(v) &&
  v.length > 0 &&
  v.every(
    (r) =>
      typeof r === "object" && r !== null && !Array.isArray(r) && Object.values(r).every(isPrim),
  );

function lines(value: unknown, indent: string): string[] {
  if (isPrim(value)) return [`${indent}${cell(value)}`];
  if (Array.isArray(value)) {
    if (value.length === 0) return [`${indent}(none)`];
    if (isFlatRows(value)) {
      const cols = [...new Set(value.flatMap((r) => Object.keys(r)))].sort();
      return [
        "",
        `| ${cols.join(" | ")} |`,
        `| ${cols.map(() => "---").join(" | ")} |`,
        ...value.map((r) => `| ${cols.map((c) => cell(r[c] ?? null)).join(" | ")} |`),
        "",
      ];
    }
    return value.flatMap((v, i) =>
      isPrim(v)
        ? [`${indent}- ${cell(v)}`]
        : [`${indent}- item ${i + 1}`, ...lines(v, `${indent}  `)],
    );
  }
  const o = value as Record<string, unknown>;
  return Object.keys(o)
    .sort()
    .flatMap((k) => {
      const v = o[k];
      if (isPrim(v)) return [`${indent}- ${k}: ${cell(v)}`];
      if (Array.isArray(v) && v.length === 0) return [`${indent}- ${k}: (none)`];
      return [`${indent}- ${k}:`, ...lines(v, `${indent}  `)];
    });
}

export interface RenderMeta {
  document_id: string;
  doc_version: number;
  generated_at: string;
  content_hash: string;
}

/** Deterministic Markdown view of a document body. The Markdown is sealed together with the JSON (its hash is part of the seal). */
export function renderMarkdown(body: DocBody, meta: RenderMeta): string {
  const out: string[] = [];
  out.push(`# Technical documentation: ${body.blueprint.name}@${body.blueprint.version}`);
  out.push("");
  out.push(`> ${body.disclaimer}`);
  out.push("");
  out.push(`- document: ${meta.document_id} (version ${meta.doc_version})`);
  out.push(`- generated at: ${meta.generated_at}`);
  out.push(`- content hash (sha256 of the canonical body): ${meta.content_hash}`);
  out.push(`- blueprint content hash: ${body.blueprint.content_hash ?? "unknown"}`);
  out.push("");
  out.push("## Sources");
  out.push("");
  for (const s of body.sources)
    out.push(`- ${s.name}: ${s.status}${s.reason !== null ? ` (${s.reason})` : ""}`);
  out.push("");
  out.push(`## Gaps (${body.gaps.length})`);
  out.push("");
  if (body.gaps.length === 0) out.push("No gaps were found by the generator.");
  else for (const g of body.gaps) out.push(`- [${g.section}] ${g.item}: ${g.reason}`);
  out.push("");
  out.push("## Annex IV coverage");
  out.push("");
  out.push("| point | title | section | status | note |");
  out.push("| --- | --- | --- | --- | --- |");
  for (const c of body.annex_iv_coverage)
    out.push(
      `| ${c.point} | ${esc(c.title)} | ${c.section ?? "-"} | ${c.status} | ${cell(c.note)} |`,
    );
  out.push("");
  for (const k of SECTION_KEYS) {
    const s = body.sections[k];
    if (!s) continue;
    out.push(`## ${s.title}`);
    out.push("");
    out.push(`- section: ${k}`);
    out.push(`- status: ${s.status}`);
    out.push(`- Annex IV: ${s.annex_iv.join(", ")}`);
    out.push("");
    if (s.data === null) out.push("No data: the source of this section was unavailable.");
    else out.push(...lines(s.data, ""));
    if (s.gaps.length > 0) {
      out.push("");
      out.push("Gaps in this section:");
      for (const g of s.gaps) out.push(`- ${g}`);
    }
    out.push("");
  }
  return `${out.join("\n")}\n`;
}
