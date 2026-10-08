import type { TranscriptMode } from "./types.js";

/** A tenant-supplied hook (names, addresses: whatever the tenant's DLP catches) applied BEFORE persistence in PHI mode. */
export type RedactionHook = (text: string) => string;

// Unicode-hardened patterns (same construction as services/memory/src/redact.ts): any decimal digit script, invisible format characters
// and unusual dashes between digits do not defeat the net (found by the PHI canary harness, services/data-governance).
const FMT = "\\p{Cf}";
const D = `\\p{Nd}[${FMT}]*`;
const SEP = `[${FMT}\\s]{0,3}[\\-\\u2010-\\u2015\\u2212.\\s][${FMT}\\s]{0,3}`;
const EDGE_BEFORE = "(?<![\\p{L}\\p{N}])";
const EDGE_AFTER = "(?![\\p{L}\\p{N}])";
const UNICODE_PATTERNS: [RegExp, string][] = [
  [
    new RegExp(`${EDGE_BEFORE}(?:${D}){3}${SEP}(?:${D}){2}${SEP}(?:${D}){4}${EDGE_AFTER}`, "gu"),
    "[ssn]",
  ],
  [
    new RegExp(
      `(?:\\bSSN|\\bsocial\\s+security(?:\\s+(?:number|no\\.?|#))?)[^\\p{L}\\p{N}]{0,12}(?:${D}){9}${EDGE_AFTER}`,
      "giu",
    ),
    "[ssn]",
  ],
  [/\bMRN\s*[:#]?\s*\d{5,}\b/gi, "[mrn]"],
  [
    new RegExp(
      `${EDGE_BEFORE}(?:\\+?1${SEP})?\\(?(?:${D}){3}\\)?${SEP}(?:${D}){3}${SEP}(?:${D}){4}${EDGE_AFTER}`,
      "gu",
    ),
    "[phone]",
  ],
];

const PATTERNS: [RegExp, string][] = [
  ...UNICODE_PATTERNS,
  [/[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,}/g, "[email]"], // bounded: an unbounded run made this quadratic on long text
  [/\b\d{3}[-\s.]?\d{2}[-\s.]?\d{4}\b/g, "[ssn]"],
  [/\b(?:\d[ -]?){13,19}\b/g, "[card]"],
  [/(?<![\w])\+?\d[\d\s().-]{8,30}\d\b/g, "[phone]"],
  [/<@[A-Z0-9]+>/g, "[mention]"],
  [/(?<![\w])@[A-Za-z0-9._-]{2,}/g, "[mention]"],
];

/** Built-in net: emails, SSN-shaped and card-shaped numbers, phone numbers, @mentions. A net, not proof (NEEDS). */
export function redactPatterns(text: string): string {
  let t = text;
  for (const [re, rep] of PATTERNS) t = t.replace(re, rep);
  return t;
}

export const PREVIEW_CHARS = 280;

/**
 * What the message log may keep of `text`. `phi` forces the built-in redaction plus the hook, and caps `full` at a preview.
 * Returns the effective mode and the content (null for hash_only).
 */
export function transcriptContent(
  text: string,
  mode: TranscriptMode,
  phi: boolean,
  hook?: RedactionHook,
): { mode: TranscriptMode; content: string | null } {
  const effective: TranscriptMode = phi && mode === "full" ? "redacted_preview" : mode;
  if (effective === "hash_only") return { mode: effective, content: null };
  let t = text;
  if (phi || effective === "redacted_preview") t = redactPatterns(t);
  if (phi && hook) {
    try {
      t = redactPatterns(hook(t));
    } catch {
      return { mode: "hash_only", content: null }; // a failing hook must never let raw text through
    }
  }
  if (effective === "redacted_preview" && t.length > PREVIEW_CHARS)
    t = `${t.slice(0, PREVIEW_CHARS - 1)}…`;
  return { mode: effective, content: t };
}
