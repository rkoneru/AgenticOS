import type { TranscriptMode } from "./types.js";

/** A tenant-supplied hook (names, addresses: whatever the tenant's DLP catches) applied BEFORE persistence in PHI mode. */
export type RedactionHook = (text: string) => string;

const PATTERNS: [RegExp, string][] = [
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
