import type { AttachmentMeta } from "./types.js";

export interface Limits {
  /** Maximum request body bytes accepted from a provider. */
  maxBodyBytes: number;
  /** Maximum inbound text length (characters). */
  maxTextChars: number;
  maxAttachments: number;
  maxAttachmentBytes: number;
  /** Attachment content types kept as metadata; others are dropped (counted). Patterns: exact or `type/*`. */
  allowedAttachmentTypes: readonly string[];
  /** Inbound messages per (tenant, channel, sender) per minute. */
  inboundPerMinute: number;
}

export const DEFAULT_LIMITS: Limits = {
  maxBodyBytes: 256 * 1024,
  maxTextChars: 8_000,
  maxAttachments: 10,
  maxAttachmentBytes: 25 * 1024 * 1024,
  allowedAttachmentTypes: [
    "image/*",
    "audio/*",
    "video/*",
    "application/pdf",
    "text/plain",
    "text/csv",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ],
  inboundPerMinute: 30,
};

const TYPE_RE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$/;

export function typeAllowed(contentType: string, allowed: readonly string[]): boolean {
  const t = contentType.split(";")[0]?.trim().toLowerCase() ?? "";
  if (!TYPE_RE.test(t)) return false;
  return allowed.some((a) => (a.endsWith("/*") ? t.startsWith(a.slice(0, -1)) : t === a));
}

/** Strip control characters / path separators from an attacker-chosen file name; the name is a label, never a path. */
export function cleanName(n: string): string {
  // eslint-disable-next-line no-control-regex
  const t = n.replace(/[\u0000-\u001f\u007f‪-‮⁦-⁩/\\]/g, "_").trim();
  return (t === "" ? "attachment" : t).slice(0, 128);
}

export interface RawAttachment {
  name?: unknown;
  content_type?: unknown;
  size?: unknown;
  ref?: unknown;
}

/** Metadata-only normalisation. Anything off-type, oversized, malformed or over the count cap is dropped and counted. */
export function normalizeAttachments(
  raw: readonly RawAttachment[],
  limits: Limits,
): { kept: AttachmentMeta[]; dropped: number } {
  const kept: AttachmentMeta[] = [];
  let dropped = 0;
  for (const a of raw) {
    const ok =
      kept.length < limits.maxAttachments &&
      typeof a.content_type === "string" &&
      typeAllowed(a.content_type, limits.allowedAttachmentTypes) &&
      typeof a.size === "number" &&
      Number.isInteger(a.size) &&
      a.size >= 0 &&
      a.size <= limits.maxAttachmentBytes;
    if (!ok) {
      dropped++;
      continue;
    }
    const m: AttachmentMeta = {
      name: cleanName(typeof a.name === "string" ? a.name : ""),
      content_type: (a.content_type as string).split(";")[0]!.trim().toLowerCase(),
      size: a.size as number,
    };
    if (typeof a.ref === "string" && /^[A-Za-z0-9._:-]{1,256}$/.test(a.ref)) m.ref = a.ref;
    kept.push(m);
  }
  return { kept, dropped };
}

/** Split `text` into <= `max` character parts at paragraph / line / space boundaries. Returns undefined if more than `maxParts` are needed. */
export function splitText(text: string, max: number, maxParts = 5): string[] | undefined {
  if (max < 1) return undefined;
  const parts: string[] = [];
  let rest = text;
  while (rest.length > max) {
    const window = rest.slice(0, max);
    let cut = Math.max(
      window.lastIndexOf("\n\n"),
      window.lastIndexOf("\n"),
      window.lastIndexOf(" "),
    );
    if (cut < max / 2) cut = max;
    parts.push(rest.slice(0, cut).trimEnd());
    rest = rest.slice(cut).trimStart();
    if (parts.length >= maxParts) return undefined;
  }
  parts.push(rest);
  return parts.length > maxParts ? undefined : parts;
}
