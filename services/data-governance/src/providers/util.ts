import type { Identifier, IdentifierKind } from "../types.js";

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const onlyUuids = (xs: readonly string[]): string[] => xs.filter((x) => UUID_RE.test(x));

/** Values of the given kinds. Personal identifiers are matched as exact values, never by LIKE, so a short value cannot widen the match. */
export const vals = (ids: readonly Identifier[], ...kinds: IdentifierKind[]): string[] =>
  ids.filter((i) => kinds.includes(i.kind)).map((i) => i.value);

/** Every value that can name a subject in a free `subject` / `owner` / `author` slot. */
export const SUBJECT_KINDS: IdentifierKind[] = [
  "subject_key",
  "end_user_id",
  "user_ref",
  "email",
  "phone",
];

export const iso = (d: unknown): string | null =>
  d instanceof Date ? d.toISOString() : d === null || d === undefined ? null : String(d);
