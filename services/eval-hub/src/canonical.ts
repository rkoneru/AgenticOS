import { createHash } from "node:crypto";
import type { EvalCase } from "./types.js";

/**
 * Canonical JSON exactly as the runner writes it (`json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`): sorted keys,
 * no whitespace, every character outside space..~ escaped as \uXXXX (lower-case hex, UTF-16 units). Numbers use JavaScript's shortest
 * form; the runner's `canonical` prints numbers the same way (an integral float, `1.0`, is `1` on both sides; shared vectors in
 * test/fixtures/eval-canonical-vectors.json).
 */
export function canonicalAscii(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return JSON.stringify(value).replace(
        /[^ -~]/g,
        (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
      );
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) throw new TypeError("canonicalAscii: non-finite number");
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map(canonicalAscii).join(",")}]`;
      const o = value as Record<string, unknown>;
      return `{${Object.keys(o)
        .sort()
        .map((k) => `${canonicalAscii(k)}:${canonicalAscii(o[k])}`)
        .join(",")}}`;
    }
    default:
      throw new TypeError("canonicalAscii: unsupported value");
  }
}

/** The dataset version hash: SHA-256 of the canonical JSON of the cases sorted by id (`dataset_content_hash` of the runner). */
export function datasetHash(cases: readonly EvalCase[]): string {
  const ordered = [...cases]
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    .map((c) => ({
      id: c.id,
      input: c.input,
      expected: c.expected ?? null,
      tags: c.tags,
      metadata: c.metadata,
    }));
  return createHash("sha256").update(canonicalAscii(ordered), "utf8").digest("hex");
}
