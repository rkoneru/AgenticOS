import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { canonicalAscii } from "../src/canonical.js";

const vectors = (
  JSON.parse(
    readFileSync(new URL("./fixtures/eval-canonical-vectors.json", import.meta.url), "utf8"),
  ) as { vectors: { json: string; canonical: string }[] }
).vectors;

describe("canonical JSON parity with the runner (shared vectors)", () => {
  it.each(vectors.map((v) => [v.json.slice(0, 30), v] as const))("%s", (_n, v) => {
    expect(canonicalAscii(JSON.parse(v.json))).toBe(v.canonical);
  });
});
