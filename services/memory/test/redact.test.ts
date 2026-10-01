import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { argsPaths, MemoryError, redactForPhi, redactPaths, scrubText } from "../src/index.js";

const vectors = JSON.parse(
  readFileSync(new URL("./redaction-vectors.json", import.meta.url), "utf8"),
);

describe("redactPaths (parity with runtime redaction.py)", () => {
  for (const v of vectors.vectors)
    it(v.name, () => {
      const before = structuredClone(v.doc);
      expect(redactPaths(v.doc, v.paths)).toEqual(v.expected);
      expect(v.doc).toEqual(before); // input untouched
    });
  it("rejects malformed paths before touching anything", () => {
    for (const p of vectors.malformed)
      expect(() => redactPaths({ a: 1 }, [p])).toThrow(MemoryError);
    expect(() => redactPaths({ a: 1 }, ["a", "b..c"])).toThrow(MemoryError);
  });
});

describe("PHI helpers", () => {
  it("argsPaths mirrors split_scope for args", () => {
    expect(argsPaths(["args", "args.a", "result.b", "result", "c"])).toEqual(["*", "a", "c"]);
  });
  it("scrubText replaces SSN, email, phone and labelled MRN", () => {
    expect(scrubText("a 123-45-6789 b x@y.io c (555) 123-4567 d MRN#1234567 e")).toBe(
      "a [REDACTED] b [REDACTED] c [REDACTED] d [REDACTED] e",
    );
    expect(scrubText("order 12345 total 99.50")).toBe("order 12345 total 99.50");
  });
  it("redactForPhi handles nested metadata arrays and keeps non-sensitive values", () => {
    const out = redactForPhi({
      content: "hi bob@x.io",
      metadata: { list: ["call 555-123-4567", 3, null, true], n: { k: "ok" }, phi: { a: 1 } },
    });
    expect(out).toEqual({
      content: "hi [REDACTED]",
      metadata: { list: ["call [REDACTED]", 3, null, true], n: { k: "ok" }, phi: "[REDACTED]" },
    });
  });
});
