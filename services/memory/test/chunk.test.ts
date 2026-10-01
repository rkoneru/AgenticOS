import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { chunkText, reassemble, MemoryError } from "../src/index.js";

const cps = (s: string): string[] => Array.from(s);

function checkInvariants(text: string, size: number, overlap: number): void {
  const chunks = chunkText(text, { size, overlap });
  const all = cps(text);
  if (all.length === 0) {
    expect(chunks).toEqual([]);
    return;
  }
  expect(chunks[0]?.start).toBe(0);
  expect(chunks.at(-1)?.end).toBe(all.length);
  chunks.forEach((c, i) => {
    expect(c.ordinal).toBe(i);
    expect(c.end).toBeGreaterThan(c.start);
    expect(c.end - c.start).toBeLessThanOrEqual(size);
    expect(c.text).toBe(all.slice(c.start, c.end).join(""));
    const next = chunks[i + 1];
    if (next) {
      expect(next.start).toBe(c.end - overlap); // exact overlap
      expect(next.start).toBeGreaterThan(c.start); // progress
      expect(next.end).toBeGreaterThan(c.end);
    }
  });
  expect(reassemble(chunks)).toBe(text); // reassembly
}

describe("chunkText", () => {
  it("property: coverage, size bound, exact overlap, progress and reassembly hold for any text", () => {
    fc.assert(
      fc.property(
        fc.oneof(
          fc.string({ unit: "grapheme-ascii", maxLength: 600 }),
          fc.string({ unit: "binary", maxLength: 300 }),
          fc.stringMatching(/^[a-z ]{0,500}$/),
        ),
        fc.integer({ min: 2, max: 120 }),
        fc.nat(),
        (text, size, o) => checkInvariants(text, size, o % (Math.floor(size / 2) + 1)),
      ),
      { numRuns: 400 },
    );
  });

  it("is deterministic", () => {
    const t = "The quick brown fox jumps over the lazy dog. ".repeat(40);
    expect(chunkText(t, { size: 90, overlap: 20 })).toEqual(
      chunkText(t, { size: 90, overlap: 20 }),
    );
  });

  it("keeps words whole when a boundary exists in the window", () => {
    const chunks = chunkText("alpha beta gamma delta epsilon", { size: 12, overlap: 0 });
    expect(chunks.map((c) => c.text)).toEqual(["alpha beta ", "gamma delta ", "epsilon"]);
  });

  it("hard-splits a long unbroken run", () => {
    const chunks = chunkText("x".repeat(25), { size: 10, overlap: 2 });
    expect(chunks.map((c) => [c.start, c.end])).toEqual([
      [0, 10],
      [8, 18],
      [16, 25],
    ]);
  });

  it("counts code points, never splitting a surrogate pair", () => {
    const t = "😀".repeat(15);
    const chunks = chunkText(t, { size: 4, overlap: 1 });
    for (const c of chunks) expect(c.text).toMatch(/^(😀)+$/u);
    expect(reassemble(chunks)).toBe(t);
  });

  it("returns no chunks for empty text and one chunk for short text", () => {
    expect(chunkText("")).toEqual([]);
    expect(chunkText("hi")).toEqual([{ ordinal: 0, start: 0, end: 2, text: "hi" }]);
  });

  it("uses defaults and rejects bad options", () => {
    expect(chunkText("a".repeat(2000)).length).toBeGreaterThan(2);
    for (const o of [
      { size: 1 },
      { size: 10, overlap: 6 },
      { size: 10, overlap: -1 },
      { size: 2.5 },
      { size: 10, overlap: 1.5 },
    ])
      expect(() => chunkText("abc", o)).toThrow(MemoryError);
  });
});
