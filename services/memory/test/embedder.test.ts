import { describe, expect, it } from "vitest";
import { EMBEDDING_DIMENSIONS, HashEmbedder } from "../src/index.js";

const dot = (a: number[], b: number[]): number =>
  a.reduce((s, x, i) => s + x * (b[i] as number), 0);

describe("HashEmbedder", () => {
  it("is deterministic, 1536-wide and unit length; related text is closer than unrelated", async () => {
    const e = new HashEmbedder();
    const [a, a2, related, other] = await e.embed([
      "red apples",
      "red apples",
      "apples are red fruit",
      "quantum chromodynamics",
    ]);
    expect(a).toEqual(a2);
    expect(a).toHaveLength(EMBEDDING_DIMENSIONS);
    expect(dot(a!, a!)).toBeCloseTo(1, 6);
    expect(dot(a!, related!)).toBeGreaterThan(dot(a!, other!));
  });
  it("gives token-less text a fixed unit vector (never a zero vector)", async () => {
    const [v] = await new HashEmbedder().embed(["!!! ???"]);
    expect(v?.[0]).toBe(1);
  });
});
