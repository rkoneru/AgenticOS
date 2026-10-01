import { createHash } from "node:crypto";
import type { Embedder } from "./types.js";

export const EMBEDDING_DIMENSIONS = 1536;

function tokens(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^\p{L}\p{N}]+/u)
    .filter((t) => t !== "");
}

/**
 * Deterministic, offline embedder for tests and local dev: a hashed bag of words (feature hashing with a sign bit),
 * L2-normalised. Texts sharing words get a high cosine similarity, identical texts get 1, unrelated texts about 0.
 * It carries no semantics beyond word overlap: it is a test double, not a retrieval-quality model.
 */
export class HashEmbedder implements Embedder {
  readonly id = "hash-bow-v1";
  readonly dimensions = EMBEDDING_DIMENSIONS;

  embed(texts: readonly string[]): Promise<number[][]> {
    return Promise.resolve(texts.map((t) => this.one(t)));
  }

  private one(text: string): number[] {
    const v = new Array<number>(this.dimensions).fill(0);
    for (const tok of tokens(text)) {
      const h = createHash("sha256").update(tok, "utf8").digest();
      const idx = h.readUInt32BE(0) % this.dimensions;
      v[idx] = (v[idx] as number) + ((h[4] as number) & 1 ? 1 : -1);
    }
    const norm = Math.sqrt(v.reduce((s, x) => s + x * x, 0));
    if (norm === 0) {
      v[0] = 1; // empty / token-less text: a fixed unit vector so the column never holds a zero vector (cosine undefined)
      return v;
    }
    return v.map((x) => x / norm);
  }
}

/** pgvector text literal. */
export function vectorLiteral(v: readonly number[]): string {
  return `[${v.join(",")}]`;
}
