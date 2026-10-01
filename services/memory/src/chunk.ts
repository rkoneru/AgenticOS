import { MemoryError } from "./types.js";

export interface ChunkOptions {
  /** Maximum chunk length in code points. Default 800. */
  size?: number;
  /** Code points shared by consecutive chunks. Default 100. Must be <= floor(size / 2). */
  overlap?: number;
}

/** `[start, end)` are code point offsets into the source: `Array.from(text).slice(start, end).join("") === text`. */
export interface Chunk {
  ordinal: number;
  start: number;
  end: number;
  text: string;
}

const isSpace = (c: string): boolean => /\s/u.test(c);

/**
 * Deterministic chunking. Invariants (property-tested):
 * - chunk 0 starts at 0 and the last chunk ends at the end of the text (the chunks cover every code point);
 * - every chunk is non-empty, at most `size` long, and equals the source slice at its offsets;
 * - chunk i+1 starts exactly `overlap` code points before chunk i ends (so consecutive chunks overlap by `overlap`);
 * - starts and ends strictly increase, so the process terminates.
 * A chunk end prefers the last whitespace boundary in the second half of the window, so words are kept whole when possible.
 */
export function chunkText(text: string, opts: ChunkOptions = {}): Chunk[] {
  const size = opts.size ?? 800;
  const overlap = opts.overlap ?? 100;
  if (!Number.isInteger(size) || size < 2)
    throw new MemoryError("INVALID", "chunk size must be an integer >= 2");
  if (!Number.isInteger(overlap) || overlap < 0 || overlap > Math.floor(size / 2))
    throw new MemoryError("INVALID", "chunk overlap must be an integer in [0, size/2]");
  const cps = Array.from(text);
  const n = cps.length;
  const out: Chunk[] = [];
  let start = 0;
  while (n > 0) {
    let end = Math.min(start + size, n);
    if (end < n) {
      // Snap back to a word boundary, but keep the chunk longer than `overlap` so the next start is > this start.
      const floor = start + Math.floor(size / 2) + 1;
      for (let i = end; i >= floor; i--) {
        if (isSpace(cps[i - 1] as string)) {
          end = i;
          break;
        }
      }
    }
    out.push({ ordinal: out.length, start, end, text: cps.slice(start, end).join("") });
    if (end >= n) break;
    start = end - overlap;
  }
  return out;
}

/** Inverse of `chunkText`: rebuild the source from chunks (drops the overlap). */
export function reassemble(chunks: readonly Chunk[]): string {
  let out = "";
  let covered = 0;
  for (const c of chunks) {
    const cps = Array.from(c.text);
    out += cps.slice(covered - c.start).join("");
    covered = c.end;
  }
  return out;
}
