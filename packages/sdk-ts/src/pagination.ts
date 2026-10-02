export interface Page<T> {
  items: T[];
  next_cursor?: string | null | undefined;
}

/** Follow `next_cursor` until the server stops returning one (or `maxItems` is reached). */
export async function* paginate<T>(
  fetchPage: (cursor: string | undefined) => Promise<Page<T>>,
  maxItems = Number.POSITIVE_INFINITY,
): AsyncGenerator<T> {
  let cursor: string | undefined;
  let n = 0;
  for (;;) {
    const page = await fetchPage(cursor);
    for (const item of page.items) {
      if (n++ >= maxItems) return;
      yield item;
    }
    if (!page.next_cursor || (page.items.length === 0 && page.next_cursor === cursor)) return;
    cursor = page.next_cursor;
  }
}

export async function collect<T>(it: AsyncIterable<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const x of it) out.push(x);
  return out;
}
