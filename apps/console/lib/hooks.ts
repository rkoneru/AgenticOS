"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "./api";

export interface Resource<T> {
  data: T | undefined;
  error: ApiError | Error | undefined;
  loading: boolean;
  reload: () => void;
}

/** Load once on mount (and on `reload` / dependency change). Stale responses are discarded. */
export function useResource<T>(
  load: () => Promise<T>,
  deps: ReadonlyArray<unknown> = [],
): Resource<T> {
  const [state, setState] = useState<{ data?: T; error?: Error; loading: boolean }>({
    loading: true,
  });
  const [tick, setTick] = useState(0);
  const loadRef = useRef(load);
  loadRef.current = load;
  useEffect(() => {
    let live = true;
    setState((s) => ({ ...s, loading: true }));
    loadRef.current().then(
      (data) => live && setState({ data, loading: false }),
      (error: unknown) =>
        live &&
        setState({
          error: error instanceof Error ? error : new Error(String(error)),
          loading: false,
        }),
    );
    return () => {
      live = false;
    };
  }, [tick, ...deps]);
  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data: state.data, error: state.error, loading: state.loading, reload };
}

/** Run an async mutation with pending/error state. */
export function useAction<A extends unknown[], R>(
  fn: (...a: A) => Promise<R>,
): {
  run: (...a: A) => Promise<R | undefined>;
  pending: boolean;
  error: Error | undefined;
  reset: () => void;
} {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<Error | undefined>();
  const run = useCallback(
    async (...a: A) => {
      setPending(true);
      setError(undefined);
      try {
        return await fn(...a);
      } catch (e) {
        setError(e instanceof Error ? e : new Error(String(e)));
        return undefined;
      } finally {
        setPending(false);
      }
    },
    [fn],
  );
  return { run, pending, error, reset: () => setError(undefined) };
}

/** Current time, ticking every `ms`. */
export function useNow(ms = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(t);
  }, [ms]);
  return now;
}

/** Human-readable text for an error, never leaking more than the problem body gave us. */
export function errorText(e: Error): string {
  if (e instanceof ApiError) {
    if (e.status === 403) return "You do not have permission to do that.";
    return e.detail ? `${e.message}: ${e.detail}` : e.message;
  }
  return e.message || "Unexpected error";
}

/** Cursor-paginated list: first page on mount, `more()` appends the next. */
export function usePaged<T>(
  load: (cursor: string | undefined) => Promise<{ items: T[]; next_cursor?: string | null }>,
  deps: ReadonlyArray<unknown> = [],
): {
  items: T[];
  cursor: string | null | undefined;
  loading: boolean;
  loadingMore: boolean;
  error: Error | undefined;
  more: () => void;
  reload: () => void;
} {
  const [items, setItems] = useState<T[]>([]);
  const [cursor, setCursor] = useState<string | null | undefined>();
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<Error | undefined>();
  const [tick, setTick] = useState(0);
  const loadRef = useRef(load);
  loadRef.current = load;
  useEffect(() => {
    let live = true;
    setLoading(true);
    setError(undefined);
    loadRef.current(undefined).then(
      (p) => {
        if (!live) return;
        setItems(p.items);
        setCursor(p.next_cursor);
        setLoading(false);
      },
      (e: unknown) => {
        if (!live) return;
        setError(e instanceof Error ? e : new Error(String(e)));
        setLoading(false);
      },
    );
    return () => {
      live = false;
    };
  }, [tick, ...deps]);
  const more = useCallback(() => {
    if (!cursor) return;
    setLoadingMore(true);
    loadRef.current(cursor).then(
      (p) => {
        setItems((cur) => [...cur, ...p.items]);
        setCursor(p.next_cursor);
        setLoadingMore(false);
      },
      (e: unknown) => {
        setError(e instanceof Error ? e : new Error(String(e)));
        setLoadingMore(false);
      },
    );
  }, [cursor]);
  return { items, cursor, loading, loadingMore, error, more, reload: () => setTick((t) => t + 1) };
}
