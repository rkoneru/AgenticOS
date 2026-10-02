// @vitest-environment jsdom
import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ApiError, createApi } from "@/lib/api";
import { errorText, useAction, useNow, usePaged, useResource } from "@/lib/hooks";

describe("useResource", () => {
  it("loads, reloads and reports errors", async () => {
    let n = 0;
    const { result } = renderHook(() => useResource(async () => ++n));
    expect(result.current.loading).toBe(true);
    await waitFor(() => expect(result.current.data).toBe(1));
    act(() => result.current.reload());
    await waitFor(() => expect(result.current.data).toBe(2));

    const bad = renderHook(() => useResource(async () => Promise.reject(new Error("nope"))));
    await waitFor(() => expect(bad.result.current.error?.message).toBe("nope"));
    const str = renderHook(() => useResource(async () => Promise.reject("plain")));
    await waitFor(() => expect(str.result.current.error?.message).toBe("plain"));
  });

  it("discards results after unmount and refetches on dependency change", async () => {
    const calls: number[] = [];
    const { result, rerender, unmount } = renderHook(
      ({ k }) => useResource(async () => (calls.push(k), k), [k]),
      { initialProps: { k: 1 } },
    );
    await waitFor(() => expect(result.current.data).toBe(1));
    rerender({ k: 2 });
    await waitFor(() => expect(result.current.data).toBe(2));
    unmount();
    expect(calls).toEqual([1, 2]);
  });
});

describe("useAction", () => {
  it("tracks pending/error and returns results", async () => {
    const fn = vi.fn(async (x: number) => {
      if (x < 0) throw new Error("neg");
      return x * 2;
    });
    const { result } = renderHook(() => useAction(fn));
    let r: number | undefined;
    await act(async () => {
      r = await result.current.run(2);
    });
    expect(r).toBe(4);
    await act(async () => {
      r = await result.current.run(-1);
    });
    expect(r).toBeUndefined();
    expect(result.current.error?.message).toBe("neg");
    act(() => result.current.reset());
    expect(result.current.error).toBeUndefined();
    const s = renderHook(() => useAction(async () => Promise.reject("str")));
    await act(async () => {
      await s.result.current.run();
    });
    expect(s.result.current.error?.message).toBe("str");
  });
});

describe("useNow", () => {
  it("ticks", () => {
    vi.useFakeTimers();
    const { result } = renderHook(() => useNow(1000));
    const a = result.current;
    act(() => {
      vi.advanceTimersByTime(3000);
    });
    expect(result.current).toBeGreaterThanOrEqual(a + 3000);
    vi.useRealTimers();
  });
});

describe("usePaged", () => {
  it("loads the first page then appends, with errors", async () => {
    const load = vi.fn(async (c: string | undefined) =>
      c ? { items: [3, 4], next_cursor: null } : { items: [1, 2], next_cursor: "n" },
    );
    const { result } = renderHook(() => usePaged(load));
    await waitFor(() => expect(result.current.items).toEqual([1, 2]));
    act(() => result.current.more());
    await waitFor(() => expect(result.current.items).toEqual([1, 2, 3, 4]));
    expect(result.current.cursor).toBeNull();
    act(() => result.current.more()); // no cursor: no-op
    expect(load).toHaveBeenCalledTimes(2);
    act(() => result.current.reload());
    await waitFor(() => expect(result.current.items).toEqual([1, 2]));

    const bad = renderHook(() => usePaged(async () => Promise.reject(new Error("x"))));
    await waitFor(() => expect(bad.result.current.error?.message).toBe("x"));

    let first = true;
    const flaky = renderHook(() =>
      usePaged(async () => {
        if (first) {
          first = false;
          return { items: [1], next_cursor: "n" };
        }
        throw "later";
      }),
    );
    await waitFor(() => expect(flaky.result.current.items).toEqual([1]));
    act(() => flaky.result.current.more());
    await waitFor(() => expect(flaky.result.current.error?.message).toBe("later"));
  });
});

describe("errorText", () => {
  it("never leaks beyond the problem body", () => {
    expect(errorText(new ApiError(403, { title: "Forbidden", status: 403 }, "x"))).toBe(
      "You do not have permission to do that.",
    );
    expect(errorText(new ApiError(422, { title: "Bad", status: 422, detail: "why" }, "x"))).toBe(
      "Bad: why",
    );
    expect(errorText(new ApiError(500, { title: "Boom", status: 500 }, "x"))).toBe("Boom");
    expect(errorText(new Error("plain"))).toBe("plain");
    expect(errorText(new Error(""))).toBe("Unexpected error");
  });
});

describe("validateAbl client call", () => {
  it("posts to the absolute console route with csrf", async () => {
    const f = vi.fn(
      async () => new Response(JSON.stringify({ ok: true, diagnostics: [] }), { status: 200 }),
    ) as unknown as typeof fetch & ReturnType<typeof vi.fn>;
    const api = createApi({ fetchImpl: f, csrf: () => "tok" });
    const ac = new AbortController();
    await api.validateAbl("a: 1", ac.signal);
    await api.validateAbl("a: 1");
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/abl/validate");
    expect((init.headers as Record<string, string>)["x-axis-csrf"]).toBe("tok");
    expect(JSON.parse(init.body as string)).toEqual({ text: "a: 1" });
  });
});
