import { describe, expect, it } from "vitest";
import { Axis, AxisWaitTimeoutError, parseEvalBlueprint } from "../src/index.js";
import { createMockServer, json, type Override } from "./mock-server.js";

const RUN = "3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f";
const run = (status: string, id = RUN) => ({ id, suite: "smoke@1.0.0", status, case_results: [] });

function client(overrides: Record<string, Override>) {
  const server = createMockServer({ overrides });
  const sleeps: number[] = [];
  const ax = new Axis({
    apiKey: "axk_test_key_123456",
    baseUrl: server.baseUrl,
    fetch: server.fetch,
    sleep: (ms) => (sleeps.push(ms), Promise.resolve()),
  });
  return { ax, server, sleeps };
}

describe("evals", () => {
  it("parses blueprint references with an optional registry namespace", () => {
    expect(parseEvalBlueprint("agent@1.0.0")).toEqual({ name: "agent", version: "1.0.0" });
    expect(parseEvalBlueprint("acme/agent@1.0.0")).toEqual({
      namespace: "acme",
      name: "agent",
      version: "1.0.0",
    });
    expect(parseEvalBlueprint({ name: "agent", version: "1" })).toEqual({
      name: "agent",
      version: "1",
    });
    expect(parseEvalBlueprint({ namespace: "acme", name: "agent", version: "1" })).toEqual({
      namespace: "acme",
      name: "agent",
      version: "1",
    });
    expect(() => parseEvalBlueprint("agent")).toThrow(/name@version/);
  });

  it("start sends the suite, the mode and the namespaced blueprint, with an idempotency key", async () => {
    const { ax, server } = client({});
    await ax.evals.start({ suite: "smoke@1.0.0", blueprint: "acme/agent@1.0.0", mode: "manual" });
    const body = server.calls[0]?.body as { suite: string; mode: string; blueprint: object };
    expect(body).toEqual({
      suite: "smoke@1.0.0",
      mode: "manual",
      blueprint: { namespace: "acme", name: "agent", version: "1.0.0" },
    });
    expect(server.calls[0]?.headers.get("idempotency-key")).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("wait polls until the run is passed, failed or errored, and times out otherwise", async () => {
    let n = 0;
    const { ax, sleeps } = client({ getEvalRun: () => json(run(++n < 3 ? "running" : "passed")) });
    expect((await ax.evals.wait(RUN, { pollIntervalMs: 50 })).status).toBe("passed");
    expect(n).toBe(3);
    expect(sleeps).toEqual([50, 50]);
    const slow = client({ getEvalRun: () => json(run("queued")) });
    await expect(slow.ax.evals.wait(RUN, { timeoutMs: 0 })).rejects.toBeInstanceOf(
      AxisWaitTimeoutError,
    );
  });

  it("iterate follows the cursor and stops at maxItems", async () => {
    const pages = [
      { items: [run("passed", "a"), run("failed", "b")], next_cursor: "c1" },
      { items: [run("errored", "c")], next_cursor: null },
    ];
    let i = 0;
    const { ax, server } = client({ listEvalRuns: () => json(pages[i++] as object) });
    const ids: string[] = [];
    for await (const r of ax.evals.iterate({ suite: "smoke@1.0.0" })) ids.push(r.id);
    expect(ids).toEqual(["a", "b", "c"]);
    expect(server.calls[1]?.url.href).toContain("cursor=c1");
    i = 0;
    const few: string[] = [];
    for await (const r of ax.evals.iterate({ maxItems: 1 })) few.push(r.id);
    expect(few).toEqual(["a"]);
  });

  it("comparison returns undefined without a baseline, and the comparison with one", async () => {
    const none = client({ getEvalRunComparison: () => json({}) });
    expect(await none.ax.evals.comparison(RUN)).toBeUndefined();
    const some = client({
      getEvalRunComparison: () =>
        json({
          comparison: {
            comparable: true,
            baseline_run_id: "b",
            tolerance: 0.02,
            regression: false,
            blocking: false,
          },
        }),
    });
    expect((await some.ax.evals.comparison(RUN))?.comparable).toBe(true);
  });

  it("gate sends the blueprint and the suites; datasets use an integer or latest", async () => {
    const { ax, server } = client({});
    await ax.evals.gate({
      blueprint: { name: "agent", version: "1", content_hash: "a".repeat(64) },
      suites: [{ ref: "s@^1.0.0", threshold: 0.9 }, { ref: "t@1.0.0" }],
    });
    expect(server.calls[0]?.body).toEqual({
      blueprint: { name: "agent", version: "1", content_hash: "a".repeat(64) },
      suites: [{ ref: "s@^1.0.0", threshold: 0.9 }, { ref: "t@1.0.0" }],
    });
    await ax.evals.datasets.get("qa");
    await ax.evals.datasets.get("qa", 3);
    expect(server.calls[1]?.url.href).toContain("/evals/datasets/qa/versions/latest");
    expect(server.calls[2]?.url.href).toContain("/evals/datasets/qa/versions/3");
    await ax.evals.runners.register("ci-1");
    expect(server.calls[3]?.body).toBeUndefined();
  });
});
