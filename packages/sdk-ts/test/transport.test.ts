import { describe, expect, it } from "vitest";
import {
  Axis,
  AxisAbortError,
  AxisConnectionError,
  AxisTimeoutError,
  HttpTransport,
  normalizeBaseUrl,
  OPERATIONS,
  PolicyDeniedError,
  RateLimitError,
  AuthenticationError,
  type RequestOptions,
} from "../src/index.js";
import { createMockServer, json, problem, rejected } from "./mock-server.js";

const RUN = "3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f";
const KEY = "axk_test_key_123456";
const BASE = "https://api.test.axis.example/v1";

function setup(
  over: Parameters<typeof createMockServer>[0] = {},
  opts: Partial<ConstructorParameters<typeof Axis>[0]> = {},
) {
  const server = createMockServer(over);
  const sleeps: number[] = [];
  const ax = new Axis({
    apiKey: KEY,
    baseUrl: server.baseUrl,
    fetch: server.fetch,
    sleep: (ms) => (sleeps.push(ms), Promise.resolve()),
    random: () => 0.5,
    ...opts,
  });
  return { server, ax, sleeps };
}
const startArgs = { blueprint: "agent-one@1.0.0" } as const;

describe("retries", () => {
  it("retries idempotent GETs on 503 with exponential, jittered backoff", async () => {
    const { ax, server, sleeps } = setup({
      overrides: { getRun: (_c, n) => (n < 3 ? problem(503, "internal") : undefined) },
    });
    await ax.runs.get(RUN);
    expect(server.calls).toHaveLength(3);
    expect(sleeps).toEqual([250, 500]); // random 0.5 * (500 * 2^attempt)
  });
  it("gives up after maxRetries and throws the typed error", async () => {
    const { ax, server } = setup(
      { overrides: { getRun: () => problem(503, "internal") } },
      { maxRetries: 1 },
    );
    await expect(ax.runs.get(RUN)).rejects.toMatchObject({ status: 503 });
    expect(server.calls).toHaveLength(2);
  });
  it("honours Retry-After on 429", async () => {
    const { ax, sleeps } = setup({
      overrides: {
        getRun: (_c, n) =>
          n === 1 ? problem(429, "rate_limited", {}, { "retry-after": "3" }) : undefined,
      },
    });
    await ax.runs.get(RUN);
    expect(sleeps).toEqual([3000]);
  });
  it("surfaces RateLimitError with retryAfterSeconds when retries are exhausted", async () => {
    const { ax } = setup(
      { overrides: { getRun: () => problem(429, "rate_limited", {}, { "retry-after": "9" }) } },
      { maxRetries: 0 },
    );
    const e = await rejected<RateLimitError>(ax.runs.get(RUN));
    expect(e).toBeInstanceOf(RateLimitError);
    expect(e.retryAfterSeconds).toBe(9);
  });
  it("does NOT retry a POST without an Idempotency-Key capability (publishPolicyPack)", async () => {
    const { ax, server } = setup({
      overrides: { publishPolicyPack: () => problem(503, "internal") },
    });
    await expect(ax.policies.publish({})).rejects.toMatchObject({ status: 503 });
    expect(server.calls).toHaveLength(1);
  });
  it("does NOT retry non-idempotent POST on network error", async () => {
    let n = 0;
    const ax = new Axis({
      apiKey: KEY,
      baseUrl: BASE,
      fetch: () => (n++, Promise.reject(new Error("reset"))),
      sleep: () => Promise.resolve(),
    });
    await expect(ax.policies.publish({})).rejects.toBeInstanceOf(AxisConnectionError);
    expect(n).toBe(1);
  });
  it("retries a keyed POST and reuses ONE Idempotency-Key across attempts", async () => {
    const { ax, server } = setup({
      overrides: { startRun: (_c, n) => (n < 3 ? problem(502, "internal") : undefined) },
    });
    await ax.runs.start(startArgs);
    expect(server.calls).toHaveLength(3);
    const keys = new Set(server.calls.map((c) => c.headers.get("idempotency-key")));
    expect(keys.size).toBe(1);
    expect([...keys][0]).toBeTruthy();
  });
  it("uses a different generated key per logical call", async () => {
    const { ax, server } = setup();
    await ax.runs.start(startArgs);
    await ax.runs.start(startArgs);
    expect(server.calls[0]?.headers.get("idempotency-key")).not.toBe(
      server.calls[1]?.headers.get("idempotency-key"),
    );
  });
  it("retries read-only POSTs (testPolicy, verifyAuditChain) and PUT (setKillSwitch)", async () => {
    const a = setup({
      overrides: { testPolicy: (_c, n) => (n < 2 ? problem(503, "internal") : undefined) },
    });
    await a.ax.policies.test({}, { enforcement_point: "tool_call", context: {} });
    expect(a.server.calls).toHaveLength(2);
    const b = setup({
      overrides: { setKillSwitch: (_c, n) => (n < 2 ? problem(503, "internal") : undefined) },
    });
    await b.ax.killSwitches.engage("tenant");
    expect(b.server.calls).toHaveLength(2);
  });
  it("never retries 4xx like 403 policy_denied or 401", async () => {
    const { ax, server } = setup({ overrides: { getRun: () => problem(403, "policy_denied") } });
    await expect(ax.runs.get(RUN)).rejects.toBeInstanceOf(PolicyDeniedError);
    expect(server.calls).toHaveLength(1);
  });
  it("retries network errors for idempotent calls", async () => {
    let n = 0;
    const server = createMockServer();
    const ax = new Axis({
      apiKey: KEY,
      baseUrl: server.baseUrl,
      sleep: () => Promise.resolve(),
      fetch: (i, o) =>
        ++n < 2 ? Promise.reject(new TypeError("fetch failed")) : server.fetch(i, o),
    });
    await ax.runs.get(RUN);
    expect(n).toBe(2);
  });
  it("per-call maxRetries override", async () => {
    const { ax, server } = setup({ overrides: { getRun: () => problem(503, "internal") } });
    await expect(ax.runs.get(RUN, { maxRetries: 0 })).rejects.toBeDefined();
    expect(server.calls).toHaveLength(1);
  });
});

describe("timeouts, aborts, ids", () => {
  it("times out with AxisTimeoutError", async () => {
    const ax = new Axis({
      apiKey: KEY,
      baseUrl: BASE,
      timeoutMs: 20,
      maxRetries: 0,
      fetch: (_i, o) =>
        new Promise((_r, rej) =>
          o?.signal?.addEventListener("abort", () => rej(new Error("aborted"))),
        ),
    });
    await expect(ax.runs.get(RUN)).rejects.toBeInstanceOf(AxisTimeoutError);
  });
  it("caller abort wins and is not retried", async () => {
    const ctl = new AbortController();
    let n = 0;
    const ax = new Axis({
      apiKey: KEY,
      baseUrl: BASE,
      fetch: (_i, o) => (
        n++,
        new Promise((_r, rej) => o?.signal?.addEventListener("abort", () => rej(new Error("x"))))
      ),
    });
    const p = ax.runs.get(RUN, { signal: ctl.signal });
    ctl.abort();
    await expect(p).rejects.toBeInstanceOf(AxisAbortError);
    expect(n).toBe(1);
  });
  it("surfaces request id and trace id on errors and via onResponse", async () => {
    const metas: unknown[] = [];
    const { ax } = setup(
      {
        overrides: {
          getRun: () =>
            problem(404, "not_found", { trace_id: "a".repeat(32) }, { "x-request-id": "req-9" }),
        },
      },
      { onResponse: (m) => metas.push(m) },
    );
    const e = await rejected<AuthenticationError>(ax.runs.get(RUN));
    expect(e.requestId).toBe("req-9");
    expect(e.traceId).toBe("a".repeat(32));
    expect(metas).toHaveLength(1);
    expect(metas[0]).toMatchObject({
      operationId: "getRun",
      status: 404,
      requestId: "req-9",
      attempts: 1,
    });
  });
  it("reads the trace id from traceparent and x-trace-id on success", async () => {
    const seen: Array<string | undefined> = [];
    const { ax } = setup(
      {
        overrides: {
          getRun: (_c, n) =>
            json(
              {
                id: RUN,
                blueprint: { name: "a", version: "1" },
                state: "running",
                created_at: "2026-01-01T00:00:00Z",
              },
              200,
              n === 1
                ? { traceparent: `00-${"c".repeat(32)}-${"d".repeat(16)}-01` }
                : { "x-trace-id": "tt" },
            ),
        },
      },
      { onResponse: (m) => seen.push(m.traceId) },
    );
    await ax.runs.get(RUN);
    await ax.runs.get(RUN);
    expect(seen).toEqual(["c".repeat(32), "tt"]);
  });
  it("reports attempts when retried", async () => {
    const attempts: number[] = [];
    const { ax } = setup(
      { overrides: { getRun: (_c, n) => (n < 2 ? problem(503, "internal") : undefined) } },
      { onResponse: (m) => attempts.push(m.attempts) },
    );
    await ax.runs.get(RUN);
    expect(attempts).toEqual([2]);
  });
  it("non-JSON success bodies and 204s", async () => {
    const t = new HttpTransport({
      baseUrl: BASE,
      apiKey: KEY,
      fetch: () => Promise.resolve(new Response("<html>", { status: 200 })),
    });
    await expect(t.call(OPERATIONS.getRun, { runId: RUN })).rejects.toThrow(/not valid JSON/);
    const t2 = new HttpTransport({
      baseUrl: BASE,
      apiKey: KEY,
      fetch: () => Promise.resolve(new Response(null, { status: 204 })),
    });
    await expect(t2.call(OPERATIONS.getRun, { runId: RUN })).resolves.toBeUndefined();
  });
  it("non-JSON error bodies still map by status", async () => {
    const t = new HttpTransport({
      baseUrl: BASE,
      apiKey: KEY,
      maxRetries: 0,
      fetch: () => Promise.resolve(new Response("gateway down", { status: 502 })),
    });
    await expect(t.call(OPERATIONS.getRun, { runId: RUN })).rejects.toMatchObject({ status: 502 });
  });
  it("opt-in validators run (off by default)", async () => {
    const seen: string[] = [];
    const { ax } = setup(
      {},
      {
        validateRequest: (op) => void seen.push(`req:${op.id}`),
        validateResponse: (op) => void seen.push(`res:${op.id}`),
      },
    );
    await ax.runs.start(startArgs);
    expect(seen).toEqual(["req:startRun", "res:startRun"]);
    const { ax: ax2, server } = setup();
    await ax2.runs.start(startArgs);
    expect(server.calls).toHaveLength(1);
  });
});

describe("credential safety", () => {
  it("sends the API key header only to the configured origin and never in the URL", async () => {
    const { ax, server } = setup();
    await ax.runs.get(RUN);
    const c = server.calls[0]!;
    expect(c.headers.get("x-axis-api-key")).toBe(KEY);
    expect(c.headers.get("authorization")).toBeNull();
    expect(c.url.origin).toBe("https://api.test.axis.example");
    expect(c.url.href).not.toContain(KEY);
  });
  it("uses Authorization: Bearer for tokens and not the api key header", async () => {
    const server = createMockServer();
    const ax = new Axis({ token: "tok_abc_123456", baseUrl: server.baseUrl, fetch: server.fetch });
    await ax.runs.get(RUN);
    expect(server.calls[0]?.headers.get("authorization")).toBe("Bearer tok_abc_123456");
    expect(server.calls[0]?.headers.get("x-axis-api-key")).toBeNull();
  });
  it("when both a key and a token are given only the API key header is sent", async () => {
    const server = createMockServer();
    const ax = new Axis({
      apiKey: KEY,
      token: "tok_abc_123456",
      baseUrl: server.baseUrl,
      fetch: server.fetch,
    });
    await ax.runs.get(RUN);
    expect(server.calls[0]?.headers.get("authorization")).toBeNull();
    expect(server.calls[0]?.headers.get("x-axis-api-key")).toBe(KEY);
  });
  it("REFUSES to follow a redirect to another origin (no credential leak)", async () => {
    const seen: string[] = [];
    const ax = new Axis({
      apiKey: KEY,
      baseUrl: BASE,
      maxRetries: 0,
      fetch: (i, o) => {
        const url = String(i);
        seen.push(`${url}|${new Headers(o?.headers).get("x-axis-api-key") ?? ""}`);
        return Promise.resolve(
          url.startsWith(BASE)
            ? new Response(null, {
                status: 307,
                headers: { location: "https://evil.example/steal" },
              })
            : json({}),
        );
      },
    });
    await expect(ax.runs.get(RUN)).rejects.toThrow(/another origin/);
    expect(seen).toHaveLength(1);
    expect(seen.some((s) => s.startsWith("https://evil.example"))).toBe(false);
  });
  it("refuses a downgrade redirect from https to http on the same host", async () => {
    const ax = new Axis({
      apiKey: KEY,
      baseUrl: BASE,
      maxRetries: 0,
      fetch: () =>
        Promise.resolve(
          new Response(null, {
            status: 302,
            headers: { location: `http://api.test.axis.example/v1/x` },
          }),
        ),
    });
    await expect(ax.runs.get(RUN)).rejects.toThrow(/another origin/);
  });
  it("follows a same-origin redirect, converting POST to GET on 303, and caps hops", async () => {
    const seen: string[] = [];
    const ax = new Axis({
      apiKey: KEY,
      baseUrl: BASE,
      maxRetries: 0,
      fetch: (i, o) => {
        seen.push(`${o?.method} ${new URL(String(i)).pathname}`);
        if (String(i).endsWith("/runs"))
          return Promise.resolve(
            new Response(null, { status: 303, headers: { location: `${BASE}/runs/${RUN}` } }),
          );
        return Promise.resolve(
          json({
            id: RUN,
            blueprint: { name: "a", version: "1" },
            state: "ready",
            created_at: "x",
          }),
        );
      },
    });
    await ax.runs.start(startArgs);
    expect(seen).toEqual(["POST /v1/runs", `GET /v1/runs/${RUN}`]);
    const loop = new Axis({
      apiKey: KEY,
      baseUrl: BASE,
      maxRetries: 0,
      fetch: () =>
        Promise.resolve(new Response(null, { status: 307, headers: { location: `${BASE}/runs` } })),
    });
    await expect(loop.runs.get(RUN)).rejects.toThrow(/too many redirects/);
    const noLoc = new Axis({
      apiKey: KEY,
      baseUrl: BASE,
      maxRetries: 0,
      fetch: () => Promise.resolve(new Response(null, { status: 307 })),
    });
    await expect(noLoc.runs.get(RUN)).rejects.toBeDefined();
  });
  it("never takes the tenant from arguments or headers", async () => {
    for (const k of ["tenant", "tenantId", "tenant_id"]) {
      expect(() => new Axis({ apiKey: KEY, baseUrl: BASE, [k]: "t-1" } as never)).toThrow(
        /derived from the credential/,
      );
    }
    const { ax } = setup();
    for (const h of [
      "X-Axis-Tenant",
      "x-axis-tenant-id",
      "X-Tenant-Id",
      "Authorization",
      "x-axis-api-key",
      "Cookie",
      "Host",
    ]) {
      await expect(
        ax.runs.get(RUN, { headers: { [h]: "evil" } } as RequestOptions),
      ).rejects.toThrow(/may not be set/);
    }
    await ax.runs.get(RUN, { headers: { "x-custom": "ok" } });
  });
  it("requires https (loopback may use http) and rejects credentials or queries in the base URL", () => {
    expect(() => normalizeBaseUrl("http://api.example.com/v1")).toThrow(/https/);
    expect(normalizeBaseUrl("http://localhost:8080/v1").href).toBe("http://localhost:8080/v1/");
    expect(normalizeBaseUrl("http://127.0.0.1:1").protocol).toBe("http:");
    expect(normalizeBaseUrl("http://api.example.com/v1", true).protocol).toBe("http:");
    expect(() => normalizeBaseUrl("https://u:p@api.example.com")).toThrow(/credentials/);
    expect(() => normalizeBaseUrl("https://api.example.com?x=1")).toThrow(/query/);
    expect(() => normalizeBaseUrl("not a url")).toThrow(/invalid base URL/);
  });
  it("requires a credential; picks env defaults", () => {
    const saved = { k: process.env["AXIS_API_KEY"], b: process.env["AXIS_BASE_URL"] };
    delete process.env["AXIS_API_KEY"];
    expect(() => new Axis({ baseUrl: BASE })).toThrow(/API key is required/);
    process.env["AXIS_API_KEY"] = "axk_env_123456";
    process.env["AXIS_BASE_URL"] = "https://env.example/v1";
    expect(new Axis().baseUrl).toBe("https://env.example/v1");
    delete process.env["AXIS_BASE_URL"];
    expect(new Axis().baseUrl).toContain("axis.example");
    if (saved.k === undefined) delete process.env["AXIS_API_KEY"];
    else process.env["AXIS_API_KEY"] = saved.k;
    if (saved.b !== undefined) process.env["AXIS_BASE_URL"] = saved.b;
  });
  it("401 maps to AuthenticationError", async () => {
    const server = createMockServer({ apiKey: "other" });
    const ax = new Axis({ apiKey: KEY, baseUrl: server.baseUrl, fetch: server.fetch });
    await expect(ax.runs.get(RUN)).rejects.toBeInstanceOf(AuthenticationError);
  });
  it("path parameters are required and URL-encoded", async () => {
    const { ax, server } = setup();
    await expect(ax.api.getRun({} as never)).rejects.toThrow(/missing path parameter/);
    await ax.blueprints.get("a b/c", "1.0.0").catch(() => undefined);
    expect(server.calls[0]?.url.pathname).toContain("a%20b%2Fc");
    await expect(ax.api.startRun({} as never)).rejects.toThrow(/body is required/);
  });
  it("a path parameter that is a dot segment is refused: '..' must not climb out of its route (URL parsers resolve it even when encoded)", async () => {
    const { ax, server } = setup();
    for (const bad of ["..", "."]) {
      await expect(ax.runs.get(bad)).rejects.toThrow(/dot segment|path parameter/);
      await expect(ax.blueprints.get("agent-one", bad)).rejects.toThrow(
        /dot segment|path parameter/,
      );
    }
    // never sent: not even to a route the caller did not name
    expect(server.calls).toHaveLength(0);
    // ordinary values that merely contain dots are still fine
    await ax.blueprints.get("a.b", "1.0.0..2").catch(() => undefined);
    expect(server.calls[0]?.url.pathname).toContain("a.b");
  });
});
