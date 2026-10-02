import http from "node:http";
import { MemoryAuditLog } from "@axis/audit";
import { afterEach, describe, expect, it } from "vitest";
import {
  AdjustmentApi,
  BillingService,
  DEV_PLAN,
  DEV_PRICE_BOOK,
  FakePaymentProvider,
  MemoryInvoiceStore,
  createDevServer,
  listenLoopback,
  staticTokenAuthenticator,
  type RunEventLite,
} from "../src/index.js";
import { Clock, memLedger } from "./helpers.js";

const T1 = "11111111-1111-4111-8111-111111111111";
const T2 = "22222222-2222-4222-8222-222222222222";
const READ1 = "tok-read-1";
const READ2 = "tok-read-2";
const INGEST1 = "tok-ingest-1";
const ADMIN1 = "tok-admin-1";

let server: http.Server | undefined;
afterEach(async () => {
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  server = undefined;
});

async function start() {
  const clock = new Clock(new Date("2026-10-02T00:00:00Z"));
  const ledger = memLedger(clock);
  const invoices = new MemoryInvoiceStore();
  const audit = new MemoryAuditLog();
  server = createDevServer({
    ledger,
    invoices,
    adjustments: new AdjustmentApi({ ledger, audit, now: clock.now }),
    authenticate: staticTokenAuthenticator({
      [READ1]: { tenantId: T1, scopes: ["read"], subject: "tenant1" },
      [READ2]: { tenantId: T2, scopes: ["read"], subject: "tenant2" },
      [INGEST1]: { tenantId: T1, scopes: ["ingest"], subject: "runtime" },
      [ADMIN1]: { tenantId: T1, scopes: ["read", "admin"], subject: "ops@axis.test" },
    }),
    classifyRules: DEV_PRICE_BOOK.modelClasses,
  });
  const port = await listenLoopback(server);
  return { port, clock, ledger, invoices, audit };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- test helper returns loosely typed JSON
const call = (
  port: number,
  method: string,
  path: string,
  token?: string,
  body?: unknown,
): Promise<{ status: number; json: any }> =>
  new Promise((resolve, reject) => {
    const text =
      body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body);
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method,
        path,
        headers: token ? { authorization: `Bearer ${token}` } : {},
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            json: JSON.parse(Buffer.concat(chunks).toString("utf8") || "null"),
          }),
        );
      },
    );
    req.on("error", reject);
    if (text) req.write(text);
    req.end();
  });

let seq = 0;
const ev = (type: string, data: Record<string, unknown>, tenant = T1): RunEventLite => ({
  run_id: "run-1",
  seq: seq++,
  ts: "2026-09-10T12:00:00Z",
  type,
  pid: "p1",
  data: type === "run_started" ? { tenant_id: tenant, ...data } : data,
});
const runLog = (tenant = T1) => {
  seq = 0;
  return [
    ev("run_started", {}, tenant),
    ev("process_spawned", { agent: "support" }),
    ev("gate_decision", { action_id: "a1", decision: "ALLOW" }),
    ev("model_call", {
      action_id: "a1",
      provider: "anthropic",
      model: "claude-opus-4",
      input_tokens: 1000,
      output_tokens: 10,
      cached_tokens: 0,
    }),
    ev("gate_decision", { action_id: "a2", decision: "DENY" }),
    ev("tool_call_result", { action_id: "a2", enforcement_point: "tool_call", ok: true }),
  ];
};

describe("dev server", () => {
  it("authenticates, routes and rejects unknown paths", async () => {
    const { port } = await start();
    expect((await call(port, "GET", "/v1/usage/periods")).status).toBe(401);
    expect((await call(port, "GET", "/v1/usage/periods", "wrong")).status).toBe(401);
    expect((await call(port, "GET", "/v1/usage/periods", READ1)).json).toEqual({ periods: [] });
    expect((await call(port, "GET", "/v1/other", READ1)).status).toBe(404);
    expect((await call(port, "DELETE", "/v1/usage/periods", READ1)).status).toBe(404);
    expect((await call(port, "POST", "/v1/usage/periods", READ1, {})).status).toBe(404);
    expect((await call(port, "GET", "/v1/usage/nope", READ1)).status).toBe(404);
  });

  it("ingests run events: bills the allowed call only, is idempotent, and refuses another tenant's run", async () => {
    const { port, ledger } = await start();
    const r1 = await call(port, "POST", "/v1/usage/run-events", INGEST1, {
      run_id: "run-1",
      events: runLog(),
    });
    expect(r1.json).toMatchObject({ records: 2, inserted: 2, duplicates: 0, conflicts: 0 });
    expect(r1.json.skipped).toEqual([
      { seq: 5, type: "tool_call_result", reason: "no ALLOW decision for this action" },
    ]);
    const r2 = await call(port, "POST", "/v1/usage/run-events", INGEST1, {
      run_id: "run-1",
      events: runLog(),
    });
    expect(r2.json).toMatchObject({ inserted: 0, duplicates: 2 });
    const e = await ledger.entries(T1);
    expect(e.map((x) => [x.meter, x.quantity, x.dimensions["model_class"]])).toEqual([
      ["tokens_in", 1000n, "frontier"],
      ["tokens_out", 10n, "frontier"],
    ]);
    // a run that claims another tenant, and a body naming another tenant, are refused
    const bad = await call(port, "POST", "/v1/usage/run-events", INGEST1, {
      run_id: "run-1",
      events: runLog(T2),
    });
    expect(bad.status).toBe(403);
    expect(
      (
        await call(port, "POST", "/v1/usage/run-events", INGEST1, {
          tenant_id: T2,
          run_id: "run-1",
          events: runLog(),
        })
      ).status,
    ).toBe(403);
    expect(await ledger.entries(T2)).toEqual([]);
    // a conflicting replay (same run seq, different quantity) is reported, not applied
    const forged = runLog();
    (forged[3] as { data: Record<string, unknown> }).data["output_tokens"] = 999_999;
    expect(
      (
        await call(port, "POST", "/v1/usage/run-events", INGEST1, {
          run_id: "run-1",
          events: forged,
        })
      ).json,
    ).toMatchObject({ conflicts: 1 });
    expect((await ledger.entries(T1)).find((x) => x.meter === "tokens_out")?.quantity).toBe(10n);
  });

  it("requires the right scope: a read token cannot ingest or adjust, an ingest token cannot read", async () => {
    const { port } = await start();
    expect(
      (await call(port, "POST", "/v1/usage/run-events", READ1, { run_id: "r", events: [{}] }))
        .status,
    ).toBe(403);
    expect((await call(port, "POST", "/v1/usage/adjustments", READ1, {})).status).toBe(403);
    expect((await call(port, "POST", "/v1/usage/adjustments", INGEST1, {})).status).toBe(403);
    expect((await call(port, "GET", "/v1/usage/periods", INGEST1)).status).toBe(403);
  });

  it("validates run-event bodies", async () => {
    const { port } = await start();
    const post = (b: unknown) => call(port, "POST", "/v1/usage/run-events", INGEST1, b);
    expect((await post({ run_id: "r", events: [] })).status).toBe(400);
    expect((await post({ events: [{}] })).status).toBe(400);
    expect(
      (
        await post({
          run_id: "r",
          events: [{ run_id: "other", seq: 0, type: "x", ts: "t", data: {} }],
        })
      ).status,
    ).toBe(400);
    expect((await post({ run_id: "r", events: [null] })).status).toBe(400);
    expect((await post("{")).status).toBe(400);
    expect((await post("[]")).status).toBe(400);
    expect(
      (
        await post({
          run_id: "r",
          events: [
            { run_id: "r", seq: 0, type: "model_call", ts: "2026-09-10T00:00:00Z", data: {} },
          ],
        })
      ).status,
    ).toBe(400); // no run_started
    const big = await call(
      port,
      "POST",
      "/v1/usage/run-events",
      INGEST1,
      JSON.stringify({ pad: "x".repeat(4_100_000) }),
    );
    expect(big.status).toBe(400);
  });

  it("serves a tenant-scoped, read-only statement, rollup and entries", async () => {
    const { port, ledger, invoices } = await start();
    await call(port, "POST", "/v1/usage/run-events", INGEST1, {
      run_id: "run-1",
      events: runLog(),
    });
    const st = await call(port, "GET", "/v1/usage/statement?period=2026-09", READ1);
    expect(st.json).toMatchObject({
      period: "2026-09",
      sealed: false,
      invoice: null,
      totals: [
        { meter: "tokens_in", dimension: "frontier", quantity: "1000" },
        { meter: "tokens_out", dimension: "frontier", quantity: "10" },
      ],
    });
    expect(
      (await call(port, "GET", "/v1/usage/statement?period=2026-09", READ2)).json.totals,
    ).toEqual([]);
    expect(
      (await call(port, "GET", `/v1/usage/statement?period=2026-09&tenant_id=${T2}`, READ1)).status,
    ).toBe(403);
    expect((await call(port, "GET", "/v1/usage/statement?period=bad", READ1)).status).toBe(400);
    expect((await call(port, "GET", "/v1/usage/statement", READ1)).status).toBe(400);
    const roll = await call(
      port,
      "GET",
      "/v1/usage/rollup?granularity=day&from=2026-09-01T00:00:00Z&to=2026-10-01T00:00:00Z&meter=tokens_in",
      READ1,
    );
    expect(roll.json.rows).toEqual([
      { bucket: "2026-09-10T00:00:00.000Z", meter: "tokens_in", quantity: "1000" },
    ]);
    expect(
      (
        await call(
          port,
          "GET",
          "/v1/usage/rollup?from=2026-09-01T00:00:00Z&to=2026-10-01T00:00:00Z",
          READ1,
        )
      ).json.rows,
    ).toHaveLength(2); // default day
    expect(
      (
        await call(
          port,
          "GET",
          "/v1/usage/rollup?granularity=week&from=2026-09-01T00:00:00Z&to=2026-10-01T00:00:00Z",
          READ1,
        )
      ).status,
    ).toBe(400);
    expect(
      (await call(port, "GET", "/v1/usage/rollup?from=nope&to=2026-10-01T00:00:00Z", READ1)).status,
    ).toBe(400);
    expect(
      (
        await call(
          port,
          "GET",
          "/v1/usage/rollup?from=2026-09-01T00:00:00Z&to=2026-10-01T00:00:00Z&meter=nope",
          READ1,
        )
      ).status,
    ).toBe(400);
    const ent = await call(port, "GET", "/v1/usage/entries?period=2026-09&meter=tokens_out", READ1);
    expect(ent.json).toMatchObject({
      truncated: false,
      entries: [{ meter: "tokens_out", quantity: "10", period: "2026-09", original_period: null }],
    });
    expect(
      (await call(port, "GET", "/v1/usage/entries?period=2026-09", READ2)).json.entries,
    ).toEqual([]);
    // close, rate: the statement now carries the seal and the invoice; periods list it
    const svc = new BillingService({
      ledger,
      invoices,
      provider: new FakePaymentProvider(),
      priceBook: DEV_PRICE_BOOK,
      config: { config: () => Promise.resolve({ plan: DEV_PLAN }) },
    });
    await svc.closeAndRate(T1, "2026-09");
    const st2 = await call(port, "GET", "/v1/usage/statement?period=2026-09", READ1);
    expect(st2.json.sealed).toBe(true);
    expect(st2.json.invoice).toMatchObject({ revision: 1, planId: "team", totalMicro: "99000000" });
    expect((await call(port, "GET", "/v1/usage/periods", READ1)).json.periods).toMatchObject([
      { period: "2026-09", seq: 1, event_count: 2 },
    ]);
    expect((await call(port, "GET", "/v1/usage/periods", READ2)).json.periods).toEqual([]);
  });

  it("applies an audited adjustment under the token's identity, with a mandatory reason", async () => {
    const { port, ledger } = await start();
    const body = {
      idempotency_key: "adj-1",
      meter: "tokens_in",
      quantity: "-5",
      event_time: "2026-09-20T00:00:00Z",
      reason: "refund of duplicate run",
      dimensions: { model_class: "standard" },
    };
    const r = await call(port, "POST", "/v1/usage/adjustments", ADMIN1, body);
    expect(r.json).toMatchObject({
      status: "inserted",
      entry: { entry_type: "adjustment", quantity: "-5", actor: "ops@axis.test" },
    });
    expect((await call(port, "POST", "/v1/usage/adjustments", ADMIN1, body)).json.status).toBe(
      "duplicate",
    );
    expect(
      (await call(port, "POST", "/v1/usage/adjustments", ADMIN1, { ...body, quantity: "-6" })).json,
    ).toEqual({ status: "conflict" });
    expect(
      (
        await call(port, "POST", "/v1/usage/adjustments", ADMIN1, {
          ...body,
          idempotency_key: "x",
          reason: "",
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await call(port, "POST", "/v1/usage/adjustments", ADMIN1, {
          ...body,
          idempotency_key: "y",
          reason: "ok!",
          quantity: "1.5",
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await call(port, "POST", "/v1/usage/adjustments", ADMIN1, {
          ...body,
          idempotency_key: "z",
          reason: "ok!",
          meter: "nope",
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await call(port, "POST", "/v1/usage/adjustments", ADMIN1, {
          ...body,
          idempotency_key: "w",
          reason: "ok!",
          event_time: "x",
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await call(port, "POST", "/v1/usage/adjustments", ADMIN1, {
          ...body,
          idempotency_key: "v",
          reason: "ok!",
          quantity: "0",
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await call(port, "POST", "/v1/usage/adjustments", ADMIN1, {
          ...body,
          idempotency_key: "u",
          reason: "ok!",
          corrects_key: "orig",
        })
      ).status,
    ).toBe(200);
    expect((await ledger.entries(T1)).length).toBe(2);
  });

  it("never echoes internals and refuses production", async () => {
    const { port, ledger } = await start();
    ledger.entries = () => Promise.reject(new Error("db password=hunter2"));
    const r = await call(port, "GET", "/v1/usage/entries?period=2026-09", READ1);
    expect(r.status).toBe(500);
    expect(JSON.stringify(r.json)).not.toContain("hunter2");
    const prev = process.env["NODE_ENV"];
    process.env["NODE_ENV"] = "production";
    try {
      expect(() =>
        createDevServer({
          ledger,
          invoices: new MemoryInvoiceStore(),
          adjustments: new AdjustmentApi({ ledger, audit: new MemoryAuditLog() }),
          authenticate: () => Promise.resolve(undefined),
        }),
      ).toThrow(/production/);
    } finally {
      if (prev === undefined) delete process.env["NODE_ENV"];
      else process.env["NODE_ENV"] = prev;
    }
  });

  it("answers 500 without detail when the ledger fails during ingestion", async () => {
    const { port, ledger } = await start();
    ledger.append = () => Promise.reject(new (class extends Error {})("boom"));
    expect(
      (
        await call(port, "POST", "/v1/usage/run-events", INGEST1, {
          run_id: "run-1",
          events: runLog(),
        })
      ).status,
    ).toBe(500);
  });

  it("the token authenticator tolerates a missing or malformed header", async () => {
    const a = staticTokenAuthenticator({ t: { tenantId: T1, scopes: ["read"], subject: "s" } });
    expect(await a(undefined)).toBeUndefined();
    expect(await a("Basic t")).toBeUndefined();
    expect(await a("Bearer t")).toMatchObject({ tenantId: T1 });
    expect(await a("Bearer tt")).toBeUndefined();
  });
});
