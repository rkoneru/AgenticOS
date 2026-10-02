import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  BillingError,
  FakePaymentProvider,
  MemoryEventDedupe,
  STRIPE_API_VERSION,
  StripePaymentProvider,
  StripeWebhookProcessor,
  assertTestKey,
  stripeSignature,
  verifyStripeSignature,
  type HttpRequest,
  type HttpResponse,
  type HttpTransport,
} from "../src/index.js";

const KEY = "sk_test_abcdefgh12345678";
const CUS = "cus_123";

class FakeTransport implements HttpTransport {
  readonly reqs: HttpRequest[] = [];
  constructor(private readonly respond: (r: HttpRequest) => HttpResponse) {}
  request(r: HttpRequest): Promise<HttpResponse> {
    this.reqs.push(r);
    return Promise.resolve(this.respond(r));
  }
}
const ok = (body: unknown): HttpResponse => ({ status: 200, body: JSON.stringify(body) });
const params = (r: HttpRequest): URLSearchParams =>
  new URLSearchParams(r.body ?? new URL(r.url).search);

describe("live key refusal", () => {
  it("refuses live, restricted-live, publishable and malformed keys without echoing them", () => {
    const t = new FakeTransport(() => ok({}));
    for (const k of [
      "sk_live_abcdefgh12345678",
      "rk_live_abcdefgh12345678",
      "pk_test_abcdefgh12345678",
      "",
      "sk_test_",
      "xx",
    ]) {
      let err: unknown;
      try {
        new StripePaymentProvider({ apiKey: k, transport: t });
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(BillingError);
      expect((err as BillingError).code).toBe("LIVE_KEY_REFUSED");
      if (k.length > 8) expect((err as BillingError).message).not.toContain(k);
    }
    expect(() => assertTestKey("sk_live_abcdefgh12345678")).toThrow(/live/);
    expect(() => assertTestKey("rk_test_abcdefgh12345678")).not.toThrow();
    expect(t.reqs).toHaveLength(0);
  });

  it("refuses an answer in live mode even with a test key", async () => {
    const p = new StripePaymentProvider({
      apiKey: KEY,
      transport: new FakeTransport(() => ok({ id: CUS, livemode: true })),
    });
    await expect(p.createCustomer({ tenantId: "t", name: "n" }, "k")).rejects.toMatchObject({
      code: "LIVE_KEY_REFUSED",
    });
  });
});

describe("stripe adapter requests", () => {
  const mk = (respond: (r: HttpRequest) => HttpResponse, extra = {}) => {
    const t = new FakeTransport(respond);
    return { t, p: new StripePaymentProvider({ apiKey: KEY, transport: t, ...extra }) };
  };

  it("creates a customer with auth, pinned version, form body and an idempotency key", async () => {
    const { t, p } = mk(() => ok({ id: CUS, livemode: false }));
    expect(
      await p.createCustomer({ tenantId: "ten-1", name: "Acme & Co", email: "a@b.co" }, "idem-1"),
    ).toEqual({ id: CUS });
    const r = t.reqs[0] as HttpRequest;
    expect([r.method, r.url]).toEqual(["POST", "https://api.stripe.com/v1/customers"]);
    expect(r.headers["authorization"]).toBe(`Bearer ${KEY}`);
    expect(r.headers["stripe-version"]).toBe(STRIPE_API_VERSION);
    expect(r.headers["idempotency-key"]).toBe("idem-1");
    expect(r.headers["content-type"]).toBe("application/x-www-form-urlencoded");
    expect(Object.fromEntries(params(r))).toEqual({
      name: "Acme & Co",
      email: "a@b.co",
      "metadata[tenant_id]": "ten-1",
    });
  });

  it("requires an idempotency key on every mutation", async () => {
    const { t, p } = mk(() => ok({ id: CUS }));
    await expect(p.createCustomer({ tenantId: "t", name: "n" }, "")).rejects.toMatchObject({
      code: "INVALID",
    });
    await expect(
      p.createCustomer({ tenantId: "t", name: "n" }, "x".repeat(256)),
    ).rejects.toMatchObject({ code: "INVALID" });
    expect(t.reqs).toHaveLength(0);
  });

  it("reports usage as a meter event with identifier, integer value and unix timestamp", async () => {
    const { t, p } = mk(() => ok({ identifier: "ev-1", livemode: false }));
    const r = await p.reportUsage(
      {
        customerId: CUS,
        meter: "tokens_in",
        quantity: 1234n,
        at: new Date("2026-09-10T12:00:00.900Z"),
        identifier: "ev-1",
      },
      "k1",
    );
    expect(r.id).toBe("ev-1");
    const req = t.reqs[0] as HttpRequest;
    expect(req.url).toBe("https://api.stripe.com/v1/billing/meter_events");
    expect(Object.fromEntries(params(req))).toEqual({
      event_name: "axis_tokens_in",
      "payload[stripe_customer_id]": CUS,
      "payload[value]": "1234",
      timestamp: String(Date.parse("2026-09-10T12:00:00Z") / 1000),
      identifier: "ev-1",
    });
    await expect(
      p.reportUsage(
        { customerId: CUS, meter: "tokens_in", quantity: -1n, at: new Date(), identifier: "x" },
        "k",
      ),
    ).rejects.toBeInstanceOf(BillingError);
    await expect(
      p.reportUsage(
        {
          customerId: CUS,
          meter: "tokens_in",
          quantity: 2n ** 60n,
          at: new Date(),
          identifier: "x",
        },
        "k",
      ),
    ).rejects.toBeInstanceOf(BillingError);
  });

  it("falls back to the id/identifier when the response has no identifier", async () => {
    const { p } = mk(() => ok({ id: "mev_1" }));
    expect(
      (
        await p.reportUsage(
          {
            customerId: CUS,
            meter: "tool_executions",
            quantity: 1n,
            at: new Date(),
            identifier: "i",
          },
          "k",
        )
      ).id,
    ).toBe("mev_1");
    const { p: p2 } = mk(() => ok({}));
    expect(
      (
        await p2.reportUsage(
          {
            customerId: CUS,
            meter: "tool_executions",
            quantity: 1n,
            at: new Date(),
            identifier: "i",
          },
          "k",
        )
      ).id,
    ).toBe("i");
  });

  it("sums event summaries over pages", async () => {
    let page = 0;
    const { t, p } = mk(
      (r) => {
        page++;
        expect(new URL(r.url).pathname).toBe("/v1/billing/meters/mtr_1/event_summaries");
        return page === 1
          ? ok({
              data: [
                { id: "s1", aggregated_value: 5 },
                { id: "s2", aggregated_value: 7 },
              ],
              has_more: true,
            })
          : ok({ data: [{ id: "s3", aggregated_value: 1 }], has_more: false });
      },
      { meterIds: { tokens_in: "mtr_1" } },
    );
    const s = await p.usageSummary({
      customerId: CUS,
      meter: "tokens_in",
      from: new Date("2026-09-01T00:00:00Z"),
      to: new Date("2026-10-01T00:00:00Z"),
    });
    expect(s.quantity).toBe(13n);
    expect(new URL((t.reqs[1] as HttpRequest).url).searchParams.get("starting_after")).toBe("s2");
    expect(new URL((t.reqs[0] as HttpRequest).url).searchParams.get("start_time")).toBe(
      String(Date.parse("2026-09-01T00:00:00Z") / 1000),
    );
    await expect(
      p.usageSummary({ customerId: CUS, meter: "tokens_out", from: new Date(), to: new Date() }),
    ).rejects.toThrow(/no Stripe meter id/);
  });

  it("stops paging on an empty page and on a runaway provider", async () => {
    const { p } = mk(() => ok({ data: [], has_more: true }), { meterIds: { tokens_in: "m" } });
    expect(
      (
        await p.usageSummary({
          customerId: CUS,
          meter: "tokens_in",
          from: new Date(),
          to: new Date(),
        })
      ).quantity,
    ).toBe(0n);
    const { p: loop } = mk(() => ok({ data: [{ id: "x", aggregated_value: 1 }], has_more: true }), {
      meterIds: { tokens_in: "m" },
    });
    await expect(
      loop.usageSummary({ customerId: CUS, meter: "tokens_in", from: new Date(), to: new Date() }),
    ).rejects.toThrow(/too many/);
    const { p: bad } = mk(() => ok({ data: [{ id: "x", aggregated_value: "1" }] }), {
      meterIds: { tokens_in: "m" },
    });
    await expect(
      bad.usageSummary({ customerId: CUS, meter: "tokens_in", from: new Date(), to: new Date() }),
    ).rejects.toThrow(/unexpected/);
  });

  it("creates an invoice from invoice items with per-call idempotency keys, then reads and lists", async () => {
    const inv = {
      id: "in_1",
      customer: CUS,
      status: "draft",
      currency: "usd",
      total: 150,
      metadata: { period_id: "2026-09" },
      lines: {
        data: [
          { description: "a", amount: 200 },
          { description: "b", amount: -50 },
        ],
      },
      livemode: false,
    };
    const { t, p } = mk((r) =>
      r.url.endsWith("/v1/invoices") && r.method === "POST"
        ? ok(inv)
        : r.url.includes("/v1/invoiceitems")
          ? ok({ id: "ii" })
          : r.url.includes("/v1/invoices/in_1")
            ? ok(inv)
            : ok({ data: [inv, { ...inv, id: "in_2", metadata: { period_id: "2026-08" } }] }),
    );
    const created = await p.createInvoice(
      {
        customerId: CUS,
        periodId: "2026-09",
        currency: "USD",
        lines: [
          { description: "a", amountMinor: 200n },
          { description: "b", amountMinor: -50n },
        ],
      },
      "inv-key",
    );
    expect(created).toEqual({
      id: "in_1",
      customerId: CUS,
      periodId: "2026-09",
      status: "draft",
      currency: "usd",
      totalMinor: 150n,
      lines: [
        { description: "a", amountMinor: 200n },
        { description: "b", amountMinor: -50n },
      ],
    });
    expect(t.reqs.map((r) => r.headers["idempotency-key"])).toEqual([
      "inv-key:item:0",
      "inv-key:item:1",
      "inv-key:invoice",
    ]);
    expect(Object.fromEntries(params(t.reqs[1] as HttpRequest))["amount"]).toBe("-50");
    expect((await p.getInvoice("in_1")).id).toBe("in_1");
    expect(await p.listInvoices(CUS, "2026-09")).toHaveLength(1);
    expect(await p.listInvoices(CUS)).toHaveLength(2);
    await expect(
      p.createInvoice(
        {
          customerId: CUS,
          periodId: "2026-09",
          currency: "USD",
          lines: [{ description: "x", amountMinor: 2n ** 60n }],
        },
        "k",
      ),
    ).rejects.toThrow(/out of range/);
  });

  it("reads an invoice that has no lines or description", async () => {
    const { p } = mk(() =>
      ok({
        id: "in_9",
        customer: CUS,
        currency: "usd",
        total: 0,
        lines: { data: [{ amount: 0 }] },
      }),
    );
    expect(await p.getInvoice("in_9")).toEqual({
      id: "in_9",
      customerId: CUS,
      periodId: "",
      status: "draft",
      currency: "usd",
      totalMinor: 0n,
      lines: [{ description: "", amountMinor: 0n }],
    });
    const { p: p2 } = mk(() => ok({ id: "in_8", customer: CUS, currency: "usd", total: 0 }));
    expect((await p2.getInvoice("in_8")).lines).toEqual([]);
  });

  it("maps provider errors and garbage to PROVIDER_ERROR without leaking the body", async () => {
    const { p } = mk(() => ({
      status: 402,
      body: JSON.stringify({ error: { code: "card_declined", message: "secret detail" } }),
    }));
    await expect(p.createCustomer({ tenantId: "t", name: "n" }, "k")).rejects.toThrow(
      "stripe 402 card_declined",
    );
    const { p: p2 } = mk(() => ({
      status: 500,
      body: JSON.stringify({ error: { type: "api_error" } }),
    }));
    await expect(p2.createCustomer({ tenantId: "t", name: "n" }, "k")).rejects.toThrow(
      "stripe 500 api_error",
    );
    const { p: p3 } = mk(() => ({ status: 500, body: JSON.stringify({}) }));
    await expect(p3.createCustomer({ tenantId: "t", name: "n" }, "k")).rejects.toThrow(
      "stripe 500 error",
    );
    const { p: p4 } = mk(() => ({ status: 200, body: "<html>" }));
    await expect(p4.createCustomer({ tenantId: "t", name: "n" }, "k")).rejects.toThrow(/non-JSON/);
    const { p: p5 } = mk(() => ok({ id: 5 }));
    await expect(p5.createCustomer({ tenantId: "t", name: "n" }, "k")).rejects.toThrow(
      /unexpected/,
    );
    const { p: p6 } = mk(() => ({ status: 200, body: "null" }));
    await expect(p6.createCustomer({ tenantId: "t", name: "n" }, "k")).rejects.toThrow(
      /unexpected/,
    );
  });
});

describe("webhook signatures", () => {
  const secret = "whsec_test_secret";
  const body = JSON.stringify({
    id: "evt_1",
    type: "invoice.paid",
    data: { object: { id: "in_1" } },
    livemode: false,
  });
  const NOW = 1_780_000_000_000;
  const header = (t = NOW / 1000, sig = stripeSignature(secret, t, body)) => `t=${t},v1=${sig}`;
  const verify = (
    h: string | undefined,
    o: { payload?: string | Buffer; secret?: string; nowMs?: number; tol?: number } = {},
  ) =>
    verifyStripeSignature({
      payload: o.payload ?? body,
      header: h,
      secret: o.secret ?? secret,
      nowMs: o.nowMs ?? NOW,
      ...(o.tol === undefined ? {} : { toleranceSeconds: o.tol }),
    });

  it("matches the documented scheme (HMAC-SHA256 of `t.payload`)", () => {
    const expected = createHmac("sha256", secret)
      .update(`${NOW / 1000}.${body}`)
      .digest("hex");
    expect(stripeSignature(secret, NOW / 1000, body)).toBe(expected);
    expect(() => verify(header())).not.toThrow();
    expect(() => verify(header(), { payload: Buffer.from(body) })).not.toThrow();
  });

  it("rejects a tampered body, wrong secret, wrong signature and missing parts", () => {
    expect(() => verify(header(), { payload: body + " " })).toThrow(/mismatch/);
    expect(() => verify(header(), { secret: "other" })).toThrow(/mismatch/);
    expect(() => verify(header(undefined, "0".repeat(64)))).toThrow(/mismatch/);
    expect(() => verify(undefined)).toThrow(/missing/);
    expect(() => verify("")).toThrow(/missing/);
    expect(() => verify("garbage")).toThrow(/malformed/);
    expect(() => verify("t=abc,v1=" + "0".repeat(64))).toThrow(/malformed/);
    expect(() => verify(`t=${NOW / 1000}`)).toThrow(/malformed/);
    expect(() => verify(`t=${NOW / 1000},v1=zz`)).toThrow(/malformed/);
    expect(() => verify(header(), { secret: "" })).toThrow(/not configured/);
  });

  it("enforces the tolerance window both ways and accepts any matching v1", () => {
    expect(() => verify(header(), { nowMs: NOW + 301_000 })).toThrow(/tolerance/);
    expect(() => verify(header(), { nowMs: NOW - 301_000 })).toThrow(/tolerance/);
    expect(() => verify(header(), { nowMs: NOW + 299_000 })).not.toThrow();
    expect(() => verify(header(), { nowMs: NOW + 400_000, tol: 500 })).not.toThrow();
    const good = stripeSignature(secret, NOW / 1000, body);
    expect(() => verify(`t=${NOW / 1000},v1=${"1".repeat(64)},v1=${good},v0=abc`)).not.toThrow();
  });

  it("processes once, ignores unknown types, refuses live events, rejects bad JSON and bad signatures", async () => {
    const seen: string[] = [];
    const proc = new StripeWebhookProcessor({
      secret,
      now: () => NOW,
      handlers: {
        "invoice.paid": (e) => {
          seen.push(e.id);
          return Promise.resolve();
        },
      },
    });
    expect(await proc.handle(body, header())).toBe("processed");
    expect(await proc.handle(body, header())).toBe("duplicate");
    expect(seen).toEqual(["evt_1"]);
    const other = JSON.stringify({ id: "evt_2", type: "customer.created" });
    expect(
      await proc.handle(other, header(NOW / 1000, stripeSignature(secret, NOW / 1000, other))),
    ).toBe("ignored");
    const sign = (b: string) => header(NOW / 1000, stripeSignature(secret, NOW / 1000, b));
    const live = JSON.stringify({ id: "evt_3", type: "invoice.paid", livemode: true });
    await expect(proc.handle(live, sign(live))).rejects.toMatchObject({ code: "LIVE_KEY_REFUSED" });
    await expect(proc.handle("{", sign("{"))).rejects.toMatchObject({ code: "INVALID" });
    const noid = JSON.stringify({ type: "x" });
    await expect(proc.handle(noid, sign(noid))).rejects.toMatchObject({ code: "INVALID" });
    await expect(proc.handle(body, "t=1,v1=" + "0".repeat(64))).rejects.toMatchObject({
      code: "SIGNATURE_INVALID",
    });
    expect(seen).toEqual(["evt_1"]);
    // default clock, explicit tolerance and shared dedupe
    const p2 = new StripeWebhookProcessor({
      secret,
      handlers: {},
      dedupe: new MemoryEventDedupe(),
      toleranceSeconds: 10,
    });
    await expect(p2.handle(body, header())).rejects.toMatchObject({ code: "SIGNATURE_INVALID" });
  });
});

describe("fake provider", () => {
  const T = "11111111-1111-4111-8111-111111111111";
  it("honours idempotency keys: same key same result, different params rejected, missing key rejected", async () => {
    const f = new FakePaymentProvider();
    const a = await f.createCustomer({ tenantId: T, name: "n" }, "k");
    expect(await f.createCustomer({ tenantId: T, name: "n" }, "k")).toEqual(a);
    expect(f.customers.size).toBe(1);
    await expect(f.createCustomer({ tenantId: T, name: "other" }, "k")).rejects.toThrow(
      /different parameters/,
    );
    await expect(f.createCustomer({ tenantId: T, name: "n" }, "")).rejects.toThrow(/idempotency/);
  });
  it("dedupes meter events by identifier, supports fault injection, and sums by window", async () => {
    const f = new FakePaymentProvider();
    const c = await f.createCustomer({ tenantId: T, name: "n" }, "c");
    const at = new Date("2026-09-10T00:00:00Z");
    const rep = (id: string, q: bigint, key = id) =>
      f.reportUsage({ customerId: c.id, meter: "tokens_in", quantity: q, at, identifier: id }, key);
    await rep("a", 5n);
    await rep("a", 5n, "other-key"); // same identifier, new key: provider dedupes
    f.dropIdentifiers.add("lost");
    await rep("lost", 9n);
    f.duplicateIdentifiers.add("dup");
    await rep("dup", 2n);
    const s = await f.usageSummary({
      customerId: c.id,
      meter: "tokens_in",
      from: new Date("2026-09-01T00:00:00Z"),
      to: new Date("2026-10-01T00:00:00Z"),
    });
    expect(s.quantity).toBe(9n);
    expect(s.records?.map((r) => r.identifier).sort()).toEqual(["a", "dup", "dup"]);
    await expect(
      f.reportUsage(
        { customerId: "nope", meter: "tokens_in", quantity: 1n, at, identifier: "z" },
        "z",
      ),
    ).rejects.toThrow(/no such customer/);
  });
  it("creates, gets and lists invoices", async () => {
    const f = new FakePaymentProvider();
    const c = await f.createCustomer({ tenantId: T, name: "n" }, "c");
    const i = await f.createInvoice(
      {
        customerId: c.id,
        periodId: "2026-09",
        currency: "USD",
        lines: [
          { description: "a", amountMinor: 3n },
          { description: "b", amountMinor: -1n },
        ],
      },
      "i",
    );
    expect(i.totalMinor).toBe(2n);
    expect((await f.getInvoice(i.id)).currency).toBe("usd");
    expect(await f.listInvoices(c.id, "2026-09")).toHaveLength(1);
    expect(await f.listInvoices(c.id, "2026-08")).toHaveLength(0);
    expect(await f.listInvoices(c.id)).toHaveLength(1);
    await expect(f.getInvoice("nope")).rejects.toMatchObject({ code: "NOT_FOUND" });
    await expect(
      f.createInvoice({ customerId: "x", periodId: "2026-09", currency: "USD", lines: [] }, "j"),
    ).rejects.toThrow(/no such customer/);
  });
});
