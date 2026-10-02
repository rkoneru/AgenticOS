import { BillingError } from "./errors.js";
import type {
  HttpTransport,
  PaymentProvider,
  ProviderInvoice,
  ProviderInvoiceLine,
  UsageSummary,
} from "./payment.js";
import type { Meter } from "./types.js";

export const STRIPE_API_BASE = "https://api.stripe.com";
/** Pinned: Billing Meters (meter events, event summaries) exist from this version. */
export const STRIPE_API_VERSION = "2024-09-30.acacia";

const TEST_KEY_RE = /^(sk|rk)_test_[A-Za-z0-9]{8,}$/;

/** TEST MODE ONLY. Anything that is not an explicit test key (live keys, publishable keys, garbage) is refused, without echoing it. */
export function assertTestKey(apiKey: string): void {
  if (!TEST_KEY_RE.test(apiKey)) {
    const live = /^(sk|rk)_live_/.test(apiKey);
    throw new BillingError(
      "LIVE_KEY_REFUSED",
      live
        ? "refusing to operate with a live Stripe key: this adapter is test mode only"
        : "a Stripe test key (sk_test_... or rk_test_...) is required",
    );
  }
}

function form(params: Record<string, string | undefined>): string {
  return Object.entries(params)
    .filter((e): e is [string, string] => e[1] !== undefined)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join("&");
}

type Json = Record<string, unknown>;
const obj = (v: unknown): Json => (typeof v === "object" && v !== null ? (v as Json) : {});
const text = (v: unknown, what: string): string => {
  if (typeof v !== "string")
    throw new BillingError("PROVIDER_ERROR", `unexpected provider response: ${what}`);
  return v;
};
const int = (v: unknown, what: string): bigint => {
  if (typeof v !== "number" || !Number.isSafeInteger(v))
    throw new BillingError("PROVIDER_ERROR", `unexpected provider response: ${what}`);
  return BigInt(v);
};

export interface StripeOptions {
  apiKey: string;
  transport: HttpTransport;
  /** Stripe billing meter ids per AXIS meter (for event summaries). */
  meterIds?: Partial<Record<Meter, string>>;
  /** Event name prefix of the Stripe meters, default `axis_`. */
  eventNamePrefix?: string;
}

/**
 * Stripe adapter over the documented REST API (customers, billing meter events + event summaries, invoice items, invoices).
 * TEST MODE ONLY: the constructor refuses a live key, and any response with `livemode: true` is refused. Every mutation carries an
 * Idempotency-Key. Real test keys and a real transport are NEEDS; this is exercised against fake transports.
 */
export class StripePaymentProvider implements PaymentProvider {
  readonly name = "stripe";
  private readonly key: string;
  private readonly t: HttpTransport;
  private readonly meterIds: Partial<Record<Meter, string>>;
  private readonly prefix: string;

  constructor(o: StripeOptions) {
    assertTestKey(o.apiKey);
    this.key = o.apiKey;
    this.t = o.transport;
    this.meterIds = o.meterIds ?? {};
    this.prefix = o.eventNamePrefix ?? "axis_";
  }

  private async call(
    method: "GET" | "POST",
    path: string,
    params: Record<string, string | undefined> = {},
    idempotencyKey?: string,
  ): Promise<Json> {
    if (method === "POST" && (!idempotencyKey || idempotencyKey.length > 255))
      throw new BillingError(
        "INVALID",
        "every Stripe mutation needs an idempotency key of 1..255 characters",
      );
    const headers: Record<string, string> = {
      authorization: `Bearer ${this.key}`,
      "stripe-version": STRIPE_API_VERSION,
    };
    let url = STRIPE_API_BASE + path;
    const q = form(params);
    const req: {
      method: "GET" | "POST";
      url: string;
      headers: Record<string, string>;
      body?: string;
    } = { method, url, headers };
    if (method === "POST") {
      headers["content-type"] = "application/x-www-form-urlencoded";
      headers["idempotency-key"] = idempotencyKey as string;
      req.body = q;
    } else if (q) {
      url += `?${q}`;
      req.url = url;
    }
    const res = await this.t.request(req);
    let body: Json;
    try {
      body = obj(JSON.parse(res.body));
    } catch {
      throw new BillingError(
        "PROVIDER_ERROR",
        `stripe returned a non-JSON body (status ${res.status})`,
      );
    }
    if (body["livemode"] === true)
      throw new BillingError("LIVE_KEY_REFUSED", "stripe answered in live mode: refusing");
    if (res.status < 200 || res.status >= 300) {
      const e = obj(body["error"]);
      const code =
        typeof e["code"] === "string"
          ? e["code"]
          : typeof e["type"] === "string"
            ? e["type"]
            : "error";
      throw new BillingError("PROVIDER_ERROR", `stripe ${res.status} ${code}`);
    }
    return body;
  }

  async createCustomer(
    a: { tenantId: string; name: string; email?: string },
    key: string,
  ): Promise<{ id: string }> {
    const r = await this.call(
      "POST",
      "/v1/customers",
      { name: a.name, email: a.email, "metadata[tenant_id]": a.tenantId },
      key,
    );
    return { id: text(r["id"], "customer id") };
  }

  async reportUsage(
    a: { customerId: string; meter: Meter; quantity: bigint; at: Date; identifier: string },
    key: string,
  ): Promise<{ id: string }> {
    if (a.quantity < 0n || a.quantity > BigInt(Number.MAX_SAFE_INTEGER))
      throw new BillingError("INVALID", "usage quantity out of range");
    const r = await this.call(
      "POST",
      "/v1/billing/meter_events",
      {
        event_name: this.prefix + a.meter,
        "payload[stripe_customer_id]": a.customerId,
        "payload[value]": a.quantity.toString(),
        timestamp: String(Math.floor(a.at.getTime() / 1000)),
        identifier: a.identifier,
      },
      key,
    );
    return { id: text(r["identifier"] ?? r["id"] ?? a.identifier, "meter event id") };
  }

  async usageSummary(a: {
    customerId: string;
    meter: Meter;
    from: Date;
    to: Date;
  }): Promise<UsageSummary> {
    const meterId = this.meterIds[a.meter];
    if (!meterId) throw new BillingError("INVALID", `no Stripe meter id configured for ${a.meter}`);
    let total = 0n;
    let after: string | undefined;
    for (let page = 0; page < 100; page++) {
      const r = await this.call(
        "GET",
        `/v1/billing/meters/${encodeURIComponent(meterId)}/event_summaries`,
        {
          customer: a.customerId,
          start_time: String(Math.floor(a.from.getTime() / 1000)),
          end_time: String(Math.floor(a.to.getTime() / 1000)),
          limit: "100",
          starting_after: after,
        },
      );
      const data = Array.isArray(r["data"]) ? (r["data"] as unknown[]) : [];
      for (const d of data) total += int(obj(d)["aggregated_value"], "aggregated_value");
      if (r["has_more"] !== true || data.length === 0) return { quantity: total };
      after = text(obj(data[data.length - 1])["id"], "summary id");
    }
    throw new BillingError("PROVIDER_ERROR", "too many summary pages");
  }

  private toInvoice(r: Json, periodId?: string): ProviderInvoice {
    const lines = Array.isArray(obj(r["lines"])["data"])
      ? (obj(r["lines"])["data"] as unknown[])
      : [];
    return {
      id: text(r["id"], "invoice id"),
      customerId: text(r["customer"], "invoice customer"),
      periodId: periodId ?? text(obj(r["metadata"])["period_id"] ?? "", "invoice period"),
      status: text(r["status"] ?? "draft", "invoice status"),
      currency: text(r["currency"], "invoice currency"),
      lines: lines.map((l) => ({
        description:
          typeof obj(l)["description"] === "string" ? (obj(l)["description"] as string) : "",
        amountMinor: int(obj(l)["amount"], "line amount"),
      })),
      totalMinor: int(r["total"], "invoice total"),
    };
  }

  async createInvoice(
    a: { customerId: string; periodId: string; currency: string; lines: ProviderInvoiceLine[] },
    key: string,
  ): Promise<ProviderInvoice> {
    for (const [i, l] of a.lines.entries()) {
      if (
        l.amountMinor < BigInt(Number.MIN_SAFE_INTEGER) ||
        l.amountMinor > BigInt(Number.MAX_SAFE_INTEGER)
      )
        throw new BillingError("INVALID", "invoice line amount out of range");
      await this.call(
        "POST",
        "/v1/invoiceitems",
        {
          customer: a.customerId,
          amount: l.amountMinor.toString(),
          currency: a.currency.toLowerCase(),
          description: l.description.slice(0, 500),
          "metadata[period_id]": a.periodId,
        },
        `${key}:item:${i}`,
      );
    }
    const r = await this.call(
      "POST",
      "/v1/invoices",
      {
        customer: a.customerId,
        auto_advance: "false",
        pending_invoice_items_behavior: "include",
        currency: a.currency.toLowerCase(),
        "metadata[period_id]": a.periodId,
      },
      `${key}:invoice`,
    );
    return this.toInvoice(r, a.periodId);
  }

  async getInvoice(id: string): Promise<ProviderInvoice> {
    return this.toInvoice(await this.call("GET", `/v1/invoices/${encodeURIComponent(id)}`));
  }

  async listInvoices(customerId: string, periodId?: string): Promise<ProviderInvoice[]> {
    const r = await this.call("GET", "/v1/invoices", { customer: customerId, limit: "100" });
    const data = Array.isArray(r["data"]) ? (r["data"] as unknown[]) : [];
    return data
      .map((d) => obj(d))
      .filter((d) => periodId === undefined || obj(d["metadata"])["period_id"] === periodId)
      .map((d) => this.toInvoice(d));
  }
}
