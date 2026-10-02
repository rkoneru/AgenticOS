import { BillingError } from "./errors.js";
import type { Meter } from "./types.js";

export interface HttpRequest {
  method: "GET" | "POST";
  url: string;
  headers: Record<string, string>;
  body?: string;
}
export interface HttpResponse {
  status: number;
  body: string;
}
/** Injected so tests (and the sandbox) never touch the network. A real transport is NEEDS (test keys). */
export interface HttpTransport {
  request(req: HttpRequest): Promise<HttpResponse>;
}

export interface ProviderInvoiceLine {
  description: string;
  amountMinor: bigint;
}

export interface ProviderInvoice {
  id: string;
  customerId: string;
  periodId: string;
  status: string;
  currency: string;
  lines: ProviderInvoiceLine[];
  totalMinor: bigint;
}

export interface ProviderUsageRecord {
  identifier: string;
  quantity: bigint;
}

export interface UsageSummary {
  quantity: bigint;
  /** Individual records, when the provider can list them (the fake can; Stripe's summaries cannot). */
  records?: ProviderUsageRecord[];
}

/** Every mutation takes an idempotency key; the provider must treat a repeat with the same key as the same request. */
export interface PaymentProvider {
  readonly name: string;
  createCustomer(
    a: { tenantId: string; name: string; email?: string },
    idempotencyKey: string,
  ): Promise<{ id: string }>;
  reportUsage(
    a: { customerId: string; meter: Meter; quantity: bigint; at: Date; identifier: string },
    idempotencyKey: string,
  ): Promise<{ id: string }>;
  usageSummary(a: {
    customerId: string;
    meter: Meter;
    from: Date;
    to: Date;
  }): Promise<UsageSummary>;
  createInvoice(
    a: { customerId: string; periodId: string; currency: string; lines: ProviderInvoiceLine[] },
    idempotencyKey: string,
  ): Promise<ProviderInvoice>;
  getInvoice(id: string): Promise<ProviderInvoice>;
  listInvoices(customerId: string, periodId?: string): Promise<ProviderInvoice[]>;
}

const stable = (v: unknown): string =>
  JSON.stringify(v, (_k, x: unknown) => (typeof x === "bigint" ? `${x}n` : x));

/** In-memory provider for tests. Behaves like a strict provider (idempotency keys, identifier dedupe) with fault injection hooks. */
export class FakePaymentProvider implements PaymentProvider {
  readonly name = "fake";
  private n = 0;
  readonly customers = new Map<string, { tenantId: string; name: string }>();
  readonly usage: {
    id: string;
    customerId: string;
    meter: Meter;
    at: Date;
    identifier: string;
    quantity: bigint;
  }[] = [];
  readonly invoices = new Map<string, ProviderInvoice>();
  private readonly idem = new Map<string, { sig: string; result: unknown }>();
  /** Fault injection: identifiers the provider "loses" (reported OK, never stored) and ones it stores twice. */
  readonly dropIdentifiers = new Set<string>();
  readonly duplicateIdentifiers = new Set<string>();
  readonly calls: string[] = [];

  private once<T>(op: string, key: string, payload: unknown, make: () => T): Promise<T> {
    try {
      return Promise.resolve(this.onceSync(op, key, payload, make));
    } catch (e) {
      return Promise.reject(e as Error);
    }
  }

  private onceSync<T>(op: string, key: string, payload: unknown, make: () => T): T {
    this.calls.push(op);
    if (key === "") throw new BillingError("INVALID", "an idempotency key is required");
    const sig = stable({ op, payload });
    const hit = this.idem.get(key);
    if (hit) {
      if (hit.sig !== sig)
        throw new BillingError(
          "PROVIDER_ERROR",
          "idempotency key reused with different parameters",
        );
      return hit.result as T;
    }
    const result = make();
    this.idem.set(key, { sig, result });
    return result;
  }

  createCustomer(
    a: { tenantId: string; name: string; email?: string },
    key: string,
  ): Promise<{ id: string }> {
    return this.once("createCustomer", key, a, () => {
      const id = `cus_fake_${++this.n}`;
      this.customers.set(id, { tenantId: a.tenantId, name: a.name });
      return { id };
    });
  }

  reportUsage(
    a: { customerId: string; meter: Meter; quantity: bigint; at: Date; identifier: string },
    key: string,
  ): Promise<{ id: string }> {
    return this.once("reportUsage", key, a, () => {
      if (!this.customers.has(a.customerId))
        throw new BillingError("PROVIDER_ERROR", "no such customer");
      const id = `mev_fake_${++this.n}`;
      if (this.dropIdentifiers.has(a.identifier)) return { id };
      if (
        this.usage.some(
          (u) => u.identifier === a.identifier && !this.duplicateIdentifiers.has(a.identifier),
        )
      )
        return { id };
      const rec = {
        id,
        customerId: a.customerId,
        meter: a.meter,
        at: a.at,
        identifier: a.identifier,
        quantity: a.quantity,
      };
      this.usage.push(rec);
      if (this.duplicateIdentifiers.has(a.identifier)) this.usage.push({ ...rec, id: `${id}_dup` });
      return { id };
    });
  }

  usageSummary(a: {
    customerId: string;
    meter: Meter;
    from: Date;
    to: Date;
  }): Promise<UsageSummary> {
    const rows = this.usage.filter(
      (u) => u.customerId === a.customerId && u.meter === a.meter && u.at >= a.from && u.at < a.to,
    );
    return Promise.resolve({
      quantity: rows.reduce((s, r) => s + r.quantity, 0n),
      records: rows.map((r) => ({ identifier: r.identifier, quantity: r.quantity })),
    });
  }

  createInvoice(
    a: { customerId: string; periodId: string; currency: string; lines: ProviderInvoiceLine[] },
    key: string,
  ): Promise<ProviderInvoice> {
    return this.once("createInvoice", key, a, () => {
      if (!this.customers.has(a.customerId))
        throw new BillingError("PROVIDER_ERROR", "no such customer");
      const inv: ProviderInvoice = {
        id: `in_fake_${++this.n}`,
        customerId: a.customerId,
        periodId: a.periodId,
        status: "draft",
        currency: a.currency.toLowerCase(),
        lines: a.lines.map((l) => ({ ...l })),
        totalMinor: a.lines.reduce((s, l) => s + l.amountMinor, 0n),
      };
      this.invoices.set(inv.id, inv);
      return inv;
    });
  }

  getInvoice(id: string): Promise<ProviderInvoice> {
    const inv = this.invoices.get(id);
    return inv
      ? Promise.resolve(inv)
      : Promise.reject(new BillingError("NOT_FOUND", "no such invoice"));
  }

  listInvoices(customerId: string, periodId?: string): Promise<ProviderInvoice[]> {
    return Promise.resolve(
      [...this.invoices.values()].filter(
        (i) => i.customerId === customerId && (periodId === undefined || i.periodId === periodId),
      ),
    );
  }
}
