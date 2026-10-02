import { BillingError } from "./errors.js";
import type { InvoiceStore, StoredInvoice } from "./invoices.js";
import type { UsageLedger } from "./ledger.js";
import type { PaymentProvider } from "./payment.js";
import { periodBounds } from "./periods.js";
import type { Credit, Invoice, Plan, PlanWindow, PriceBook } from "./rating.js";
import { rate } from "./rating.js";
import {
  invoiceMinorLines,
  reconcile,
  reportableTotals,
  type ReconciliationReport,
} from "./reconcile.js";
import type { PeriodSeal } from "./seal.js";
import { METERS } from "./types.js";

/** What a tenant is subscribed to. Real source: the control plane (NEEDS); tests inject a static resolver. */
export interface TenantBillingConfig {
  plan: Plan;
  windows?: readonly PlanWindow[];
  credits?: readonly Credit[];
  /** Provider customer id, once created. */
  customerId?: string;
}
export interface BillingConfigSource {
  config(tenantId: string, periodId: string): Promise<TenantBillingConfig>;
}

export class BillingService {
  constructor(
    private readonly o: {
      ledger: UsageLedger;
      invoices: InvoiceStore;
      provider: PaymentProvider;
      priceBook: PriceBook;
      config: BillingConfigSource;
    },
  ) {}

  /** Closes (seals) a period and rates it. The invoice is stored; nothing is sent to the provider yet. */
  async closeAndRate(
    tenantId: string,
    periodId: string,
  ): Promise<{ seal: PeriodSeal; invoice: StoredInvoice }> {
    const seal = await this.o.ledger.closePeriod(tenantId, periodId);
    return { seal, invoice: await this.rateSealed(tenantId, periodId) };
  }

  /** Rates a sealed period (a new revision each time). */
  async rateSealed(tenantId: string, periodId: string): Promise<StoredInvoice> {
    const verdict = await this.o.ledger.verifySeal(tenantId, periodId); // throws PERIOD_NOT_SEALED if open
    if (!verdict.ok)
      throw new BillingError("INVALID", `period seal does not verify: ${verdict.reason}`);
    const cfg = await this.o.config.config(tenantId, periodId);
    const invoice = rate({
      tenantId,
      periodId,
      totals: await this.o.ledger.totals(tenantId, periodId),
      plan: cfg.plan,
      priceBook: this.o.priceBook,
      ...(cfg.windows ? { windows: cfg.windows } : {}),
      ...(cfg.credits ? { credits: cfg.credits } : {}),
    });
    return this.o.invoices.save(invoice);
  }

  /** One meter event per meter for the period (identifier = tenant:period:meter), so a retry is harmless on both sides. */
  async pushUsage(tenantId: string, periodId: string, customerId: string): Promise<number> {
    const { start } = periodBounds(periodId);
    let n = 0;
    for (const [meter, quantity] of reportableTotals(
      await this.o.ledger.totals(tenantId, periodId),
    )) {
      if (quantity === 0n) continue;
      const identifier = `axis:${tenantId}:${periodId}:${meter}`;
      await this.o.provider.reportUsage(
        { customerId, meter, quantity, at: start, identifier },
        identifier,
      );
      n++;
    }
    return n;
  }

  /** Sends a stored invoice to the provider as a draft; the idempotency key is the stored invoice id. */
  async pushInvoice(tenantId: string, stored: StoredInvoice, customerId: string): Promise<string> {
    const inv = stored.invoice;
    const pi = await this.o.provider.createInvoice(
      { customerId, periodId: inv.periodId, currency: inv.currency, lines: invoiceMinorLines(inv) },
      `invoice:${stored.id}`,
    );
    await this.o.invoices.linkProvider(tenantId, stored.id, this.o.provider.name, pi.id);
    return pi.id;
  }

  /** Read-only comparison of ledger, provider usage and provider invoice for a period (uses the latest stored revision). */
  async reconcile(
    tenantId: string,
    periodId: string,
    customerId: string,
  ): Promise<ReconciliationReport> {
    const { start, end } = periodBounds(periodId);
    const providerUsage: Partial<
      Record<(typeof METERS)[number], Awaited<ReturnType<PaymentProvider["usageSummary"]>>>
    > = {};
    for (const meter of METERS)
      providerUsage[meter] = await this.o.provider.usageSummary({
        customerId,
        meter,
        from: start,
        to: end,
      });
    const stored = await this.o.invoices.list(tenantId, periodId);
    const latest: Invoice | null =
      stored.length === 0 ? null : (stored[stored.length - 1] as StoredInvoice).invoice;
    return reconcile({
      tenantId,
      periodId,
      ledgerTotals: await this.o.ledger.totals(tenantId, periodId),
      providerUsage,
      invoice: latest,
      providerInvoices: await this.o.provider.listInvoices(customerId, periodId),
    });
  }
}
