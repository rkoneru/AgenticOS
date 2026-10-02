import { createHash } from "node:crypto";
import { canonicalize } from "@axis/contracts";
import { withTenant } from "@axis/db";
import { BillingError } from "./errors.js";
import type { Invoice, InvoiceLine } from "./rating.js";
import type { PgPoolLike } from "./pg-ledger.js";
import { assertTenant, type Meter } from "./types.js";
import { randomUUID } from "node:crypto";

type JsonLine = Omit<
  InvoiceLine,
  "quantity" | "amountMicro" | "creditAppliedMicro" | "netMicro"
> & {
  quantity: string;
  amountMicro: string;
  creditAppliedMicro: string;
  netMicro: string;
};
export interface InvoiceJson {
  tenantId: string;
  periodId: string;
  planId: string;
  priceBook: { id: string; version: number };
  currency: string;
  lines: JsonLine[];
  subtotalMicro: string;
  creditsAppliedMicro: string;
  creditsConsumed: { id: string; amountMicro: string }[];
  taxMicro: string;
  totalMicro: string;
  warnings: string[];
}

export const invoiceToJson = (i: Invoice): InvoiceJson => ({
  ...i,
  lines: i.lines.map((l) => ({
    ...l,
    quantity: l.quantity.toString(),
    amountMicro: l.amountMicro.toString(),
    creditAppliedMicro: l.creditAppliedMicro.toString(),
    netMicro: l.netMicro.toString(),
  })),
  subtotalMicro: i.subtotalMicro.toString(),
  creditsAppliedMicro: i.creditsAppliedMicro.toString(),
  creditsConsumed: i.creditsConsumed.map((c) => ({
    id: c.id,
    amountMicro: c.amountMicro.toString(),
  })),
  taxMicro: i.taxMicro.toString(),
  totalMicro: i.totalMicro.toString(),
});

export const invoiceFromJson = (j: InvoiceJson): Invoice => ({
  ...j,
  lines: j.lines.map((l) => ({
    ...l,
    meter: l.meter as Meter | null,
    quantity: BigInt(l.quantity),
    amountMicro: BigInt(l.amountMicro),
    creditAppliedMicro: BigInt(l.creditAppliedMicro),
    netMicro: BigInt(l.netMicro),
  })),
  subtotalMicro: BigInt(j.subtotalMicro),
  creditsAppliedMicro: BigInt(j.creditsAppliedMicro),
  creditsConsumed: j.creditsConsumed.map((c) => ({ id: c.id, amountMicro: BigInt(c.amountMicro) })),
  taxMicro: BigInt(j.taxMicro),
  totalMicro: BigInt(j.totalMicro),
});

export const invoiceHash = (i: Invoice): string =>
  createHash("sha256")
    .update(canonicalize(invoiceToJson(i)), "utf8")
    .digest("hex");

export interface StoredInvoice {
  id: string;
  revision: number;
  hash: string;
  invoice: Invoice;
  providerInvoiceId: string | null;
}

/** Invoices are immutable: re-rating a period saves a NEW revision. */
export interface InvoiceStore {
  save(invoice: Invoice): Promise<StoredInvoice>;
  list(tenantId: string, periodId?: string): Promise<StoredInvoice[]>;
  linkProvider(
    tenantId: string,
    invoiceId: string,
    provider: string,
    providerInvoiceId: string,
  ): Promise<void>;
}

export class MemoryInvoiceStore implements InvoiceStore {
  private readonly rows: (StoredInvoice & { tenantId: string; links: Map<string, string> })[] = [];
  save(invoice: Invoice): Promise<StoredInvoice> {
    assertTenant(invoice.tenantId);
    const revision =
      this.rows.filter(
        (r) => r.tenantId === invoice.tenantId && r.invoice.periodId === invoice.periodId,
      ).length + 1;
    const row = {
      id: randomUUID(),
      revision,
      hash: invoiceHash(invoice),
      invoice,
      providerInvoiceId: null,
      tenantId: invoice.tenantId,
      links: new Map<string, string>(),
    };
    this.rows.push(row);
    return Promise.resolve(strip(row));
  }
  list(tenantId: string, periodId?: string): Promise<StoredInvoice[]> {
    return Promise.resolve(
      this.rows
        .filter(
          (r) =>
            r.tenantId === tenantId && (periodId === undefined || r.invoice.periodId === periodId),
        )
        .map(strip),
    );
  }
  linkProvider(
    tenantId: string,
    invoiceId: string,
    provider: string,
    providerInvoiceId: string,
  ): Promise<void> {
    const row = this.rows.find((r) => r.tenantId === tenantId && r.id === invoiceId);
    if (!row) return Promise.reject(new BillingError("NOT_FOUND", "no such invoice"));
    if (row.links.has(provider))
      return Promise.reject(new BillingError("INVALID", "invoice already linked to this provider"));
    row.links.set(provider, providerInvoiceId);
    row.providerInvoiceId = providerInvoiceId;
    return Promise.resolve();
  }
}
const strip = (r: StoredInvoice & { links: Map<string, string> }): StoredInvoice => ({
  id: r.id,
  revision: r.revision,
  hash: r.hash,
  invoice: r.invoice,
  providerInvoiceId: [...r.links.values()][0] ?? null,
});

export class PgInvoiceStore implements InvoiceStore {
  constructor(private readonly o: { pool: PgPoolLike; role?: string }) {}
  private async tx<T>(tenantId: string, fn: Parameters<typeof withTenant<T>>[2]): Promise<T> {
    assertTenant(tenantId);
    const c = await this.o.pool.connect();
    try {
      return await withTenant(c, tenantId, fn, this.o.role ? { role: this.o.role } : {});
    } finally {
      c.release();
    }
  }
  save(invoice: Invoice): Promise<StoredInvoice> {
    const hash = invoiceHash(invoice);
    return this.tx(invoice.tenantId, async (c) => {
      await c.query("SELECT pg_advisory_xact_lock(727281, hashtext($1))", [
        `${invoice.tenantId}${invoice.periodId}`,
      ]);
      const rev = await c.query<{ n: number }>(
        "SELECT count(*)::int AS n FROM invoices WHERE tenant_id = $1 AND period_id = $2",
        [invoice.tenantId, invoice.periodId],
      );
      const revision = (rev.rows[0]?.n ?? 0) + 1;
      const r = await c.query<{ id: string }>(
        `INSERT INTO invoices (tenant_id, period_id, revision, plan_id, price_book, currency, lines, total_micro, invoice_hash)
         VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9) RETURNING id`,
        [
          invoice.tenantId,
          invoice.periodId,
          revision,
          invoice.planId,
          `${invoice.priceBook.id}@${invoice.priceBook.version}`,
          invoice.currency,
          JSON.stringify(invoiceToJson(invoice)),
          invoice.totalMicro.toString(),
          hash,
        ],
      );
      return {
        id: (r.rows[0] as { id: string }).id,
        revision,
        hash,
        invoice,
        providerInvoiceId: null,
      };
    });
  }
  list(tenantId: string, periodId?: string): Promise<StoredInvoice[]> {
    return this.tx(tenantId, async (c) => {
      const r = await c.query<{
        id: string;
        revision: number;
        invoice_hash: string;
        lines: InvoiceJson;
        pid: string | null;
      }>(
        `SELECT i.id, i.revision, i.invoice_hash, i.lines,
                (SELECT provider_invoice_id FROM invoice_provider_links l WHERE l.tenant_id = i.tenant_id AND l.invoice_id = i.id LIMIT 1) AS pid
           FROM invoices i WHERE i.tenant_id = $1 AND ($2::text IS NULL OR i.period_id = $2) ORDER BY i.period_id, i.revision`,
        [tenantId, periodId ?? null],
      );
      return r.rows.map((x) => ({
        id: x.id,
        revision: x.revision,
        hash: x.invoice_hash,
        invoice: invoiceFromJson(x.lines),
        providerInvoiceId: x.pid,
      }));
    });
  }
  linkProvider(
    tenantId: string,
    invoiceId: string,
    provider: string,
    providerInvoiceId: string,
  ): Promise<void> {
    return this.tx(tenantId, async (c) => {
      await c.query(
        "INSERT INTO invoice_provider_links (tenant_id, invoice_id, provider, provider_invoice_id) VALUES ($1,$2,$3,$4)",
        [tenantId, invoiceId, provider, providerInvoiceId],
      );
    });
  }
}
