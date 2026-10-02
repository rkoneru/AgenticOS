import { toMinorUnits } from "./money.js";
import type { TotalRow } from "./ledger.js";
import type { Invoice } from "./rating.js";
import type { ProviderInvoice, UsageSummary } from "./payment.js";
import { METERS, type Meter } from "./types.js";

export type DiscrepancyKind =
  | "usage_missing_at_provider"
  | "usage_quantity_mismatch"
  | "usage_orphan_at_provider"
  | "usage_duplicated_at_provider"
  | "invoice_missing_at_provider"
  | "invoice_duplicate_at_provider"
  | "invoice_total_mismatch"
  | "invoice_line_mismatch"
  | "invoice_missing_line"
  | "invoice_orphan_line";

export interface Discrepancy {
  kind: DiscrepancyKind;
  meter?: Meter;
  /** What the ledger / our rated invoice says. */
  expected: bigint | null;
  /** What the provider says. */
  actual: bigint | null;
  detail: string;
}

export interface ReconciliationReport {
  tenantId: string;
  periodId: string;
  clean: boolean;
  discrepancies: Discrepancy[];
}

export interface ReconcileInput {
  tenantId: string;
  periodId: string;
  /** Ledger totals of the period (the source of truth). */
  ledgerTotals: readonly TotalRow[];
  /** Provider-reported usage per meter (absent meter = the provider reported nothing / was not asked). */
  providerUsage: Readonly<Partial<Record<Meter, UsageSummary>>>;
  /** Our rated invoice for the period (null if none was produced). */
  invoice: Invoice | null;
  providerInvoices: readonly ProviderInvoice[];
}

/** The quantity we report to the provider for a meter: the ledger net total, never below zero (providers cannot take negative usage). */
export function reportableTotals(totals: readonly TotalRow[]): Map<Meter, bigint> {
  const m = new Map<Meter, bigint>();
  for (const t of totals) m.set(t.meter, (m.get(t.meter) ?? 0n) + t.quantity);
  for (const [k, v] of m) if (v < 0n) m.set(k, 0n);
  return m;
}

/** Our invoice lines in the provider's minor unit, by cumulative rounding so they sum to round(total). */
export function invoiceMinorLines(inv: Invoice): { description: string; amountMinor: bigint }[] {
  const minor = toMinorUnits(inv.lines.map((l) => l.netMicro));
  return inv.lines.map((l, i) => ({ description: l.description, amountMinor: minor[i] as bigint }));
}

/**
 * Compares ledger totals, provider-reported usage and provider invoice lines. READ-ONLY: it reports and never changes anything.
 * A discrepancy is fixed only by an explicit, audited adjustment (AdjustmentApi) or by repairing the provider side.
 */
export function reconcile(input: ReconcileInput): ReconciliationReport {
  const out: Discrepancy[] = [];
  const ledger = reportableTotals(input.ledgerTotals);

  for (const meter of METERS) {
    const expected = ledger.get(meter) ?? 0n;
    const prov = input.providerUsage[meter];
    if (prov === undefined) continue;
    const actual = prov.quantity;
    if (prov.records) {
      const seen = new Map<string, number>();
      for (const r of prov.records) seen.set(r.identifier, (seen.get(r.identifier) ?? 0) + 1);
      for (const [id, n] of seen)
        if (n > 1)
          out.push({
            kind: "usage_duplicated_at_provider",
            meter,
            expected: null,
            actual: BigInt(n),
            detail: `identifier ${id} reported ${n} times`,
          });
    }
    if (expected === actual) continue;
    if (expected > 0n && actual === 0n)
      out.push({
        kind: "usage_missing_at_provider",
        meter,
        expected,
        actual,
        detail: "the ledger has usage the provider never received",
      });
    else if (expected === 0n && actual > 0n)
      out.push({
        kind: "usage_orphan_at_provider",
        meter,
        expected,
        actual,
        detail: "the provider holds usage the ledger does not",
      });
    else
      out.push({
        kind: "usage_quantity_mismatch",
        meter,
        expected,
        actual,
        detail: `provider differs by ${actual - expected}`,
      });
  }

  if (input.invoice) {
    const mine = invoiceMinorLines(input.invoice);
    const myTotal = mine.reduce((s, l) => s + l.amountMinor, 0n);
    if (input.providerInvoices.length === 0)
      out.push({
        kind: "invoice_missing_at_provider",
        expected: myTotal,
        actual: null,
        detail: "no provider invoice for the period",
      });
    if (input.providerInvoices.length > 1)
      out.push({
        kind: "invoice_duplicate_at_provider",
        expected: 1n,
        actual: BigInt(input.providerInvoices.length),
        detail: "more than one provider invoice for the period",
      });
    const theirs = input.providerInvoices[0];
    if (theirs) {
      if (theirs.totalMinor !== myTotal)
        out.push({
          kind: "invoice_total_mismatch",
          expected: myTotal,
          actual: theirs.totalMinor,
          detail: "provider invoice total differs",
        });
      const n = Math.max(mine.length, theirs.lines.length);
      for (let i = 0; i < n; i++) {
        const a = mine[i];
        const b = theirs.lines[i];
        if (a && !b)
          out.push({
            kind: "invoice_missing_line",
            expected: a.amountMinor,
            actual: null,
            detail: `line ${i} (${a.description}) is missing at the provider`,
          });
        else if (!a && b)
          out.push({
            kind: "invoice_orphan_line",
            expected: null,
            actual: b.amountMinor,
            detail: `line ${i} (${b.description}) exists only at the provider`,
          });
        else if (a && b && a.amountMinor !== b.amountMinor)
          out.push({
            kind: "invoice_line_mismatch",
            expected: a.amountMinor,
            actual: b.amountMinor,
            detail: `line ${i} (${a.description}) differs`,
          });
      }
    }
  } else if (input.providerInvoices.length > 0) {
    out.push({
      kind: "invoice_orphan_line",
      expected: null,
      actual: BigInt(input.providerInvoices.length),
      detail: "provider invoice(s) exist but no rated invoice does",
    });
  }
  return {
    tenantId: input.tenantId,
    periodId: input.periodId,
    clean: out.length === 0,
    discrepancies: out,
  };
}
