import { governedTx, type PgGovOptions } from "../store.js";
import type {
  CountResult,
  EraseResult,
  ExportCollection,
  FindResult,
  Identifier,
  ProviderContext,
  ProviderDeclaration,
  PurgeRequest,
  PurgeResult,
  SubjectDataProvider,
} from "../types.js";
import { SUBJECT_KINDS, iso, vals } from "./util.js";

type Row = { id: string; actor: string | null; dimensions: Record<string, string> };

/**
 * Billing: `usage_events` are FINANCIAL RECORDS (append-only; trigger 0020 lets only the governance role rewrite `actor` and
 * `dimensions`). They are retained and the subject reference inside them is replaced by a keyed pseudonym.
 */
export class BillingProvider implements SubjectDataProvider {
  readonly id = "billing";
  readonly declaration: ProviderDeclaration = {
    exports: [
      "usage ledger rows that name the person (actor or a dimension value): meter, quantity, period, timestamps",
    ],
    erases: [],
    retains: [
      {
        what: "usage_events rows, period seals and invoices (quantities, amounts, periods)",
        legalBasis:
          "GDPR Art. 17(3)(b): legal obligation to keep accounting records; the ledger reconciles to the invoice",
      },
    ],
    pseudonymises: [
      "`actor` and any dimension value equal to the person's identifier become a keyed token",
    ],
    dataClasses: ["billing"],
  };
  constructor(private readonly o: PgGovOptions) {}
  private values(ids: readonly Identifier[]): string[] {
    return vals(ids, ...SUBJECT_KINDS, "billing_customer");
  }
  private static MATCH = `(actor = ANY($1) OR EXISTS (SELECT 1 FROM jsonb_each_text(dimensions) d WHERE d.value = ANY($1)))`;

  find(ctx: ProviderContext, ids: readonly Identifier[]): Promise<FindResult> {
    return governedTx(this.o, ctx.tenantId, async (c) => ({
      count: Number(
        (
          (
            await c.query(`SELECT count(*) n FROM usage_events WHERE ${BillingProvider.MATCH}`, [
              this.values(ids),
            ])
          ).rows[0] as { n: string }
        ).n,
      ),
    }));
  }
  export(ctx: ProviderContext, ids: readonly Identifier[]): Promise<ExportCollection[]> {
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const { rows } = await c.query(
        `SELECT id, entry_type, meter, quantity, event_time, period_id, source, actor, dimensions FROM usage_events WHERE ${BillingProvider.MATCH} ORDER BY event_time, id`,
        [this.values(ids)],
      );
      return [
        {
          name: "usage_events",
          records: rows.map((r) => ({ ...r, event_time: iso(r.event_time) })),
        },
      ];
    });
  }
  async erase(ctx: ProviderContext, ids: readonly Identifier[]): Promise<EraseResult> {
    const values = this.values(ids);
    const tok = new Map<string, string>();
    for (const v of values) tok.set(v, await ctx.pseudonym("subject_key", v));
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const { rows } = await c.query(
        `SELECT id, actor, dimensions FROM usage_events WHERE ${BillingProvider.MATCH} FOR UPDATE`,
        [values],
      );
      for (const r of rows as Row[]) {
        const dims: Record<string, string> = {};
        for (const [k, v] of Object.entries(r.dimensions)) dims[k] = tok.get(v) ?? v;
        const actor = r.actor !== null ? (tok.get(r.actor) ?? r.actor) : null;
        await c.query("UPDATE usage_events SET actor = $2, dimensions = $3 WHERE id = $1", [
          r.id,
          actor,
          JSON.stringify(dims),
        ]);
      }
      return { erased: 0, pseudonymised: rows.length, retained: rows.length };
    });
  }
  async count(ctx: ProviderContext, ids: readonly Identifier[]): Promise<CountResult> {
    const values = this.values(ids);
    const tokens: string[] = [];
    for (const v of values) tokens.push(await ctx.pseudonym("subject_key", v).catch(() => ""));
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const raw = Number(
        (
          (
            await c.query(`SELECT count(*) n FROM usage_events WHERE ${BillingProvider.MATCH}`, [
              values,
            ])
          ).rows[0] as { n: string }
        ).n,
      );
      const kept = Number(
        (
          (
            await c.query(`SELECT count(*) n FROM usage_events WHERE ${BillingProvider.MATCH}`, [
              tokens.filter(Boolean),
            ])
          ).rows[0] as { n: string }
        ).n,
      );
      return { residual: raw, retained: kept, pseudonymised: kept };
    });
  }
  /** Billing "purge" past the (floored) retention period scrubs the actor; the financial rows themselves are never deleted. */
  async purge(ctx: ProviderContext, req: PurgeRequest): Promise<PurgeResult> {
    const prot = req.protect.subjects.flatMap((g) => this.values(g));
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const w = `event_time < $1 AND actor IS NOT NULL AND actor <> 'anon_expired'`;
      const matched = Number(
        (
          (await c.query(`SELECT count(*) n FROM usage_events WHERE ${w}`, [req.olderThan]))
            .rows[0] as { n: string }
        ).n,
      );
      const open = Number(
        (
          (
            await c.query(
              `SELECT count(*) n FROM usage_events WHERE ${w} AND NOT actor = ANY($2)`,
              [req.olderThan, prot],
            )
          ).rows[0] as { n: string }
        ).n,
      );
      if (req.dryRun) return { matched, purged: 0, protectedByHold: matched - open };
      const u = await c.query(
        `UPDATE usage_events SET actor = 'anon_expired' WHERE ${w} AND NOT actor = ANY($2)`,
        [req.olderThan, prot],
      );
      return { matched, purged: u.rowCount ?? 0, protectedByHold: matched - open };
    });
  }
}
