import type { ClientBase } from "pg";
import { governedTx, type PgGovOptions } from "../store.js";
import type {
  CountResult,
  EraseResult,
  ExportCollection,
  FindResult,
  Identifier,
  ProviderContext,
  ProviderDeclaration,
  SubjectDataProvider,
} from "../types.js";
import { iso, vals } from "./util.js";

/** The slice of `@axis/approvals`' request the provider reads and rewrites. */
export interface ApprovalLike {
  id: string;
  version: number;
  requester: { type: string; id: string; pid?: string };
  conflicted: string[];
  claimed_by: string | null;
  decided_by: string | null;
  comment: string | null;
  reason: string | null;
}
/** Structural port; `ApprovalStore` satisfies it. */
export interface ApprovalsPort {
  list(tenantId: string, filter: { limit: number }): Promise<ApprovalLike[]>;
  compareAndSet(next: never, expectedVersion: number): Promise<boolean>;
}

const names = (a: ApprovalLike): string[] => [
  a.requester.id,
  a.claimed_by ?? "",
  a.decided_by ?? "",
  ...a.conflicted,
];

/**
 * Approvals: requester/approver references. Decisions are accountability records, so they are PSEUDONYMISED (ids replaced by keyed tokens,
 * free-text comment/reason removed), not deleted. Covers the in-memory service store (port) and the `approvals` table (decided_by, comment).
 */
export class ApprovalsProvider implements SubjectDataProvider {
  readonly id = "approvals";
  readonly declaration: ProviderDeclaration = {
    exports: [
      "approval requests where the person is requester, claimer, approver or conflicted (ids, tool, risk, status, timestamps, comment)",
    ],
    erases: ["free-text comment and reason of those approvals"],
    retains: [
      {
        what: "approval decision records (tool, args hash, status, timestamps)",
        legalBasis:
          "accountability for risky actions (GDPR Art. 17(3)(e)); the actor id is pseudonymised",
      },
    ],
    pseudonymises: ["requester, claimed_by, decided_by and conflicted ids"],
    dataClasses: ["run_logs"],
  };
  constructor(private readonly src: { pg?: PgGovOptions; store?: ApprovalsPort; limit?: number }) {}

  private who(ids: readonly Identifier[]): Set<string> {
    return new Set(vals(ids, "user_ref", "email", "subject_key", "end_user_id"));
  }
  private async mem(ctx: ProviderContext, w: Set<string>): Promise<ApprovalLike[]> {
    if (!this.src.store) return [];
    return (await this.src.store.list(ctx.tenantId, { limit: this.src.limit ?? 1000 })).filter(
      (a) => names(a).some((n) => w.has(n)),
    );
  }
  private pg<T>(ctx: ProviderContext, fn: (c: ClientBase) => Promise<T>): Promise<T | undefined> {
    return this.src.pg ? governedTx(this.src.pg, ctx.tenantId, fn) : Promise.resolve(undefined);
  }

  async find(ctx: ProviderContext, ids: readonly Identifier[]): Promise<FindResult> {
    const w = this.who(ids);
    const m = (await this.mem(ctx, w)).length;
    const p =
      (await this.pg(ctx, async (c) =>
        Number(
          (
            (await c.query("SELECT count(*) n FROM approvals WHERE decided_by = ANY($1)", [[...w]]))
              .rows[0] as { n: string }
          ).n,
        ),
      )) ?? 0;
    return { count: m + p };
  }

  async export(ctx: ProviderContext, ids: readonly Identifier[]): Promise<ExportCollection[]> {
    const w = this.who(ids);
    const mem = (await this.mem(ctx, w)).map((a) => ({ ...a }));
    const tbl =
      (await this.pg(ctx, async (c) =>
        (
          await c.query(
            "SELECT id, run_id, action, status, requested_at, decided_by, decided_at, comment FROM approvals WHERE decided_by = ANY($1) ORDER BY requested_at, id",
            [[...w]],
          )
        ).rows.map((r) => ({
          ...r,
          requested_at: iso(r.requested_at),
          decided_at: iso(r.decided_at),
        })),
      )) ?? [];
    return [
      { name: "approval_requests", records: mem },
      { name: "approvals_table", records: tbl },
    ];
  }

  async erase(ctx: ProviderContext, ids: readonly Identifier[]): Promise<EraseResult> {
    const w = this.who(ids);
    let n = 0;
    for (const a of await this.mem(ctx, w)) {
      const sw = async (v: string | null): Promise<string | null> =>
        v !== null && w.has(v) ? ctx.pseudonym("user_ref", v) : v;
      const next = {
        ...a,
        requester: { ...a.requester, id: (await sw(a.requester.id)) as string },
        claimed_by: await sw(a.claimed_by),
        decided_by: await sw(a.decided_by),
        conflicted: await Promise.all(a.conflicted.map(async (x) => (await sw(x)) as string)),
        comment: null,
        reason: null,
        version: a.version + 1,
      };
      if (await (this.src.store as ApprovalsPort).compareAndSet(next as never, a.version)) n++;
    }
    const pgRes = await this.pg(ctx, async (c) => {
      const { rows } = await c.query(
        "SELECT id, decided_by FROM approvals WHERE decided_by = ANY($1)",
        [[...w]],
      );
      for (const r of rows as { id: string; decided_by: string }[])
        await c.query("UPDATE approvals SET decided_by = $2, comment = NULL WHERE id = $1", [
          r.id,
          await ctx.pseudonym("user_ref", r.decided_by),
        ]);
      return rows.length;
    });
    const total = n + (pgRes ?? 0);
    return { erased: 0, pseudonymised: total, retained: total };
  }

  async count(ctx: ProviderContext, ids: readonly Identifier[]): Promise<CountResult> {
    const f = await this.find(ctx, ids);
    return { residual: f.count, retained: 0, pseudonymised: 0 };
  }
}
