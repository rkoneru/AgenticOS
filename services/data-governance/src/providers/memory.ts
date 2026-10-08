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
  PurgeRequest,
  PurgeResult,
  SubjectDataProvider,
} from "../types.js";
import { SUBJECT_KINDS, iso, vals } from "./util.js";

/** Memory service: `memory_chunks` and `memory_documents` (subject column; created_by authorship). */
export class MemoryProvider implements SubjectDataProvider {
  readonly id = "memory";
  readonly declaration: ProviderDeclaration = {
    exports: [
      "memory entries and knowledge-base chunks whose subject is the person (content, metadata, scope, timestamps; no embeddings)",
      "knowledge-base documents whose subject is the person",
    ],
    erases: ["chunks, documents (and, by cascade, their embeddings) whose `subject` is the person"],
    retains: [],
    pseudonymises: ["`created_by` of rows the person authored about someone else or about nothing"],
    dataClasses: ["memory"],
  };
  constructor(private readonly o: PgGovOptions) {}

  private subj(ids: readonly Identifier[]): string[] {
    return vals(ids, ...SUBJECT_KINDS);
  }
  private authors(ids: readonly Identifier[]): string[] {
    return vals(ids, "user_ref", "email", "end_user_id");
  }

  async find(ctx: ProviderContext, ids: readonly Identifier[]): Promise<FindResult> {
    return { count: (await this.count0(ctx, ids)).chunks + (await this.count0(ctx, ids)).docs };
  }

  private count0(
    ctx: ProviderContext,
    ids: readonly Identifier[],
  ): Promise<{ chunks: number; docs: number; authored: number }> {
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const s = this.subj(ids);
      const a = this.authors(ids);
      const q = async (sql: string, p: unknown[]): Promise<number> =>
        Number(((await c.query(sql, p)).rows[0] as { n: string }).n);
      return {
        chunks: await q("SELECT count(*) n FROM memory_chunks WHERE subject = ANY($1)", [s]),
        docs: await q("SELECT count(*) n FROM memory_documents WHERE subject = ANY($1)", [s]),
        authored: await q(
          "SELECT (SELECT count(*) FROM memory_chunks WHERE created_by = ANY($1) AND (subject IS NULL OR NOT subject = ANY($2))) + (SELECT count(*) FROM memory_documents WHERE created_by = ANY($1) AND (subject IS NULL OR NOT subject = ANY($2))) n",
          [a, s],
        ),
      };
    });
  }

  export(ctx: ProviderContext, ids: readonly Identifier[]): Promise<ExportCollection[]> {
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const s = this.subj(ids);
      const chunks = await c.query(
        "SELECT id, scope, owner_ref, content, metadata, subject, document_id, created_at FROM memory_chunks WHERE subject = ANY($1) ORDER BY created_at, id",
        [s],
      );
      const docs = await c.query(
        "SELECT id, kb_id, source, title, metadata, subject, created_at FROM memory_documents WHERE subject = ANY($1) ORDER BY created_at, id",
        [s],
      );
      return [
        {
          name: "memory_chunks",
          records: chunks.rows.map((r) => ({ ...r, created_at: iso(r.created_at) })),
        },
        {
          name: "memory_documents",
          records: docs.rows.map((r) => ({ ...r, created_at: iso(r.created_at) })),
        },
      ];
    });
  }

  async erase(ctx: ProviderContext, ids: readonly Identifier[]): Promise<EraseResult> {
    const authors = this.authors(ids);
    const tokens = new Map<string, string>();
    for (const a of authors) tokens.set(a, await ctx.pseudonym("user_ref", a));
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const s = this.subj(ids);
      const ch = await c.query("DELETE FROM memory_chunks WHERE subject = ANY($1)", [s]);
      const dc = await c.query("DELETE FROM memory_documents WHERE subject = ANY($1)", [s]);
      let pseud = 0;
      for (const [a, tok] of tokens) {
        pseud +=
          (
            await c.query("UPDATE memory_chunks SET created_by = $2 WHERE created_by = $1", [
              a,
              tok,
            ])
          ).rowCount ?? 0;
        pseud +=
          (
            await c.query("UPDATE memory_documents SET created_by = $2 WHERE created_by = $1", [
              a,
              tok,
            ])
          ).rowCount ?? 0;
      }
      return { erased: (ch.rowCount ?? 0) + (dc.rowCount ?? 0), pseudonymised: pseud, retained: 0 };
    });
  }

  async count(ctx: ProviderContext, ids: readonly Identifier[]): Promise<CountResult> {
    const k = await this.count0(ctx, ids);
    return { residual: k.chunks + k.docs + k.authored, retained: 0, pseudonymised: 0 };
  }

  async purge(ctx: ProviderContext, req: PurgeRequest): Promise<PurgeResult> {
    const prot = req.protect.subjects.flatMap((g) => vals(g, ...SUBJECT_KINDS));
    return governedTx(this.o, ctx.tenantId, async (c: ClientBase) => {
      const n = async (sql: string): Promise<number> =>
        Number(((await c.query(sql, [req.olderThan, prot])).rows[0] as { n: string }).n);
      const where = "created_at < $1 AND cardinality($2::text[]) >= 0";
      const guard = "(subject IS NULL OR NOT subject = ANY($2))";
      const matched =
        (await n(`SELECT count(*) n FROM memory_chunks WHERE ${where}`)) +
        (await n(`SELECT count(*) n FROM memory_documents WHERE ${where}`));
      const open =
        (await n(`SELECT count(*) n FROM memory_chunks WHERE ${where} AND ${guard}`)) +
        (await n(`SELECT count(*) n FROM memory_documents WHERE ${where} AND ${guard}`));
      if (req.dryRun) return { matched, purged: 0, protectedByHold: matched - open };
      const a = await c.query(`DELETE FROM memory_chunks WHERE ${where} AND ${guard}`, [
        req.olderThan,
        prot,
      ]);
      const b = await c.query(`DELETE FROM memory_documents WHERE ${where} AND ${guard}`, [
        req.olderThan,
        prot,
      ]);
      return {
        matched,
        purged: (a.rowCount ?? 0) + (b.rowCount ?? 0),
        protectedByHold: matched - open,
      };
    });
  }
}
