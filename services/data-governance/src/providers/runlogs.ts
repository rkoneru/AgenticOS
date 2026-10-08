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

/** Top-level keys of `runs.input` / `run_events.data` that name the person on whose behalf a run executed (documented convention). */
export const SUBJECT_KEYS = [
  "subject",
  "subject_ref",
  "principal",
  "end_user_id",
  "user_ref",
  "email",
  "requested_by",
];
const ERASED = JSON.stringify({ governance: "erased" });
const PURGED = JSON.stringify({ governance: "purged" });

/**
 * Run logs (`runs`, `run_events`): rows are immutable and gapless, so erasure SCRUBS the payload (`input`, `data`) and keeps the row
 * skeleton (ids, sequence, type, pid, audit_event_id, timestamps). Only the governance role can do this (trigger 0020).
 */
export class RunLogsProvider implements SubjectDataProvider {
  readonly id = "run-logs";
  readonly declaration: ProviderDeclaration = {
    exports: [
      "runs whose input names the person (input, state, timestamps) and the payload of their events",
    ],
    erases: ["`runs.input` and `run_events.data` of those runs (scrubbed to a marker)"],
    retains: [
      {
        what: "run and event skeleton: ids, sequence, event type, pid, audit event reference, timestamps",
        legalBasis:
          "event-sourced replay integrity and accountability (GDPR Art. 17(3)(e)); contains no personal data",
      },
    ],
    pseudonymises: [],
    dataClasses: ["run_logs"],
  };
  constructor(private readonly o: PgGovOptions) {}

  private values(ids: readonly Identifier[]): string[] {
    const v = vals(ids, ...SUBJECT_KINDS);
    return [
      ...v,
      ...vals(ids, "end_user_id").map((e) => `enduser:${e}`),
      ...vals(ids, "user_ref").map((u) => `user:${u}`),
    ];
  }
  private static RUN = `EXISTS (SELECT 1 FROM jsonb_each_text(r.input) e WHERE e.key = ANY($2) AND e.value = ANY($1))`;
  private static EV = `EXISTS (SELECT 1 FROM jsonb_each_text(ev.data) e WHERE e.key = ANY($2) AND e.value = ANY($1))`;

  private runIds(c: import("pg").ClientBase, ids: readonly Identifier[]): Promise<string[]> {
    return c
      .query(`SELECT id::text FROM runs r WHERE ${RunLogsProvider.RUN}`, [
        this.values(ids),
        SUBJECT_KEYS,
      ])
      .then((q) => q.rows.map((r: { id: string }) => r.id));
  }

  find(ctx: ProviderContext, ids: readonly Identifier[]): Promise<FindResult> {
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const runs = await this.runIds(c, ids);
      const ev = Number(
        (
          (
            await c.query(`SELECT count(*) n FROM run_events ev WHERE ${RunLogsProvider.EV}`, [
              this.values(ids),
              SUBJECT_KEYS,
            ])
          ).rows[0] as { n: string }
        ).n,
      );
      return { count: runs.length + ev };
    });
  }

  export(ctx: ProviderContext, ids: readonly Identifier[]): Promise<ExportCollection[]> {
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const runs = await c.query(
        `SELECT id, blueprint_name, blueprint_version, state, exit_reason, input, created_at, finished_at FROM runs r WHERE ${RunLogsProvider.RUN} ORDER BY created_at, id`,
        [this.values(ids), SUBJECT_KEYS],
      );
      const ev = await c.query(
        `SELECT run_id, sequence, type, data, at FROM run_events ev WHERE run_id = ANY($3::uuid[]) OR ${RunLogsProvider.EV} ORDER BY run_id, sequence`,
        [this.values(ids), SUBJECT_KEYS, runs.rows.map((r: { id: string }) => r.id)],
      );
      return [
        {
          name: "runs",
          records: runs.rows.map((r) => ({
            ...r,
            created_at: iso(r.created_at),
            finished_at: iso(r.finished_at),
          })),
        },
        { name: "run_events", records: ev.rows.map((r) => ({ ...r, at: iso(r.at) })) },
      ];
    });
  }

  erase(ctx: ProviderContext, ids: readonly Identifier[]): Promise<EraseResult> {
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const v = this.values(ids);
      const runs = await this.runIds(c, ids);
      const e1 = await c.query(
        "UPDATE run_events SET data = $3::jsonb WHERE run_id = ANY($1::uuid[]) AND data <> $3::jsonb",
        [runs, 0, ERASED],
      );
      const e2 = await c.query(
        `UPDATE run_events ev SET data = $3::jsonb WHERE ${RunLogsProvider.EV} AND data <> $3::jsonb`,
        [v, SUBJECT_KEYS, ERASED],
      );
      const r = await c.query(
        "UPDATE runs SET input = $2::jsonb WHERE id = ANY($1::uuid[]) AND input <> $2::jsonb",
        [runs, ERASED],
      );
      return {
        erased: (r.rowCount ?? 0) + (e1.rowCount ?? 0) + (e2.rowCount ?? 0),
        pseudonymised: 0,
        retained: 0,
      };
    });
  }

  async count(ctx: ProviderContext, ids: readonly Identifier[]): Promise<CountResult> {
    const f = await this.find(ctx, ids);
    return { residual: f.count, retained: 0, pseudonymised: 0 };
  }

  async purge(ctx: ProviderContext, req: PurgeRequest): Promise<PurgeResult> {
    const prot = req.protect.subjects.flatMap((g) => this.values(g));
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const old = `r.state = 'terminated' AND r.created_at < $1 AND r.input <> $3::jsonb AND r.input <> $4::jsonb`;
      const protectedRun = `EXISTS (SELECT 1 FROM jsonb_each_text(r.input) e WHERE e.key = ANY($5) AND e.value = ANY($2))`;
      const p = [req.olderThan, prot, ERASED, PURGED, SUBJECT_KEYS];
      const matched = Number(
        ((await c.query(`SELECT count(*) n FROM runs r WHERE ${old}`, p)).rows[0] as { n: string })
          .n,
      );
      const open = Number(
        (
          (await c.query(`SELECT count(*) n FROM runs r WHERE ${old} AND NOT ${protectedRun}`, p))
            .rows[0] as { n: string }
        ).n,
      );
      if (req.dryRun) return { matched, purged: 0, protectedByHold: matched - open };
      await c.query(
        `UPDATE run_events SET data = $4::jsonb WHERE data <> $4::jsonb AND run_id IN (SELECT r.id FROM runs r WHERE ${old} AND NOT ${protectedRun})`,
        p,
      );
      const u = await c.query(
        `UPDATE runs r SET input = $4::jsonb WHERE ${old} AND NOT ${protectedRun}`,
        p,
      );
      return { matched, purged: u.rowCount ?? 0, protectedByHold: matched - open };
    });
  }
}
