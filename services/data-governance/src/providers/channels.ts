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
import { iso, onlyUuids, vals } from "./util.js";

/** The end users a set of identifiers points at: direct end_user_id, or any channel identity whose external id / "channel:external" matches. */
async function endUsers(c: ClientBase, ids: readonly Identifier[]): Promise<string[]> {
  const direct = onlyUuids(vals(ids, "end_user_id"));
  const ext = vals(ids, "email", "phone", "user_ref", "subject_key");
  const pairs = vals(ids, "channel_identity");
  const { rows } = await c.query(
    `SELECT DISTINCT end_user_id::text id FROM channel_identities
      WHERE end_user_id = ANY($1::uuid[]) OR external_id = ANY($2) OR (channel || ':' || external_id) = ANY($3)`,
    [direct, ext, pairs],
  );
  return [...new Set([...direct, ...rows.map((r: { id: string }) => r.id)])];
}

const VOICE = "voice";

/**
 * Channels: end users, channel identities, conversations, threads, messages. `voiceOnly` selects the voice-transcript view of the same
 * tables (messages with channel = 'voice'). The non-voice provider erases voice messages too when it deletes a conversation (FK),
 * and declares both classes so a hold on either suspends it.
 */
export class ChannelsProvider implements SubjectDataProvider {
  readonly id: string;
  readonly declaration: ProviderDeclaration;
  constructor(
    private readonly o: PgGovOptions,
    private readonly voiceOnly = false,
  ) {
    this.id = voiceOnly ? "voice-transcripts" : "channels";
    this.declaration = voiceOnly
      ? {
          exports: [
            "voice call transcript messages (text only when the tenant's transcript policy stored it; always the content hash and size)",
          ],
          erases: ["voice transcript messages of the person's conversations"],
          retains: [],
          pseudonymises: [],
          dataClasses: ["transcripts"],
        }
      : {
          exports: [
            "end user record, channel identities, conversations, provider threads and messages (all channels incl. voice)",
          ],
          erases: [
            "messages, threads, conversations, link challenges, channel identities and the end user",
          ],
          retains: [
            {
              what: "audit events about the conversation (hashes and pseudonymous references only)",
              legalBasis:
                "GDPR Art. 17(3)(b)/(e) and security accountability; contains no personal data",
            },
          ],
          pseudonymises: [],
          dataClasses: ["conversation", "transcripts"],
        };
  }

  async find(ctx: ProviderContext, ids: readonly Identifier[]): Promise<FindResult> {
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const eu = await endUsers(c, ids);
      const { rows } = await c.query(
        "SELECT channel, external_id FROM channel_identities WHERE end_user_id = ANY($1::uuid[])",
        [eu],
      );
      const discovered: Identifier[] = [
        ...eu.map((v) => ({ kind: "end_user_id" as const, value: v })),
        ...rows.map((r: { channel: string; external_id: string }) => ({
          kind: "channel_identity" as const,
          value: `${r.channel}:${r.external_id}`,
        })),
      ];
      return { count: (await this.counts(c, eu)).total, discovered };
    });
  }

  private async counts(c: ClientBase, eu: string[]): Promise<{ total: number }> {
    const q = async (sql: string): Promise<number> =>
      Number(
        ((await c.query(sql, sql.includes("$2") ? [eu, VOICE] : [eu])).rows[0] as { n: string }).n,
      );
    const msg = this.voiceOnly
      ? "SELECT count(*) n FROM conversation_messages WHERE channel = $2 AND conversation_id IN (SELECT id FROM conversations WHERE end_user_id = ANY($1::uuid[]))"
      : "SELECT count(*) n FROM conversation_messages WHERE conversation_id IN (SELECT id FROM conversations WHERE end_user_id = ANY($1::uuid[]))";
    if (this.voiceOnly) return { total: await q(msg) };
    return {
      total:
        (await q(msg)) +
        (await q("SELECT count(*) n FROM conversations WHERE end_user_id = ANY($1::uuid[])")) +
        (await q("SELECT count(*) n FROM channel_identities WHERE end_user_id = ANY($1::uuid[])")) +
        (await q("SELECT count(*) n FROM end_users WHERE id = ANY($1::uuid[])")) +
        (await q("SELECT count(*) n FROM link_challenges WHERE end_user_id = ANY($1::uuid[])")),
    };
  }

  export(ctx: ProviderContext, ids: readonly Identifier[]): Promise<ExportCollection[]> {
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const eu = await endUsers(c, ids);
      const msgs = await c.query(
        `SELECT id, conversation_id, direction, channel, content_mode, content, content_hash, size_bytes, attachments, created_at
           FROM conversation_messages WHERE conversation_id IN (SELECT id FROM conversations WHERE end_user_id = ANY($1::uuid[]))
            AND ($3::boolean = false OR channel = $2) ORDER BY created_at, id`,
        [eu, VOICE, this.voiceOnly],
      );
      const cols: ExportCollection[] = [
        {
          name: this.voiceOnly ? "voice_transcript_messages" : "messages",
          records: msgs.rows.map((r) => ({ ...r, created_at: iso(r.created_at) })),
        },
      ];
      if (!this.voiceOnly) {
        const idn = await c.query(
          "SELECT id, end_user_id, channel, external_id, verified_by, created_at FROM channel_identities WHERE end_user_id = ANY($1::uuid[]) ORDER BY id",
          [eu],
        );
        const cv = await c.query(
          "SELECT id, end_user_id, agent_name, agent_version, status, last_channel, created_at FROM conversations WHERE end_user_id = ANY($1::uuid[]) ORDER BY id",
          [eu],
        );
        cols.push(
          {
            name: "channel_identities",
            records: idn.rows.map((r) => ({ ...r, created_at: iso(r.created_at) })),
          },
          {
            name: "conversations",
            records: cv.rows.map((r) => ({ ...r, created_at: iso(r.created_at) })),
          },
        );
      }
      return cols;
    });
  }

  erase(ctx: ProviderContext, ids: readonly Identifier[]): Promise<EraseResult> {
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const eu = await endUsers(c, ids);
      const del = async (sql: string, p: unknown[] = [eu, VOICE]): Promise<number> =>
        (await c.query(sql, p)).rowCount ?? 0;
      let n = 0;
      if (this.voiceOnly) {
        n += await del(
          "DELETE FROM conversation_messages WHERE channel = $2 AND conversation_id IN (SELECT id FROM conversations WHERE end_user_id = ANY($1::uuid[]))",
        );
      } else {
        n += await del(
          "DELETE FROM conversation_messages WHERE conversation_id IN (SELECT id FROM conversations WHERE end_user_id = ANY($1::uuid[]))",
          [eu],
        );
        n += await del(
          "DELETE FROM conversation_threads WHERE conversation_id IN (SELECT id FROM conversations WHERE end_user_id = ANY($1::uuid[]))",
          [eu],
        );
        n += await del("DELETE FROM conversations WHERE end_user_id = ANY($1::uuid[])", [eu]);
        n += await del("DELETE FROM link_challenges WHERE end_user_id = ANY($1::uuid[])", [eu]);
        n += await del("DELETE FROM channel_identities WHERE end_user_id = ANY($1::uuid[])", [eu]);
        n += await del("DELETE FROM end_users WHERE id = ANY($1::uuid[])", [eu]);
      }
      return { erased: n, pseudonymised: 0, retained: 0 };
    });
  }

  async count(ctx: ProviderContext, ids: readonly Identifier[]): Promise<CountResult> {
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const eu = await endUsers(c, ids);
      return { residual: (await this.counts(c, eu)).total, retained: 0, pseudonymised: 0 };
    });
  }

  async purge(ctx: ProviderContext, req: PurgeRequest): Promise<PurgeResult> {
    const wantVoice = req.dataClass === "transcripts";
    if (this.voiceOnly && !wantVoice) return { matched: 0, purged: 0, protectedByHold: 0 };
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const prot: string[] = [];
      for (const g of req.protect.subjects) prot.push(...(await endUsers(c, g)));
      // wantVoice: only voice messages; otherwise (conversation class): everything that is not voice.
      const cond = wantVoice ? "m.channel = $3" : "m.channel <> $3";
      const base = `FROM conversation_messages m JOIN conversations v ON v.tenant_id = m.tenant_id AND v.id = m.conversation_id
                     WHERE m.created_at < $1 AND cardinality($2::uuid[]) >= 0 AND ${cond}`;
      const matched = Number(
        (
          (await c.query(`SELECT count(*) n ${base}`, [req.olderThan, prot, VOICE])).rows[0] as {
            n: string;
          }
        ).n,
      );
      const open = Number(
        (
          (
            await c.query(`SELECT count(*) n ${base} AND NOT v.end_user_id = ANY($2::uuid[])`, [
              req.olderThan,
              prot,
              VOICE,
            ])
          ).rows[0] as { n: string }
        ).n,
      );
      if (req.dryRun) return { matched, purged: 0, protectedByHold: matched - open };
      const d = await c.query(
        `DELETE FROM conversation_messages WHERE (tenant_id, id) IN (SELECT m.tenant_id, m.id ${base} AND NOT v.end_user_id = ANY($2::uuid[]))`,
        [req.olderThan, prot, VOICE],
      );
      if (!wantVoice) {
        // empty, old conversations (and their threads) go too
        await c.query(
          `DELETE FROM conversation_threads WHERE conversation_id IN (SELECT id FROM conversations v WHERE v.updated_at < $1 AND NOT v.end_user_id = ANY($2::uuid[])
             AND NOT EXISTS (SELECT 1 FROM conversation_messages m WHERE m.conversation_id = v.id))`,
          [req.olderThan, prot],
        );
        await c.query(
          `DELETE FROM conversations v WHERE v.updated_at < $1 AND NOT v.end_user_id = ANY($2::uuid[])
             AND NOT EXISTS (SELECT 1 FROM conversation_messages m WHERE m.conversation_id = v.id)`,
          [req.olderThan, prot],
        );
      }
      return { matched, purged: d.rowCount ?? 0, protectedByHold: matched - open };
    });
  }
}
