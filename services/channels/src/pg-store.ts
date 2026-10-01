import { withTenant } from "@axis/db";
import type { ClientBase, PoolClient } from "pg";
import type {
  Conversation,
  ConversationStore,
  Identity,
  NewMessage,
  RedeemResult,
  StoredMessage,
} from "./store.js";
import { ChannelError, type AgentRef, type ChannelId } from "./types.js";

export interface PgPoolLike {
  connect(): Promise<PoolClient>;
}

export interface PgConversationStoreOptions {
  pool: PgPoolLike;
  /** Tests only: `SET LOCAL ROLE` per transaction (production connects as axis_app). */
  role?: string;
}

type Row = Record<string, unknown>;
const MS = (col: string): string => `(extract(epoch from ${col}) * 1000)::float8`;

const identityOf = (r: Row): Identity => ({
  id: r["id"] as string,
  tenant_id: r["tenant_id"] as string,
  end_user_id: r["end_user_id"] as string,
  channel: r["channel"] as ChannelId,
  external_id: r["external_id"] as string,
  verified_by: r["verified_by"] as Identity["verified_by"],
});
const convOf = (r: Row): Conversation => ({
  id: r["id"] as string,
  tenant_id: r["tenant_id"] as string,
  end_user_id: r["end_user_id"] as string,
  agent: { name: r["agent_name"] as string, version: r["agent_version"] as string },
  status: r["status"] as Conversation["status"],
  last_channel: r["last_channel"] as ChannelId,
  created_at_ms: Number(r["created_ms"]),
  updated_at_ms: Number(r["updated_ms"]),
});
const msgOf = (r: Row): StoredMessage => ({
  id: r["id"] as string,
  tenant_id: r["tenant_id"] as string,
  conversation_id: r["conversation_id"] as string,
  direction: r["direction"] as "in" | "out",
  channel: r["channel"] as ChannelId,
  idempotency_key: r["idempotency_key"] as string,
  content_mode: r["content_mode"] as StoredMessage["content_mode"],
  content: (r["content"] as string | null) ?? null,
  content_hash: r["content_hash"] as string,
  size_bytes: r["size_bytes"] as number,
  attachments: r["attachments"] as StoredMessage["attachments"],
  audit_event_id: (r["audit_event_id"] as string | null) ?? null,
  audit_hash: (r["audit_hash"] as string | null) ?? null,
  created_at_ms: Number(r["created_ms"]),
});

const CONV_COLS = `tenant_id, id, end_user_id, agent_name, agent_version, status, last_channel,
  ${MS("created_at")} AS created_ms, ${MS("updated_at")} AS updated_ms`;
const MSG_COLS = `tenant_id, id, conversation_id, direction, channel, idempotency_key, content_mode, content, content_hash,
  size_bytes, attachments, audit_event_id, audit_hash, ${MS("created_at")} AS created_ms`;

/** Postgres store. Every statement runs inside `withTenant`: the tenant is set transaction-locally and FORCED RLS does the rest. */
export class PgConversationStore implements ConversationStore {
  constructor(private readonly o: PgConversationStoreOptions) {}

  private async tx<T>(tenant: string, fn: (c: ClientBase) => Promise<T>): Promise<T> {
    const client = await this.o.pool.connect();
    try {
      return await withTenant(client, tenant, fn, this.o.role ? { role: this.o.role } : {});
    } finally {
      client.release();
    }
  }

  private async getIdentity(
    c: ClientBase,
    tenant: string,
    channel: ChannelId,
    ext: string,
  ): Promise<Identity | undefined> {
    const { rows } = await c.query(
      "SELECT * FROM channel_identities WHERE tenant_id = $1 AND channel = $2 AND external_id = $3",
      [tenant, channel, ext],
    );
    return rows[0] ? identityOf(rows[0]) : undefined;
  }

  private async resolveIn(c: ClientBase, tenant: string, channel: ChannelId, ext: string) {
    const found = await this.getIdentity(c, tenant, channel, ext);
    if (found) return { identity: found, created: false };
    // An orphan end user is possible if two first messages race (the loser's row stays empty); it carries no identity or data.
    const eu = await c.query("INSERT INTO end_users (tenant_id) VALUES ($1) RETURNING id", [
      tenant,
    ]);
    const ins = await c.query(
      `INSERT INTO channel_identities (tenant_id, end_user_id, channel, external_id, verified_by)
       VALUES ($1, $2, $3, $4, 'provider') ON CONFLICT (tenant_id, channel, external_id) DO NOTHING RETURNING *`,
      [tenant, eu.rows[0].id, channel, ext],
    );
    if (ins.rows[0]) return { identity: identityOf(ins.rows[0]), created: true };
    return { identity: (await this.getIdentity(c, tenant, channel, ext))!, created: false };
  }

  resolveIdentity(tenant: string, channel: ChannelId, externalId: string) {
    return this.tx(tenant, (c) => this.resolveIn(c, tenant, channel, externalId));
  }

  findIdentity(tenant: string, channel: ChannelId, externalId: string) {
    return this.tx(tenant, (c) => this.getIdentity(c, tenant, channel, externalId));
  }

  identitiesOf(tenant: string, endUserId: string) {
    return this.tx(tenant, async (c) => {
      const { rows } = await c.query(
        "SELECT * FROM channel_identities WHERE tenant_id = $1 AND end_user_id = $2 ORDER BY created_at",
        [tenant, endUserId],
      );
      return rows.map(identityOf);
    });
  }

  createChallenge(tenant: string, endUserId: string, codeHash: string, expiresAtMs: number) {
    return this.tx(tenant, async (c) => {
      try {
        await c.query(
          "INSERT INTO link_challenges (tenant_id, end_user_id, code_hash, expires_at) VALUES ($1, $2, $3, to_timestamp($4 / 1000.0))",
          [tenant, endUserId, codeHash, expiresAtMs],
        );
      } catch (e) {
        if ((e as { code?: string }).code === "23503")
          throw new ChannelError("NOT_FOUND", "unknown end user");
        throw e;
      }
    });
  }

  redeemChallenge(
    tenant: string,
    codeHash: string,
    nowMs: number,
    redeemer: { channel: ChannelId; externalId: string },
  ): Promise<RedeemResult> {
    return this.tx(tenant, async (c): Promise<RedeemResult> => {
      const ch = await c.query(
        `SELECT id, end_user_id, consumed_at IS NOT NULL AS consumed, expires_at <= to_timestamp($2 / 1000.0) AS expired
           FROM link_challenges WHERE tenant_id = $1 AND code_hash = $3 FOR UPDATE`,
        [tenant, nowMs, codeHash],
      );
      const row = ch.rows[0];
      if (!row) return { ok: false, reason: "invalid" };
      if (row.consumed) return { ok: false, reason: "consumed" };
      if (row.expired) return { ok: false, reason: "expired" };
      await c.query(
        "UPDATE link_challenges SET consumed_at = now() WHERE tenant_id = $1 AND id = $2",
        [tenant, row.id],
      );
      const target = row.end_user_id as string;
      const { identity } = await this.resolveIn(c, tenant, redeemer.channel, redeemer.externalId);
      if (identity.end_user_id === target)
        return {
          ok: true,
          end_user_id: target,
          identity,
          moved_conversations: 0,
          already_linked: true,
        };
      const from = identity.end_user_id;
      const up = await c.query(
        "UPDATE channel_identities SET end_user_id = $3, verified_by = 'link' WHERE tenant_id = $1 AND id = $2 RETURNING *",
        [tenant, identity.id, target],
      );
      const left = await c.query(
        "SELECT 1 FROM channel_identities WHERE tenant_id = $1 AND end_user_id = $2 LIMIT 1",
        [tenant, from],
      );
      let moved = 0;
      if (left.rowCount === 0) {
        const m = await c.query(
          "UPDATE conversations SET end_user_id = $3 WHERE tenant_id = $1 AND end_user_id = $2",
          [tenant, from, target],
        );
        moved = m.rowCount ?? 0;
      }
      return {
        ok: true,
        end_user_id: target,
        identity: identityOf(up.rows[0]),
        moved_conversations: moved,
        already_linked: false,
      };
    });
  }

  findOpenConversation(tenant: string, endUserId: string, agentName: string) {
    return this.tx(tenant, async (c) => {
      const { rows } = await c.query(
        `SELECT ${CONV_COLS} FROM conversations WHERE tenant_id = $1 AND end_user_id = $2 AND agent_name = $3 AND status = 'open'
          ORDER BY updated_at DESC LIMIT 1`,
        [tenant, endUserId, agentName],
      );
      return rows[0] ? convOf(rows[0]) : undefined;
    });
  }

  findByThread(tenant: string, channel: ChannelId, threadKey: string) {
    return this.tx(tenant, async (c) => {
      const t = await c.query(
        "SELECT conversation_id FROM conversation_threads WHERE tenant_id = $1 AND channel = $2 AND thread_key = $3",
        [tenant, channel, threadKey],
      );
      if (!t.rows[0]) return undefined;
      const { rows } = await c.query(
        `SELECT ${CONV_COLS} FROM conversations WHERE tenant_id = $1 AND id = $2`,
        [tenant, t.rows[0].conversation_id],
      );
      return rows[0] ? convOf(rows[0]) : undefined;
    });
  }

  getConversation(tenant: string, id: string) {
    return this.tx(tenant, async (c) => {
      const { rows } = await c.query(
        `SELECT ${CONV_COLS} FROM conversations WHERE tenant_id = $1 AND id = $2`,
        [tenant, id],
      );
      return rows[0] ? convOf(rows[0]) : undefined;
    });
  }

  createConversation(tenant: string, endUserId: string, agent: AgentRef, channel: ChannelId) {
    return this.tx(tenant, async (c) => {
      try {
        const { rows } = await c.query(
          `INSERT INTO conversations (tenant_id, end_user_id, agent_name, agent_version, last_channel)
           VALUES ($1, $2, $3, $4, $5) RETURNING ${CONV_COLS}`,
          [tenant, endUserId, agent.name, agent.version, channel],
        );
        return convOf(rows[0]);
      } catch (e) {
        if ((e as { code?: string }).code === "23503")
          throw new ChannelError("NOT_FOUND", "unknown end user");
        throw e;
      }
    });
  }

  touchConversation(tenant: string, id: string, channel: ChannelId) {
    return this.tx(tenant, async (c) => {
      await c.query(
        "UPDATE conversations SET updated_at = now(), last_channel = $3 WHERE tenant_id = $1 AND id = $2",
        [tenant, id, channel],
      );
    });
  }

  addThread(tenant: string, channel: ChannelId, threadKey: string, conversationId: string) {
    return this.tx(tenant, async (c) => {
      try {
        await c.query(
          "INSERT INTO conversation_threads (tenant_id, channel, thread_key, conversation_id) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
          [tenant, channel, threadKey, conversationId],
        );
      } catch (e) {
        if ((e as { code?: string }).code === "23503")
          throw new ChannelError("NOT_FOUND", "unknown conversation");
        throw e;
      }
    });
  }

  lastThread(tenant: string, conversationId: string, channel: ChannelId) {
    return this.tx(tenant, async (c) => {
      const { rows } = await c.query(
        "SELECT thread_key FROM conversation_threads WHERE tenant_id = $1 AND conversation_id = $2 AND channel = $3 ORDER BY created_at DESC, thread_key LIMIT 1",
        [tenant, conversationId, channel],
      );
      return (rows[0]?.thread_key as string | undefined) ?? undefined;
    });
  }

  appendMessage(tenant: string, m: NewMessage) {
    return this.tx(tenant, async (c) => {
      try {
        const ins = await c.query(
          `INSERT INTO conversation_messages (tenant_id, conversation_id, direction, channel, idempotency_key, content_mode, content,
             content_hash, size_bytes, attachments, audit_event_id, audit_hash)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12)
           ON CONFLICT (tenant_id, channel, direction, idempotency_key) DO NOTHING RETURNING ${MSG_COLS}`,
          [
            tenant,
            m.conversation_id,
            m.direction,
            m.channel,
            m.idempotency_key,
            m.content_mode,
            m.content,
            m.content_hash,
            m.size_bytes,
            JSON.stringify(m.attachments),
            m.audit_event_id,
            m.audit_hash,
          ],
        );
        if (ins.rows[0]) return { inserted: true, message: msgOf(ins.rows[0]) };
      } catch (e) {
        if ((e as { code?: string }).code === "23503")
          throw new ChannelError("NOT_FOUND", "unknown conversation");
        throw e;
      }
      const { rows } = await c.query(
        `SELECT ${MSG_COLS} FROM conversation_messages WHERE tenant_id = $1 AND channel = $2 AND direction = $3 AND idempotency_key = $4`,
        [tenant, m.channel, m.direction, m.idempotency_key],
      );
      return { inserted: false, message: msgOf(rows[0]) };
    });
  }

  messages(tenant: string, conversationId: string, limit = 100) {
    return this.tx(tenant, async (c) => {
      const { rows } = await c.query(
        `SELECT * FROM (SELECT ${MSG_COLS} FROM conversation_messages WHERE tenant_id = $1 AND conversation_id = $2
           ORDER BY created_at DESC, id LIMIT $3) s ORDER BY created_ms, id`,
        [tenant, conversationId, limit],
      );
      return rows.map(msgOf);
    });
  }
}
