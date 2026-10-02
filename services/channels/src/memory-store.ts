import { randomUUID } from "node:crypto";
import type {
  Conversation,
  ConversationStore,
  Identity,
  NewMessage,
  RedeemResult,
  StoredMessage,
} from "./store.js";
import { ChannelError, type AgentRef, type ChannelId } from "./types.js";

interface TenantState {
  endUsers: Set<string>;
  identities: Map<string, Identity>; // channel\0external -> identity
  challenges: Map<string, { end_user_id: string; expires_at_ms: number; consumed: boolean }>;
  conversations: Map<string, Conversation>;
  threads: Map<string, { conversation_id: string; seq: number }>; // channel\0key
  messages: Map<string, StoredMessage[]>; // conversation -> messages
  dedupe: Map<string, StoredMessage>;
}

/** In-memory store behind the same port. Tenant state is a separate object per tenant: there is no code path across tenants. */
export class MemoryConversationStore implements ConversationStore {
  private readonly tenants = new Map<string, TenantState>();
  private threadSeq = 0;

  constructor(private readonly now: () => number = Date.now) {}

  private t(tenant: string): TenantState {
    if (!tenant) throw new ChannelError("INVALID", "tenant is required");
    let s = this.tenants.get(tenant);
    if (!s) {
      s = {
        endUsers: new Set(),
        identities: new Map(),
        challenges: new Map(),
        conversations: new Map(),
        threads: new Map(),
        messages: new Map(),
        dedupe: new Map(),
      };
      this.tenants.set(tenant, s);
    }
    return s;
  }

  async resolveIdentity(tenant: string, channel: ChannelId, externalId: string) {
    const s = this.t(tenant);
    const k = `${channel}\u0000${externalId}`;
    const found = s.identities.get(k);
    if (found) return { identity: { ...found }, created: false };
    const endUser = randomUUID();
    s.endUsers.add(endUser);
    const identity: Identity = {
      id: randomUUID(),
      tenant_id: tenant,
      end_user_id: endUser,
      channel,
      external_id: externalId,
      verified_by: "provider",
    };
    s.identities.set(k, identity);
    return { identity: { ...identity }, created: true };
  }

  async findIdentity(tenant: string, channel: ChannelId, externalId: string) {
    const i = this.t(tenant).identities.get(`${channel}\u0000${externalId}`);
    return i && { ...i };
  }

  async identitiesOf(tenant: string, endUserId: string) {
    return [...this.t(tenant).identities.values()]
      .filter((i) => i.end_user_id === endUserId)
      .map((i) => ({ ...i }));
  }

  async createChallenge(tenant: string, endUserId: string, codeHash: string, expiresAtMs: number) {
    const s = this.t(tenant);
    if (!s.endUsers.has(endUserId)) throw new ChannelError("NOT_FOUND", "unknown end user");
    s.challenges.set(codeHash, {
      end_user_id: endUserId,
      expires_at_ms: expiresAtMs,
      consumed: false,
    });
  }

  async redeemChallenge(
    tenant: string,
    codeHash: string,
    nowMs: number,
    redeemer: { channel: ChannelId; externalId: string },
  ): Promise<RedeemResult> {
    const s = this.t(tenant);
    const c = s.challenges.get(codeHash);
    if (!c) return { ok: false, reason: "invalid" };
    if (c.consumed) return { ok: false, reason: "consumed" };
    if (c.expires_at_ms <= nowMs) return { ok: false, reason: "expired" };
    c.consumed = true;
    await this.resolveIdentity(tenant, redeemer.channel, redeemer.externalId);
    const identity = s.identities.get(`${redeemer.channel}\u0000${redeemer.externalId}`)!; // the stored row, mutated below
    if (identity.end_user_id === c.end_user_id)
      return {
        ok: true,
        end_user_id: c.end_user_id,
        identity: { ...identity },
        moved_conversations: 0,
        already_linked: true,
      };
    const from = identity.end_user_id;
    identity.end_user_id = c.end_user_id;
    identity.verified_by = "link";
    let moved = 0;
    const stillHas = [...s.identities.values()].some((i) => i.end_user_id === from);
    if (!stillHas) {
      for (const conv of s.conversations.values())
        if (conv.end_user_id === from) {
          conv.end_user_id = c.end_user_id;
          moved++;
        }
      s.endUsers.delete(from);
    }
    return {
      ok: true,
      end_user_id: c.end_user_id,
      identity: { ...identity },
      moved_conversations: moved,
      already_linked: false,
    };
  }

  async findOpenConversation(tenant: string, endUserId: string, agentName: string) {
    let best: Conversation | undefined;
    for (const c of this.t(tenant).conversations.values())
      if (c.end_user_id === endUserId && c.agent.name === agentName && c.status === "open")
        if (!best || c.updated_at_ms >= best.updated_at_ms) best = c;
    return best && structuredClone(best);
  }

  async findByThread(tenant: string, channel: ChannelId, threadKey: string) {
    const s = this.t(tenant);
    const th = s.threads.get(`${channel}\u0000${threadKey}`);
    const c = th ? s.conversations.get(th.conversation_id) : undefined;
    return c && structuredClone(c);
  }

  async getConversation(tenant: string, id: string) {
    const c = this.t(tenant).conversations.get(id);
    return c && structuredClone(c);
  }

  async createConversation(tenant: string, endUserId: string, agent: AgentRef, channel: ChannelId) {
    const s = this.t(tenant);
    if (!s.endUsers.has(endUserId)) throw new ChannelError("NOT_FOUND", "unknown end user");
    const now = this.now();
    const c: Conversation = {
      id: randomUUID(),
      tenant_id: tenant,
      end_user_id: endUserId,
      agent,
      status: "open",
      last_channel: channel,
      created_at_ms: now,
      updated_at_ms: now,
    };
    s.conversations.set(c.id, c);
    return structuredClone(c);
  }

  async touchConversation(tenant: string, id: string, channel: ChannelId) {
    const c = this.t(tenant).conversations.get(id);
    if (c) {
      c.updated_at_ms = this.now();
      c.last_channel = channel;
    }
  }

  async addThread(tenant: string, channel: ChannelId, threadKey: string, conversationId: string) {
    const s = this.t(tenant);
    if (!s.conversations.has(conversationId))
      throw new ChannelError("NOT_FOUND", "unknown conversation");
    const k = `${channel}\u0000${threadKey}`;
    if (!s.threads.has(k))
      s.threads.set(k, { conversation_id: conversationId, seq: ++this.threadSeq });
  }

  async lastThread(tenant: string, conversationId: string, channel: ChannelId) {
    let best: { key: string; seq: number } | undefined;
    for (const [k, v] of this.t(tenant).threads) {
      const [ch, key] = k.split("\u0000") as [string, string];
      if (ch === channel && v.conversation_id === conversationId && (!best || v.seq > best.seq))
        best = { key, seq: v.seq };
    }
    return best?.key;
  }

  async appendMessage(tenant: string, m: NewMessage) {
    const s = this.t(tenant);
    if (!s.conversations.has(m.conversation_id))
      throw new ChannelError("NOT_FOUND", "unknown conversation");
    const dk = `${m.channel}\u0000${m.direction}\u0000${m.idempotency_key}`;
    const dup = s.dedupe.get(dk);
    if (dup) return { inserted: false, message: structuredClone(dup) };
    const stored: StoredMessage = {
      ...structuredClone(m),
      tenant_id: tenant,
      id: randomUUID(),
      created_at_ms: this.now(),
    };
    s.dedupe.set(dk, stored);
    const list = s.messages.get(m.conversation_id) ?? [];
    list.push(stored);
    s.messages.set(m.conversation_id, list);
    return { inserted: true, message: structuredClone(stored) };
  }

  async hasMessage(
    tenant: string,
    channel: ChannelId,
    direction: "in" | "out",
    idempotencyKey: string,
  ) {
    return this.t(tenant).dedupe.has(`${channel}\u0000${direction}\u0000${idempotencyKey}`);
  }

  async messages(tenant: string, conversationId: string, limit = 100) {
    return structuredClone((this.t(tenant).messages.get(conversationId) ?? []).slice(-limit));
  }
}
