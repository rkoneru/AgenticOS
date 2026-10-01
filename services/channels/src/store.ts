import type { AgentRef, AttachmentMeta, ChannelId, TranscriptMode } from "./types.js";

export interface Conversation {
  id: string;
  tenant_id: string;
  end_user_id: string;
  agent: AgentRef;
  status: "open" | "closed";
  last_channel: ChannelId;
  created_at_ms: number;
  updated_at_ms: number;
}

export interface Identity {
  id: string;
  tenant_id: string;
  end_user_id: string;
  channel: ChannelId;
  external_id: string;
  verified_by: "provider" | "link";
}

export interface StoredMessage {
  id: string;
  tenant_id: string;
  conversation_id: string;
  direction: "in" | "out";
  channel: ChannelId;
  idempotency_key: string;
  content_mode: TranscriptMode;
  content: string | null;
  content_hash: string;
  size_bytes: number;
  attachments: AttachmentMeta[];
  audit_event_id: string | null;
  audit_hash: string | null;
  created_at_ms: number;
}

export type NewMessage = Omit<StoredMessage, "id" | "created_at_ms">;

export type RedeemResult =
  | {
      ok: true;
      end_user_id: string;
      identity: Identity;
      moved_conversations: number;
      already_linked: boolean;
    }
  | { ok: false; reason: "invalid" | "expired" | "consumed" };

/**
 * Tenant-scoped conversation state. EVERY method takes the tenant and can only see that tenant's rows (Postgres: forced RLS plus
 * composite foreign keys; memory: per-tenant maps). Implementations must make `appendMessage` idempotent on
 * (tenant, channel, direction, idempotency_key).
 */
export interface ConversationStore {
  /** Get-or-create the identity of a PROVIDER-VERIFIED identifier; a first sight creates a fresh end user. Never merges. */
  resolveIdentity(
    tenant: string,
    channel: ChannelId,
    externalId: string,
  ): Promise<{ identity: Identity; created: boolean }>;
  findIdentity(
    tenant: string,
    channel: ChannelId,
    externalId: string,
  ): Promise<Identity | undefined>;
  identitiesOf(tenant: string, endUserId: string): Promise<Identity[]>;

  createChallenge(
    tenant: string,
    endUserId: string,
    codeHash: string,
    expiresAtMs: number,
  ): Promise<void>;
  /**
   * Atomically consume a challenge and attach the redeeming identity (already provider-verified on its own channel) to the
   * challenge's end user. Single use; expired and unknown codes fail.
   */
  redeemChallenge(
    tenant: string,
    codeHash: string,
    nowMs: number,
    redeemer: { channel: ChannelId; externalId: string },
  ): Promise<RedeemResult>;

  findOpenConversation(
    tenant: string,
    endUserId: string,
    agentName: string,
  ): Promise<Conversation | undefined>;
  findByThread(
    tenant: string,
    channel: ChannelId,
    threadKey: string,
  ): Promise<Conversation | undefined>;
  getConversation(tenant: string, id: string): Promise<Conversation | undefined>;
  createConversation(
    tenant: string,
    endUserId: string,
    agent: AgentRef,
    channel: ChannelId,
  ): Promise<Conversation>;
  touchConversation(tenant: string, id: string, channel: ChannelId): Promise<void>;
  addThread(
    tenant: string,
    channel: ChannelId,
    threadKey: string,
    conversationId: string,
  ): Promise<void>;
  /** The most recent thread key of a conversation on a channel (the reply anchor). */
  lastThread(
    tenant: string,
    conversationId: string,
    channel: ChannelId,
  ): Promise<string | undefined>;

  appendMessage(
    tenant: string,
    m: NewMessage,
  ): Promise<{ inserted: boolean; message: StoredMessage }>;
  messages(tenant: string, conversationId: string, limit?: number): Promise<StoredMessage[]>;
}
