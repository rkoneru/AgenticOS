-- 0007: unified end-user conversation state for the channels service (docs/adr/0015). ADDITIVE: new tables only; nothing existing is
-- altered. Every table carries tenant_id and FORCED RLS. Cross-table references are composite (tenant_id, id), so a row can never
-- point at another tenant's row even if a bug supplied the wrong id.

-- A person talking to an agent. One end user can hold identities on several channels, linked ONLY with proof (see link_challenges).
CREATE TABLE end_users (
  tenant_id   uuid NOT NULL REFERENCES tenants (id),
  id          uuid NOT NULL DEFAULT gen_random_uuid(),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);
SELECT axis.enable_tenant_rls('end_users', 'tenant_id', 'SELECT, INSERT');

-- A provider-verified identifier (Slack user id, E.164 number, WhatsApp wa_id, email address, widget session id, Teams AAD object id).
-- `verified_by` records HOW it was verified: 'provider' (the inbound request signature) or 'link' (a redeemed link challenge).
CREATE TABLE channel_identities (
  tenant_id    uuid NOT NULL REFERENCES tenants (id),
  id           uuid NOT NULL DEFAULT gen_random_uuid(),
  end_user_id  uuid NOT NULL,
  channel      text NOT NULL CHECK (channel IN ('web', 'slack', 'teams', 'email', 'sms', 'whatsapp', 'voice')),
  external_id  text NOT NULL CHECK (external_id <> '' AND length(external_id) <= 512),
  verified_by  text NOT NULL CHECK (verified_by IN ('provider', 'link')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, channel, external_id),
  FOREIGN KEY (tenant_id, end_user_id) REFERENCES end_users (tenant_id, id)
);
CREATE INDEX channel_identities_user_idx ON channel_identities (tenant_id, end_user_id);
SELECT axis.enable_tenant_rls('channel_identities', 'tenant_id', 'SELECT, INSERT, UPDATE');

-- A one-time proof that the holder of an identity on channel A also controls an identity on channel B. Only the hash of the code is kept.
CREATE TABLE link_challenges (
  tenant_id    uuid NOT NULL REFERENCES tenants (id),
  id           uuid NOT NULL DEFAULT gen_random_uuid(),
  end_user_id  uuid NOT NULL,
  code_hash    text NOT NULL CHECK (code_hash ~ '^[0-9a-f]{64}$'),
  expires_at   timestamptz NOT NULL,
  consumed_at  timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, code_hash),
  FOREIGN KEY (tenant_id, end_user_id) REFERENCES end_users (tenant_id, id)
);
SELECT axis.enable_tenant_rls('link_challenges', 'tenant_id', 'SELECT, INSERT, UPDATE');

CREATE TABLE conversations (
  tenant_id     uuid NOT NULL REFERENCES tenants (id),
  id            uuid NOT NULL DEFAULT gen_random_uuid(),
  end_user_id   uuid NOT NULL,
  agent_name    text NOT NULL,
  agent_version text NOT NULL,
  status        text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
  last_channel  text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, end_user_id) REFERENCES end_users (tenant_id, id)
);
CREATE INDEX conversations_user_idx ON conversations (tenant_id, end_user_id, agent_name, status, updated_at DESC);
SELECT axis.enable_tenant_rls('conversations', 'tenant_id', 'SELECT, INSERT, UPDATE');

-- A provider thread (Slack thread_ts, email thread root, ...) that belongs to a conversation.
CREATE TABLE conversation_threads (
  tenant_id        uuid NOT NULL REFERENCES tenants (id),
  channel          text NOT NULL,
  thread_key       text NOT NULL CHECK (thread_key <> '' AND length(thread_key) <= 512),
  conversation_id  uuid NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, channel, thread_key),
  FOREIGN KEY (tenant_id, conversation_id) REFERENCES conversations (tenant_id, id)
);
SELECT axis.enable_tenant_rls('conversation_threads', 'tenant_id', 'SELECT, INSERT');

-- The message log. `content` is NULL unless the tenant's transcript policy stores text (docs/adr/0015); hash and size are always kept.
-- Idempotency: one row per (tenant, channel, direction, idempotency_key), so a replayed webhook cannot add a second message.
CREATE TABLE conversation_messages (
  tenant_id        uuid NOT NULL REFERENCES tenants (id),
  id               uuid NOT NULL DEFAULT gen_random_uuid(),
  conversation_id  uuid NOT NULL,
  direction        text NOT NULL CHECK (direction IN ('in', 'out')),
  channel          text NOT NULL,
  idempotency_key  text NOT NULL CHECK (idempotency_key <> '' AND length(idempotency_key) <= 512),
  content_mode     text NOT NULL CHECK (content_mode IN ('hash_only', 'redacted_preview', 'full')),
  content          text,
  content_hash     text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
  size_bytes       integer NOT NULL CHECK (size_bytes >= 0),
  attachments      jsonb NOT NULL DEFAULT '[]',          -- metadata only: name, content type, size; never bytes, never a fetched URL
  audit_event_id   text,
  audit_hash       text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, channel, direction, idempotency_key),
  FOREIGN KEY (tenant_id, conversation_id) REFERENCES conversations (tenant_id, id),
  CHECK ((content_mode = 'hash_only') = (content IS NULL))
);
CREATE INDEX conversation_messages_conv_idx ON conversation_messages (tenant_id, conversation_id, created_at);
SELECT axis.enable_tenant_rls('conversation_messages', 'tenant_id', 'SELECT, INSERT');
