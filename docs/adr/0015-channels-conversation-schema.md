# 0015. Channels service: conversation schema (migration 0007) and transcript policy

Status: Accepted · Date: 2026-10-01 · Amends: 0007 (post-freeze addition, same procedure as 0008, 0010 and 0013)
(Number chosen on branch p5/channels; the integrating branch renumbers on collision, together with the migration version.)

## Context

Phase 5 component A (`services/channels`) keeps one end user's conversation across channels. Migrations 0001-0006 have no
conversation, identity or message-log table (`runs` and `run_events` are per run, not per person). Contracts stay frozen, so the
audit event shape (hashes only, `reason` free text) cannot change either.

## Decision

1. Additive migration `0007_channels.sql` (no existing object altered; `FREEZE.json` regenerated): `end_users`,
   `channel_identities`, `link_challenges`, `conversations`, `conversation_threads`, `conversation_messages`. All tenant RLS FORCED
   via `axis.enable_tenant_rls`; cross-table references are composite `(tenant_id, id)` so a row can never reference another
   tenant's row. Messages and thread rows are insert-only for the app role.
2. Identity linking (never auto-merge). An identity row exists only for an identifier verified by the provider's request signature
   (`verified_by = 'provider'`). Two identities become one end user only through a link challenge: a one-time code (hash stored,
   TTL, single use) issued to an end user from an authenticated channel and redeemed from a provider-verified identity on another
   channel of the SAME tenant (`verified_by = 'link'`). Claims in message text ("I am alice@...") never link anything.
3. Routing is NOT stored in Postgres in this phase: it is resolved before the tenant is known, so a tenant-RLS table cannot serve it.
   `RoutingTable` is a port with a static implementation (NEEDS: control-plane store).
4. Transcript policy (per tenant, `hash_only | redacted_preview | full`; DEFAULT `redacted_preview`). The audit event carries only
   what the frozen schema allows: SHA-256 of the content, size, channel, direction, message id (`reason` is a `key=value` list,
   `inputs_hash`/`outputs_hash` are hashes). Raw text never goes into the audit chain. The message log stores `content` as
   follows: `hash_only` stores none; `redacted_preview` stores the first 280 characters after the redaction hook; `full` stores the
   whole text after the redaction hook. A PHI-mode tenant ALWAYS runs the redaction hook (names are caught by the tenant-supplied
   hook, patterns by the built-in one) and is capped at `redacted_preview` even if configured `full`. Rationale: a preview makes a
   transcript useful to support staff without making the log a second copy of every customer's text.

## Consequences

- Tests: `packages/db` migration list, `services/channels` store tests on real Postgres (tenancy, FK, RLS).
- Voice (component B) reuses `end_users`/`conversations`; the `voice` channel value is already allowed.

## Addendum (Phase 5 adversarial review): digests are keyed

Section 4 said the audit event carries a SHA-256 of the content. A plain SHA-256 of low-entropy chat text (a lone SSN, phone number,
"yes") is confirmable by guessing, including in PHI mode (NEEDS 151), and the same holds for the end-user reference (a hash of a
phone number) in the actor id. Decision: every digest the gateway writes to the chain or to `conversation_messages.content_hash`
(text, end-user reference, route reference, idempotency key, and the re-keyed voice text/audio digests) is
`HMAC-SHA256(tenantKey, label || 0x00 || data)` with `tenantKey = HMAC-SHA256(hashKey, "axis-digest.v1:" || tenant_id)` and `hashKey`
a configured service secret (>= 32 bytes). The frozen audit shape is unchanged: the `reason` token is now `hmac=<64 hex>` (free
text) and the hashed `outputs` carry `content_hmac`. Rotating `hashKey` makes old digests incomparable with new ones (acceptable: they
are evidence of integrity within the chain, not a lookup key). A KMS-held key replaces the env secret in production (NEEDS 156).
