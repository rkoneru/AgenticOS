# Channels service (`services/channels`, `@axis/channels`)

Status: Prototype-to-Built for the dev surface (fake transports only; no live provider). Evidence: vitest incl. real Postgres 16, property tests, 30/30 mutants killed by `scripts-mutation.mjs`; runtime `axis_runtime.channels`.

## Model

A **channel adapter** turns provider traffic into `InboundMessage`s and `OutboundMessage`s into provider payloads:

| Member                    | Meaning                                                                                                                                                                                                            |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `verifyInbound(req, ctx)` | Authenticate the request with the provider's own scheme. Returns `Reject{code}` or `VerifiedInbound{route, payload?, reply?}`. Nothing in an unverified body selects a tenant.                                     |
| `normalize(verified)`     | Authenticated payload to `InboundMessage[]` (tenant, channel, external user, conversation hint, text, attachment metadata, idempotency key, timestamp). Bots, edits, auto-replies, oversize text yield no message. |
| `render(msg, route)`      | Pure: provider call (`http` / `email` / `web`). Validates destination formats; escapes mentions (Slack).                                                                                                           |
| `capabilities`            | threading, richText, attachments, maxLength, rateLimitPerMinute. Long text is split (max 5 parts) or refused.                                                                                                      |

| Channel  | Authenticity                                                                                      | Replay                                      | Route key (provider identity)     |
| -------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------- | --------------------------------- |
| web      | HMAC session token (`v1.<payload>.<mac>`) + Origin allowlist                                      | token exp, `client_message_id`              | site key                          |
| slack    | `v0=` HMAC-SHA256 over `v0:<ts>:<raw body>`, `url_verification`                                   | 5 min window + `event_id`                   | team id (+ optional `api_app_id`) |
| teams    | `Authorization: Bearer` RS256 JWT, injected JWKS; iss, aud = app id, exp, nbf, `serviceurl` claim | JWT window, activity timestamp, activity id | bot app id                        |
| email    | `x-axis-signature` = hex HMAC-SHA256(`<x-axis-timestamp>.<raw body>`) from the inbound-parse edge | 5 min window + Message-ID                   | recipient mailbox                 |
| sms      | `X-Twilio-Signature` = base64 HMAC-SHA1(url + sorted params), over the CONFIGURED `public_url`    | MessageSid only (no timestamp)              | `To` number                       |
| whatsapp | `X-Hub-Signature-256: sha256=<hex HMAC>` over raw body; GET `hub.verify_token` handshake          | 24 h window + message id                    | `phone_number_id`                 |

All signature comparisons are constant time (`safeEqual` hashes both sides first).

## Tenant routing

`RouteConfig{channel, provider_key, tenant_id, agent, secrets, settings, transcript, phi, enabled}`. The claimed provider key only selects which secret to verify with; the tenant is read from the route after the signature verifies. Unknown route: rejected with the same 401 as a bad signature and audited (platform tenant if configured). A message whose tenant differs from the verified route's is dropped.

## Pipeline (`ChannelGateway.handleInbound`)

verify, then per message: idempotency claim (replay: acknowledged, audited `channel.inbound.replayed`), per-sender rate limit (429, claim released), `link CODE` command, identity resolve, conversation resolve, **audit append (fail closed)**, message log append (idempotent), handler (`onMessage`; failure logged, message stays recorded). Rejections are audited as `channel.inbound.rejected` (DENY), rate limited per tenant/channel.

## Identity and conversations

`end_users`, `channel_identities` (provider-verified identifiers only), `conversations`, `conversation_threads`, `conversation_messages` (migration 0007, ADR-0015). One identifier = one identity per tenant+channel. Two identities become one end user ONLY via a link challenge: a one-time code issued to an identity (`issueLinkCode`) and redeemed as the whole message `link CODE` from a provider-verified identity of the same tenant. Redeeming moves that identity (and the conversations of its old end user if it has no other identity). A thread hint resumes a conversation only for the same end user and agent. Continuity: inbound on channel B for a linked identity lands in the same open conversation.

## Transcripts and audit

Audit events (`enforcement_point` `lifecycle` inbound, `message_send` outbound): `reason` = `channel=… dir=… conv=… size=… sha256=… mode=…`, `inputs_hash`/`outputs_hash` over hashes; actor id is a hash of the external id. Raw text is never in the chain. The message log stores `content` per tenant policy (`hash_only | redacted_preview (default) | full`); PHI mode always redacts (built-in patterns + `redactionHook`; a throwing hook stores nothing) and caps `full` at a preview.

## Outbound (the perform half)

`POST /v1/channels/send` (bearer token fixes the tenant) is reached from the runtime only through `MessageSend` in `ActionExecutor` (gate, audit, perform): a DENY never sends. In the service: tenant route chosen (`from` when ambiguous), destination must be a known identity (or `allow_unsolicited`), must belong to the conversation's end user, outbound rate limit, **audit append before the provider call (fail closed)**, idempotency per `idempotency_key:part`, provider response checked (Slack `ok`), `channel.outbound.failed` audited on failure, then the log row. HTTP egress only through `HttpTransport`; `GuardedHttpTransport` enforces https, allowlisted host, default port, no IP literal, no credentials, no redirects.

## Dev wire

`services/channels/contract/wire-v1.json` is shared by `test/wire.test.ts` (real server) and `runtime/tests/test_channels.py` (client). Routes: `POST /v1/channels/<channel>/inbound` (+GET whatsapp), `POST /v1/channels/web/session`, `GET /v1/channels/web/events` (SSE), `POST /v1/channels/send`, `POST /v1/channels/identity/link-code`, `GET /v1/channels/conversations/<id>/messages`. Dev only (NEEDS 503-504).

## Quality evidence

See the final report in the commit history; numbers are re-run, not copied: `pnpm --filter @axis/channels cov` (thresholds: 85% overall; 95% on crypto, jwt, routing, replay, identity), `node scripts-mutation.mjs` (mutation check of the safety lines).
