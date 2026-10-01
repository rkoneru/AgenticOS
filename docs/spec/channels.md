# Channels service (`services/channels`, `@axis/channels`)

Status: Prototype-to-Built for the dev surface (fake transports only; no live provider). Evidence: vitest incl. real Postgres 16, property tests, 30/30 mutants killed by `scripts-mutation.mjs`; runtime `axis_runtime.channels`; `make e2e-phase5` (web, Slack, SMS, email against recording fakes, real kernel and audit chain; ADR 0017).

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

Email: the HMAC authenticates the edge, not the author. The edge must attest the sender (`sender_auth.dmarc === "pass"` in the normalised JSON) or the request is refused (`bad_signature`); a route may set `allow_unauthenticated_sender: true` for dev only. Without it `From` is spoofable and a stranger could write into, and be answered as, any other person's identity.

All signature comparisons are constant time (`safeEqual` hashes both sides first).

## Tenant routing

`RouteConfig{channel, provider_key, tenant_id, agent, secrets, settings, transcript, phi, enabled}`. The claimed provider key only selects which secret to verify with; the tenant is read from the route after the signature verifies. Unknown route: rejected with the same 401 as a bad signature and audited (platform tenant if configured). A message whose tenant differs from the verified route's is dropped.

## Pipeline (`ChannelGateway.handleInbound`)

verify, then per message: idempotency claim (replay: acknowledged, audited `channel.inbound.replayed`), per-sender rate limit (429, claim released), `link CODE` command, identity resolve, conversation resolve, **audit append (fail closed)**, message log append (idempotent), handler (`onMessage`; failure logged, message stays recorded). Rejections are audited as `channel.inbound.rejected` (DENY), rate limited per tenant/channel.

## Identity and conversations

`end_users`, `channel_identities` (provider-verified identifiers only), `conversations`, `conversation_threads`, `conversation_messages` (migration 0007, ADR-0015). One identifier = one identity per tenant+channel. Two identities become one end user ONLY via a link challenge: a one-time code issued to an identity (`issueLinkCode`) and redeemed as the whole message `link CODE` from a provider-verified identity of the same tenant. Redeeming moves that identity (and the conversations of its old end user if it has no other identity). A thread hint resumes a conversation only for the same end user and agent. Continuity: inbound on channel B for a linked identity lands in the same open conversation.

## Transcripts and audit

Audit events (`enforcement_point` `lifecycle` inbound, `message_send` outbound): `reason` = `channel=… dir=… conv=… size=… hmac=… mode=…`, `inputs_hash`/`outputs_hash` over keyed digests; actor id is a keyed digest of the external id. Every digest of end-user text, end-user reference, route reference or idempotency key is an HMAC-SHA256 under a per-tenant key derived from the service secret `hashKey` (`AXIS_CHANNELS_HASH_KEY`, >= 32 bytes; `HMAC(master, "axis-digest.v1:<tenant>")`, then `HMAC(tenantKey, label || 0x00 || data)`), never a plain SHA-256, so a low-entropy value (SSN, phone number, "yes") cannot be confirmed by guessing a value and grepping the chain (NEEDS 151, ADR 0015 addendum). Voice digests are computed by the runtime as SHA-256 of the persisted text and re-keyed by the service (`label = voice-text`) before they reach the chain. Without a configured key the service uses a random per-process key (safe; digests are not comparable across restarts or instances). Raw text is never in the chain. The message log stores `content` per tenant policy (`hash_only | redacted_preview (default) | full`); PHI mode always redacts (built-in patterns + `redactionHook`; a throwing hook stores nothing) and caps `full` at a preview.

## Outbound (the perform half)

`POST /v1/channels/send` (bearer token fixes the tenant) is reached from the runtime only through `MessageSend` in `ActionExecutor` (gate, audit, perform): a DENY never sends. In the service: tenant route chosen (`from` when ambiguous), destination must be a known identity (or `allow_unsolicited`), must belong to the conversation's end user, outbound rate limit, **audit append before the provider call (fail closed)**, idempotency per `idempotency_key:part`, provider response checked (Slack `ok`), `channel.outbound.failed` audited on failure, then the log row. HTTP egress only through `HttpTransport`; `GuardedHttpTransport` enforces https, allowlisted host, default port, no IP literal, no credentials, no redirects.

## Inbound to agent run (ADR 0017, dev bridge)

`onMessage` is `InboxQueue.handler`: it enqueues an `InboxItem` per tenant (verified sender, conversation, message id, text, and the
trace id of the inbound audit event, `InboundContext.trace_id`). The runtime's `ChannelAgentRunner` calls
`POST /v1/channels/inbox/next {wait_ms}` with its tenant's token (`{item}` or `{item: null}`; a body `tenant_id` that differs from the
credential is refused), fetches the conversation log, runs the agent named by the route with `RunDeps.channels` + `RunDeps.reply`
and the reply goes out as a gated `MessageSend` named `channel.reply` (the kernel decides; DENY/kill-switch/gate error send nothing).
A link command, a rejected, replayed or rate-limited message enqueues nothing. The inbox is in memory with no ack (NEEDS #147).

## Voice transcript relay (ADR 0017)

`POST /v1/channels/transcript-events` (service token; tenant from the token) appends one voice call/turn event to the tenant's chain:
`voice.call.<connected|consent|ended>` and `voice.turn.<user|agent|system|dtmf>`, hashes and sizes only, on the call's trace; strict
charset validation (`parseTranscriptEvent`); fail closed.

## Dev wire

`services/channels/contract/wire-v1.json` is shared by `test/wire.test.ts` (real server) and `runtime/tests/test_channels.py` (client). Routes: `POST /v1/channels/<channel>/inbound` (+GET whatsapp), `POST /v1/channels/web/session`, `GET /v1/channels/web/events` (SSE), `POST /v1/channels/send`, `POST /v1/channels/identity/link-code`, `GET /v1/channels/conversations/<id>/messages`, `POST /v1/channels/inbox/next`, `POST /v1/channels/transcript-events`. Dev only (NEEDS 122-123).

## Quality evidence

See the final report in the commit history; numbers are re-run, not copied: `pnpm --filter @axis/channels cov` (thresholds: 85% overall; 95% on crypto, jwt, routing, replay, identity), `node scripts-mutation.mjs` (mutation check of the safety lines).
