# 0017. Channels and voice wiring: inbound to run, gated reply, transcripts in the audit chain

Status: Accepted · Date: 2026-10-01 · Phase 5 component C (integration) · **No frozen contract changed** (`FREEZE.json` untouched, no
migration, no proto, no new audit event type).

## Context

Components A (`services/channels`, ADR 0015) and B (voice, ADR 0016) were built and tested in isolation. Three seams were open:
the gateway's `onMessage` hook started nothing (NEEDS #131), `Backends.channels` had no `RunDeps` wiring, and voice transcripts lived
only in the run log, not in the tenant's hash-chained audit log (NEEDS #140). The Phase 5 exit needs one agent serving chat and
voice with transcripts in the chain.

## Decisions

1. **Inbound message to agent run: a pull bridge, dev only.** The gateway's `onMessage` is `InboxQueue.handler`: it enqueues an
   `InboxItem` (verified sender, tenant, conversation, message id, text, trace id) per tenant. The runtime's `ChannelAgentRunner`
   long-polls `POST /v1/channels/inbox/next` with a bearer token that FIXES the tenant (the same credential shape as
   `/v1/channels/send`), so a runner of tenant B cannot receive tenant A's message even if it asks for it. The runner re-checks
   `item.tenant_id` and starts nothing for an agent it has no manifest for. Chosen over a push from the gateway into the runtime
   (no inbound network path into the runtime, no second credential model) and over the e2e harness driving the runtime directly
   (that would test nothing of the bridge). It follows the dev-bridge pattern of approvals and memory: loopback HTTP, static tokens,
   in-memory, labelled non-production (NEEDS #147).
2. **One trace per turn.** The gateway generates the trace id of the inbound audit event and passes it in `InboundContext.trace_id`;
   the runner uses it for the run. The chain then shows, on one trace: `channel.inbound.message` (lifecycle), the gated model
   call(s), the gated reply (`message_send`, decided by the kernel) and `channel.outbound.message` (written by the channels service
   before it calls the provider).
3. **The reply is a gated action performed inside the root process.** `RunDeps.channels` (a `ChannelWiring`) gives each run a
   `ChannelSender` bound to that run's tenant, run id and trace id (closing NEEDS #131 for the non-Temporal path);
   `RunDeps.reply` (a `ReplyTarget`: channel, conversation, sender address, route) makes the root agent's final output a
   `MessageSend` named `channel.reply`, run through the executor like any tool call. A DENY, a gate error, a kill-switch or a pending
   approval sends nothing and is reported in `RunResult.reply` (`sent`/`denied`/`failed`). Policy keys on `tool.name`:
   a message the MODEL composes through a `kind: channel` tool has another name and is a separately decided action (the e2e pack
   allows only `channel.reply`). The model never chooses the destination of the reply.
4. **Continuity comes from the conversation log, not from a new store.** The runner fetches the conversation (all channels the end
   user is linked on, ADR 0015) from `GET /v1/channels/conversations/<id>/messages` and puts it in the agent input; the new message
   is fenced as untrusted input (and cannot close the fence). `session_id` is the conversation id (session-scope memory follows the
   person, not the channel) and the memory principal is `enduser:<id>`. Unlinked identities are different end users (ADR 0015), so
   they get different conversations and no shared history. What the agent sees of the past is what the tenant's transcript policy
   stored: a redacted preview by default, nothing under `hash_only`, a PHI route's redacted text.
5. **Voice transcripts in the audit chain through the channels service.** The audit chain has one writer implementation (TypeScript,
   per-tenant advisory lock) and the kernel does not serve `AuditService.Append`; a second hash-chain writer in Python would be a
   second place to get the chain wrong. `TranscriptWriter` therefore calls a `TranscriptAudit` mirror BEFORE it persists a call or
   turn event (no audit row, no transcript: it raises and the call ends); the production mirror (`VoiceTranscriptRelay`) posts to
   `POST /v1/channels/transcript-events`, where `ChannelGateway.recordTranscriptEvent` appends through the existing `AuditSink`.
   **Existing event shape only:** `enforcement_point` `lifecycle` (call events, caller turns) or `message_send` (agent turns),
   `action` `voice.call.<connected|consent|ended>` / `voice.turn.<user|agent|system|dtmf>`, `decision` ALLOW (DENY for a declined
   consent), `reason` a `key=value` list, hashes in `inputs_hash`/`outputs_hash`, `trace_id` = the call's trace (the same one the
   gated STT, TTS and agent model calls use). Every free-form field is checked against a narrow charset because the service builds
   `reason` from it.
6. **What is in the chain for a transcript:** channel, direction, size, keyed digest (HMAC, ADR 0015 addendum) of the text AS PERSISTED (so in PHI mode, of the
   redacted text; the runtime hashes, the channels service re-keys), whether it was redacted/truncated, the audio hash and byte count; never the text (ADR 0015 section 4). The
   redacted preview of a voice turn lives in the run log's `voice_turn` event (redacted before it is built, ADR 0016); the
   preview of a chat message lives in `conversation_messages`. Voice has no `ChannelId`/route and is not linked to an end user's
   conversation yet (NEEDS #148).
7. **The e2e fakes sit at the transports** (provider HTTP/SMTP, LLM, STT socket, TTS bytes, telephony loopback). The channels
   harness (`e2e/scripts/channels-stack.mjs`) is test code that wires the real gateway on Postgres to recording transports.

## Consequences

- New surface in the dev server: `POST /v1/channels/inbox/next`, `POST /v1/channels/transcript-events` (both service-token routes).
- The mutation script `e2e/mutation_phase5.py` checks the safety lines of this wiring (docs/spec/channels.md).
- Not solved here, recorded in `docs/NEEDS.md` #147-#155: the inbox is in memory with no ack; no Temporal path; no production
  worker/entrypoint; voice is not in the end user's conversation; the voice audit relay is a dev HTTP hop.
