# ADR 0015: Voice pipeline (STT -> agent -> TTS) in the Python runtime

Status: accepted · Phase 5 component B · **No frozen contract changed** (`packages/contracts/FREEZE.json` untouched)

## Context

Voice is latency-sensitive and drives the agent loop directly, so it lives in `runtime/src/axis_runtime/voice/` rather than a
TS service. Invariants 1, 4 and 5 apply: every outbound action is gated, runs are replayable, and only the ModelGateway talks to
model providers.

## Decisions

1. **STT and TTS vendors are model providers, so they go through the ModelGateway.** `ModelGateway.open_stt` and
   `synthesize` carry the same tripwire as `complete` (they raise `DirectExecutionError` outside the executor), use the tenant's
   own key from `SecretStore` (platform keys only if the tenant policy allows, never to a custom endpoint), validate endpoint
   overrides with the SSRF guard (`wss://` is checked as `https://`), and sit behind the per-(tenant, provider, endpoint) circuit
   breaker. Vendor wire formats are pure adapters (`models/speech_vendors.py`); bytes move over an injected HTTP `Transport` (TTS)
   and an injected `WsTransport` (STT). No real WebSocket transport ships.
2. **Gating granularity.** One `SttOpen` action gates a whole STT stream (audio frames are not individually gated: the stream is
   the unit of egress); every TTS request is a `TtsSynthesize` action gated with its text (`args.text`, redactable). Both use the
   existing `model_call` enforcement point with `tool.kind = "model"`, `tool.name = "stt:<provider>/<model>"` or `tts:...` and an
   `args.modality`. A DENY, a gate error or a pending approval becomes `SpeechDeniedError` (a live call cannot wait for a human);
   a denied TTS ends the call (`tts_denied`), a denied STT ends it (`stt_denied`).
3. **Outbound calls are `message_send` actions of kind `voice`** (`VoiceCall`); no new enforcement point (the proto is frozen).
   The gate sees country prefix, a masked number and the number's hash, never the raw number, plus the tenant's cap state.
   `Backends.voice` (a `VoiceDialer`) is the only path to the telephony gateway; the bypass scanner treats it as a backend handle.
4. **Toll-fraud limits run BEFORE the gate** (`voice/outbound.py`): per-tenant allowed country prefixes (empty = deny all), a
   premium-rate/satellite deny list, concurrency and rolling-window caps, a per-destination cool-down. A refusal is an
   `action_blocked` event, never a gate request or a dial. The gate additionally receives the same facts as args.
5. **A call is a run.** `voice/callrun.py` starts a run with one root "voice" process (so events and gated actions have a runnable
   actor); each agent turn is its own run (`<call_id>-t<n>`) started with `start_agent` on the call's trace id, so every model and
   tool call is gated exactly as in chat. The agent loop returns a whole reply, so the agent yields one delta (NEEDS #603).
6. **Three additive run-event types**: `voice_call` (connected / consent / ended), `voice_turn` (transcript turn) and `voice_stage`
   (latency). Same rule as ADR 0012: `run_events.type` is free text, not in `FREEZE.json`; older runtimes replaying such a log
   fail loudly. They are NOT in the audit chain (NEEDS #606).
7. **Transcripts: redaction before persistence, no raw audio.** `TranscriptWriter` is the only path to storage; in PHI mode text is
   redacted (heuristics plus names the caller introduced) or omitted (`PhiMode.OMIT`) before the event is built. Audio is never
   stored: only a SHA-256 and byte count per user turn. DTMF digits are persisted as a count unless configured otherwise.
8. **Everything timed uses an injected `VoiceClock`**, so barge-in latency, endpointing, idle and call-length limits are asserted
   in virtual milliseconds.
9. **Bypass guard unchanged in strength**: no network or process primitive was added to agent-loop code. The only scanner
   edits are additions: `voice` joined the backend-handle names. Method names that collide with restricted names (`open`,
   `complete`, `stream`) were renamed in voice code rather than allowlisted.

## Consequences

- Cost accounting for audio seconds / characters is not built (NEEDS #608). Per-sentence TTS gating adds one gate round trip per
  sentence, partly hidden by the playout buffer.
