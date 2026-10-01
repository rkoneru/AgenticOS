# Voice (Python runtime)

Status: **Prototype**. Code: `runtime/src/axis_runtime/voice/`, speech plane `runtime/src/axis_runtime/models/speech*.py`.
Tests: `runtime/tests/test_voice_*.py`, mutation check `runtime/tests/mutation_voice.py`. Decision record: `docs/adr/0015-voice-pipeline.md`.
Evidence: fakes and virtual time only; no real telephony, vendor, audio or credentials (docs/NEEDS.md #600-#612).

## Pipeline

caller audio -> `AudioTransport` -> STT stream -> `TurnDetector` -> `AgentTurn` -> `SentenceChunker` -> TTS -> transport playout.

Seams (`interfaces.py`): `SttProvider.start -> SttStream` (audio in, `SttEvent` partial/final/speech_start out, with timestamps),
`TtsProvider.synthesize -> TtsStream` (chunks, cancellable), `AudioTransport` (events: connected, frame, DTMF, hangup; paced
`send_audio` with backpressure; `clear_output`). Production providers are `gated.GatedSttProvider/GatedTtsProvider`: each open is a
gated action through the `ModelGateway` speech plane. Fakes (`fakes.py`, `gateway.py`): `ScriptedStt` decodes its transcript from
directive frames, `FakeTts` emits identifiable chunks, `LoopbackGateway/LoopbackTransport/LoopbackCaller` is an in-process SIP/WebRTC
stand-in. A real SIP/WebRTC stack is not built.

Vendors (prototype, from public docs, fake transports only): STT Deepgram and AssemblyAI (WebSocket); TTS ElevenLabs and OpenAI
(HTTP streaming). Keys: tenant BYO via `SecretStore`.

## Turn-taking

`TurnDetector` ends a turn after silence that depends on the text: `terminal_silence_ms` (350) after `. ? !`, `silence_ms` (700)
otherwise, `incomplete_silence_ms` (1200) after a comma, ellipsis or dangling word; `max_utterance_ms` forces the end. All configurable
(`EndpointingConfig`). A late FINAL of an utterance already answered is dropped, not a second turn. Speech while the agent speaks
is ignored unless it is a barge-in (backchannel such as "mm" does not interrupt; it is lost at turn end, see limits).

## Barge-in

While the agent is thinking or speaking, STT text of at least `min_words` (2) words or a keyword (`stop`, `wait`, ...), a DTMF key
(`dtmf_interrupts`), or optionally provider speech-start, interrupts. The session cancels the agent run (producer, speaker, run is sent
`KILL`), cancels the TTS request, flushes the transport playout (`clear_output`) and records the turn with `truncated=true` and
the words actually spoken: whole sentences whose audio finished playing plus the played fraction of the cut one (provider alignment
`chars_through` when given, else proportional to played ms; cut at a word boundary). The next agent turn sees the cut turn marked
`[interrupted by the caller]`. Measured: `barge_in_latencies_ms` = flush time minus the audio timestamp of the interrupting speech
(equals the STT latency in the loopback tests; test bound: STT latency + one tick) and a `voice_stage barge_in` event.
`grace_ms` ignores interruptions right after audio starts. The consent notice and the farewell cannot be interrupted.

## DTMF, timeouts, limits

Keys outside `0-9*#A-D` are dropped; the digit buffer is capped (`max_digits`, flood is counted in `dtmf_dropped`); digits flush on
`#` or after the inter-digit timeout and reach the agent as `[Keypad digits]` input; persisted transcripts hold only
`[N keypad digits]` (PINs, card numbers). Idle: one reprompt after `idle_prompt_ms`, end after `idle_timeout_ms` of caller silence.
`max_call_ms` speaks a farewell (grace `farewell_grace_ms`) then ends. `max_turns`, an agent timeout (fallback phrase, agent
cancelled) and repeated TTS failure (`tts_failed`) end or recover the call.

Backpressure: inbound frames in a bounded queue (oldest dropped, counted), frames over `max_frame_bytes` rejected, bounded event and
sentence queues (a slow TTS backs up the agent producer), playout buffer capacity blocks `send_audio`.

## Metrics

Per user turn (`StageMetrics`, `voice_stage` events, spans `voice.stt`/`voice.agent`/`voice.tts` on the NEXUS tracer): `endpoint`
silence, `stt` (first speech to utterance finalised), `agent` (finalised to first text), `tts` first byte (first sentence requested to
first audio sent), `response` (finalised to first audio), `perceived` (end of caller speech to first audio).

## Compliance

Consent (`consent.py`): required when the manifest has `risk.transparency_notice` (`RuntimeManifest.transparency_notice`), the
tenant requires it, or the operator says so; a required policy cannot be switched off. Modes: `notice` (played in full; staying on
the line is consent), `dtmf` (press the accept digit), `speech` (spoken yes, FINAL only; unclear answers wait, timeout refuses).
Fail closed: if the notice cannot be played completely, consent is declined, or it times out, the call ends (`consent_*`) with no
agent turn; before consent frames are dropped, STT is not opened (notice, dtmf), nothing reaches the transcript, and the audio hash
restarts at consent. Events: `voice_call` phases `connected`, `consent` (mode, granted, notice SHA-256), `ended` (reason, duration,
counters). Transcript: one `voice_turn` per turn with timestamps, `truncated`, text hash/length, user-audio SHA-256 and byte count
(raw audio is never stored). PHI tenants/manifests: text is redacted before persistence (`phi.py`: digits as numbers or words,
e-mail, dates, addresses, labelled ids, introduced names and later mentions of them) or omitted (`PhiMode.OMIT`); the live agent
still receives the raw words (it needs them), and its model calls are gated with `data.phi`.

## Outbound calls and toll fraud

`OutboundCaller.place` -> `OutboundLimiter` (pre-gate) -> gated `VoiceCall` -> `GatewayDialer`. See ADR 0015 #3-#4.

## Threat model

| Threat | Mitigation | Residual |
| --- | --- | --- |
| Voice prompt injection ("ignore your instructions") | caller speech is fenced and labelled untrusted in the agent input; every tool/model call is gated; the agent never speaks internal policy text (`RunAgentTurn` uses fixed phrases) | the model may still be persuaded within what policy allows; no injection classifier (NEEDS #609) |
| DTMF abuse (floods, digit injection, PIN capture) | key allowlist, bounded buffer, digits not persisted, DTMF only reaches the agent as labelled input, consent keys only count after the notice | none known in the fakes |
| Toll fraud via outbound calls | pre-gate allowed prefixes (empty denies all), premium/satellite deny list, concurrency and rate caps, per-destination cool-down, raw number never in the gate view, every call gated and audited, max duration passed to the gate | deny list is not exhaustive; no carrier-side spend cap; caps are in memory per process (NEEDS #607) |
| Transcript leakage of PHI | redaction before persistence, omit mode, no raw audio | heuristics (NEEDS #604); raw text lives in process memory for the live call |
| Recording without notice | consent required by manifest/tenant, fail closed, mutation-checked | notice wording and jurisdiction rules (two-party consent) are the operator's |
| Echo / self-transcription loops, TTS SSRF | barge-in needs words; speech endpoint overrides pass the SSRF guard | no acoustic echo cancellation (NEEDS #610); no connect-time IP pinning (NEEDS #99 family) |

## Known limits

Agent replies arrive whole (no token streaming); one-word backchannel during speech is dropped at turn end; sentence TTS is gated
per sentence; Temporal path does not wire voice; speech results are live handles (not serialisable activities).
