"""VoiceSession: one phone call, from connect to hang-up (docs/spec/voice.md).

caller audio -> STT -> endpointing -> agent turn -> sentence chunks -> TTS -> playout, with
barge-in: caller speech while the agent is thinking or speaking cancels the in-flight turn, flushes
the playout buffer and records what was ACTUALLY spoken.

Structure.  One loop (``run``) owns all session state and reacts to events from a bounded queue:
transport events (DTMF, hang-up), STT events, timers and "turn finished" notices.  The slow parts
run in their own tasks and only report back through that queue: the transport pump, the audio pump,
the STT pump and, per agent turn, a producer (agent text -> sentences) and a speaker (sentences ->
TTS -> transport).  Every timer is a task on the injected ``VoiceClock``, so the whole pipeline
runs on virtual time in tests.

Fail closed: when consent is required nothing the caller says reaches STT (NOTICE / DTMF), the
transcript or the agent until the notice has been played completely (and, for DTMF / SPEECH, an
accept has been heard).  A refused or timed-out consent ends the call.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import itertools
import logging
from collections.abc import AsyncGenerator, Coroutine
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from axis_runtime.nexus.telemetry import NoopTracer, Tracer
from axis_runtime.voice.agent import AgentTurn, AgentTurnRequest
from axis_runtime.voice.chunker import SentenceChunker, speakable
from axis_runtime.voice.clock import VoiceClock
from axis_runtime.voice.consent import (
    ConsentMode,
    ConsentPolicy,
    classify_consent_speech,
)
from axis_runtime.voice.endpointing import EndpointingConfig, TurnDetector
from axis_runtime.voice.errors import SpeechDeniedError
from axis_runtime.voice.interfaces import (
    AudioTransport,
    SttProvider,
    SttStream,
    TtsProvider,
    TtsStream,
)
from axis_runtime.voice.transcript import TranscriptWriter
from axis_runtime.voice.types import (
    CallSummary,
    Dtmf,
    Frame,
    Hangup,
    StageMetrics,
    SttConfig,
    SttEvent,
    SttEventKind,
    TransportEvent,
    TtsConfig,
    TurnRole,
    VoiceTurn,
)

log = logging.getLogger("axis_runtime.voice")

_DTMF_KEYS = frozenset("0123456789*#ABCD")


@dataclass(frozen=True)
class BargeInConfig:
    enabled: bool = True
    #: Words of speech needed to interrupt (a lone cough or "mm" must not cut the agent off).
    min_words: int = 2
    #: One-word interruptions that always count.
    keywords: tuple[str, ...] = ("stop", "wait", "no", "hold", "cancel", "sorry", "pardon")
    #: Provider VAD ``speech_start`` interrupts without any text (noisy lines: leave off).
    speech_start_triggers: bool = False
    #: Ignore interruptions this long after the first audio of a turn went out (echo of our own
    #: voice through the line before the network's echo canceller has converged).
    grace_ms: int = 0
    dtmf_interrupts: bool = True


@dataclass(frozen=True)
class DtmfConfig:
    enabled: bool = True
    terminator: str = "#"
    interdigit_timeout_ms: int = 3000
    max_digits: int = 32
    #: DTMF can be a PIN or a card number: by default the persisted transcript records only that
    #: N digits were entered; the agent still receives them.
    persist_digits: bool = False


@dataclass(frozen=True)
class VoiceSessionConfig:
    endpointing: EndpointingConfig = field(default_factory=EndpointingConfig)
    barge_in: BargeInConfig = field(default_factory=BargeInConfig)
    dtmf: DtmfConfig = field(default_factory=DtmfConfig)
    stt: SttConfig = field(default_factory=SttConfig)
    tts: TtsConfig = field(default_factory=TtsConfig)
    greeting: str | None = None
    idle_prompt_text: str | None = "Are you still there?"
    idle_prompt_ms: int = 12_000
    idle_timeout_ms: int = 20_000
    max_call_ms: int = 600_000
    farewell_text: str | None = "We have reached the time limit for this call. Goodbye."
    farewell_grace_ms: int = 5_000
    agent_timeout_ms: int = 30_000
    agent_timeout_text: str = "Sorry, I am having trouble answering. Please try again."
    max_turns: int = 500
    # bounded queues and sizes
    inbound_queue_frames: int = 256
    max_frame_bytes: int = 4096
    event_queue: int = 256
    sentence_queue: int = 4
    sentence_min_chars: int = 12
    sentence_max_chars: int = 240
    #: Speaking-rate estimate for a sentence that was cut before its audio length was known.
    ms_per_char: int = 65

    def __post_init__(self) -> None:
        sizes = (self.inbound_queue_frames, self.event_queue, self.sentence_queue)
        if min(sizes) < 1 or self.max_turns < 1 or self.max_call_ms < 1:
            raise ValueError("queue sizes, max_turns and max_call_ms must be positive")
        if self.idle_timeout_ms < 1 or self.agent_timeout_ms < 1:
            raise ValueError("timeouts must be positive")


class _Phase(StrEnum):
    STARTING = "starting"
    CONSENT_NOTICE = "consent_notice"  # the notice is playing
    CONSENT_WAIT = "consent_wait"  # waiting for a keypress / spoken yes
    ACTIVE = "active"
    CLOSING = "closing"


# ---- internal events --------------------------------------------------------------------------


@dataclass(frozen=True)
class _TransportEv:
    event: TransportEvent


@dataclass(frozen=True)
class _SttEv:
    event: SttEvent


@dataclass(frozen=True)
class _SttEnded:
    pass


@dataclass(frozen=True)
class _Timer:
    kind: str
    token: int


@dataclass(frozen=True)
class _TurnDone:
    turn_id: int


@dataclass(frozen=True)
class _PumpFailed:
    name: str
    error: str
    denied: bool = False


_Ev = _TransportEv | _SttEv | _SttEnded | _Timer | _TurnDone | _PumpFailed


@dataclass
class _Sentence:
    text: str  # what was sent to TTS (speakable form)
    sent_ms: int = 0
    done: bool = False
    #: (cumulative ms after the chunk, chars_through) for each chunk sent
    chunks: list[tuple[int, int | None]] = field(default_factory=list)


@dataclass
class _Turn:
    turn_id: int
    kind: str  # "agent" | "consent" | "greeting" | "idle" | "farewell" | "error"
    turn_no: int  # the transcript turn number this reply answers (0 for system speech)
    barge_eligible: bool
    begin_ms: int
    utterance: str = ""
    sentences: list[_Sentence] = field(default_factory=list)
    intended: list[str] = field(default_factory=list)
    queue: asyncio.Queue[str | None] | None = None
    producer: asyncio.Task[None] | None = None
    speaker: asyncio.Task[None] | None = None
    runner: asyncio.Task[None] | None = None
    synth: TtsStream | None = None
    first_text_ms: int | None = None
    agent_done_ms: int | None = None
    first_audio_ms: int | None = None
    tts_request_ms: int | None = None
    sent_ms_total: int = 0
    error: str | None = None
    denied: bool = False
    metrics: StageMetrics | None = None
    speech_end_ms: int = 0  # when the caller's utterance ended (voice clock)


class VoiceSession:
    def __init__(
        self,
        *,
        transport: AudioTransport,
        stt: SttProvider,
        tts: TtsProvider,
        agent: AgentTurn,
        transcript: TranscriptWriter,
        clock: VoiceClock,
        config: VoiceSessionConfig | None = None,
        consent: ConsentPolicy | None = None,
        tracer: Tracer | None = None,
    ) -> None:
        self._transport = transport
        self._stt_provider = stt
        self._tts = tts
        self._agent = agent
        self._tw = transcript
        self._clock = clock
        self.config = config or VoiceSessionConfig()
        self._consent = consent or ConsentPolicy()
        self._tracer: Tracer = tracer or NoopTracer()
        self._call_id = transport.info.call_id

        cfg = self.config
        self._detector = TurnDetector(cfg.endpointing)
        self._events: asyncio.Queue[_Ev] = asyncio.Queue(maxsize=cfg.event_queue)
        self._frames: asyncio.Queue[Frame] = asyncio.Queue(maxsize=cfg.inbound_queue_frames)
        self._stt: SttStream | None = None
        self._phase = _Phase.STARTING
        self._turn: _Turn | None = None
        self._turn_ids = itertools.count(1)
        self._turn_no = 0
        self._tokens = itertools.count(1)
        self._timer_tokens: dict[str, int] = {}
        self._timer_tasks: dict[str, asyncio.Task[None]] = {}
        self._tasks: list[asyncio.Task[None]] = []
        self._audio_enabled = False
        self._history: list[VoiceTurn] = []
        self._end_reason: str | None = None
        self._ending_by_peer = False
        self._t0 = 0
        self._last_activity = 0
        self._idle_prompted = False
        self._dtmf_buf = ""
        self._dtmf_started = 0
        self._consent_granted: bool | None = None
        self._audio_hash = hashlib.sha256()
        self._audio_bytes = 0
        self._last_utterance = ""
        self._last_utterance_end = -1
        self._ignore_stt_until = -1
        self._tts_failures = 0
        # outcomes
        self.metrics: list[StageMetrics] = []
        self.barge_in_latencies_ms: list[int] = []
        self.frames_dropped = 0
        self.frames_rejected = 0
        self.dtmf_dropped = 0
        self._barge_ins = 0

    # ---- public --------------------------------------------------------------------------
    @property
    def history(self) -> tuple[VoiceTurn, ...]:
        """What the agent has been told (raw text: lives in memory only, never persisted)."""
        return tuple(self._history)

    async def run(self) -> CallSummary:
        self._t0 = self._clock.now_ms()
        self._last_activity = self._t0
        reason = "completed"
        try:
            await self._start()
            while self._end_reason is None:
                await self._dispatch(await self._events.get())
            reason = self._end_reason
        except asyncio.CancelledError:
            reason = "cancelled"
            raise
        except Exception as exc:
            log.warning("voice session failed", exc_info=True)
            reason = f"error:{type(exc).__name__}"
        finally:
            await self._shutdown(reason)
        return self._summary(reason)

    # ---- start ---------------------------------------------------------------------------
    async def _start(self) -> None:
        info = self._transport.info
        await self._tw.call_event(
            "connected",
            detail={"direction": info.direction.value, "consent_mode": self._consent.mode.value},
        )
        self._spawn(self._pump_transport(), "transport")
        self._arm("max_call", self.config.max_call_ms)
        if self._consent.mode is ConsentMode.NONE:
            await self._tw.call_event("consent", reason="not_required")
            await self._begin_conversation()
            return
        self._phase = _Phase.CONSENT_NOTICE
        self._begin_turn(
            self._say(self._consent.notice), kind="consent", barge_eligible=False, turn_no=0
        )

    async def _begin_conversation(self) -> None:
        self._phase = _Phase.ACTIVE
        await self._ensure_stt()
        if self._end_reason is not None:
            return
        self._audio_enabled = True
        self._detector.reset()
        greeting = self.config.greeting
        if greeting:
            self._begin_turn(self._say(greeting), kind="greeting", barge_eligible=True, turn_no=0)
        else:
            self._enter_listening()

    async def _ensure_stt(self) -> None:
        if self._stt is not None:
            return
        try:
            self._stt = await self._stt_provider.start(self.config.stt)
        except SpeechDeniedError:
            self._end("stt_denied")
            return
        except Exception as exc:
            log.warning("stt open failed: %s", type(exc).__name__)
            self._end("stt_failed")
            return
        self._spawn(self._pump_audio(self._stt), "audio")
        self._spawn(self._pump_stt(self._stt), "stt")

    def _spawn(self, coro: Coroutine[Any, Any, None], name: str) -> None:
        self._tasks.append(asyncio.create_task(coro, name=f"voice-{name}"))

    # ---- pumps ---------------------------------------------------------------------------
    async def _pump_transport(self) -> None:
        try:
            async for ev in self._transport.events():
                if isinstance(ev, Frame):
                    self._accept_frame(ev)
                else:
                    await self._events.put(_TransportEv(ev))
                if isinstance(ev, Hangup):
                    return
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await self._events.put(_PumpFailed("transport", type(exc).__name__))

    def _accept_frame(self, ev: Frame) -> None:
        if not self._audio_enabled or self._phase is _Phase.CLOSING:
            return  # before consent nothing the caller says is processed
        if len(ev.frame.data) > self.config.max_frame_bytes:
            self.frames_rejected += 1
            return
        if self._frames.full():  # live audio: drop the oldest, never block the line
            with contextlib.suppress(Exception):
                self._frames.get_nowait()
            self.frames_dropped += 1
        self._frames.put_nowait(ev)

    async def _pump_audio(self, stt: SttStream) -> None:
        try:
            while True:
                item = await self._frames.get()
                self._audio_hash.update(item.frame.data)
                self._audio_bytes += len(item.frame.data)
                await stt.send_audio(item.frame)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await self._events.put(_PumpFailed("stt_audio", type(exc).__name__))

    async def _pump_stt(self, stt: SttStream) -> None:
        try:
            async for ev in stt.events():
                await self._events.put(_SttEv(ev))
            await self._events.put(_SttEnded())
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await self._events.put(_PumpFailed("stt", type(exc).__name__))

    # ---- timers --------------------------------------------------------------------------
    def _arm(self, kind: str, ms: int) -> None:
        self._cancel_timer(kind)
        token = next(self._tokens)
        self._timer_tokens[kind] = token
        self._timer_tasks[kind] = asyncio.create_task(self._fire(kind, token, ms))

    def _cancel_timer(self, kind: str) -> None:
        self._timer_tokens.pop(kind, None)
        task = self._timer_tasks.pop(kind, None)
        if task is not None:
            task.cancel()

    async def _fire(self, kind: str, token: int, ms: int) -> None:
        await self._clock.sleep_ms(ms)
        await self._events.put(_Timer(kind, token))

    # ---- dispatch ------------------------------------------------------------------------
    async def _dispatch(self, ev: _Ev) -> None:
        if self._end_reason is not None:
            return
        if isinstance(ev, _TransportEv):
            t = ev.event
            if isinstance(t, Hangup):
                self._ending_by_peer = True
                self._end(t.reason)
            elif isinstance(t, Dtmf):
                await self._on_dtmf(t)
        elif isinstance(ev, _SttEv):
            await self._on_stt(ev.event)
        elif isinstance(ev, _Timer):
            if self._timer_tokens.get(ev.kind) == ev.token:
                self._timer_tokens.pop(ev.kind, None)
                self._timer_tasks.pop(ev.kind, None)
                await self._on_timer(ev.kind)
        elif isinstance(ev, _TurnDone):
            if self._turn is not None and self._turn.turn_id == ev.turn_id:
                await self._on_turn_done(self._turn)
        elif isinstance(ev, _SttEnded):
            if self._phase is not _Phase.CLOSING:
                self._end("stt_closed")
        elif isinstance(ev, _PumpFailed):
            self._end(f"{ev.name}_failed")

    def _end(self, reason: str) -> None:
        if self._end_reason is None:
            self._end_reason = reason
            self._phase = _Phase.CLOSING

    # ---- STT events ----------------------------------------------------------------------
    async def _on_stt(self, ev: SttEvent) -> None:
        now = self._clock.now_ms()
        if self._phase is _Phase.CONSENT_WAIT:
            await self._consent_from_speech(ev)
            return
        if self._phase is not _Phase.ACTIVE:
            return
        if 0 < ev.ts_ms <= self._ignore_stt_until or self._is_late_echo(ev):
            return
        has_speech = bool(ev.text.strip()) or ev.kind is SttEventKind.SPEECH_START
        turn = self._turn
        if turn is not None and turn.barge_eligible and self._barge_trigger(ev, turn, now):
            self._detector.on_stt(ev, now)
            self._note_activity(now)
            await self._barge_in(ev)
            self._arm_endpoint()
            return
        self._detector.on_stt(ev, now)
        if has_speech:
            self._note_activity(now)
        if turn is None:
            self._arm_endpoint()

    def _is_late_echo(self, ev: SttEvent) -> bool:
        """A late final / duplicate of the utterance a turn already answers is neither a new turn
        nor an interruption."""
        text = _norm(ev.text)
        if not text or ev.ts_ms <= 0 or ev.ts_ms > self._last_utterance_end:
            return False
        return text in self._last_utterance

    def _barge_trigger(self, ev: SttEvent, turn: _Turn, now: int) -> bool:
        cfg = self.config.barge_in
        if not cfg.enabled:
            return False
        if turn.first_audio_ms is not None and now - turn.first_audio_ms < cfg.grace_ms:
            return False
        if ev.kind is SttEventKind.SPEECH_START:
            return cfg.speech_start_triggers
        words = [w.strip(".,!?;:\"'").lower() for w in ev.text.split()]
        words = [w for w in words if w]
        if not words:
            return False
        if any(w in cfg.keywords for w in words):
            return True
        return len(words) >= cfg.min_words

    def _arm_endpoint(self) -> None:
        deadline = self._detector.deadline_ms()
        if deadline is None:
            return
        self._arm("endpoint", max(0, deadline - self._clock.now_ms()))

    def _note_activity(self, now: int) -> None:
        self._last_activity = now
        self._idle_prompted = False
        if self._turn is None:
            self._arm_idle()

    # ---- timers ----------------------------------------------------------------------------
    async def _on_timer(self, kind: str) -> None:
        now = self._clock.now_ms()
        if kind == "max_call":
            await self._on_max_call()
        elif kind == "endpoint":
            await self._on_endpoint(now)
        elif kind == "idle":
            await self._on_idle(now)
        elif kind == "dtmf":
            await self._flush_dtmf()
        elif kind == "consent":
            if self._phase is _Phase.CONSENT_WAIT:
                await self._consent_refused("timeout", "consent_timeout")
        elif kind == "agent":
            await self._on_agent_timeout()
        elif kind == "farewell":
            self._end("max_duration")

    async def _on_max_call(self) -> None:
        cfg = self.config
        if self._phase in (_Phase.ACTIVE,) and cfg.farewell_text:
            if self._turn is not None:
                await self._cancel_turn(self._turn, record=True)
            self._phase = _Phase.CLOSING
            self._begin_turn(
                self._say(cfg.farewell_text), kind="farewell", barge_eligible=False, turn_no=0
            )
            self._arm("farewell", cfg.farewell_grace_ms)  # the farewell is spoken first
            return
        self._end("max_duration")

    async def _on_endpoint(self, now: int) -> None:
        if self._phase is not _Phase.ACTIVE or self._turn is not None:
            return
        started = self._detector.started_ms
        first_ts = self._detector.first_ts_ms
        last_activity = self._detector.last_activity_ms
        text = self._detector.poll(now)
        if text is None:
            self._arm_endpoint()
            return
        await self._start_user_turn(
            text,
            input_kind="speech",
            started_ms=started if started is not None else now,
            first_ts=first_ts if first_ts is not None else now,
            last_activity=last_activity if last_activity is not None else now,
        )

    async def _on_idle(self, now: int) -> None:
        cfg = self.config
        if self._phase is not _Phase.ACTIVE or self._turn is not None or self._detector.active:
            return
        quiet = now - self._last_activity
        if quiet >= cfg.idle_timeout_ms:
            self._end("idle_timeout")
            return
        if cfg.idle_prompt_text and not self._idle_prompted and quiet >= cfg.idle_prompt_ms:
            self._idle_prompted = True
            self._begin_turn(
                self._say(cfg.idle_prompt_text), kind="idle", barge_eligible=True, turn_no=0
            )
            return
        self._arm_idle()

    def _arm_idle(self) -> None:
        cfg = self.config
        now = self._clock.now_ms()
        quiet = now - self._last_activity
        targets = [cfg.idle_timeout_ms]
        if cfg.idle_prompt_text and not self._idle_prompted:
            targets.append(cfg.idle_prompt_ms)
        remaining = min(max(1, t - quiet) for t in targets)
        self._arm("idle", remaining)

    def _enter_listening(self, *, reset_idle: bool = True) -> None:
        self._turn = None
        self._detector.reset()
        if reset_idle:
            self._last_activity = self._clock.now_ms()
        self._arm_idle()

    # ---- DTMF ----------------------------------------------------------------------------
    async def _on_dtmf(self, ev: Dtmf) -> None:
        digit = ev.digit.upper()
        if len(digit) != 1 or digit not in _DTMF_KEYS:
            self.dtmf_dropped += 1
            return
        if self._phase is _Phase.CONSENT_WAIT and self._consent.mode is ConsentMode.DTMF:
            if digit == self._consent.accept_digit:
                await self._grant_consent("dtmf")
            elif digit == self._consent.decline_digit:
                await self._consent_refused("declined", "consent_declined")
            return
        cfg = self.config.dtmf
        if self._phase is not _Phase.ACTIVE or not cfg.enabled:
            self.dtmf_dropped += 1  # nothing is processed before consent, or when DTMF is off
            return
        turn = self._turn
        if turn is not None and turn.barge_eligible and self.config.barge_in.dtmf_interrupts:
            if self.config.barge_in.enabled:
                await self._barge_in(None)
        if len(self._dtmf_buf) >= cfg.max_digits:
            self.dtmf_dropped += 1  # a flood cannot grow the buffer
            return
        now = self._clock.now_ms()
        if not self._dtmf_buf:
            self._dtmf_started = now
        self._note_activity(now)
        if digit == cfg.terminator:
            await self._flush_dtmf()
            return
        self._dtmf_buf += digit
        self._arm("dtmf", cfg.interdigit_timeout_ms)

    async def _flush_dtmf(self) -> None:
        digits, self._dtmf_buf = self._dtmf_buf, ""
        self._cancel_timer("dtmf")
        if not digits or self._phase is not _Phase.ACTIVE:
            return
        if self._turn is not None:
            self._dtmf_buf = digits  # an uninterruptible turn is speaking: hold the digits
            self._arm("dtmf", self.config.dtmf.interdigit_timeout_ms)
            return
        now = self._clock.now_ms()
        await self._start_user_turn(
            digits,
            input_kind="dtmf",
            started_ms=self._dtmf_started,
            first_ts=self._dtmf_started,
            last_activity=now,
        )

    # ---- turns ---------------------------------------------------------------------------
    async def _start_user_turn(
        self, text: str, *, input_kind: str, started_ms: int, first_ts: int, last_activity: int
    ) -> None:
        now = self._clock.now_ms()
        if self._turn_no >= self.config.max_turns:
            self._end("max_turns")
            return
        self._turn_no += 1
        n = self._turn_no
        self._cancel_timer("idle")
        self._cancel_timer("endpoint")
        role = TurnRole.DTMF if input_kind == "dtmf" else TurnRole.USER
        audio_sha = self._audio_hash.hexdigest() if input_kind == "speech" else None
        audio_bytes = self._audio_bytes if input_kind == "speech" else 0
        self._audio_hash, self._audio_bytes = hashlib.sha256(), 0
        stored = text
        if input_kind == "dtmf" and not self.config.dtmf.persist_digits:
            stored = f"[{len(text)} keypad digits]"
        persisted = VoiceTurn(n, role, stored, started_ms, now)
        await self._tw.add_turn(persisted, audio_sha256=audio_sha, audio_bytes=audio_bytes)
        request = AgentTurnRequest(
            call_id=self._call_id,
            turn=n,
            utterance=text,
            input_kind=input_kind,
            history=tuple(self._history),
        )
        self._history.append(VoiceTurn(n, role, text, started_ms, now))
        self._last_utterance = _norm(text)
        self._last_utterance_end = now
        metrics = StageMetrics(
            turn=n,
            endpoint_silence_ms=max(0, now - last_activity),
            stt_ms=max(0, now - started_ms),
        )
        turn = self._begin_turn(
            self._agent.reply(request), kind="agent", barge_eligible=True, turn_no=n
        )
        turn.utterance = _norm(text)
        turn.metrics = metrics
        turn.speech_end_ms = last_activity
        self._arm("agent", self.config.agent_timeout_ms)

    def _say(self, text: str) -> AsyncGenerator[str, None]:
        async def one() -> AsyncGenerator[str, None]:
            yield text

        return one()

    def _begin_turn(
        self, deltas: AsyncGenerator[str, None], *, kind: str, barge_eligible: bool, turn_no: int
    ) -> _Turn:
        cfg = self.config
        turn = _Turn(
            next(self._turn_ids), kind, turn_no, barge_eligible, begin_ms=self._clock.now_ms()
        )
        turn.queue = asyncio.Queue(maxsize=cfg.sentence_queue)
        self._turn = turn
        turn.runner = asyncio.create_task(
            self._run_turn(turn, deltas), name=f"voice-turn-{turn_no}"
        )
        return turn

    async def _run_turn(self, turn: _Turn, deltas: AsyncGenerator[str, None]) -> None:
        turn.producer = asyncio.create_task(self._produce(turn, deltas))
        turn.speaker = asyncio.create_task(self._speak(turn))
        parts = (turn.producer, turn.speaker)
        try:
            results = await asyncio.gather(*parts, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    turn.error = turn.error or type(r).__name__
            await self._drain_playout()
        except asyncio.CancelledError:
            for t in parts:
                t.cancel()
            await asyncio.gather(*parts, return_exceptions=True)
            raise
        await self._events.put(_TurnDone(turn.turn_id))

    async def _drain_playout(self) -> None:
        while True:
            queued = self._transport.queued_ms()
            if queued <= 0:
                return
            await self._clock.sleep_ms(queued)

    async def _produce(self, turn: _Turn, deltas: AsyncGenerator[str, None]) -> None:
        cfg = self.config
        assert turn.queue is not None  # noqa: S101
        chunker = SentenceChunker(
            min_chars=cfg.sentence_min_chars, max_chars=cfg.sentence_max_chars
        )
        try:
            async for delta in deltas:
                if delta and turn.first_text_ms is None:
                    turn.first_text_ms = self._clock.now_ms()
                    self._cancel_timer("agent")
                turn.intended.append(delta)
                for sentence in chunker.feed(delta):
                    await turn.queue.put(sentence)
            for sentence in chunker.flush():
                await turn.queue.put(sentence)
            turn.agent_done_ms = self._clock.now_ms()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            turn.error = type(exc).__name__
            log.warning("agent turn failed: %s", type(exc).__name__)
            turn.agent_done_ms = self._clock.now_ms()
        finally:
            with contextlib.suppress(Exception):
                await deltas.aclose()
        await turn.queue.put(None)

    async def _speak(self, turn: _Turn) -> None:
        assert turn.queue is not None  # noqa: S101
        cfg = self.config
        while True:
            item = await turn.queue.get()
            if item is None:
                return
            text = speakable(item)
            if not text:
                continue
            sentence = _Sentence(text)
            turn.sentences.append(sentence)
            requested = self._clock.now_ms()
            if turn.tts_request_ms is None:
                turn.tts_request_ms = requested
            try:
                stream = await self._tts.synthesize(text, cfg.tts)
            except SpeechDeniedError:
                turn.denied = True
                turn.error = "tts_denied"
                self._stop_producer(turn)
                return
            except Exception as exc:
                turn.error = f"tts:{type(exc).__name__}"
                self._stop_producer(turn)
                return
            turn.synth = stream
            try:
                async for chunk in stream.chunks():
                    if turn.first_audio_ms is None:
                        turn.first_audio_ms = self._clock.now_ms()
                    await self._transport.send_audio(chunk.audio, chunk.duration_ms)
                    sentence.sent_ms += chunk.duration_ms
                    turn.sent_ms_total += chunk.duration_ms
                    sentence.chunks.append((sentence.sent_ms, chunk.chars_through))
                sentence.done = True
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                turn.error = f"tts:{type(exc).__name__}"
                self._stop_producer(turn)
                return
            finally:
                if not sentence.done:
                    with contextlib.suppress(Exception):
                        await stream.cancel()
                turn.synth = None

    @staticmethod
    def _stop_producer(turn: _Turn) -> None:
        if turn.producer is not None:
            turn.producer.cancel()

    # ---- turn completion -----------------------------------------------------------------
    async def _on_turn_done(self, turn: _Turn) -> None:
        self._cancel_timer("agent")
        spoken = self._spoken_text(turn, discarded_ms=0)
        intended = "".join(turn.intended)
        completed = turn.error is None and all(s.done for s in turn.sentences)
        if turn.kind == "consent":
            await self._record_system(turn, spoken)
            self._turn = None
            await self._after_consent_notice(completed and bool(turn.sentences))
            return
        await self._finish_turn_record(turn, spoken, intended, truncated=False)
        self._turn = None
        if turn.denied:
            self._end("tts_denied")
            return
        if turn.error is not None and turn.error.startswith("tts:"):
            self._tts_failures += 1
            if self._tts_failures >= 2:
                self._end("tts_failed")
                return
        elif turn.sentences:
            self._tts_failures = 0
        if turn.kind == "farewell":
            self._end("max_duration")
            return
        if turn.kind == "agent" and turn.error is not None and not turn.sentences:
            # the agent failed before saying anything: tell the caller instead of going silent
            self._begin_turn(
                self._say(self.config.agent_timeout_text),
                kind="error",
                barge_eligible=True,
                turn_no=0,
            )
            return
        self._enter_listening(reset_idle=turn.kind != "idle")
        await self._flush_dtmf()

    async def _record_system(self, turn: _Turn, spoken: str) -> None:
        now = self._clock.now_ms()
        await self._tw.add_turn(VoiceTurn(0, TurnRole.SYSTEM, spoken, turn.begin_ms, now))

    async def _finish_turn_record(
        self, turn: _Turn, spoken: str, intended: str, *, truncated: bool
    ) -> None:
        now = self._clock.now_ms()
        role = TurnRole.AGENT if turn.kind == "agent" else TurnRole.SYSTEM
        n = turn.turn_no
        record = VoiceTurn(n, role, spoken, turn.begin_ms, now, truncated, intended)
        await self._tw.add_turn(record)
        if role is TurnRole.AGENT or spoken:
            self._history.append(
                VoiceTurn(n, role, spoken, turn.begin_ms, now, truncated, intended)
            )
        m = turn.metrics
        if m is not None:
            self._complete_metrics(turn, m)
            self.metrics.append(m)
            await self._tw.metrics(m)
            self._emit_spans(m)

    def _complete_metrics(self, turn: _Turn, m: StageMetrics) -> None:
        decided = turn.begin_ms
        if turn.first_text_ms is not None:
            m.agent_first_ms = turn.first_text_ms - decided
        if turn.agent_done_ms is not None:
            m.agent_total_ms = turn.agent_done_ms - decided
        if turn.first_audio_ms is not None:
            if turn.tts_request_ms is not None:
                m.tts_first_byte_ms = turn.first_audio_ms - turn.tts_request_ms
            m.response_ms = turn.first_audio_ms - decided
            m.perceived_ms = turn.first_audio_ms - turn.speech_end_ms

    def _emit_spans(self, m: StageMetrics) -> None:
        stages = (
            ("voice.stt", m.stt_ms),
            ("voice.agent", m.agent_first_ms),
            ("voice.tts", m.tts_first_byte_ms),
        )
        for name, value in stages:
            if value is None:
                continue
            span = self._tracer.start_span(
                name, attributes={"call_id": self._call_id, "turn": m.turn, "latency_ms": value}
            )
            span.end()

    async def _on_agent_timeout(self) -> None:
        turn = self._turn
        if turn is None or turn.kind != "agent" or turn.first_text_ms is not None:
            return
        await self._cancel_turn(turn, record=True, error="agent_timeout")
        self._begin_turn(
            self._say(self.config.agent_timeout_text), kind="error", barge_eligible=True, turn_no=0
        )

    # ---- barge-in ------------------------------------------------------------------------
    async def _barge_in(self, trigger: SttEvent | None) -> None:
        turn = self._turn
        if turn is None:
            return
        await self._cancel_turn(turn, record=True)
        now = self._clock.now_ms()
        latency = now - (trigger.ts_ms if trigger is not None else now)
        self.barge_in_latencies_ms.append(max(0, latency))
        self._barge_ins += 1
        await self._tw.stage(turn.turn_no, "barge_in", max(0, latency))
        self._turn = None
        self._phase = _Phase.ACTIVE
        self._last_activity = now

    async def _cancel_turn(self, turn: _Turn, *, record: bool, error: str | None = None) -> None:
        """Stop a turn NOW: cancel its tasks, flush playout, record what was spoken."""
        self._cancel_timer("agent")
        for t in (turn.runner, turn.producer, turn.speaker):
            if t is not None:
                t.cancel()
        discarded = 0
        with contextlib.suppress(Exception):
            discarded = await self._transport.clear_output()
        tasks = [t for t in (turn.runner, turn.producer, turn.speaker) if t is not None]
        await asyncio.gather(*tasks, return_exceptions=True)
        if turn.synth is not None:
            with contextlib.suppress(Exception):
                await turn.synth.cancel()
        if turn.kind == "consent":
            return  # an unfinished notice is handled by the caller (consent not given)
        if not record:
            return
        spoken = self._spoken_text(turn, discarded_ms=discarded)
        intended = "".join(turn.intended)
        if error is not None:
            turn.error = error
        await self._finish_turn_record(turn, spoken, intended, truncated=True)

    def _spoken_text(self, turn: _Turn, *, discarded_ms: int) -> str:
        """The words that actually reached the caller: all sentences whose audio finished playing,
        plus the played fraction of the one that was cut (word boundary, never beyond the text)."""
        remaining = max(0, turn.sent_ms_total - discarded_ms)
        parts: list[str] = []
        for s in turn.sentences:
            total = s.sent_ms if s.done else max(s.sent_ms, self.config.ms_per_char * len(s.text))
            if s.done and s.sent_ms <= remaining:
                parts.append(s.text)
                remaining -= s.sent_ms
                continue
            if remaining <= 0:
                break
            chars = _chars_played(s, remaining, total)
            cut = s.text[:chars]
            if chars < len(s.text) and not s.text[chars].isspace() and " " in cut:
                cut = cut.rsplit(None, 1)[0]
            elif chars < len(s.text) and not s.text[chars].isspace():
                cut = ""
            if cut.strip():
                parts.append(cut.strip())
            break
        return " ".join(parts)

    # ---- consent -------------------------------------------------------------------------
    async def _after_consent_notice(self, played_fully: bool) -> None:
        if not played_fully:
            await self._consent_refused("notice_not_played", "consent_notice_failed")
            return
        if self._consent.mode is ConsentMode.NOTICE:
            await self._grant_consent("notice")
            return
        self._phase = _Phase.CONSENT_WAIT
        self._arm("consent", self._consent.timeout_ms)
        if self._consent.mode is ConsentMode.SPEECH:
            await self._ensure_stt()
            self._audio_enabled = self._stt is not None

    async def _consent_from_speech(self, ev: SttEvent) -> None:
        # Only a FINAL answers: partials of the same sentence must not grant early, and the rest
        # of the answering utterance is consumed here instead of leaking into the conversation.
        if (
            self._consent.mode is not ConsentMode.SPEECH
            or ev.kind is not SttEventKind.FINAL
            or not ev.text.strip()
        ):
            return
        verdict = classify_consent_speech(ev.text, self._consent)
        if verdict == "accept":
            await self._grant_consent("speech")
        elif verdict == "decline":
            await self._consent_refused("declined", "consent_declined")

    async def _grant_consent(self, how: str) -> None:
        self._cancel_timer("consent")
        self._consent_granted = True
        sha = hashlib.sha256(self._consent.notice.encode("utf-8")).hexdigest()
        await self._tw.call_event(
            "consent",
            reason=f"granted:{how}",
            detail={"mode": self._consent.mode.value, "notice_sha256": sha, "granted": True},
        )
        self._audio_hash, self._audio_bytes = hashlib.sha256(), 0  # nothing before consent counts
        self._ignore_stt_until = self._clock.now_ms()  # nor does speech heard before it
        await self._begin_conversation()

    async def _consent_refused(self, why: str, end_reason: str) -> None:
        self._cancel_timer("consent")
        self._consent_granted = False
        self._audio_enabled = False
        await self._tw.call_event(
            "consent",
            reason=f"refused:{why}",
            detail={"mode": self._consent.mode.value, "granted": False},
        )
        self._end(end_reason)

    # ---- shutdown ------------------------------------------------------------------------
    async def _shutdown(self, reason: str) -> None:
        self._phase = _Phase.CLOSING
        self._audio_enabled = False
        timers = list(self._timer_tasks.values())
        for kind in list(self._timer_tasks):
            self._cancel_timer(kind)
        await asyncio.gather(*timers, return_exceptions=True)
        turn = self._turn
        if turn is not None:
            record = turn.kind != "consent" and reason != "cancelled"
            with contextlib.suppress(Exception):
                await self._cancel_turn(turn, record=record)
            self._turn = None
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._stt is not None:
            with contextlib.suppress(Exception):
                await self._stt.aclose()
        if not self._ending_by_peer:
            with contextlib.suppress(Exception):
                await self._transport.hangup(reason)
        duration = self._clock.now_ms() - self._t0
        with contextlib.suppress(Exception):
            await self._tw.call_event(
                "ended",
                reason=reason,
                duration_ms=duration,
                detail={
                    "turns": self._turn_no,
                    "barge_ins": self._barge_ins,
                    "frames_dropped": self.frames_dropped,
                    "frames_rejected": self.frames_rejected,
                    "dtmf_dropped": self.dtmf_dropped,
                },
            )

    def _summary(self, reason: str) -> CallSummary:
        return CallSummary(
            call_id=self._call_id,
            reason=reason,
            duration_ms=self._clock.now_ms() - self._t0,
            turns=self._turn_no,
            barge_ins=self._barge_ins,
            frames_dropped=self.frames_dropped,
            consent_granted=self._consent_granted,
            metrics=tuple(self.metrics),
            barge_in_latencies_ms=tuple(self.barge_in_latencies_ms),
        )


def _norm(text: str) -> str:
    return " ".join("".join(c.lower() if c.isalnum() else " " for c in text).split())


def _chars_played(s: _Sentence, remaining_ms: int, total_ms: int) -> int:
    """Characters of ``s`` covered after ``remaining_ms`` of its audio played."""
    through: int | None = None
    for cum_ms, chars in s.chunks:
        if cum_ms <= remaining_ms:
            through = chars if chars is not None else through
        else:
            break
    if through is not None and any(c is not None for _, c in s.chunks):
        return min(len(s.text), through)
    if total_ms <= 0:
        return 0
    return min(len(s.text), int(len(s.text) * min(1.0, remaining_ms / total_ms)))
