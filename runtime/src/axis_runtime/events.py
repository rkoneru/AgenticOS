"""Event-sourced run state.

Process state is derived ONLY by folding events (``reduce``/``apply_event``).  The log is
append-only with gapless per-run sequence numbers and a SHA-256 hash chain, so a corrupted,
gapped, reordered or tampered log is rejected on replay.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from axis_runtime._decision import Decision
from axis_runtime.process import (
    ExitReason,
    IllegalTransitionError,
    ProcessState,
    Signal,
    is_terminal,
    is_valid_pid,
    next_state,
)

GENESIS_HASH = "0" * 64
JSON = Any


class EventType(StrEnum):
    RUN_STARTED = "run_started"
    PROCESS_SPAWNED = "process_spawned"
    PROCESS_TRANSITION = "process_transition"
    SIGNAL_DELIVERED = "signal_delivered"
    GATE_DECISION = "gate_decision"
    TOOL_CALL_RESULT = "tool_call_result"
    MODEL_CALL = "model_call"
    ACTION_BLOCKED = "action_blocked"
    BUDGET_WARNING = "budget_warning"
    PROCESS_OUTPUT = "process_output"
    # Additive (ADR 0012): NEXUS routing telemetry. Folded into RunState; older readers reject them.
    NEXUS_STAGE = "nexus_stage"
    NEXUS_ROUTE = "nexus_route"
    # Additive (ADR 0015): voice call lifecycle, transcript turns and per-stage latency.
    VOICE_CALL = "voice_call"
    VOICE_TURN = "voice_turn"
    VOICE_STAGE = "voice_stage"


class CorruptLogError(Exception):
    """The event log violates an invariant (gap, bad hash, illegal transition, ...)."""

    def __init__(self, reason: str, seq: int | None = None) -> None:
        super().__init__(reason if seq is None else f"seq {seq}: {reason}")
        self.reason = reason
        self.seq = seq


class SequenceConflictError(Exception):
    """An append did not extend the log head (concurrent writer or stale state)."""


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RunEvent:
    run_id: str
    seq: int
    ts: str
    type: str
    pid: str | None
    data: Mapping[str, JSON]
    prev_hash: str
    hash: str

    def body(self) -> dict[str, JSON]:
        return {
            "run_id": self.run_id,
            "seq": self.seq,
            "ts": self.ts,
            "type": self.type,
            "pid": self.pid,
            "data": self.data,
            "prev_hash": self.prev_hash,
        }

    def to_dict(self) -> dict[str, JSON]:
        return {**self.body(), "hash": self.hash}

    @classmethod
    def from_dict(cls, raw: Mapping[str, JSON]) -> RunEvent:
        try:
            return cls(
                run_id=str(raw["run_id"]),
                seq=int(raw["seq"]),
                ts=str(raw["ts"]),
                type=str(raw["type"]),
                pid=None if raw["pid"] is None else str(raw["pid"]),
                data=dict(raw["data"]),
                prev_hash=str(raw["prev_hash"]),
                hash=str(raw["hash"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CorruptLogError(f"malformed event: {type(exc).__name__}") from exc


def compute_hash(body: Mapping[str, JSON]) -> str:
    return sha256_hex(body)


def seal_event(
    *,
    run_id: str,
    seq: int,
    ts: str,
    type: str,
    pid: str | None,
    data: Mapping[str, JSON],
    prev_hash: str,
) -> RunEvent:
    body = {
        "run_id": run_id,
        "seq": seq,
        "ts": ts,
        "type": type,
        "pid": pid,
        "data": dict(data),
        "prev_hash": prev_hash,
    }
    return RunEvent(
        run_id=run_id,
        seq=seq,
        ts=ts,
        type=type,
        pid=pid,
        data=dict(data),
        prev_hash=prev_hash,
        hash=compute_hash(body),
    )


# --------------------------------------------------------------------------------------
# Folded state
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ProcessInfo:
    pid: str
    ppid: str | None
    agent: str
    state: ProcessState
    exit_reason: ExitReason | None = None
    exit_detail: str | None = None


@dataclass(frozen=True)
class GateDecisionRecord:
    action_id: str
    pid: str
    enforcement_point: str
    action: str
    decision: Decision
    reason: str
    policy_version: str
    redact_fields: tuple[str, ...]
    approval_id: str
    audit_event_id: str


@dataclass(frozen=True)
class ToolCallRecord:
    action_id: str
    pid: str
    enforcement_point: str
    name: str
    ok: bool
    result: JSON
    error: str | None


@dataclass(frozen=True)
class ModelCallSummary:
    action_id: str
    pid: str
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    cached_tokens: int
    cost_micro_usd: int | None
    finish_reason: str
    latency_ms: int


@dataclass(frozen=True)
class NexusStageRecord:
    """One routing stage attempt (``docs/spec/nexus.md``): name, hit/miss, tokens and cost."""

    pid: str
    stage: str
    outcome: str  # "hit" | "miss"
    reason: str
    latency_ms: float
    tokens: int
    cost_usd: str  # decimal string: never a float
    cache_key_hash: str | None
    confidence: float | None


@dataclass(frozen=True)
class NexusRouteRecord:
    pid: str
    status: str  # "hit" | "blocked" | "exhausted"
    hit_stage: str | None
    total_tokens: int
    total_cost_usd: str
    cost_by_stage: Mapping[str, str]


@dataclass(frozen=True)
class VoiceCallRecord:
    """A call lifecycle step (``connected`` / ``consent`` / ``ended`` ...): docs/spec/voice.md."""

    pid: str
    call_id: str
    phase: str
    reason: str | None
    duration_ms: int | None
    detail: Mapping[str, JSON]


@dataclass(frozen=True)
class VoiceTurnRecord:
    """One transcript turn as PERSISTED: ``text`` is already redacted in PHI mode, and there is no
    audio, only its hash and size."""

    pid: str
    call_id: str
    turn: int
    role: str  # "user" | "agent" | "system" | "dtmf"
    text: str
    redacted: bool
    truncated: bool
    start_ms: int
    end_ms: int
    text_sha256: str
    text_chars: int
    audio_sha256: str | None
    audio_bytes: int
    intended_chars: int = 0  # agent turns: characters the agent meant to say (>= text_chars if cut)


@dataclass(frozen=True)
class VoiceStageRecord:
    pid: str
    call_id: str
    turn: int
    stage: str  # "stt" | "agent" | "tts" | "response" | "barge_in"
    latency_ms: int


@dataclass(frozen=True)
class RunState:
    run_id: str
    tenant_id: str
    last_seq: int = 0
    last_hash: str = GENESIS_HASH
    processes: Mapping[str, ProcessInfo] = field(default_factory=dict)
    gate_decisions: tuple[GateDecisionRecord, ...] = ()
    tool_calls: tuple[ToolCallRecord, ...] = ()
    model_calls: tuple[ModelCallSummary, ...] = ()
    blocked_actions: int = 0
    warnings: tuple[str, ...] = ()
    outputs: Mapping[str, str] = field(default_factory=dict)
    signals: tuple[tuple[str, str], ...] = ()
    nexus_stages: tuple[NexusStageRecord, ...] = ()
    nexus_routes: tuple[NexusRouteRecord, ...] = ()
    voice_calls: tuple[VoiceCallRecord, ...] = ()
    voice_turns: tuple[VoiceTurnRecord, ...] = ()
    voice_stages: tuple[VoiceStageRecord, ...] = ()

    @property
    def tokens_used(self) -> int:
        return sum(m.input_tokens + m.output_tokens for m in self.model_calls)

    @property
    def cost_micro_usd(self) -> int:
        return sum(m.cost_micro_usd or 0 for m in self.model_calls)

    @property
    def tool_calls_used(self) -> int:
        return len(self.tool_calls)


# --------------------------------------------------------------------------------------
# Reducer
# --------------------------------------------------------------------------------------


def _get(data: Mapping[str, JSON], key: str, typ: type | tuple[type, ...], seq: int) -> Any:
    value = data.get(key)
    if not isinstance(value, typ) or (typ is not bool and isinstance(value, bool)):
        raise CorruptLogError(f"missing or mistyped field {key!r}", seq)
    return value


def _proc(state: RunState, event: RunEvent, *, live: bool = False) -> ProcessInfo:
    if event.pid is None or event.pid not in state.processes:
        raise CorruptLogError("event references unknown pid", event.seq)
    info = state.processes[event.pid]
    if live and is_terminal(info.state):
        raise CorruptLogError("action event for a terminated process", event.seq)
    return info


def initial_state(run_id: str, tenant_id: str) -> RunState:
    return RunState(run_id=run_id, tenant_id=tenant_id)


def apply_event(state: RunState | None, event: RunEvent) -> RunState:
    """Validate ``event`` against ``state`` and return the next state (pure)."""
    expected_seq = 1 if state is None else state.last_seq + 1
    prev_hash = GENESIS_HASH if state is None else state.last_hash
    if event.seq != expected_seq:
        kind = "gap" if event.seq > expected_seq else "duplicate or reordered"
        raise CorruptLogError(f"{kind}: expected seq {expected_seq}", event.seq)
    if event.prev_hash != prev_hash:
        raise CorruptLogError("broken hash chain (prev_hash)", event.seq)
    if event.hash != compute_hash(event.body()):
        raise CorruptLogError("event content does not match its hash", event.seq)
    if state is not None and event.run_id != state.run_id:
        raise CorruptLogError("event belongs to a different run", event.seq)

    d = event.data
    seq = event.seq
    if state is None:
        if event.type != EventType.RUN_STARTED:
            raise CorruptLogError("first event must be run_started", seq)
        tenant = _get(d, "tenant_id", str, seq)
        state = initial_state(event.run_id, tenant)
        return replace(state, last_seq=seq, last_hash=event.hash)
    base = replace(state, last_seq=seq, last_hash=event.hash)

    if event.type == EventType.RUN_STARTED:
        raise CorruptLogError("duplicate run_started", seq)

    if event.type == EventType.PROCESS_SPAWNED:
        pid = event.pid
        if not is_valid_pid(pid) or pid is None:
            raise CorruptLogError("invalid pid", seq)
        if pid in state.processes:
            raise CorruptLogError("duplicate pid", seq)
        ppid = d.get("ppid")
        if ppid is not None:
            if ppid not in state.processes:
                raise CorruptLogError("unknown ppid", seq)
            if is_terminal(state.processes[ppid].state):
                raise CorruptLogError("spawn under a terminated parent", seq)
        elif state.processes:
            raise CorruptLogError("a run has exactly one init process (ppid null)", seq)
        info = ProcessInfo(
            pid=pid, ppid=ppid, agent=_get(d, "agent", str, seq), state=ProcessState.SPAWN
        )
        return replace(base, processes={**state.processes, pid: info})

    if event.type == EventType.PROCESS_TRANSITION:
        info = _proc(state, event)
        src = _get(d, "from", str, seq)
        dst = _get(d, "to", str, seq)
        trigger = _get(d, "trigger", str, seq)
        if src != info.state.value:
            raise CorruptLogError(
                f"transition from {src!r} but process is {info.state.value!r}", seq
            )
        try:
            target = next_state(info.state, trigger)
        except IllegalTransitionError as exc:
            raise CorruptLogError(str(exc), seq) from exc
        if target.value != dst:
            raise CorruptLogError(
                f"{trigger!r} from {src!r} leads to {target.value!r}, not {dst!r}", seq
            )
        reason: ExitReason | None = None
        detail: str | None = None
        exit_reason = d.get("exit_reason")
        if is_terminal(target):
            try:
                reason = ExitReason(str(exit_reason))
            except ValueError as exc:
                raise CorruptLogError("terminated requires a valid exit_reason", seq) from exc
            detail = d.get("detail") if isinstance(d.get("detail"), str) else None
        elif exit_reason is not None:
            raise CorruptLogError("exit_reason only valid on terminated", seq)
        updated = replace(info, state=target, exit_reason=reason, exit_detail=detail)
        return replace(base, processes={**state.processes, info.pid: updated})

    if event.type == EventType.SIGNAL_DELIVERED:
        info = _proc(state, event)
        try:
            sig = Signal(_get(d, "signal", str, seq))
        except ValueError as exc:
            raise CorruptLogError("unknown signal", seq) from exc
        return replace(base, signals=(*state.signals, (info.pid, sig.value)))

    if event.type == EventType.GATE_DECISION:
        info = _proc(state, event, live=True)
        try:
            decision = Decision(_get(d, "decision", str, seq))
        except ValueError as exc:
            raise CorruptLogError("unknown decision", seq) from exc
        rec = GateDecisionRecord(
            action_id=_get(d, "action_id", str, seq),
            pid=info.pid,
            enforcement_point=_get(d, "enforcement_point", str, seq),
            action=_get(d, "action", str, seq),
            decision=decision,
            reason=_get(d, "reason", str, seq),
            policy_version=_get(d, "policy_version", str, seq),
            redact_fields=tuple(_get(d, "redact_fields", list, seq)),
            approval_id=_get(d, "approval_id", str, seq),
            audit_event_id=_get(d, "audit_event_id", str, seq),
        )
        return replace(base, gate_decisions=(*state.gate_decisions, rec))

    if event.type == EventType.TOOL_CALL_RESULT:
        info = _proc(state, event, live=True)
        err = d.get("error")
        trec = ToolCallRecord(
            action_id=_get(d, "action_id", str, seq),
            pid=info.pid,
            enforcement_point=_get(d, "enforcement_point", str, seq),
            name=_get(d, "name", str, seq),
            ok=_get(d, "ok", bool, seq),
            result=d.get("result"),
            error=err if isinstance(err, str) else None,
        )
        return replace(base, tool_calls=(*state.tool_calls, trec))

    if event.type == EventType.MODEL_CALL:
        info = _proc(state, event, live=True)
        cost = d.get("cost_micro_usd")
        if cost is not None and (not isinstance(cost, int) or isinstance(cost, bool)):
            raise CorruptLogError("cost_micro_usd must be an integer", seq)
        mrec = ModelCallSummary(
            action_id=_get(d, "action_id", str, seq),
            pid=info.pid,
            provider=_get(d, "provider", str, seq),
            model=_get(d, "model", str, seq),
            input_tokens=_get(d, "input_tokens", int, seq),
            output_tokens=_get(d, "output_tokens", int, seq),
            cached_tokens=_get(d, "cached_tokens", int, seq),
            cost_micro_usd=cost,
            finish_reason=_get(d, "finish_reason", str, seq),
            latency_ms=_get(d, "latency_ms", int, seq),
        )
        return replace(base, model_calls=(*state.model_calls, mrec))

    if event.type == EventType.ACTION_BLOCKED:
        _proc(state, event)
        return replace(base, blocked_actions=state.blocked_actions + 1)

    if event.type == EventType.BUDGET_WARNING:
        _proc(state, event)
        return replace(base, warnings=(*state.warnings, _get(d, "budget", str, seq)))

    if event.type == EventType.PROCESS_OUTPUT:
        info = _proc(state, event)
        return replace(base, outputs={**state.outputs, info.pid: _get(d, "output", str, seq)})

    if event.type == EventType.NEXUS_STAGE:
        info = _proc(state, event)
        conf = d.get("confidence")
        if conf is not None and (not isinstance(conf, int | float) or isinstance(conf, bool)):
            raise CorruptLogError("confidence must be a number or null", seq)
        key_hash = d.get("cache_key_hash")
        if key_hash is not None and not isinstance(key_hash, str):
            raise CorruptLogError("cache_key_hash must be a string or null", seq)
        outcome = _get(d, "outcome", str, seq)
        if outcome not in ("hit", "miss"):
            raise CorruptLogError("nexus stage outcome must be hit or miss", seq)
        srec = NexusStageRecord(
            pid=info.pid,
            stage=_get(d, "stage", str, seq),
            outcome=outcome,
            reason=_get(d, "reason", str, seq),
            latency_ms=float(_get(d, "latency_ms", (int, float), seq)),
            tokens=_get(d, "tokens", int, seq),
            cost_usd=_get(d, "cost_usd", str, seq),
            cache_key_hash=key_hash,
            confidence=None if conf is None else float(conf),
        )
        return replace(base, nexus_stages=(*state.nexus_stages, srec))

    if event.type == EventType.NEXUS_ROUTE:
        info = _proc(state, event)
        hit_stage = d.get("hit_stage")
        if hit_stage is not None and not isinstance(hit_stage, str):
            raise CorruptLogError("hit_stage must be a string or null", seq)
        by_stage = _get(d, "cost_by_stage", dict, seq)
        if not all(isinstance(k, str) and isinstance(v, str) for k, v in by_stage.items()):
            raise CorruptLogError("cost_by_stage must map stage names to decimal strings", seq)
        rrec = NexusRouteRecord(
            pid=info.pid,
            status=_get(d, "status", str, seq),
            hit_stage=hit_stage,
            total_tokens=_get(d, "total_tokens", int, seq),
            total_cost_usd=_get(d, "total_cost_usd", str, seq),
            cost_by_stage=dict(by_stage),
        )
        return replace(base, nexus_routes=(*state.nexus_routes, rrec))

    if event.type == EventType.VOICE_CALL:
        info = _proc(state, event)
        reason = d.get("reason")
        dur = d.get("duration_ms")
        detail = d.get("detail", {})
        if reason is not None and not isinstance(reason, str):
            raise CorruptLogError("voice_call reason must be a string or null", seq)
        if dur is not None and (not isinstance(dur, int) or isinstance(dur, bool)):
            raise CorruptLogError("voice_call duration_ms must be an integer or null", seq)
        if not isinstance(detail, dict):
            raise CorruptLogError("voice_call detail must be an object", seq)
        crec = VoiceCallRecord(
            pid=info.pid,
            call_id=_get(d, "call_id", str, seq),
            phase=_get(d, "phase", str, seq),
            reason=reason,
            duration_ms=dur,
            detail=dict(detail),
        )
        return replace(base, voice_calls=(*state.voice_calls, crec))

    if event.type == EventType.VOICE_TURN:
        info = _proc(state, event)
        role = _get(d, "role", str, seq)
        if role not in ("user", "agent", "system", "dtmf"):
            raise CorruptLogError("unknown voice turn role", seq)
        audio_hash = d.get("audio_sha256")
        if audio_hash is not None and not isinstance(audio_hash, str):
            raise CorruptLogError("audio_sha256 must be a string or null", seq)
        vtrec = VoiceTurnRecord(
            pid=info.pid,
            call_id=_get(d, "call_id", str, seq),
            turn=_get(d, "turn", int, seq),
            role=role,
            text=_get(d, "text", str, seq),
            redacted=_get(d, "redacted", bool, seq),
            truncated=_get(d, "truncated", bool, seq),
            start_ms=_get(d, "start_ms", int, seq),
            end_ms=_get(d, "end_ms", int, seq),
            text_sha256=_get(d, "text_sha256", str, seq),
            text_chars=_get(d, "text_chars", int, seq),
            audio_sha256=audio_hash,
            audio_bytes=_get(d, "audio_bytes", int, seq),
            intended_chars=int(d.get("intended_chars") or 0),
        )
        return replace(base, voice_turns=(*state.voice_turns, vtrec))

    if event.type == EventType.VOICE_STAGE:
        info = _proc(state, event)
        vrec = VoiceStageRecord(
            pid=info.pid,
            call_id=_get(d, "call_id", str, seq),
            turn=_get(d, "turn", int, seq),
            stage=_get(d, "stage", str, seq),
            latency_ms=_get(d, "latency_ms", int, seq),
        )
        return replace(base, voice_stages=(*state.voice_stages, vrec))

    raise CorruptLogError(f"unknown event type {event.type!r}", seq)


def reduce(events: Iterable[RunEvent], state: RunState | None = None) -> RunState:
    """Fold ``events`` (optionally onto ``state``) into a RunState; raises on any corruption."""
    for event in events:
        state = apply_event(state, event)
    if state is None:
        raise CorruptLogError("empty log")
    return state


def replay(events: Iterable[RunEvent]) -> RunState:
    """Rebuild the complete run state from scratch. Deterministic and idempotent."""
    return reduce(events, None)


# --------------------------------------------------------------------------------------
# Log interface + in-memory implementation
# --------------------------------------------------------------------------------------


class RunEventLog(Protocol):
    """Append-only, gapless per-run event store. Implementations MUST enforce the head check."""

    async def append(self, event: RunEvent) -> None:
        """Append a sealed event; raise SequenceConflictError unless it extends the head."""

    async def read(self, run_id: str) -> list[RunEvent]:
        """All events of a run in sequence order."""

    async def read_after(self, run_id: str, after_seq: int) -> list[RunEvent]:
        """Events with seq > after_seq, in order (used to fold what another writer appended)."""


class InMemoryRunEventLog:
    """Single-process reference implementation (tests and local dev)."""

    def __init__(self) -> None:
        self._runs: dict[str, list[RunEvent]] = {}
        self._lock = asyncio.Lock()

    async def append(self, event: RunEvent) -> None:
        async with self._lock:
            events = self._runs.setdefault(event.run_id, [])
            head_seq = len(events)
            head_hash = events[-1].hash if events else GENESIS_HASH
            if head_seq and events[-1] == event:
                return  # idempotent retry of the exact same append
            if event.seq != head_seq + 1 or event.prev_hash != head_hash:
                raise SequenceConflictError(f"expected seq {head_seq + 1}, got {event.seq}")
            events.append(event)

    async def read(self, run_id: str) -> list[RunEvent]:
        async with self._lock:
            return list(self._runs.get(run_id, ()))

    async def read_after(self, run_id: str, after_seq: int) -> list[RunEvent]:
        async with self._lock:
            return list(self._runs.get(run_id, ())[after_seq:])


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


def format_ts(moment: datetime) -> str:
    """UTC, millisecond precision, trailing Z (same shape as the audit log)."""
    utc = moment.astimezone(UTC)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


class RunRecorder:
    MAX_CONFLICT_RETRIES = 3

    """Seals, validates, persists and folds events; the single writer of a run's state.

    ``state`` is always ``reduce(log)``: events are validated against the folded state BEFORE
    they are appended, so an illegal event never reaches the log.
    """

    def __init__(self, log: RunEventLog, state: RunState | None, clock: Clock, run_id: str) -> None:
        self.log = log
        self.clock = clock
        self.run_id = run_id
        self._state = state
        self._lock = asyncio.Lock()
        self._listeners: list[Callable[[RunEvent, RunState], None]] = []

    @classmethod
    async def start(
        cls,
        log: RunEventLog,
        clock: Clock,
        *,
        run_id: str,
        tenant_id: str,
        meta: Mapping[str, JSON],
    ) -> RunRecorder:
        rec = cls(log, None, clock, run_id)
        await rec.record(EventType.RUN_STARTED, None, {"tenant_id": tenant_id, **meta})
        return rec

    @classmethod
    async def resume(cls, log: RunEventLog, clock: Clock, run_id: str) -> RunRecorder:
        return cls(log, replay(await log.read(run_id)), clock, run_id)

    @property
    def state(self) -> RunState:
        if self._state is None:
            raise CorruptLogError("run not started")
        return self._state

    def on_event(self, listener: Callable[[RunEvent, RunState], None]) -> None:
        self._listeners.append(listener)

    async def record(self, type: str, pid: str | None, data: Mapping[str, JSON]) -> RunEvent:
        async with self._lock:
            for attempt in range(self.MAX_CONFLICT_RETRIES + 1):
                seq = 1 if self._state is None else self._state.last_seq + 1
                prev = GENESIS_HASH if self._state is None else self._state.last_hash
                event = seal_event(
                    run_id=self.run_id,
                    seq=seq,
                    ts=format_ts(self.clock.now()),
                    type=str(type),
                    pid=pid,
                    data=data,
                    prev_hash=prev,
                )
                new_state = apply_event(self._state, event)  # validate first
                try:
                    await self.log.append(event)
                except SequenceConflictError:
                    # Another writer (e.g. an in-flight Temporal activity) extended the log.
                    # Fold what it appended and rebuild on the new head; never overwrite or fork.
                    if attempt == self.MAX_CONFLICT_RETRIES:
                        raise
                    self.ingest(
                        await self.log.read_after(
                            self.run_id, self._state.last_seq if self._state else 0
                        )
                    )
                    continue
                self._state = new_state
                break
        for listener in self._listeners:
            listener(event, new_state)
        return event

    def ingest(self, events: Iterable[RunEvent]) -> None:
        """Fold events that another writer already appended (e.g. a Temporal activity)."""
        for event in events:
            self._state = apply_event(self._state, event)
