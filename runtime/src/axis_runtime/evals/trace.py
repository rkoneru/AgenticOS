"""Build a ``CaseTrace`` from a run's event log (the run's own hash-chained record).

Graders see the trace, not the agent's account of itself. Tool results are reduced to a hash (the
trace is persisted by the hub; raw tool output may hold customer data). This module imports only
the event model, so the online sampler can use it without touching anything on the decision path.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import datetime

from axis_runtime.evals.types import (
    CaseTrace,
    GateDecisionTrace,
    ModelCallTrace,
    ToolCallTrace,
    canonical,
)
from axis_runtime.events import RunEvent, RunState, reduce

MAX_OUTPUT_CHARS = 20_000


def _root_pid(state: RunState) -> str | None:
    for pid, info in state.processes.items():
        if info.ppid is None:
            return pid
    return None


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def trace_from_state(
    state: RunState,
    *,
    trace_id: str,
    latency_ms: int | None = None,
    events: Sequence[RunEvent] = (),
) -> CaseTrace:
    """The trace of a (finished) run. ``latency_ms`` is the wall time the caller measured; without
    it the span between the first and last event timestamps is used."""
    root = _root_pid(state)
    info = state.processes.get(root or "")
    exit_reason = info.exit_reason.value if info is not None and info.exit_reason else "running"
    output = state.outputs.get(root or "") if root else None
    if latency_ms is None and len(events) >= 2:
        latency_ms = int((_ts(events[-1].ts) - _ts(events[0].ts)).total_seconds() * 1000)
    return CaseTrace(
        run_id=state.run_id,
        trace_id=trace_id,
        exit_reason=exit_reason,
        output=None if output is None else output[:MAX_OUTPUT_CHARS],
        tool_calls=tuple(
            ToolCallTrace(
                name=t.name,
                ok=t.ok,
                result_sha256=hashlib.sha256(canonical(t.result).encode("utf-8")).hexdigest(),
                error=None if t.error is None else t.error[:200],
            )
            for t in state.tool_calls
            if t.enforcement_point != "model_call"
        ),
        gate_decisions=tuple(
            GateDecisionTrace(d.action, d.enforcement_point, d.decision.value, d.reason[:200])
            for d in state.gate_decisions
        ),
        model_calls=tuple(
            ModelCallTrace(
                m.provider,
                m.model,
                m.input_tokens,
                m.output_tokens,
                m.cost_micro_usd or 0,
                m.latency_ms,
            )
            for m in state.model_calls
        ),
        latency_ms=max(0, latency_ms or 0),
        events_hash=state.last_hash,
        event_count=state.last_seq,
    )


def trace_from_events(events: Sequence[RunEvent], *, trace_id: str = "") -> CaseTrace:
    """Fold a stored log (verifying its hash chain) into a trace; raises ``CorruptLogError``."""
    state = reduce(events)
    return trace_from_state(state, trace_id=trace_id or _meta_trace_id(events), events=events)


def _meta_trace_id(events: Sequence[RunEvent]) -> str:
    first = events[0].data.get("trace_id") if events else None
    return first if isinstance(first, str) else ""
