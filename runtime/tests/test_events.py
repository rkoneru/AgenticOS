"""Event-sourced state: replay == live, idempotence, corruption rejection."""

from __future__ import annotations

import asyncio
import random
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from axis_runtime import Decision
from axis_runtime.events import (
    GENESIS_HASH,
    CorruptLogError,
    EventType,
    InMemoryRunEventLog,
    RunEvent,
    RunRecorder,
    SequenceConflictError,
    SystemClock,
    apply_event,
    canonical_json,
    format_ts,
    reduce,
    replay,
    seal_event,
)
from axis_runtime.process import (
    ExitReason,
    ProcessState,
    is_terminal,
    legal_triggers,
    new_pid,
    next_state,
)
from conftest import TENANT, FakeClock, started_recorder

PID = "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV"


async def _walk(rec: RunRecorder, steps: list[tuple[str, dict[str, Any], str | None]]) -> None:
    for typ, data, pid in steps:
        await rec.record(typ, pid, data)


def _gate(action_id: str = "act_000001", decision: str = "ALLOW", **over: Any) -> dict[str, Any]:
    return {
        "action_id": action_id,
        "enforcement_point": "tool_call",
        "action": "lookup",
        "decision": decision,
        "reason": "",
        "policy_version": "v1",
        "redact_fields": [],
        "approval_id": "",
        "audit_event_id": "",
        **over,
    }


def _tool(action_id: str = "act_000001", **over: Any) -> dict[str, Any]:
    return {
        "action_id": action_id,
        "enforcement_point": "tool_call",
        "name": "lookup",
        "ok": True,
        "result": {"a": 1},
        "error": None,
        **over,
    }


def _model(action_id: str = "act_000002", **over: Any) -> dict[str, Any]:
    return {
        "action_id": action_id,
        "provider": "openai",
        "model": "gpt-4o",
        "input_tokens": 10,
        "output_tokens": 5,
        "cached_tokens": 0,
        "cost_micro_usd": 123,
        "finish_reason": "stop",
        "latency_ms": 7,
        **over,
    }


def _tr(frm: str, to: str, trig: str, **extra: Any) -> dict[str, Any]:
    return {"from": frm, "to": to, "trigger": trig, **extra}


FULL_RUN: list[tuple[str, dict[str, Any], str | None]] = [
    (EventType.PROCESS_SPAWNED, {"ppid": None, "agent": "a@1"}, PID),
    (EventType.PROCESS_TRANSITION, _tr("spawn", "ready", "init_complete"), PID),
    (EventType.PROCESS_TRANSITION, _tr("ready", "running", "scheduled"), PID),
    (EventType.PROCESS_TRANSITION, _tr("running", "waiting", "await"), PID),
    (EventType.GATE_DECISION, _gate(), PID),
    (EventType.TOOL_CALL_RESULT, _tool(), PID),
    (EventType.MODEL_CALL, _model(), PID),
    (EventType.PROCESS_TRANSITION, _tr("waiting", "running", "wake"), PID),
    (EventType.BUDGET_WARNING, {"budget": "tokens"}, PID),
    (EventType.SIGNAL_DELIVERED, {"signal": "INTERRUPT"}, PID),
    (EventType.ACTION_BLOCKED, {"action_id": "x"}, PID),
    (EventType.PROCESS_OUTPUT, {"output": "hello"}, PID),
    (
        EventType.PROCESS_TRANSITION,
        _tr("running", "terminated", "exit", exit_reason="completed"),
        PID,
    ),
]


async def test_replay_equals_live_state_after_every_step() -> None:
    rec = await started_recorder()
    assert replay(await rec.log.read("run_1")) == rec.state
    for typ, data, pid in FULL_RUN:
        await rec.record(typ, pid, data)
        assert replay(await rec.log.read("run_1")) == rec.state
    st = rec.state
    assert st.processes[PID].state is ProcessState.TERMINATED
    assert st.processes[PID].exit_reason is ExitReason.COMPLETED
    assert st.outputs[PID] == "hello"
    assert st.tokens_used == 15 and st.cost_micro_usd == 123 and st.tool_calls_used == 1
    assert st.gate_decisions[0].decision is Decision.ALLOW
    assert st.model_calls[0].model == "gpt-4o" and st.tool_calls[0].result == {"a": 1}
    assert st.blocked_actions == 1 and st.warnings == ("tokens",)
    assert st.signals == ((PID, "INTERRUPT"),)


async def test_replay_is_idempotent_and_chunk_fold_equal() -> None:
    rec = await started_recorder()
    await _walk(rec, FULL_RUN)
    events = await rec.log.read("run_1")
    assert replay(events) == replay(events) == rec.state
    head = reduce(events[:5])
    assert reduce(events[5:], head) == rec.state
    assert [e.seq for e in events] == list(range(1, len(events) + 1))  # gapless


async def test_random_legal_walks_replay_equal_live() -> None:
    """Property-style: for many seeded random legal lifecycles replay(log) == live after each step."""
    for seed in range(60):
        rng = random.Random(seed)
        rec = await started_recorder()
        await rec.record(EventType.PROCESS_SPAWNED, PID, {"ppid": None, "agent": "a@1"})
        state = ProcessState.SPAWN
        for _ in range(rng.randint(1, 25)):
            if is_terminal(state):
                break
            trig = rng.choice(sorted(legal_triggers(state)))
            nxt = next_state(state, trig)
            extra = {"exit_reason": rng.choice(list(ExitReason)).value} if is_terminal(nxt) else {}
            await rec.record(
                EventType.PROCESS_TRANSITION, PID, _tr(state.value, nxt.value, trig, **extra)
            )
            state = nxt
            live = rec.state
            assert live.processes[PID].state is state
            assert replay(await rec.log.read("run_1")) == live
        events = await rec.log.read("run_1")
        assert replay(events) == replay(events)


async def _log_events() -> list[RunEvent]:
    rec = await started_recorder()
    await _walk(rec, FULL_RUN[:6])
    return await rec.log.read("run_1")


async def test_gap_is_rejected() -> None:
    ev = await _log_events()
    with pytest.raises(CorruptLogError, match="gap"):
        replay(ev[:3] + ev[4:])


async def test_duplicate_and_reordered_are_rejected() -> None:
    ev = await _log_events()
    with pytest.raises(CorruptLogError, match="duplicate or reordered"):
        replay([*ev[:3], ev[2], *ev[3:]])
    with pytest.raises(CorruptLogError, match="expected seq 2"):
        replay([ev[0], ev[2], ev[1], *ev[3:]])


async def test_tampered_content_is_rejected() -> None:
    ev = await _log_events()
    forged = replace(ev[4], data={**ev[4].data, "decision": "DENY"})  # hash now stale
    with pytest.raises(CorruptLogError, match="does not match its hash"):
        replay([*ev[:4], forged, *ev[5:]])


async def test_rehashed_forgery_breaks_the_chain() -> None:
    ev = await _log_events()
    forged = seal_event(
        run_id="run_1",
        seq=5,
        ts=ev[4].ts,
        type=ev[4].type,
        pid=ev[4].pid,
        data={**ev[4].data, "decision": "DENY"},
        prev_hash=ev[4].prev_hash,
    )
    assert forged.hash != ev[4].hash
    with pytest.raises(CorruptLogError, match="prev_hash"):
        replay([*ev[:4], forged, *ev[5:]])


async def test_truncated_head_and_wrong_first_event_are_rejected() -> None:
    ev = await _log_events()
    with pytest.raises(CorruptLogError, match="expected seq 1"):
        replay(ev[1:])
    first = seal_event(
        run_id="r",
        seq=1,
        ts="t",
        type=EventType.PROCESS_SPAWNED,
        pid=PID,
        data={"ppid": None, "agent": "a"},
        prev_hash=GENESIS_HASH,
    )
    with pytest.raises(CorruptLogError, match="first event must be run_started"):
        replay([first])
    with pytest.raises(CorruptLogError, match="empty"):
        replay([])


async def test_cross_run_splice_is_rejected() -> None:
    ev = await _log_events()
    other = seal_event(
        run_id="run_2",
        seq=ev[-1].seq + 1,
        ts="t",
        type=EventType.BUDGET_WARNING,
        pid=PID,
        data={"budget": "x"},
        prev_hash=ev[-1].hash,
    )
    with pytest.raises(CorruptLogError, match="different run"):
        replay([*ev, other])


def _seal_next(rec: RunRecorder, typ: str, pid: str | None, data: dict[str, Any]) -> RunEvent:
    st = rec.state
    return seal_event(
        run_id=st.run_id,
        seq=st.last_seq + 1,
        ts="t",
        type=typ,
        pid=pid,
        data=data,
        prev_hash=st.last_hash,
    )


BAD_EVENTS: list[tuple[str, str | None, dict[str, Any], str]] = [
    ("nonsense", None, {}, "unknown event type"),
    (EventType.RUN_STARTED, None, {"tenant_id": "t"}, "duplicate run_started"),
    (EventType.PROCESS_SPAWNED, "not-a-pid", {"ppid": None, "agent": "a"}, "invalid pid"),
    (EventType.PROCESS_SPAWNED, PID, {"ppid": None, "agent": "a"}, "duplicate pid"),
    (
        EventType.PROCESS_SPAWNED,
        "axp_01ARZ3NDEKTSV4RRFFQ69G5FAW",
        {"ppid": None, "agent": "a"},
        "exactly one init",
    ),
    (
        EventType.PROCESS_SPAWNED,
        "axp_01ARZ3NDEKTSV4RRFFQ69G5FAW",
        {"ppid": "axp_01ARZ3NDEKTSV4RRFFQ69G5FAX", "agent": "a"},
        "unknown ppid",
    ),
    (
        EventType.PROCESS_SPAWNED,
        "axp_01ARZ3NDEKTSV4RRFFQ69G5FAW",
        {"ppid": PID, "agent": 5},
        "mistyped",
    ),
    (
        EventType.PROCESS_TRANSITION,
        "axp_01ARZ3NDEKTSV4RRFFQ69G5FAW",
        _tr("spawn", "ready", "init_complete"),
        "unknown pid",
    ),
    (EventType.PROCESS_TRANSITION, None, _tr("spawn", "ready", "init_complete"), "unknown pid"),
    (EventType.PROCESS_TRANSITION, PID, _tr("ready", "running", "scheduled"), "but process is"),
    (EventType.PROCESS_TRANSITION, PID, _tr("running", "ready", "yield"), "but process is"),
    (EventType.PROCESS_TRANSITION, PID, _tr("spawn", "running", "scheduled"), "illegal transition"),
    (EventType.PROCESS_TRANSITION, PID, _tr("spawn", "terminated", "init_complete"), "leads to"),
    (
        EventType.PROCESS_TRANSITION,
        PID,
        _tr("spawn", "terminated", "init_failed"),
        "valid exit_reason",
    ),
    (
        EventType.PROCESS_TRANSITION,
        PID,
        _tr("spawn", "terminated", "init_failed", exit_reason="bogus"),
        "valid exit_reason",
    ),
    (
        EventType.PROCESS_TRANSITION,
        PID,
        _tr("spawn", "ready", "init_complete", exit_reason="failed"),
        "only valid on terminated",
    ),
    (EventType.SIGNAL_DELIVERED, PID, {"signal": "SIGFOO"}, "unknown signal"),
    (EventType.GATE_DECISION, PID, _gate(decision="MAYBE"), "unknown decision"),
    (EventType.GATE_DECISION, PID, {"action_id": "a"}, "mistyped"),
    (EventType.TOOL_CALL_RESULT, PID, _tool(ok="yes"), "mistyped"),
    (EventType.MODEL_CALL, PID, _model(cost_micro_usd=1.5), "integer"),
    (EventType.MODEL_CALL, PID, _model(cost_micro_usd=True), "integer"),
    (EventType.MODEL_CALL, PID, _model(input_tokens=True), "mistyped"),
    (EventType.PROCESS_OUTPUT, PID, {"output": 3}, "mistyped"),
    (EventType.BUDGET_WARNING, PID, {}, "mistyped"),
]


@pytest.mark.parametrize(
    ("typ", "pid", "data", "msg"), BAD_EVENTS, ids=[b[3] + str(i) for i, b in enumerate(BAD_EVENTS)]
)
async def test_invalid_events_are_rejected_before_reaching_the_log(
    typ: str, pid: str | None, data: dict[str, Any], msg: str
) -> None:
    rec = await started_recorder()
    await rec.record(EventType.PROCESS_SPAWNED, PID, {"ppid": None, "agent": "a@1"})
    before = await rec.log.read("run_1")
    with pytest.raises(CorruptLogError, match=msg):
        await rec.record(typ, pid, data)
    assert await rec.log.read("run_1") == before  # the log was never polluted
    assert rec.state == replay(before)


async def test_terminal_process_rejects_action_events_and_children() -> None:
    rec = await started_recorder()
    await rec.record(EventType.PROCESS_SPAWNED, PID, {"ppid": None, "agent": "a"})
    await rec.record(
        EventType.PROCESS_TRANSITION, PID, _tr("spawn", "terminated", "KILL", exit_reason="killed")
    )
    with pytest.raises(CorruptLogError, match="terminated process"):
        await rec.record(EventType.GATE_DECISION, PID, _gate())
    with pytest.raises(CorruptLogError, match="terminated parent"):
        await rec.record(
            EventType.PROCESS_SPAWNED, "axp_01ARZ3NDEKTSV4RRFFQ69G5FAW", {"ppid": PID, "agent": "c"}
        )
    with pytest.raises(CorruptLogError, match="leads to|illegal"):
        await rec.record(EventType.PROCESS_TRANSITION, PID, _tr("terminated", "ready", "RESUME"))
    await rec.record(
        EventType.ACTION_BLOCKED, PID, {"action_id": "x"}
    )  # blocked attempts are still logged


async def test_bad_ppid_shapes() -> None:
    rec = await started_recorder()
    await rec.record(EventType.PROCESS_SPAWNED, PID, {"ppid": None, "agent": "a"})
    child = "axp_01ARZ3NDEKTSV4RRFFQ69G5FAW"
    await rec.record(EventType.PROCESS_SPAWNED, child, {"ppid": PID, "agent": "c"})
    assert rec.state.processes[child].ppid == PID


async def test_event_roundtrip_and_malformed_dicts() -> None:
    ev = await _log_events()
    assert [RunEvent.from_dict(e.to_dict()) for e in ev] == ev
    with pytest.raises(CorruptLogError, match="malformed"):
        RunEvent.from_dict({"run_id": "r"})
    with pytest.raises(CorruptLogError, match="malformed"):
        RunEvent.from_dict({**ev[0].to_dict(), "seq": "x"})
    assert canonical_json({"b": 1, "a": [1]}) == '{"a":[1],"b":1}'


async def test_in_memory_log_enforces_head_and_is_idempotent() -> None:
    log = InMemoryRunEventLog()
    e1 = seal_event(
        run_id="r",
        seq=1,
        ts="t",
        type=EventType.RUN_STARTED,
        pid=None,
        data={"tenant_id": "t"},
        prev_hash=GENESIS_HASH,
    )
    await log.append(e1)
    await log.append(e1)  # retry of the head is a no-op
    assert await log.read("r") == [e1]
    bad_seq = seal_event(run_id="r", seq=3, ts="t", type="x", pid=None, data={}, prev_hash=e1.hash)
    bad_prev = seal_event(
        run_id="r", seq=2, ts="t", type="x", pid=None, data={}, prev_hash=GENESIS_HASH
    )
    for bad in (bad_seq, bad_prev):
        with pytest.raises(SequenceConflictError):
            await log.append(bad)
    assert await log.read("other") == []


async def test_a_stale_writer_folds_the_other_writers_events_and_cannot_fork_the_run() -> None:
    rec_a = await started_recorder()
    rec_b = await RunRecorder.resume(rec_a.log, rec_a.clock, "run_1")
    await rec_a.record(EventType.PROCESS_SPAWNED, PID, {"ppid": None, "agent": "a"})
    # b's state is stale. Re-spawning the same pid is illegal once b folds a's event: nothing is appended.
    with pytest.raises(CorruptLogError, match="duplicate pid"):
        await rec_b.record(EventType.PROCESS_SPAWNED, PID, {"ppid": None, "agent": "a"})
    assert len(await rec_a.log.read("run_1")) == 2
    # A legal event from the stale writer is rebuilt on the new head: gapless, hash-linked, single history.
    await rec_b.record(EventType.BUDGET_WARNING, PID, {"budget": "tokens"})
    events = await rec_a.log.read("run_1")
    assert [e.seq for e in events] == [1, 2, 3]
    assert replay(events) == rec_b.state


class _AlwaysConflicts(InMemoryRunEventLog):
    async def append(self, event: RunEvent) -> None:
        raise SequenceConflictError("someone else is always ahead")


async def test_conflict_retries_are_bounded() -> None:
    rec = await started_recorder()
    rec.log = _AlwaysConflicts()  # type: ignore[assignment]
    with pytest.raises(SequenceConflictError):
        await rec.record(EventType.PROCESS_SPAWNED, PID, {"ppid": None, "agent": "a"})


async def test_concurrent_records_stay_gapless() -> None:
    rec = await started_recorder()
    await rec.record(EventType.PROCESS_SPAWNED, PID, {"ppid": None, "agent": "a"})
    await asyncio.gather(
        *(rec.record(EventType.BUDGET_WARNING, PID, {"budget": f"b{i}"}) for i in range(20))
    )
    ev = await rec.log.read("run_1")
    assert [e.seq for e in ev] == list(range(1, 23))
    assert replay(ev) == rec.state


async def test_listener_ingest_and_unstarted_state() -> None:
    rec = await started_recorder()
    seen: list[int] = []
    rec.on_event(lambda e, s: seen.append(s.last_seq))
    await rec.record(EventType.PROCESS_SPAWNED, PID, {"ppid": None, "agent": "a"})
    assert seen == [2]
    follower = await RunRecorder.resume(rec.log, rec.clock, "run_1")
    await rec.record(EventType.BUDGET_WARNING, PID, {"budget": "x"})
    follower.ingest((await rec.log.read("run_1"))[2:])
    assert follower.state == rec.state
    blank = RunRecorder(InMemoryRunEventLog(), None, FakeClock(), "run_9")
    with pytest.raises(CorruptLogError, match="not started"):
        _ = blank.state
    with pytest.raises(CorruptLogError, match="empty"):
        await RunRecorder.resume(InMemoryRunEventLog(), FakeClock(), "missing")


def test_timestamps_are_utc_millisecond() -> None:
    assert (
        format_ts(datetime(2026, 1, 2, 3, 4, 5, 678901, tzinfo=UTC)) == "2026-01-02T03:04:05.678Z"
    )
    tz = timezone(timedelta(hours=2))
    assert format_ts(datetime(2026, 1, 2, 5, 4, 5, 1000, tzinfo=tz)) == "2026-01-02T03:04:05.001Z"
    assert SystemClock().now().tzinfo is not None


async def test_apply_event_is_pure() -> None:
    rec = await started_recorder()
    before = rec.state
    ev = _seal_next(rec, EventType.PROCESS_SPAWNED, PID, {"ppid": None, "agent": "a"})
    after = apply_event(before, ev)
    assert before == rec.state and PID not in before.processes and PID in after.processes
    assert new_pid() != PID
    assert TENANT == before.tenant_id
