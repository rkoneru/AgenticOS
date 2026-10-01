"""The run that records one call.

A call is a run of its own: one root "voice" process (so every event has a pid, and the gated
STT / TTS / outbound-call actions of the call have a runnable actor) whose log holds the call
lifecycle, the transcript turns and the stage latencies.  The agent's own turns are separate runs
(``agent.RunAgentTurn``) on the same trace id, so a call is replayed from its log and each turn from
its own.
"""

from __future__ import annotations

import secrets

from axis_runtime.events import Clock, EventType, RunEventLog, RunRecorder
from axis_runtime.process import ExitReason, Lifecycle, ProcessState, new_pid, next_state


async def start_call_run(
    log: RunEventLog,
    clock: Clock,
    *,
    tenant_id: str,
    call_id: str,
    agent: str,
    version: str,
    trace_id: str | None = None,
    run_id: str | None = None,
) -> tuple[RunRecorder, str]:
    """Create the call's run and its root process, already RUNNING.  Returns ``(recorder, pid)``."""
    rid = run_id or f"call_{secrets.token_hex(12)}"
    rec = await RunRecorder.start(
        log,
        clock,
        run_id=rid,
        tenant_id=tenant_id,
        meta={
            "blueprint": agent,
            "version": version,
            "kind": "voice_call",
            "call_id": call_id,
            "trace_id": trace_id or secrets.token_hex(16),
        },
    )
    pid = new_pid()
    await rec.record(
        EventType.PROCESS_SPAWNED, pid, {"ppid": None, "agent": f"voice:{agent}@{version}"}
    )
    state = ProcessState.SPAWN
    for trigger in (Lifecycle.INIT_COMPLETE, Lifecycle.SCHEDULED):
        nxt = next_state(state, trigger)
        await rec.record(
            EventType.PROCESS_TRANSITION,
            pid,
            {"from": state.value, "to": nxt.value, "trigger": str(trigger)},
        )
        state = nxt
    return rec, pid


async def end_call_run(
    rec: RunRecorder, pid: str, *, reason: ExitReason = ExitReason.COMPLETED, detail: str = ""
) -> None:
    info = rec.state.processes[pid]
    if info.state is ProcessState.TERMINATED:
        return
    data = {
        "from": info.state.value,
        "to": ProcessState.TERMINATED.value,
        "trigger": str(Lifecycle.EXIT),
        "exit_reason": reason.value,
    }
    if detail:
        data["detail"] = detail[:300]
    await rec.record(EventType.PROCESS_TRANSITION, pid, data)
