"""Temporal integration.

* Activities and (de)serialisation: unit-tested with ``ActivityEnvironment`` (no server).
* ``AgentRunWorkflow``: executed on the real Temporal time-skipping test server (a Java binary), with a real
  ``Worker`` and ``Replayer`` determinism check.  Not tested against a production cluster.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from dataclasses import asdict
from decimal import Decimal
from typing import Any

import pytest
from axis_runtime import Decision
from axis_runtime.actions import ModelCall, ToolCall
from axis_runtime.events import EventType, RunEvent, replay
from axis_runtime.executor import Completed, Denied, Failed, PendingApproval
from axis_runtime.gate import GateDecision
from axis_runtime.models.types import Attempt, FinishReason, ModelResponse, ToolCallRequest, Usage
from axis_runtime.temporal import (
    RUN_ACTION_ACTIVITY,
    AgentActivities,
    AgentRunInput,
    AgentRunOutput,
    AgentRunWorkflow,
    RunActionInput,
    build_worker,
    outcome_from_dict,
    outcome_to_dict,
)
from conftest import TENANT, ScriptedGate, allow, deny, final_body, manifest_dict, tool_turn_body
from helpers import PID, SAMPLES, Effects, identity, recording_backends, running_recorder
from temporal_server import ensure_test_server
from temporalio import activity
from temporalio.client import Client, WorkflowFailureError
from temporalio.testing import ActivityEnvironment, WorkflowEnvironment
from temporalio.worker import Replayer

# ---- serialisation -----------------------------------------------------------------------------------


def test_model_response_dict_roundtrip() -> None:
    resp = ModelResponse(
        "hi",
        (ToolCallRequest("c1", "f", {"a": 1}),),
        Usage(10, 5, 2, 1),
        FinishReason.TOOL_CALLS,
        "openai",
        "gpt-4o",
        12,
        Decimal("0.001234"),
        (Attempt("openai", "gpt-4o", "ok"),),
    )
    assert ModelResponse.from_dict(resp.to_dict()) == resp
    bare = ModelResponse("", (), Usage(), FinishReason.STOP, "p", "m")
    assert ModelResponse.from_dict(bare.to_dict()) == bare


def test_outcome_roundtrip_for_every_kind() -> None:
    d = GateDecision(Decision.ALLOW_WITH_REDACTION, "r", "v1", ("r1",), ("args.ssn",), "", "ae1")
    tool = ToolCall(name="lookup")
    for outcome in (
        Completed({"a": [1, 2]}, d),
        Denied("no", GateDecision(Decision.DENY, "no")),
        PendingApproval(
            "ap", "ask", GateDecision(Decision.REQUIRE_APPROVAL, "ask", approval_id="ap")
        ),
        Failed("boom", d),
    ):
        assert outcome_from_dict(outcome_to_dict(outcome), tool) == outcome
    model = SAMPLES[ModelCall]()
    resp = ModelResponse("x", (), Usage(1, 1), FinishReason.STOP, "openai", "m")
    rebuilt = outcome_from_dict(outcome_to_dict(Completed(resp, d)), model)
    assert isinstance(rebuilt, Completed) and rebuilt.result == resp


# ---- activities (no server) --------------------------------------------------------------------------------


async def _acts(gate: Any = None) -> tuple[AgentActivities, Effects, Any]:
    effects = Effects()
    rec = await running_recorder()
    acts = AgentActivities(
        log=rec.log, gate=gate or ScriptedGate(), backends=recording_backends(effects)
    )
    return acts, effects, rec


def _inp(action: Any) -> RunActionInput:
    ident = identity()
    return RunActionInput(
        "run_1",
        PID,
        {
            "tenant_id": ident.tenant_id,
            "run_id": ident.run_id,
            "trace_id": ident.trace_id,
            "span_id": ident.span_id,
            "blueprint_name": ident.blueprint_name,
            "blueprint_version": ident.blueprint_version,
            "phi": ident.phi,
        },
        action.to_spec(),
    )


async def test_run_action_activity_returns_the_events_it_appended() -> None:
    acts, effects, rec = await _acts()
    before = rec.state.last_seq
    out = await ActivityEnvironment().run(
        acts.run_action, _inp(ToolCall(name="lookup", args={"q": "x"}))
    )
    events = [RunEvent.from_dict(e) for e in out.events]
    assert [e.type for e in events] == [EventType.GATE_DECISION, EventType.TOOL_CALL_RESULT]
    assert [e.seq for e in events] == [before + 1, before + 2]
    assert out.outcome["kind"] == "completed" and effects.calls == [("tool", {"q": "x"})]
    assert (
        replay(await rec.log.read("run_1")).last_seq == before + 2
    )  # the store is the source of truth


async def test_run_action_activity_denies_without_side_effects() -> None:
    acts, effects, _ = await _acts(ScriptedGate(deny("no")))
    for make in SAMPLES.values():
        out = await ActivityEnvironment().run(acts.run_action, _inp(make()))
        assert out.outcome["kind"] == "denied" and out.outcome["decision"]["decision"] == "DENY"
    assert effects.total() == 0


async def test_append_and_read_activities_are_idempotent_and_ordered() -> None:
    acts, _, rec = await _acts()
    env = ActivityEnvironment()
    await env.run(acts.run_action, _inp(ToolCall(name="lookup")))
    events = await rec.log.read("run_1")
    await env.run(
        acts.append_run_event, events[-1].to_dict()
    )  # activity retry: same event again is a no-op
    assert len(await rec.log.read("run_1")) == len(events)
    tail = await env.run(acts.read_run_events, "run_1", len(events) - 2)
    assert [e["seq"] for e in tail] == [len(events) - 1, len(events)]
    assert len(acts.all()) == 3


async def test_run_action_activity_rejects_unknown_action_specs() -> None:
    acts, _, _ = await _acts()
    bad = _inp(ToolCall(name="lookup"))
    bad.action = {"type": "FormatDisk", "fields": {}}
    with pytest.raises(ValueError, match="unknown action type"):
        await ActivityEnvironment().run(acts.run_action, bad)


# ---- workflow on the real Temporal test server ---------------------------------------------------------------


@pytest.fixture
async def env() -> AsyncIterator[WorkflowEnvironment]:
    server = ensure_test_server()  # fails (never skips) if the binary cannot be obtained
    e = await WorkflowEnvironment.start_time_skipping(test_server_existing_path=str(server))
    try:
        yield e
    finally:
        await e.shutdown()


def workflow_input(**over: Any) -> AgentRunInput:
    base = dict(
        manifest=manifest_dict(
            tools=[{"name": "lookup", "kind": "function", "side_effects": "read"}]
        ),
        input="status of C-1?",
        tenant_id=TENANT,
        run_id=f"run_{uuid.uuid4().hex[:12]}",
        trace_id="e" * 32,
        tool_schemas={
            "lookup": {"description": "Look up a claim", "input_schema": {"type": "object"}}
        },
    )
    return AgentRunInput(**{**base, **over})


def scripted_effects(*bodies: Any) -> Effects:
    effects = Effects()
    effects.transport.responses = [(200, b) for b in bodies]
    return effects


async def run_workflow(
    env: WorkflowEnvironment,
    inp: AgentRunInput,
    acts: AgentActivities,
    *,
    before_result: Any = None,
) -> tuple[AgentRunOutput, Any]:
    queue = f"q-{uuid.uuid4().hex[:8]}"
    async with build_worker(env.client, task_queue=queue, activities=acts):
        handle = await env.client.start_workflow(
            AgentRunWorkflow.run, inp, id=f"wf-{inp.run_id}", task_queue=queue
        )
        if before_result is not None:
            await before_result(handle)
        return await handle.result(), handle


async def test_workflow_runs_an_agent_end_to_end_and_replays_deterministically(
    env: WorkflowEnvironment,
) -> None:
    effects = scripted_effects(
        tool_turn_body(("lookup", {"id": "C-1"})), final_body("Claim C-1 is open.")
    )
    gate = ScriptedGate()
    from axis_runtime.events import InMemoryRunEventLog

    log = InMemoryRunEventLog()
    acts = AgentActivities(log=log, gate=gate, backends=recording_backends(effects))
    inp = workflow_input()
    out, handle = await run_workflow(env, inp, acts)

    assert (out.status, out.exit_reason, out.output) == (
        "completed",
        "completed",
        "Claim C-1 is open.",
    )
    assert effects.calls == [
        ("tool", {"id": "C-1"})
    ]  # the tool ran in an activity, through the gate
    assert [r.enforcement_point.value for r in gate.requests] == [
        "model_call",
        "tool_call",
        "model_call",
    ]
    state = replay(
        await log.read(inp.run_id)
    )  # the event log the activities wrote is complete and valid
    assert (state.last_seq, state.last_hash) == (out.last_seq, out.last_hash)
    assert state.processes[out.pid].exit_reason.value == "completed"  # type: ignore[union-attr]
    assert [m.provider for m in state.model_calls] == [
        "openai",
        "openai",
    ] and state.tool_calls_used == 1
    # Determinism: re-executing the recorded history against the workflow code must not diverge.
    history = await handle.fetch_history()
    await Replayer(workflows=[AgentRunWorkflow]).replay_workflow(history)


async def test_workflow_denies_fail_closed(env: WorkflowEnvironment) -> None:
    from axis_runtime.events import InMemoryRunEventLog

    effects = scripted_effects(final_body())
    log = InMemoryRunEventLog()
    acts = AgentActivities(
        log=log, gate=ScriptedGate(deny("egress blocked")), backends=recording_backends(effects)
    )
    inp = workflow_input()
    out, _ = await run_workflow(env, inp, acts)
    assert out.status == "policy_denied" and effects.total() == 0
    assert replay(await log.read(inp.run_id)).gate_decisions[0].decision is Decision.DENY


async def test_workflow_require_approval_parks_the_run(env: WorkflowEnvironment) -> None:
    from axis_runtime.events import InMemoryRunEventLog

    def gate_fn(r: Any) -> GateDecision:
        if r.enforcement_point.value == "tool_call":
            return GateDecision(Decision.REQUIRE_APPROVAL, "human", approval_id="ap_9")
        return allow()

    effects = scripted_effects(tool_turn_body(("lookup", {})), final_body())
    acts = AgentActivities(
        log=InMemoryRunEventLog(), gate=ScriptedGate(gate_fn), backends=recording_backends(effects)
    )
    out, _ = await run_workflow(env, workflow_input(), acts)
    assert (
        out.status == "awaiting_approval" and out.approval_id == "ap_9" and out.exit_reason is None
    )
    assert [c[0] for c in effects.calls] == []


class Blocker:
    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def __call__(self) -> None:
        self.entered.set()
        await self.release.wait()


async def test_workflow_signals_and_query(env: WorkflowEnvironment) -> None:
    from axis_runtime.events import InMemoryRunEventLog

    effects = scripted_effects(final_body())
    blocker = Blocker()
    effects.transport.delay = blocker
    acts = AgentActivities(
        log=InMemoryRunEventLog(), gate=ScriptedGate(), backends=recording_backends(effects)
    )
    states: dict[str, str] = {}

    async def kill_while_the_model_call_is_in_flight(handle: Any) -> None:
        await asyncio.wait_for(blocker.entered.wait(), 20)
        states.update(await handle.query(AgentRunWorkflow.process_states))
        await handle.signal(AgentRunWorkflow.send_signal, args=["KILL", None])

    try:
        out, _ = await run_workflow(
            env, workflow_input(), acts, before_result=kill_while_the_model_call_is_in_flight
        )
    finally:
        blocker.release.set()  # let the orphaned provider call finish so the worker can shut down
    assert out.status == "killed" and out.exit_reason == "killed"
    assert list(states.values()) == ["waiting"]  # the query saw the live process state


async def test_workflow_process_timeout(env: WorkflowEnvironment) -> None:
    from axis_runtime.events import InMemoryRunEventLog

    effects = scripted_effects(final_body())
    blocker = Blocker()
    effects.transport.delay = blocker
    acts = AgentActivities(
        log=InMemoryRunEventLog(), gate=ScriptedGate(), backends=recording_backends(effects)
    )
    inp = workflow_input(manifest=manifest_dict(process={"timeout_seconds": 0.5}))
    try:
        out, _ = await run_workflow(env, inp, acts)
    finally:
        blocker.release.set()
    assert out.status == "timeout"


class CrashAfterAppend(AgentActivities):
    """Simulates a worker crash after the action ran and its events were persisted."""

    @activity.defn(name=RUN_ACTION_ACTIVITY)
    async def run_action(self, inp: RunActionInput) -> Any:
        await super().run_action(inp)
        raise RuntimeError("worker died before reporting the result")

    def all(self) -> list[Any]:
        return [self.append_run_event, self.read_run_events, self.run_action]


async def test_lost_activity_result_is_resynced_from_the_log_not_guessed(
    env: WorkflowEnvironment,
) -> None:
    from axis_runtime.events import InMemoryRunEventLog

    effects = scripted_effects(final_body())
    log = InMemoryRunEventLog()
    acts = CrashAfterAppend(log=log, gate=ScriptedGate(), backends=recording_backends(effects))
    inp = workflow_input()
    out, _ = await run_workflow(env, inp, acts)
    assert out.status == "failed"  # the workflow does not pretend the model answered
    state = replay(await log.read(inp.run_id))
    assert (state.last_seq, state.last_hash) == (
        out.last_seq,
        out.last_hash,
    )  # workflow caught up with the store
    assert len(effects.transport.calls) == 1  # at-most-once: the crashed action was NOT retried


async def test_workflow_rejects_a_bad_manifest(env: WorkflowEnvironment) -> None:
    from axis_runtime.events import InMemoryRunEventLog

    acts = AgentActivities(
        log=InMemoryRunEventLog(), gate=ScriptedGate(), backends=recording_backends(Effects())
    )
    queue = f"q-{uuid.uuid4().hex[:8]}"
    bad = workflow_input(manifest={"manifest_version": 9})
    async with build_worker(env.client, task_queue=queue, activities=acts):
        with pytest.raises(WorkflowFailureError):
            await env.client.execute_workflow(
                AgentRunWorkflow.run, bad, id="wf-bad", task_queue=queue
            )


def test_types_used_by_the_dataclass_converter_are_plain() -> None:
    assert set(asdict(workflow_input())) >= {"manifest", "input", "tenant_id", "run_id", "trace_id"}
    assert isinstance(Client, type)
