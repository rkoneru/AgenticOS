"""AgentProcess / run_agent: lifecycle, budgets, signals, supervision, replay."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

import pytest
from axis_runtime import Decision
from axis_runtime.events import EventType, RunState, replay
from axis_runtime.gate import EvaluateRequest, GateDecision
from axis_runtime.manifest import ManifestError, RuntimeManifest
from axis_runtime.process import ExitReason, ProcessState, Signal
from axis_runtime.run import RunDeps, RunHandle, run_agent, start_agent
from axis_runtime.tools import ToolRegistry
from conftest import (
    FakeClock,
    ScriptedGate,
    ScriptedTransport,
    allow,
    deny,
    make_deps,
    make_manifest,
    manifest_dict,
    openai_body,
)
from helpers import Effects, recording_backends


def tool_turn(
    *calls: tuple[str, dict[str, Any]], prompt: int = 10, completion: int = 5
) -> dict[str, Any]:
    return openai_body(
        None, [(f"call_{i}", n, a) for i, (n, a) in enumerate(calls)], prompt, completion
    )


def final(text: str = "all done", prompt: int = 10, completion: int = 5) -> dict[str, Any]:
    return openai_body(text, None, prompt, completion)


def registry(effects: Effects | None = None) -> ToolRegistry:
    reg = ToolRegistry()

    def lookup(args: Any) -> Any:
        if effects is not None:
            effects.calls.append(("tool", dict(args)))
        return {"claim": args.get("id"), "status": "open"}

    reg.register("lookup_claim", lookup, description="Look up a claim")
    return reg


def deps_for(*bodies: Any, gate: Any = None, effects: Effects | None = None, **kw: Any) -> RunDeps:
    transport = ScriptedTransport([(200, b) if not isinstance(b, tuple) else b for b in bodies])
    return make_deps(gate=gate, transport=transport, tools=registry(effects), **kw)


async def settle(pred: Callable[[], bool], timeout: float = 3.0) -> None:
    async def poll() -> None:
        while not pred():
            await asyncio.sleep(0.005)

    await asyncio.wait_for(poll(), timeout)


async def transitions(deps: RunDeps, run_id: str, pid: str) -> list[str]:
    events = await deps.log.read(run_id)
    return [
        e.data["trigger"] for e in events if e.type == EventType.PROCESS_TRANSITION and e.pid == pid
    ]


# ---- happy path and replay ---------------------------------------------------------------------


async def test_agent_calls_tool_then_answers_and_replays() -> None:
    effects = Effects()
    gate = ScriptedGate()
    deps = deps_for(
        tool_turn(("lookup_claim", {"id": "C-1"})),
        final("Claim C-1 is open."),
        gate=gate,
        effects=effects,
    )
    result = await run_agent(make_manifest(), "status of C-1?", deps)

    assert result.status == "completed" and result.output == "Claim C-1 is open."
    assert result.exit_reason is ExitReason.COMPLETED
    assert effects.calls == [("tool", {"id": "C-1"})]
    assert [r.enforcement_point.value for r in gate.requests] == [
        "model_call",
        "tool_call",
        "model_call",
    ]
    assert await transitions(deps, result.run_id, result.pid) == [
        "init_complete",
        "scheduled",
        "await",
        "wake",  # model
        "await",
        "wake",  # tool
        "await",
        "wake",  # model
        "exit",
    ]
    st = result.state
    assert st.processes[result.pid].state is ProcessState.TERMINATED
    assert [m.output_tokens for m in st.model_calls] == [5, 5] and st.tokens_used == 30
    assert st.tool_calls[0].name == "lookup_claim" and st.tool_calls[0].result == {
        "claim": "C-1",
        "status": "open",
    }
    assert [g.decision for g in st.gate_decisions] == [Decision.ALLOW] * 3
    # Replay from the log reproduces everything, twice.
    events = await deps.log.read(result.run_id)
    assert replay(events) == st == replay(events)
    # the model saw the tool result in its second request
    second = json.loads(deps.models._transport.calls[1].body)  # type: ignore[attr-defined]  # noqa: SLF001
    assert second["messages"][-1] == {
        "role": "tool",
        "tool_call_id": "call_0",
        "content": '{"claim": "C-1", "status": "open"}',
    }
    assert second["messages"][0] == {"role": "system", "content": "You triage claims."}


async def test_every_event_is_replay_consistent_during_a_run() -> None:
    deps = deps_for(tool_turn(("lookup_claim", {})), final())
    handle = await start_agent(make_manifest(), "go", deps)
    seen = 0

    def check(event: Any, state: RunState) -> None:
        nonlocal seen
        seen += 1

    handle.ctx.recorder.on_event(check)
    result = await handle.result()
    assert seen > 10
    assert replay(await deps.log.read(result.run_id)) == result.state


async def test_unknown_tool_requested_by_model_is_an_error_message_not_an_action() -> None:
    gate = ScriptedGate()
    deps = deps_for(tool_turn(("rm_rf", {"path": "/"})), final("ok"), gate=gate)
    result = await run_agent(make_manifest(), "x", deps)
    assert result.status == "completed"
    assert [r.enforcement_point.value for r in gate.requests] == ["model_call", "model_call"]
    body = json.loads(deps.models._transport.calls[1].body)  # type: ignore[attr-defined]  # noqa: SLF001
    assert "unknown tool" in body["messages"][-1]["content"]


async def test_tool_failure_is_reported_to_the_model_and_run_continues() -> None:
    deps = deps_for(tool_turn(("lookup_claim", {})), final("recovered"))

    def boom(args: Any) -> Any:
        raise RuntimeError("db down")

    deps.tools.register("lookup_claim", boom)
    result = await run_agent(make_manifest(), "x", deps)
    assert result.output == "recovered"
    assert result.state.tool_calls[0].ok is False


async def test_max_steps_guard() -> None:
    deps = deps_for(tool_turn(("lookup_claim", {})), max_steps=3)
    result = await run_agent(make_manifest(), "x", deps)
    assert result.status == "failed" and result.exit_reason is ExitReason.FAILED
    assert "max_steps" in (result.state.processes[result.pid].exit_detail or "")


async def test_agent_without_system_prompt_or_tools() -> None:
    deps = deps_for(final("hi"))
    m = make_manifest(system_prompt="", tools=[])
    result = await run_agent(m, "hello", deps)
    body = json.loads(deps.models._transport.calls[0].body)  # type: ignore[attr-defined]  # noqa: SLF001
    assert [x["role"] for x in body["messages"]] == ["user"] and "tools" not in body
    assert result.output == "hi"


@pytest.mark.parametrize(
    ("kind", "extra", "effect"),
    [
        ("mcp", {"mcp_server": "kb"}, "mcp"),
        ("code", {}, "code"),
        ("browser", {}, "browser"),
        ("channel", {}, "channel"),
    ],
)
async def test_every_tool_kind_routes_through_the_gate_to_its_backend(
    kind: str, extra: dict[str, Any], effect: str
) -> None:
    effects = Effects()
    gate = ScriptedGate()
    deps = deps_for(
        tool_turn(("t", {"a": 1, "language": "python", "code": "print(1)"})), final(), gate=gate
    )
    deps.backends = recording_backends(effects)
    m = make_manifest(tools=[{"name": "t", "kind": kind, "side_effects": "external", **extra}])
    result = await run_agent(m, "x", deps)
    assert result.status == "completed"
    assert [c[0] for c in effects.calls] == [effect]
    assert (
        gate.requests[1].enforcement_point.value
        == {
            "mcp": "mcp_call",
            "code": "code_exec",
            "browser": "browser_exec",
            "channel": "message_send",
        }[kind]
    )


# ---- policy ----------------------------------------------------------------------------------------


async def test_denied_tool_is_not_executed_and_model_is_told() -> None:
    effects = Effects()
    gate = ScriptedGate(
        lambda r: deny("tool blocked") if r.enforcement_point.value == "tool_call" else allow()
    )
    deps = deps_for(
        tool_turn(("lookup_claim", {"id": "x"})), final("sorry"), gate=gate, effects=effects
    )
    result = await run_agent(make_manifest(), "x", deps)
    assert effects.total() == 0 and result.output == "sorry"
    assert [g.decision for g in result.state.gate_decisions] == [
        Decision.ALLOW,
        Decision.DENY,
        Decision.ALLOW,
    ]
    body = json.loads(deps.models._transport.calls[1].body)  # type: ignore[attr-defined]  # noqa: SLF001
    assert body["messages"][-1]["content"] == "denied by policy: tool blocked"


async def test_exit_on_deny_terminates_with_policy_denied() -> None:
    gate = ScriptedGate(
        lambda r: deny("no") if r.enforcement_point.value == "tool_call" else allow()
    )
    deps = deps_for(tool_turn(("lookup_claim", {})), final(), gate=gate, exit_on_deny=True)
    result = await run_agent(make_manifest(), "x", deps)
    assert result.status == "policy_denied" and result.exit_reason is ExitReason.POLICY_DENIED


async def test_denied_model_call_ends_the_run_and_nothing_reaches_the_provider() -> None:
    deps = deps_for(final(), gate=ScriptedGate(deny("egress blocked")))
    result = await run_agent(make_manifest(), "secret prompt", deps)
    assert result.status == "policy_denied"
    assert deps.models._transport.calls == []  # type: ignore[attr-defined]  # noqa: SLF001


async def test_gate_outage_fails_the_run_closed() -> None:
    class Down:
        async def evaluate(self, r: EvaluateRequest) -> GateDecision:
            raise ConnectionError("down")

    deps = deps_for(final(), gate=Down())
    result = await run_agent(make_manifest(), "x", deps)
    assert result.status == "policy_denied"
    assert deps.models._transport.calls == []  # type: ignore[attr-defined]  # noqa: SLF001


async def test_require_approval_parks_the_run_in_waiting() -> None:
    effects = Effects()
    gate = ScriptedGate(
        lambda r: (
            GateDecision(Decision.REQUIRE_APPROVAL, "human", approval_id="ap_1")
            if r.enforcement_point.value == "tool_call"
            else allow()
        )
    )
    deps = deps_for(tool_turn(("lookup_claim", {})), final(), gate=gate, effects=effects)
    result = await run_agent(make_manifest(), "x", deps)
    assert result.status == "awaiting_approval" and result.approval_id == "ap_1"
    assert result.exit_reason is None and effects.total() == 0
    assert result.state.processes[result.pid].state is ProcessState.WAITING


async def test_model_provider_failure_fails_the_run() -> None:
    deps = deps_for((401, {"error": {"type": "invalid_api_key"}}))
    result = await run_agent(make_manifest(), "x", deps)
    assert result.status == "failed"
    assert "model call failed" in (result.state.processes[result.pid].exit_detail or "")


# ---- budgets and timeouts --------------------------------------------------------------------------


def budgets(**kv: dict[str, Any]) -> dict[str, Any]:
    return {"budgets": kv}


async def test_token_hard_cap_exits_budget_exceeded() -> None:
    deps = deps_for(tool_turn(("lookup_claim", {}), prompt=90, completion=20), final())
    m = make_manifest(**budgets(tokens={"soft": 50, "hard": 100}))
    result = await run_agent(m, "x", deps)
    assert result.status == "budget_exceeded"
    assert result.state.warnings == (f"{result.pid}:tokens",)  # soft cap warned first, once
    assert result.state.tool_calls_used == 0  # stopped before acting on the over-budget turn


async def test_token_cap_is_checked_before_the_next_model_call() -> None:
    deps = deps_for(tool_turn(("lookup_claim", {}), prompt=60, completion=40), final())
    m = make_manifest(
        **budgets(tokens={"hard": 100})
    )  # exactly at the cap: no budget left for another call
    result = await run_agent(m, "x", deps)
    assert result.status == "budget_exceeded" and len(result.state.model_calls) == 1


async def test_tool_call_hard_cap_blocks_the_extra_call() -> None:
    effects = Effects()
    deps = deps_for(
        tool_turn(("lookup_claim", {"n": 1}), ("lookup_claim", {"n": 2})), final(), effects=effects
    )
    m = make_manifest(**budgets(tool_calls={"hard": 1}))
    result = await run_agent(m, "x", deps)
    assert result.status == "budget_exceeded"
    assert effects.calls == [("tool", {"n": 1})]  # the second call never ran


async def test_cost_hard_cap() -> None:
    deps = deps_for(final(prompt=1_000_000, completion=0))  # gpt-4o: $2.50
    m = make_manifest(**budgets(cost_usd={"hard": 1.0}))
    result = await run_agent(m, "x", deps)
    assert result.status == "budget_exceeded" and result.state.cost_micro_usd == 2_500_000


async def test_runtime_seconds_hard_cap_uses_the_injected_clock() -> None:
    clock = FakeClock()
    effects = Effects()
    deps = deps_for(tool_turn(("lookup_claim", {})), final(), effects=effects, clock=clock)
    deps.tools.register("lookup_claim", lambda a: clock.advance(120) or {"ok": 1})
    m = make_manifest(**budgets(runtime_seconds={"hard": 60}))
    result = await run_agent(m, "x", deps)
    assert result.status == "budget_exceeded"


async def test_process_timeout_kills_a_hung_model_call() -> None:
    transport = ScriptedTransport([(200, final())])

    async def hang() -> None:
        await asyncio.sleep(30)

    transport.delay = hang
    deps = make_deps(transport=transport)
    m = make_manifest(process={"timeout_seconds": 0.05})
    result = await run_agent(m, "x", deps)
    assert result.status == "timeout" and result.exit_reason is ExitReason.TIMEOUT
    # the hung process was `waiting`: it leaves through the KILL edge and never recorded a result
    assert (await transitions(deps, result.run_id, result.pid))[-1] == "KILL"
    assert result.state.model_calls == ()


async def test_timeout_error_raised_by_a_tool_is_a_failure_not_a_process_timeout() -> None:
    deps = deps_for(tool_turn(("lookup_claim", {})), final("ok"))

    def slow(args: Any) -> Any:
        raise TimeoutError("upstream")

    deps.tools.register("lookup_claim", slow)
    m = make_manifest(process={"timeout_seconds": 5})
    result = await run_agent(m, "x", deps)
    assert result.status == "completed"  # tool error was reported to the model


# ---- signals -----------------------------------------------------------------------------------------


class Gated:
    """Transport delay hook: the test decides when each model call may return."""

    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def __call__(self) -> None:
        self.entered.set()
        await self.release.wait()


async def started_with_gate(
    *bodies: Any, m: RuntimeManifest | None = None, **kw: Any
) -> tuple[RunHandle, RunDeps, Gated]:
    g = Gated()
    deps = deps_for(*bodies, **kw)
    deps.models._transport.delay = g  # type: ignore[attr-defined]  # noqa: SLF001
    handle = await start_agent(m or make_manifest(), "go", deps)
    await asyncio.wait_for(g.entered.wait(), 2)
    return handle, deps, g


async def test_pause_suspends_at_a_safe_point_and_resume_continues() -> None:
    handle, deps, g = await started_with_gate(
        tool_turn(("lookup_claim", {})), final("after resume")
    )
    await handle.signal(Signal.PAUSE)
    g.release.set()  # model call finishes; the very next safe point suspends
    await settle(lambda: handle.state.processes[handle.pid].state is ProcessState.SUSPENDED)
    assert handle.state.tool_calls == ()  # paused before the tool ran
    await handle.signal(Signal.RESUME)
    result = await handle.result()
    assert result.output == "after resume" and result.status == "completed"
    trig = await transitions(deps, result.run_id, result.pid)
    assert trig[trig.index("PAUSE") : trig.index("PAUSE") + 3] == ["PAUSE", "RESUME", "scheduled"]
    assert (result.pid, "PAUSE") in result.state.signals and (
        result.pid,
        "RESUME",
    ) in result.state.signals


async def test_resume_racing_with_pause_does_not_hang() -> None:
    handle, _, g = await started_with_gate(final("ok"))
    await handle.signal(Signal.PAUSE)
    await handle.signal(Signal.RESUME)
    g.release.set()
    assert (await asyncio.wait_for(handle.result(), 3)).status == "completed"


async def test_term_while_suspended_exits_killed_via_term_edge() -> None:
    handle, deps, g = await started_with_gate(tool_turn(("lookup_claim", {})), final())
    await handle.signal(Signal.PAUSE)
    g.release.set()
    await settle(lambda: handle.state.processes[handle.pid].state is ProcessState.SUSPENDED)
    await handle.signal(Signal.TERM)
    result = await handle.result()
    assert result.status == "killed"
    assert (await transitions(deps, result.run_id, result.pid))[-1] == "TERM"


async def test_term_while_running_exits_at_next_safe_point() -> None:
    effects = Effects()
    handle, deps, g = await started_with_gate(
        tool_turn(("lookup_claim", {})), final(), effects=effects
    )
    await handle.signal(Signal.TERM)
    g.release.set()
    result = await handle.result()
    assert (
        result.status == "killed" and effects.total() == 0
    )  # graceful: no further external action
    assert (await transitions(deps, result.run_id, result.pid))[
        -1
    ] == "exit"  # woke to running, then left


async def test_kill_cancels_in_flight_action_immediately() -> None:
    handle, deps, g = await started_with_gate(final())
    await handle.signal(Signal.KILL)
    result = await asyncio.wait_for(handle.result(), 2)
    assert result.status == "killed" and result.state.model_calls == ()
    assert result.state.processes[result.pid].state is ProcessState.TERMINATED
    assert replay(await deps.log.read(result.run_id)) == result.state


async def test_term_escalates_to_kill_after_the_grace_period() -> None:
    m = make_manifest()
    deps = deps_for(final(), term_grace_seconds=0.05)
    hang = Gated()
    deps.models._transport.delay = hang  # type: ignore[attr-defined]  # noqa: SLF001
    handle = await start_agent(m, "go", deps)
    await hang.entered.wait()
    await handle.signal(Signal.TERM)  # the process is stuck inside the provider call
    result = await asyncio.wait_for(handle.result(), 2)
    assert result.status == "killed"
    assert [s for _, s in result.state.signals] == ["TERM", "KILL"]


async def test_signals_to_a_terminated_process_are_ignored() -> None:
    deps = deps_for(final())
    handle = await start_agent(make_manifest(), "x", deps)
    result = await handle.result()
    before = len(await deps.log.read(result.run_id))
    await handle.signal(Signal.KILL)
    assert len(await deps.log.read(result.run_id)) == before


async def test_interrupt_delivers_a_message_without_a_state_change() -> None:
    handle, deps, g = await started_with_gate(tool_turn(("lookup_claim", {})), final("ok"))
    await handle.signal(Signal.INTERRUPT, "human is taking over the account")
    g.release.set()
    result = await handle.result()
    assert result.status == "completed"
    body = json.loads(deps.models._transport.calls[1].body)  # type: ignore[attr-defined]  # noqa: SLF001
    assert any("[interrupt] human is taking over" in (m["content"] or "") for m in body["messages"])
    trig = await transitions(deps, result.run_id, result.pid)
    assert "INTERRUPT" not in trig


# ---- init failures --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("proc", "needle"),
    [
        ({"supervisor": "one-for-all"}, "supervisor"),
        ({"restart_policy": "always"}, "restart_policy"),
    ],
)
async def test_unimplemented_manifest_features_fail_at_init(
    proc: dict[str, Any], needle: str
) -> None:
    deps = deps_for(final())
    result = await run_agent(make_manifest(process=proc), "x", deps)
    assert result.status == "failed" and deps.models._transport.calls == []  # type: ignore[attr-defined]  # noqa: SLF001
    info = result.state.processes[result.pid]
    assert info.state is ProcessState.TERMINATED and needle in (info.exit_detail or "")
    assert await transitions(deps, result.run_id, result.pid) == ["init_failed"]


# ---- supervision ------------------------------------------------------------------------------------------


def parent_and_child(**child_proc: Any) -> tuple[RuntimeManifest, RuntimeManifest]:
    parent = make_manifest(
        blueprint={"name": "lead", "version": "1.0.0"},
        tools=[{"name": "delegate", "kind": "agent", "ref": "worker", "side_effects": "write"}],
        process={"max_children": 1},
    )
    worker = make_manifest(
        blueprint={"name": "worker", "version": "2.0.0"}, tools=[], process=child_proc or {}
    )
    return parent, worker


async def test_child_spawn_builds_a_process_tree_and_returns_output() -> None:
    parent, worker = parent_and_child()
    gate = ScriptedGate()
    deps = deps_for(
        tool_turn(("delegate", {"input": "summarise C-1"})),
        final("child summary"),
        final("lead final"),
        gate=gate,
        child_manifests={"worker": worker},
    )
    result = await run_agent(parent, "go", deps)
    assert result.status == "completed" and result.output == "lead final"
    procs = list(result.state.processes.values())
    assert len(procs) == 2
    child = next(p for p in procs if p.ppid == result.pid)
    assert child.state is ProcessState.TERMINATED and child.exit_reason is ExitReason.COMPLETED
    assert child.agent == "worker@2.0.0"
    assert result.state.outputs[child.pid] == "child summary"
    assert result.state.tool_calls[-1].result == "child summary"
    # the spawn itself went through the gate as a tool_call by the parent; the child's model call too
    assert [(r.enforcement_point.value, r.pid == result.pid) for r in gate.requests] == [
        ("model_call", True),
        ("tool_call", True),
        ("model_call", False),
        ("model_call", True),
    ]
    assert replay(await deps.log.read(result.run_id)) == result.state


async def test_child_without_json_input_gets_the_args_as_its_prompt() -> None:
    parent, worker = parent_and_child()
    deps = deps_for(
        tool_turn(("delegate", {"claim": "C-9"})),
        final("x"),
        final("y"),
        child_manifests={"worker": worker},
    )
    await run_agent(parent, "go", deps)
    child_body = json.loads(deps.models._transport.calls[1].body)  # type: ignore[attr-defined]  # noqa: SLF001
    assert child_body["messages"][-1]["content"] == '{"claim": "C-9"}'


async def test_one_for_one_restart_replaces_only_the_failed_child() -> None:
    parent, worker = parent_and_child(restart_policy="on_failure", max_restarts=1)
    deps = deps_for(
        tool_turn(("delegate", {"input": "t"})),
        (400, {"error": {"type": "invalid_request_error"}}),  # first child attempt fails
        final("second attempt ok"),
        final("lead final"),
        child_manifests={"worker": worker},
    )
    # the provider error only applies to the child's first call: scripted order parent, child, child, parent
    deps.models._transport.responses = [  # type: ignore[attr-defined]  # noqa: SLF001
        (200, tool_turn(("delegate", {"input": "t"}))),
        (400, {"error": {"type": "invalid_request_error"}}),
        (200, final("second attempt ok")),
        (200, final("lead final")),
    ]
    result = await run_agent(parent, "go", deps)
    assert result.status == "completed" and result.output == "lead final"
    kids = [p for p in result.state.processes.values() if p.ppid == result.pid]
    assert [k.exit_reason for k in kids] == [ExitReason.FAILED, ExitReason.COMPLETED]
    assert len({k.pid for k in kids}) == 2
    assert (
        result.state.processes[result.pid].exit_reason is ExitReason.COMPLETED
    )  # parent untouched


async def test_restart_budget_exhaustion_surfaces_a_tool_error_to_the_parent() -> None:
    parent, worker = parent_and_child(restart_policy="on_failure", max_restarts=1)
    deps = deps_for(child_manifests={"worker": worker})
    deps.models._transport.responses = [  # type: ignore[attr-defined]  # noqa: SLF001
        (200, tool_turn(("delegate", {"input": "t"}))),
        (400, {"error": {}}),
        (400, {"error": {}}),
        (200, final("gave up on the child")),
    ]
    result = await run_agent(parent, "go", deps)
    assert result.status == "completed"
    kids = [p for p in result.state.processes.values() if p.ppid == result.pid]
    assert [k.exit_reason for k in kids] == [ExitReason.FAILED, ExitReason.FAILED]
    assert result.state.tool_calls[-1].ok is False and "ChildError" in (
        result.state.tool_calls[-1].error or ""
    )


async def test_no_restart_when_policy_is_never() -> None:
    parent, worker = parent_and_child()
    deps = deps_for(child_manifests={"worker": worker})
    deps.models._transport.responses = [  # type: ignore[attr-defined]  # noqa: SLF001
        (200, tool_turn(("delegate", {"input": "t"}))),
        (400, {"error": {}}),
        (200, final("ok")),
    ]
    result = await run_agent(parent, "go", deps)
    assert len([p for p in result.state.processes.values() if p.ppid == result.pid]) == 1


async def test_max_children_and_unknown_child_are_tool_errors() -> None:
    parent, worker = parent_and_child()
    zero = make_manifest(
        tools=[
            {"name": "delegate", "kind": "agent", "ref": "worker"},
            {"name": "ghost", "kind": "agent", "ref": "nobody"},
        ],
        process={"max_children": 0},
    )
    deps = deps_for(
        tool_turn(("delegate", {})),
        tool_turn(("ghost", {})),
        final("done"),
        child_manifests={"worker": worker},
    )
    result = await run_agent(zero, "go", deps)
    errors = [t.error for t in result.state.tool_calls]
    assert any("max_children" in (e or "") for e in errors)
    assert len(result.state.processes) == 1  # nothing was spawned
    deps2 = deps_for(tool_turn(("ghost", {})), final("done"), child_manifests={"worker": worker})
    bigger = make_manifest(
        tools=[{"name": "ghost", "kind": "agent", "ref": "nobody"}], process={"max_children": 2}
    )
    result2 = await run_agent(bigger, "go", deps2)
    assert any("unknown child agent" in (t.error or "") for t in result2.state.tool_calls)


async def test_killing_the_parent_terminates_an_in_flight_child_with_parent_terminated() -> None:
    parent, worker = parent_and_child()
    g = Gated()
    calls = {"n": 0}

    async def delay() -> None:
        calls["n"] += 1
        if calls["n"] >= 2:  # 1st = parent's model call, 2nd = the child's, which hangs
            await g()

    deps = deps_for(child_manifests={"worker": worker})
    deps.models._transport.responses = [  # type: ignore[attr-defined]  # noqa: SLF001
        (200, tool_turn(("delegate", {"input": "t"}))),
        (200, final("never")),
    ]
    deps.models._transport.delay = delay  # type: ignore[attr-defined]  # noqa: SLF001
    handle = await start_agent(parent, "go", deps)
    await asyncio.wait_for(g.entered.wait(), 2)
    child = next(p for p in handle.ctx.processes.values() if p.pid != handle.pid)
    await handle.signal(Signal.KILL)
    result = await asyncio.wait_for(handle.result(), 3)
    assert result.status == "killed"
    child_info = result.state.processes[child.pid]
    assert child_info.state is ProcessState.TERMINATED
    assert child_info.exit_reason is ExitReason.PARENT_TERMINATED
    assert replay(await deps.log.read(result.run_id)) == result.state


async def test_parent_timeout_terminates_the_child_tree() -> None:
    parent, worker = parent_and_child()
    parent = make_manifest(
        blueprint={"name": "lead", "version": "1.0.0"},
        tools=[{"name": "delegate", "kind": "agent", "ref": "worker"}],
        process={"max_children": 1, "timeout_seconds": 0.15},
    )
    g = Gated()  # the child's model call never returns
    calls = {"n": 0}

    async def delay() -> None:
        calls["n"] += 1
        if calls["n"] >= 2:  # 1st = parent's model call, 2nd = child's
            await g()

    deps = deps_for(child_manifests={"worker": worker})
    deps.models._transport.responses = [  # type: ignore[attr-defined]  # noqa: SLF001
        (200, tool_turn(("delegate", {"input": "t"}))),
        (200, final("never")),
    ]
    deps.models._transport.delay = delay  # type: ignore[attr-defined]  # noqa: SLF001
    result = await asyncio.wait_for(run_agent(parent, "go", deps), 3)
    assert result.status == "timeout"
    child = next(p for p in result.state.processes.values() if p.ppid == result.pid)
    assert (
        child.state is ProcessState.TERMINATED and child.exit_reason is ExitReason.PARENT_TERMINATED
    )
    assert replay(await deps.log.read(result.run_id)) == result.state


# ---- manifest ------------------------------------------------------------------------------------------------


def test_manifest_parses_the_plan_shape_and_defaults() -> None:
    m = RuntimeManifest.from_dict(manifest_dict())
    assert (m.name, m.version, m.risk_level, m.phi) == ("claims-triage", "1.0.0", "limited", False)
    assert m.tools[0].side_effects == "read" and m.primary.model == "gpt-4o"
    minimal = RuntimeManifest.from_dict(
        {
            "manifest_version": 1,
            "blueprint": {"name": "a", "version": "1"},
            "models": {"primary": {"provider": "p", "model": "m"}},
        }
    )
    assert (
        minimal.tools == ()
        and minimal.process.supervisor == "one-for-one"
        and minimal.budgets.tokens.hard is None
    )
    assert minimal.tool("x") is None


@pytest.mark.parametrize(
    ("patch", "path"),
    [
        ({"manifest_version": 2}, "manifest_version"),
        ({"blueprint": {"name": ""}}, "blueprint.name"),
        ({"blueprint": None}, "blueprint"),
        ({"models": {"primary": {"provider": "x"}}}, "models.primary.model"),
        ({"models": {"primary": None}}, "models.primary"),
        ({"tools": [{"name": "t", "kind": "telepathy"}]}, "tools[0].kind"),
        ({"tools": [{"name": "t", "side_effects": "chaos"}]}, "tools[0].side_effects"),
        ({"tools": [{"name": "t", "kind": "mcp"}]}, "tools[0].mcp_server"),
        ({"tools": [{"name": "t"}, {"name": "t"}]}, "tools"),
        ({"tools": [{"kind": "function"}]}, "tools[0].name"),
        ({"budgets": {"tokens": {"hard": -1}}}, "budgets.tokens.hard"),
        ({"budgets": {"tokens": {"soft": 10, "hard": 5}}}, "budgets.tokens"),
        ({"budgets": {"tokens": {"hard": True}}}, "budgets.tokens.hard"),
    ],
)
def test_manifest_validation_errors_carry_a_path(patch: dict[str, Any], path: str) -> None:
    raw = manifest_dict()
    for k, v in patch.items():
        raw[k] = v
    with pytest.raises(ManifestError) as exc:
        RuntimeManifest.from_dict(raw)
    assert exc.value.path == path


async def test_review_in_run_restart_continues_the_childs_token_budget() -> None:
    """The built-in one-for-one loop gave every restart a fresh budget (usage was summed per pid)."""
    parent = make_manifest(
        blueprint={"name": "lead", "version": "1.0.0"},
        tools=[{"name": "delegate", "kind": "agent", "ref": "worker", "side_effects": "write"}],
        process={"max_children": 1},
    )
    worker = make_manifest(
        blueprint={"name": "worker", "version": "2.0.0"},
        tools=[],
        process={"restart_policy": "on_failure", "max_restarts": 1},
        budgets={"tokens": {"soft": None, "hard": 30}},
    )
    deps = deps_for(child_manifests={"worker": worker})
    deps.models._transport.responses = [  # type: ignore[attr-defined]  # noqa: SLF001
        (200, tool_turn(("delegate", {"input": "t"}))),
        (200, tool_turn(("noop", {}))),  # attempt 1: 15 tokens...
        (400, {"error": {}}),  # ...then fails
        (200, tool_turn(("noop", {}))),  # attempt 2: another 15 = the whole 30 token budget
        (200, final("c2 would complete on a fresh budget")),
        (200, final("lead final")),
    ]
    result = await run_agent(parent, "go", deps)
    kids = [p for p in result.state.processes.values() if p.ppid == result.pid]
    assert [k.exit_reason for k in kids] == [ExitReason.FAILED, ExitReason.BUDGET_EXCEEDED]
    pids = {k.pid for k in kids}
    spent = sum(m.input_tokens + m.output_tokens for m in result.state.model_calls if m.pid in pids)
    assert spent <= 30  # across both incarnations (a fresh budget let the worker spend 45)


async def test_invalid_code_tool_arguments_are_a_tool_error_not_a_crashed_run() -> None:
    effects = Effects()
    gate = ScriptedGate()
    deps = deps_for(
        tool_turn(("t", {"language": "cobol", "code": "SECRET-CODE"})), final(), gate=gate
    )
    deps.backends = recording_backends(effects)
    m = make_manifest(tools=[{"name": "t", "kind": "code", "side_effects": "external"}])
    result = await run_agent(m, "x", deps)
    assert result.status == "completed" and effects.total() == 0
    assert all(r.enforcement_point.value != "code_exec" for r in gate.requests)
