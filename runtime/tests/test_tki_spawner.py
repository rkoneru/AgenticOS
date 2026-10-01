"""``TkiChildSpawner``: in-run children supervised by TKI, budgeted, and still gated."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from axis_runtime.events import EventType
from axis_runtime.manifest import RuntimeManifest
from axis_runtime.process import ExitReason, ProcessState
from axis_runtime.run import RunDeps
from axis_runtime.tki import Limit, Resource, SchedulerConfig, TkiEventType
from axis_runtime.tki.adapter import agent_workload, tki_spawner_factory
from axis_runtime.tki.budget import AccountKey, ScopeKind
from axis_runtime.tki.supervisor import SupervisorConfig
from conftest import ScriptedGate, ScriptedTransport, allow, deny, make_deps, make_manifest
from helpers import Effects
from test_run import final, registry, tool_turn
from tki_helpers import T1, Kernel, make_kernel, spec

TOK = Resource.TOKENS
LEAD_RUN = "run_lead"


def lead_and_workers(**worker_proc: Any) -> tuple[RuntimeManifest, dict[str, RuntimeManifest]]:
    lead = make_manifest(
        blueprint={"name": "lead", "version": "1.0.0"},
        tools=[
            {"name": "delegate", "kind": "agent", "ref": "worker", "side_effects": "write"},
            {"name": "delegate-b", "kind": "agent", "ref": "worker-b", "side_effects": "write"},
            {"name": "ghost", "kind": "agent", "ref": "nobody", "side_effects": "write"},
        ],
        process={"max_children": 5},
    )
    workers = {
        ref: make_manifest(
            blueprint={"name": ref, "version": "2.0.0"}, tools=[], process=worker_proc or {}
        )
        for ref in ("worker", "worker-b")
    }
    return lead, workers


def deps_for(*bodies: Any, gate: Any = None, effects: Effects | None = None, **kw: Any) -> RunDeps:
    transport = ScriptedTransport([(200, b) if not isinstance(b, tuple) else b for b in bodies])
    return make_deps(gate=gate, transport=transport, tools=registry(effects), run_id=LEAD_RUN, **kw)


def start(
    k: Kernel,
    lead: RuntimeManifest,
    deps: RunDeps,
    *,
    limits: Any = None,
    child_limits: Any = None,
) -> str:
    factory = tki_spawner_factory(
        k.sched, SupervisorConfig(max_children=5), deps, child_limits=child_limits
    )
    return k.sched.spawn(
        spec(agent="lead@1.0.0", limits=limits or {}),
        agent_workload(lead, "go", deps, spawner_factory=factory),
    )


def committed(k: Kernel, pid: str) -> Any:
    """Live usage (an account is closed when its process exits)."""
    return k.ledger.usage(AccountKey(T1, ScopeKind.PROCESS, pid)).committed


def granted(k: Kernel, pid: str, res: Resource = TOK) -> int:
    """Everything the ledger committed to this process's own account, from the audit events."""
    return sum(
        e.data["granted"].get(res.value, 0)
        for e in k.sink.of(TkiEventType.BUDGET_COMMITTED)
        if e.data["account"] == f"process:{pid}"
    )


async def lead_tool_errors(deps: RunDeps) -> list[str]:
    events = await deps.log.read(LEAD_RUN)
    return [
        e.data["error"] for e in events if e.type == EventType.TOOL_CALL_RESULT and e.data["error"]
    ]


async def test_two_children_run_under_a_supervisor_through_the_gate_and_roll_up_spend() -> None:
    lead, workers = lead_and_workers()
    seen: dict[str, Any] = {}

    def watch(r: Any) -> Any:
        if r.context["run"]["id"].endswith(".c2"):  # the second child's first action
            seen["parent_committed"] = dict(committed(k, seen["pid"]))
        return allow()

    gate = ScriptedGate(watch)
    deps = deps_for(
        tool_turn(("delegate", {"input": "task A"}), ("delegate-b", {"input": "task B"})),
        final("A done"),
        final("B done"),
        final("lead final"),
        gate=gate,
        child_manifests=workers,
        trace_id="e" * 32,
    )
    k = make_kernel()
    pid = start(k, lead, deps, limits={TOK: Limit(hard=100_000)})
    seen["pid"] = pid
    assert (await k.sched.wait(pid)).exit_reason is ExitReason.COMPLETED
    kids = k.sched.children_of(pid)
    assert len(kids) == 2 and all(c.exit_reason is ExitReason.COMPLETED for c in kids)
    assert {c.agent for c in kids} == {"worker@2.0.0", "worker-b@2.0.0"}
    # lead: 2 model calls + 2 spawn tool calls; each child: 1 model call. All gated, on one trace.
    assert len(gate.requests) == 6
    assert {r.trace_id for r in gate.requests} == {"e" * 32}
    run_ids = sorted({r.context["run"]["id"] for r in gate.requests})
    assert run_ids == [LEAD_RUN, f"{LEAD_RUN}.c1", f"{LEAD_RUN}.c2"]
    # spend rolls up: the parent's account includes both children's
    assert [granted(k, c.pid) for c in kids] == [15, 15]  # 10 + 5 tokens each
    # when the second child starts, the parent's account already holds its own first call (15) and
    # the first child's (15), although that child's process account is long closed
    assert seen["parent_committed"][TOK] == 30
    assert granted(k, pid) == 30  # (events name the leaf account: the lead's own two calls)
    assert await lead_tool_errors(deps) == []


@pytest.mark.parametrize(
    ("cap", "reported", "event"),
    [
        (100, 15, TkiEventType.BUDGET_DENIED),  # the reservation estimate alone exceeds the cap
        (
            5_000,
            9_000,
            TkiEventType.BUDGET_HARD_CAP,
        ),  # the provider reports more than it was allowed
    ],
    ids=["refused-before-spend", "clamped-after-spend"],
)
async def test_a_child_over_its_hard_cap_is_terminated_alone_and_the_parent_is_told(
    cap: int, reported: int, event: TkiEventType
) -> None:
    lead, workers = lead_and_workers()
    deps = deps_for(
        tool_turn(("delegate", {"input": "greedy"}), ("delegate-b", {"input": "modest"})),
        final("greedy", prompt=reported, completion=0),
        final("modest answer"),
        final("lead final"),
        child_manifests=workers,
    )
    k = make_kernel()
    pid = start(
        k,
        lead,
        deps,
        limits={TOK: Limit(hard=100_000)},
        child_limits={"worker": {TOK: Limit(hard=cap)}},
    )
    assert (await k.sched.wait(pid)).exit_reason is ExitReason.COMPLETED  # the parent finished
    by_agent = {c.agent: c for c in k.sched.children_of(pid)}
    greedy, modest = by_agent["worker@2.0.0"], by_agent["worker-b@2.0.0"]
    assert greedy.exit_reason is ExitReason.BUDGET_EXCEEDED
    assert modest.exit_reason is ExitReason.COMPLETED  # sibling unaffected
    assert granted(k, greedy.pid) <= cap  # the cap is never exceeded
    assert k.sink.of(event)
    assert not k.sink.of(TkiEventType.PROCESS_RESTARTED)  # a cap trip is never restarted
    errors = await lead_tool_errors(deps)
    assert len(errors) == 1 and "budget_exceeded" in errors[0]


async def test_unknown_child_ref_is_a_tool_error_and_nothing_is_spawned() -> None:
    lead, workers = lead_and_workers()
    deps = deps_for(tool_turn(("ghost", {})), final("fine"), child_manifests=workers)
    k = make_kernel()
    pid = start(k, lead, deps)
    assert (await k.sched.wait(pid)).exit_reason is ExitReason.COMPLETED
    assert k.sched.children_of(pid) == []
    assert any("unknown child agent" in e for e in await lead_tool_errors(deps))


async def test_a_failed_child_is_restarted_by_the_supervisor_and_the_parent_gets_the_retry() -> (
    None
):
    lead, workers = lead_and_workers(restart_policy="on_failure", max_restarts=1)
    deps = deps_for(
        tool_turn(("delegate", {"input": "flaky"})),
        (400, {"error": {"type": "invalid_request_error"}}),  # the child's first attempt fails
        final("recovered"),
        final("lead final"),
        child_manifests=workers,
    )
    k = make_kernel()
    pid = start(k, lead, deps)
    assert (await asyncio.wait_for(k.sched.wait(pid), 10)).exit_reason is ExitReason.COMPLETED
    assert k.sink.of(TkiEventType.PROCESS_RESTARTED)
    states = [(c.exit_reason, c.state) for c in k.sched.children_of(pid)]
    assert (ExitReason.FAILED, ProcessState.TERMINATED) in states
    assert (ExitReason.COMPLETED, ProcessState.TERMINATED) in states
    assert await lead_tool_errors(deps) == []


async def test_a_parent_waiting_on_a_child_does_not_hold_a_scheduler_slot() -> None:
    lead, workers = lead_and_workers()
    deps = deps_for(
        tool_turn(("delegate", {"input": "x"})),
        final("child"),
        final("lead"),
        child_manifests=workers,
    )
    k = make_kernel(SchedulerConfig(max_running=1, default_tenant_limit=1))
    pid = start(k, lead, deps)
    # with a single slot, a parent that kept it while its child waited for one would deadlock
    v = await asyncio.wait_for(k.sched.wait(pid), 10)
    assert v.exit_reason is ExitReason.COMPLETED


async def test_a_child_whose_actions_the_gate_denies_does_not_complete_and_runs_no_tool() -> None:
    lead, workers = lead_and_workers()
    gate = ScriptedGate(
        lambda r: deny("not for children") if r.context["run"]["id"] != LEAD_RUN else allow()
    )
    deps = deps_for(
        tool_turn(("delegate", {"input": "x"})),
        final("lead"),
        gate=gate,
        child_manifests=workers,
    )
    k = make_kernel()
    pid = start(k, lead, deps)
    assert (await k.sched.wait(pid)).exit_reason is ExitReason.COMPLETED
    (kid,) = k.sched.children_of(pid)
    assert kid.exit_reason is ExitReason.POLICY_DENIED  # the gate still governs TKI-spawned agents
    assert len(await lead_tool_errors(deps)) == 1
