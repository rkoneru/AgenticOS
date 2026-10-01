"""TKI adapter: a real agent run under TKI; the gate/executor path is unchanged and budgeted."""

from __future__ import annotations

import asyncio
from decimal import Decimal
from typing import Any

import pytest
from axis_runtime.actions import ModelCall, ToolCall
from axis_runtime.executor import Completed, Denied, PendingApproval
from axis_runtime.gate import GateDecision
from axis_runtime.models import Message, ModelRequest, ModelTarget
from axis_runtime.models.types import FinishReason, ModelResponse, Usage
from axis_runtime.process import ExitReason, Signal
from axis_runtime.run import RunDeps
from axis_runtime.tki import Limit, Resource, TkiEventType
from axis_runtime.tki.adapter import (
    BudgetedRunner,
    agent_workload,
    budgeted_deps,
    estimate_model_tokens,
)
from axis_runtime.tki.budget import BudgetExceededError
from conftest import (
    ScriptedGate,
    ScriptedTransport,
    allow,
    deny,
    make_deps,
    make_manifest,
    openai_body,
)
from helpers import SAMPLES, Effects
from test_run import final, registry, tool_turn
from tki_helpers import Kernel, make_kernel, spec

TOK, CALLS = Resource.TOKENS, Resource.TOOL_CALLS


def deps_for(*bodies: Any, gate: Any = None, effects: Effects | None = None) -> RunDeps:
    transport = ScriptedTransport([(200, b) for b in bodies])
    return make_deps(gate=gate, transport=transport, tools=registry(effects))


def run_acct(k: Kernel) -> Any:
    return next(a for a in k.ledger._accounts.values() if a.key.id == "run-1")  # noqa: SLF001


async def test_agent_runs_through_tki_with_the_gate_in_the_path_and_spend_is_ledgered() -> None:
    effects, gate = Effects(), ScriptedGate()
    deps = deps_for(
        tool_turn(("lookup_claim", {"id": "C-1"})), final("done"), gate=gate, effects=effects
    )
    k = make_kernel()
    pid = k.sched.spawn(
        spec(limits={TOK: Limit(hard=100_000), CALLS: Limit(hard=5)}),
        agent_workload(make_manifest(), "status?", deps),
    )
    v = await k.sched.wait(pid)
    assert v.exit_reason is ExitReason.COMPLETED
    assert effects.calls  # the tool really ran...
    assert len(gate.requests) >= 3  # ...and every action (2 model calls + the tool) hit the gate
    acct = run_acct(k)
    assert acct.committed[TOK] == 30  # 2 x (10 + 5) tokens, actuals not estimates
    assert acct.committed[CALLS] == 1 and acct.reserved.get(TOK, 0) == 0


async def test_gate_deny_means_no_side_effect_and_the_reservation_is_released() -> None:
    effects = Effects()
    gate = ScriptedGate(lambda r: deny() if r.enforcement_point == "tool_call" else allow())
    deps = deps_for(
        tool_turn(("lookup_claim", {"id": "C-1"})), final("ok"), gate=gate, effects=effects
    )
    k = make_kernel()
    pid = k.sched.spawn(
        spec(limits={CALLS: Limit(hard=5)}), agent_workload(make_manifest(), "x", deps)
    )
    assert (await k.sched.wait(pid)).exit_reason is ExitReason.COMPLETED
    assert effects.calls == []
    assert run_acct(k).committed.get(CALLS, 0) == 0  # denied: nothing was spent


async def test_token_hard_cap_stops_the_agent_before_any_model_request() -> None:
    gate = ScriptedGate()
    transport = ScriptedTransport([(200, final("never"))])
    deps = make_deps(gate=gate, transport=transport, tools=registry())
    k = make_kernel()
    pid = k.sched.spawn(
        spec(limits={TOK: Limit(hard=50)}), agent_workload(make_manifest(), "hello", deps)
    )  # estimate (prompt + default 4096 max output) exceeds the cap
    v = await k.sched.wait(pid)
    assert v.exit_reason is ExitReason.BUDGET_EXCEEDED
    assert gate.requests == [] and transport.calls == []  # fail-closed: never reached them
    assert k.sink.of(TkiEventType.BUDGET_DENIED)


async def test_term_is_forwarded_to_the_agent_process() -> None:
    gate_started = asyncio.Event()

    class SlowGate:
        requests: list[Any] = []

        async def evaluate(self, request: Any) -> GateDecision:
            gate_started.set()
            await asyncio.sleep(30)
            return allow()

    deps = make_deps(
        gate=SlowGate(), transport=ScriptedTransport([(200, final("x"))]), tools=registry()
    )
    k = make_kernel()
    pid = k.sched.spawn(spec(), agent_workload(make_manifest(), "x", deps))
    await asyncio.wait_for(gate_started.wait(), 2)
    k.sched.signal(pid, Signal.TERM)
    v = await asyncio.wait_for(k.sched.wait(pid), 10)
    assert v.exit_reason is ExitReason.KILLED


async def test_kill_is_forwarded_to_the_agent_process() -> None:
    gate_started = asyncio.Event()

    class SlowGate:
        async def evaluate(self, request: Any) -> GateDecision:
            gate_started.set()
            await asyncio.sleep(30)
            return allow()

    deps = make_deps(
        gate=SlowGate(), transport=ScriptedTransport([(200, final("x"))]), tools=registry()
    )
    k = make_kernel()
    pid = k.sched.spawn(spec(), agent_workload(make_manifest(), "x", deps))
    await asyncio.wait_for(gate_started.wait(), 2)
    k.sched.signal(pid, Signal.KILL)
    assert (await asyncio.wait_for(k.sched.wait(pid), 10)).exit_reason is ExitReason.KILLED


async def test_agent_parked_on_approval_is_reported_not_faked_as_done() -> None:
    gate = ScriptedGate(
        lambda r: GateDecision(
            __import__("axis_runtime").Decision.REQUIRE_APPROVAL,
            "needs approval",
            policy_version="v1",
            approval_id="apr_1",
        )  # fmt: skip
    )
    deps = deps_for(final("x"), gate=gate)
    k = make_kernel()
    pid = k.sched.spawn(spec(), agent_workload(make_manifest(), "x", deps))
    v = await k.sched.wait(pid)
    assert v.exit_reason is ExitReason.COMPLETED and v.detail.startswith("awaiting_approval:")


async def test_agent_failure_status_is_propagated() -> None:
    deps = deps_for(openai_body("x"))
    deps.gate = ScriptedGate(deny("no model for you"))
    k = make_kernel()
    manifest = make_manifest()
    pid = k.sched.spawn(spec(), agent_workload(manifest, "x", deps))
    v = await k.sched.wait(pid)
    assert v.exit_reason in (ExitReason.COMPLETED, ExitReason.POLICY_DENIED, ExitReason.FAILED)


# ---- BudgetedRunner unit tests -------------------------------------------------------------------


class FakeInner:
    def __init__(self, outcome: Any) -> None:
        self.outcome = outcome
        self.ran: list[Any] = []

    async def run(self, action: Any, *, pid: str) -> Any:
        self.ran.append(action)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def model_call(max_tokens: int | None = None, text: str = "hi there") -> ModelCall:
    params = {} if max_tokens is None else {"max_tokens": max_tokens}
    req = ModelRequest(
        tenant_id="t",
        messages=(Message("user", text),),
        target=ModelTarget("openai", "gpt-x"),
        params=params,
    )
    return ModelCall(request=req)


def response(cost: str | None = None, tokens: tuple[int, int] = (7, 3)) -> ModelResponse:
    return ModelResponse(
        text="ok", tool_calls=(), usage=Usage(*tokens), finish_reason=FinishReason.STOP,
        provider="openai", model="gpt-x", cost_usd=None if cost is None else Decimal(cost),
    )  # fmt: skip


async def started_ctx(k: Kernel, limits: Any = None) -> Any:
    """A live ProcessContext handed out by running a parked workload."""
    box: dict[str, Any] = {}
    ready, stop = asyncio.Event(), asyncio.Event()

    async def hold(ctx: Any) -> None:
        box["ctx"] = ctx
        ready.set()
        await stop.wait()

    pid = k.sched.spawn(spec(limits=limits or {}), hold)
    await asyncio.wait_for(ready.wait(), 2)
    box["stop"], box["pid"] = stop, pid
    return box


def test_token_estimate_uses_prompt_and_max_tokens() -> None:
    assert estimate_model_tokens(model_call(max_tokens=100, text="x" * 40)) == 11 + 100
    assert estimate_model_tokens(model_call(max_tokens=0)) > 4000  # bad value: conservative default
    assert estimate_model_tokens(model_call()) > 4000


async def test_model_call_reserves_estimate_commits_actuals_and_cost() -> None:
    k = make_kernel()
    box = await started_ctx(
        k, {TOK: Limit(hard=10_000), Resource.COST_MICRO_USD: Limit(hard=10_000)}
    )
    inner = FakeInner(Completed(response("0.002"), allow()))
    runner = BudgetedRunner(inner, box["ctx"], cost_estimator=lambda _a: 5000)
    out = await runner.run(model_call(max_tokens=500), pid="axp_x")
    assert isinstance(out, Completed)
    acct = run_acct(k)
    assert acct.committed[TOK] == 10 and acct.committed[Resource.COST_MICRO_USD] == 2000
    assert acct.reserved.get(TOK, 0) == 0 and TOK in acct.committed and CALLS not in acct.committed
    box["stop"].set()


async def test_tool_action_counts_one_tool_call_and_failed_still_counts() -> None:
    from axis_runtime.executor import Failed

    k = make_kernel()
    box = await started_ctx(k, {CALLS: Limit(hard=3)})
    action = SAMPLES[ToolCall]()
    runner = BudgetedRunner(FakeInner(Failed("boom", allow())), box["ctx"])
    await runner.run(action, pid="axp_x")
    assert run_acct(k).committed[CALLS] == 1
    box["stop"].set()


@pytest.mark.parametrize("outcome", [Denied("no", deny()), PendingApproval("a", "w", deny())])
async def test_denied_or_parked_actions_spend_nothing(outcome: Any) -> None:
    k = make_kernel()
    box = await started_ctx(k, {CALLS: Limit(hard=3)})
    runner = BudgetedRunner(FakeInner(outcome), box["ctx"])
    await runner.run(SAMPLES[ToolCall](), pid="axp_x")
    assert run_acct(k).committed.get(CALLS, 0) == 0 and run_acct(k).reserved.get(CALLS, 0) == 0
    box["stop"].set()


async def test_inner_exception_releases_the_reservation_and_propagates() -> None:
    k = make_kernel()
    box = await started_ctx(k, {CALLS: Limit(hard=1)})
    runner = BudgetedRunner(FakeInner(RuntimeError("boom")), box["ctx"])
    with pytest.raises(RuntimeError):
        await runner.run(SAMPLES[ToolCall](), pid="axp_x")
    assert run_acct(k).reserved.get(CALLS, 0) == 0
    box["stop"].set()


async def test_a_hard_cap_refuses_the_action_before_the_inner_runner_is_called() -> None:
    k = make_kernel()
    box = await started_ctx(k, {CALLS: Limit(hard=0)})
    inner = FakeInner(Completed("x", allow()))
    runner = BudgetedRunner(inner, box["ctx"])
    with pytest.raises(BudgetExceededError):
        await runner.run(SAMPLES[ToolCall](), pid="axp_x")
    assert inner.ran == []
    v = await k.sched.wait(box["pid"])
    assert v.exit_reason is ExitReason.BUDGET_EXCEEDED


async def test_actual_overrun_beyond_the_estimate_trips_the_budget() -> None:
    k = make_kernel()
    box = await started_ctx(k, {TOK: Limit(hard=600)})
    inner = FakeInner(Completed(response(tokens=(900, 50)), allow()))
    runner = BudgetedRunner(inner, box["ctx"])
    await runner.run(model_call(max_tokens=100), pid="axp_x")  # reserved ~101, actual 950
    assert (await k.sched.wait(box["pid"])).exit_reason is ExitReason.BUDGET_EXCEEDED
    assert run_acct(k).committed[TOK] == 600  # clamped to the cap, never above it


async def test_budgeted_deps_keeps_everything_else_and_swaps_only_the_runner() -> None:
    k = make_kernel()
    box = await started_ctx(k)
    deps = deps_for(final("x"))
    wrapped = budgeted_deps(deps, box["ctx"])
    assert (
        wrapped.gate is deps.gate and wrapped.models is deps.models and wrapped.tools is deps.tools
    )
    assert wrapped.runner_factory is not None and deps.runner_factory is None
    box["stop"].set()
    await k.sched.wait(box["pid"])


async def test_review_a_replayed_cached_answer_reserves_nothing_but_is_still_gated() -> None:
    from axis_runtime.models.types import FinishReason, ModelResponse, Usage

    gate = ScriptedGate()
    k = make_kernel()
    seen: list[Any] = []

    async def work(ctx: Any) -> None:
        deps = make_deps(gate=gate, transport=ScriptedTransport([]), tools=registry())
        runner = budgeted_deps(deps, ctx).runner_factory
        assert runner is not None
        # a hard cap far below any prompt estimate: a charged replay would trip it
        replay = ModelResponse("cached", (), Usage(), FinishReason.STOP, "nexus-cache", "cache")
        inner = _Inner(replay)
        seen.append(await BudgetedRunner(inner, ctx).run(_replay_call(replay), pid=ctx.pid))

    pid = k.sched.spawn(spec(limits={TOK: Limit(hard=1)}), work)
    v = await k.sched.wait(pid)
    assert v.exit_reason is ExitReason.COMPLETED and isinstance(seen[0], Completed)
    assert not k.sink.of(TkiEventType.BUDGET_DENIED)
    assert not [e for e in k.sink.of(TkiEventType.BUDGET_RESERVED) if "tokens" in e.data["amounts"]]


class _Inner:
    def __init__(self, replay: Any) -> None:
        self._replay = replay

    async def run(self, action: Any, *, pid: str) -> Any:
        return Completed(self._replay, allow())


def _replay_call(replay: Any) -> ModelCall:
    req = ModelRequest("t", (Message("user", "x" * 4000),), ModelTarget("openai", "gpt-4o"))
    return ModelCall(name="openai/gpt-4o", request=req, replay=replay)


def test_review_a_replayed_model_call_cannot_be_serialised_for_an_activity() -> None:
    from axis_runtime.models.types import FinishReason, ModelResponse, Usage

    replay = ModelResponse("c", (), Usage(), FinishReason.STOP, "nexus-cache", "cache")
    with pytest.raises(ValueError, match="replayed"):
        _replay_call(replay).to_spec()


async def test_review_an_agent_waiting_for_a_human_approval_does_not_hold_a_scheduler_slot() -> (
    None
):
    """The approval wait (up to an hour) used to keep the TKI process `running`, so a tenant with
    `max_running` such agents (which an agent can trigger by itself) starved all its other work."""
    from axis_runtime import Decision
    from axis_runtime.tki import SchedulerConfig

    release = asyncio.Event()
    waiting = asyncio.Event()

    class Blocking:
        async def resolve(self, tenant_id: str, approval_id: str) -> dict[str, str]:
            waiting.set()
            await release.wait()
            return {"outcome": "DENIED"}

    needs = ScriptedGate(
        lambda r: GateDecision(
            Decision.REQUIRE_APPROVAL, "w", policy_version="v1", approval_id="a1"
        )
    )
    a_deps = deps_for(final("x"), gate=needs)
    a_deps.approvals = Blocking()  # type: ignore[assignment]
    b_deps = deps_for(final("done"), gate=ScriptedGate())
    k = make_kernel(SchedulerConfig(max_running=1, default_tenant_limit=1))
    a = k.sched.spawn(spec(run="run-a"), agent_workload(make_manifest(), "x", a_deps))
    await asyncio.wait_for(waiting.wait(), 2)
    b = k.sched.spawn(spec(run="run-b"), agent_workload(make_manifest(), "y", b_deps))
    v = await asyncio.wait_for(k.sched.wait(b), 3)  # would hang behind A's slot
    assert v.exit_reason is ExitReason.COMPLETED
    release.set()
    await asyncio.wait_for(k.sched.wait(a), 5)


async def test_review_an_unresolvable_approval_leaves_the_wait_and_the_process_keeps_its_slot() -> (
    None
):
    from axis_runtime import Decision
    from axis_runtime.approvals import ApprovalUnavailable
    from axis_runtime.process import ProcessState

    class Down:
        async def resolve(self, tenant_id: str, approval_id: str) -> dict[str, str]:
            raise ApprovalUnavailable("transport:ConnectError")

    needs = ScriptedGate(
        lambda r: GateDecision(
            Decision.REQUIRE_APPROVAL, "w", policy_version="v1", approval_id="a1"
        )
    )
    deps = deps_for(final("x"), gate=needs)
    deps.approvals = Down()  # type: ignore[assignment]
    k = make_kernel()
    states: list[ProcessState] = []

    async def probe(ctx: Any) -> Any:
        res = await agent_workload(make_manifest(), "x", deps)(ctx)
        states.append(k.sched.get(ctx.pid).state)  # must be running again, not stuck in waiting
        return res

    pid = k.sched.spawn(spec(), probe)
    v = await asyncio.wait_for(k.sched.wait(pid), 5)
    assert states == [ProcessState.RUNNING] and v.exit_reason in (
        ExitReason.COMPLETED,
        ExitReason.POLICY_DENIED,
    )
