"""TKI supervisor trees: strategies, restart policy/intensity, never-restart reasons, limits."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from axis_runtime.manifest import ProcessConfig, RuntimeManifest
from axis_runtime.process import ExitReason, ProcessState, Signal
from axis_runtime.tki import (
    ChildSpec,
    Limit,
    ProcessContext,
    Resource,
    RestartPolicy,
    Strategy,
    Supervisor,
    SupervisorConfig,
    TkiEventType,
    WorkloadResult,
)
from axis_runtime.tki.supervisor import (
    ChildLimitError,
    DuplicateChildError,
    limits_from_manifest,
    should_restart,
)
from conftest import make_manifest
from tki_helpers import Kernel, make_kernel, spec, until


class Counter:
    """A child workload factory: records starts, fails/exits per script, otherwise blocks."""

    def __init__(self, *script: ExitReason | None) -> None:
        self.script = list(script)
        self.starts = 0
        self.gate = asyncio.Event()

    async def __call__(self, ctx: ProcessContext) -> WorkloadResult | None:
        self.starts += 1
        step = self.script.pop(0) if self.script else None
        if step is None:
            await self.gate.wait()
            return None
        if step is ExitReason.FAILED:
            raise RuntimeError("child crash")
        return WorkloadResult(step, "scripted")


async def boot(k: Kernel, config: SupervisorConfig, **kw: Any) -> tuple[str, Supervisor]:
    gate = asyncio.Event()

    async def parent(_c: ProcessContext) -> None:
        await gate.wait()

    pid = k.sched.spawn(spec(), parent)
    k.gate = gate  # type: ignore[attr-defined]
    return pid, Supervisor(k.sched, pid, config, **kw)


def child(name: str, work: Any, **kw: Any) -> ChildSpec:
    return ChildSpec(name=name, agent=f"agent-{name}", workload=work, **kw)


CFG = SupervisorConfig(max_children=10)


# ---- restart eligibility -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("policy", "reason", "expected"),
    [
        (RestartPolicy.NEVER, ExitReason.FAILED, False),
        (RestartPolicy.ON_FAILURE, ExitReason.FAILED, True),
        (RestartPolicy.ON_FAILURE, ExitReason.TIMEOUT, True),
        (RestartPolicy.ON_FAILURE, ExitReason.COMPLETED, False),
        (RestartPolicy.ALWAYS, ExitReason.COMPLETED, True),
        (RestartPolicy.ALWAYS, ExitReason.FAILED, True),
        # never, whatever the policy: a restart must not defeat a cap, a denial or a kill
        (RestartPolicy.ALWAYS, ExitReason.BUDGET_EXCEEDED, False),
        (RestartPolicy.ALWAYS, ExitReason.POLICY_DENIED, False),
        (RestartPolicy.ALWAYS, ExitReason.KILLED, False),
        (RestartPolicy.ALWAYS, ExitReason.PARENT_TERMINATED, False),
        (RestartPolicy.ON_FAILURE, ExitReason.BUDGET_EXCEEDED, False),
        (RestartPolicy.ON_FAILURE, ExitReason.KILLED, False),
        (RestartPolicy.ON_FAILURE, ExitReason.POLICY_DENIED, False),
        (RestartPolicy.ON_FAILURE, ExitReason.PARENT_TERMINATED, False),
        (RestartPolicy.NEVER, ExitReason.TIMEOUT, False),
    ],
)
def test_restart_matrix(policy: RestartPolicy, reason: ExitReason, expected: bool) -> None:
    assert should_restart(policy, reason) is expected


def test_policy_parse_accepts_both_spellings() -> None:
    assert RestartPolicy.parse("on_failure") is RestartPolicy.ON_FAILURE
    assert RestartPolicy.parse("on-failure") is RestartPolicy.ON_FAILURE
    assert RestartPolicy.parse("always") is RestartPolicy.ALWAYS


def test_config_and_spec_from_manifest() -> None:
    cfg = SupervisorConfig.from_process_config(
        ProcessConfig(max_children=3, supervisor="rest-for-one"), window_seconds=None
    )
    assert cfg.strategy is Strategy.REST_FOR_ONE and cfg.max_children == 3
    assert cfg.window_seconds is None
    m = make_manifest()
    assert isinstance(m, RuntimeManifest)
    cs = ChildSpec.from_manifest("c", m, Counter())
    assert cs.agent == f"{m.name}@{m.version}" and cs.restart is RestartPolicy.NEVER
    assert isinstance(limits_from_manifest(m), dict)


def test_limits_from_manifest_converts_units() -> None:
    from axis_runtime.manifest import Budget, Budgets

    m = make_manifest()
    m = type(m)(
        **{
            **m.__dict__,
            "budgets": Budgets(
                tokens=Budget(100.0, 1000.0),
                cost_usd=Budget(None, 1.5),
                runtime_seconds=Budget(2.0, 30.0),
                tool_calls=Budget(),
            ),
        }
    )
    lim = limits_from_manifest(m)
    assert lim[Resource.TOKENS] == Limit(100, 1000)
    assert lim[Resource.COST_MICRO_USD] == Limit(None, 1_500_000)
    assert lim[Resource.RUNTIME_MS] == Limit(2000, 30_000)
    assert Resource.TOOL_CALLS not in lim


# ---- one-for-one ---------------------------------------------------------------------------------


async def test_one_for_one_restarts_only_the_failed_child_with_a_new_pid() -> None:
    k = make_kernel()
    parent, sup = await boot(k, CFG)
    flaky = Counter(ExitReason.FAILED, ExitReason.FAILED, None)
    steady = Counter()
    p_flaky = sup.start_child(
        child("flaky", flaky, restart=RestartPolicy.ON_FAILURE, max_restarts=5)
    )
    p_steady = sup.start_child(child("steady", steady))
    await until(lambda: flaky.starts == 3)
    await sup.settle()
    assert steady.starts == 1 and k.sched.get(p_steady).state is ProcessState.RUNNING
    now = sup.pid_of("flaky")
    assert now != p_flaky and k.sched.get(now).state is ProcessState.RUNNING
    assert k.sched.get(p_flaky).exit_reason is ExitReason.FAILED
    info = {c.name: c for c in sup.children()}
    assert info["flaky"].restarts == 2 and info["steady"].restarts == 0
    restarted = k.sink.of(TkiEventType.PROCESS_RESTARTED)
    assert [e.data["restart_count"] for e in restarted] == [1, 2]
    assert restarted[0].data["previous_pid"] == p_flaky and restarted[0].data["cause"] == "failed"
    assert k.sched.get(now).ppid == parent
    k.gate.set()  # type: ignore[attr-defined]
    await sup.shutdown()


async def test_restart_intensity_is_bounded_per_child() -> None:
    k = make_kernel()
    _, sup = await boot(k, CFG)
    always_fail = Counter(*[ExitReason.FAILED] * 10)
    sup.start_child(child("bad", always_fail, restart=RestartPolicy.ON_FAILURE, max_restarts=2))
    await until(lambda: always_fail.starts == 3)
    await sup.settle()
    assert always_fail.starts == 3  # first run + 2 restarts, then it stays down
    assert k.sched.get(sup.pid_of("bad")).exit_reason is ExitReason.FAILED
    esc = k.sink.of(TkiEventType.SUPERVISOR_ESCALATED)
    assert len(esc) == 1 and "intensity" in esc[0].data["reason"]
    await sup.shutdown()


async def test_intensity_window_slides() -> None:
    now = [0.0]
    k = make_kernel()
    cfg = SupervisorConfig(max_children=2, window_seconds=10.0)
    _, sup = await boot(k, cfg, monotonic=lambda: now[0])
    work = Counter(ExitReason.FAILED, None)  # fails once, then runs until told otherwise
    sup.start_child(child("w", work, restart=RestartPolicy.ON_FAILURE, max_restarts=1))
    await until(lambda: work.starts == 2)  # restart #1 at t=0
    await sup.settle()
    now[0] = 5.0  # still inside the window: a second failure would NOT be restarted
    now[0] = 100.0  # the t=0 restart has left the window: the budget is available again
    k.sched.terminate(sup.pid_of("w"), ExitReason.FAILED, "second failure")
    await until(lambda: work.starts == 3)
    await sup.settle()
    assert not k.sink.of(TkiEventType.SUPERVISOR_ESCALATED)
    await sup.shutdown()


async def test_failure_inside_the_window_is_not_restarted_beyond_the_budget() -> None:
    now = [0.0]
    k = make_kernel()
    _, sup = await boot(
        k, SupervisorConfig(max_children=2, window_seconds=10.0), monotonic=lambda: now[0]
    )
    work = Counter(ExitReason.FAILED, None)
    sup.start_child(child("w", work, restart=RestartPolicy.ON_FAILURE, max_restarts=1))
    await until(lambda: work.starts == 2)
    await sup.settle()
    now[0] = 5.0
    pid = sup.pid_of("w")
    k.sched.terminate(pid, ExitReason.FAILED, "second failure")
    await k.sched.wait(pid)
    await sup.settle()
    assert work.starts == 2 and k.sink.of(TkiEventType.SUPERVISOR_ESCALATED)
    await sup.shutdown()


async def test_unbounded_window_counts_lifetime_restarts() -> None:
    k = make_kernel()
    _, sup = await boot(k, SupervisorConfig(max_children=1, window_seconds=None))
    work = Counter(*[ExitReason.FAILED] * 5)
    sup.start_child(child("w", work, restart=RestartPolicy.ALWAYS, max_restarts=1))
    await until(lambda: work.starts == 2)
    await sup.settle()
    assert work.starts == 2
    await sup.shutdown()


@pytest.mark.parametrize(
    "reason",
    [ExitReason.BUDGET_EXCEEDED, ExitReason.POLICY_DENIED, ExitReason.KILLED],
)
async def test_children_that_hit_a_cap_denial_or_kill_are_never_restarted(
    reason: ExitReason,
) -> None:
    k = make_kernel()
    _, sup = await boot(k, CFG)
    work = Counter(reason)
    pid = sup.start_child(child("c", work, restart=RestartPolicy.ALWAYS, max_restarts=50))
    await k.sched.wait(pid)
    await sup.settle()
    await asyncio.sleep(0.02)
    assert work.starts == 1 and sup.pid_of("c") == pid
    assert not k.sink.of(TkiEventType.PROCESS_RESTARTED)
    await sup.shutdown()


async def test_a_kill_switch_signal_is_not_undone_by_always_restart() -> None:
    k = make_kernel()
    _, sup = await boot(k, CFG)
    work = Counter()
    pid = sup.start_child(child("c", work, restart=RestartPolicy.ALWAYS, max_restarts=50))
    await until(lambda: work.starts == 1)
    k.sched.signal(pid, Signal.KILL)
    await k.sched.wait(pid)
    await sup.settle()
    assert work.starts == 1 and k.sched.get(pid).exit_reason is ExitReason.KILLED
    await sup.shutdown()


async def test_completed_child_restarts_only_under_always() -> None:
    k = make_kernel()
    _, sup = await boot(k, CFG)
    once = Counter(ExitReason.COMPLETED)
    again = Counter(ExitReason.COMPLETED, None)
    sup.start_child(child("once", once, restart=RestartPolicy.ON_FAILURE, max_restarts=3))
    sup.start_child(child("again", again, restart=RestartPolicy.ALWAYS, max_restarts=3))
    await until(lambda: again.starts == 2)
    await sup.settle()
    assert once.starts == 1
    await sup.shutdown()


async def test_restarted_child_keeps_counting_against_the_parent_budget() -> None:
    k = make_kernel()
    gate = asyncio.Event()

    async def parent(_c: ProcessContext) -> None:
        await gate.wait()

    pid = k.sched.spawn(spec(limits={Resource.TOKENS: Limit(hard=100)}), parent)
    sup = Supervisor(k.sched, pid, CFG)
    runs = {"n": 0}

    async def spender(ctx: ProcessContext) -> None:
        runs["n"] += 1
        ctx.commit(ctx.reserve({Resource.TOKENS: 40}))
        raise RuntimeError("crash after spending")

    sup.start_child(child("s", spender, restart=RestartPolicy.ALWAYS, max_restarts=10))
    await until(lambda: runs["n"] >= 3)
    await sup.settle()
    # 40 + 40 spent, the third attempt needs 40 more > 100 cap: it dies with budget_exceeded
    # and, being a budget exit, is not restarted again.
    final = k.sched.get(sup.pid_of("s"))
    assert runs["n"] == 3 and final.exit_reason is ExitReason.BUDGET_EXCEEDED
    gate.set()
    await sup.shutdown()


# ---- one-for-all / rest-for-one ------------------------------------------------------------------


async def three(k: Kernel, strategy: Strategy) -> tuple[Supervisor, list[Counter]]:
    _, sup = await boot(k, SupervisorConfig(strategy=strategy, max_children=5))
    work = [Counter(ExitReason.FAILED, None) if i == 1 else Counter() for i in range(3)]
    # child 1 fails right away on its first start; the others run until bounced
    for i, w in enumerate(work):
        sup.start_child(child(f"c{i}", w, restart=RestartPolicy.ON_FAILURE, max_restarts=3))
    return sup, work


async def test_one_for_all_bounces_every_sibling_and_restarts_in_start_order() -> None:
    k = make_kernel()
    sup, work = await three(k, Strategy.ONE_FOR_ALL)
    await until(lambda: all(w.starts == 2 for w in work))
    await sup.settle()
    assert [w.starts for w in work] == [2, 2, 2]
    assert all(c.state is ProcessState.RUNNING for c in sup.children())
    bounced = [
        e
        for e in k.sink.of(TkiEventType.PROCESS_TRANSITION)
        if e.data.get("detail") == "supervisor one-for-all"
    ]
    assert len(bounced) == 2 and all(e.data["exit_reason"] == "killed" for e in bounced)
    order = [e.data["child"] for e in k.sink.of(TkiEventType.PROCESS_RESTARTED)]
    assert order == ["c0", "c1", "c2"]
    await sup.shutdown()


async def test_rest_for_one_restarts_the_failed_child_and_those_started_after_it() -> None:
    k = make_kernel()
    sup, work = await three(k, Strategy.REST_FOR_ONE)
    await until(lambda: work[1].starts == 2 and work[2].starts == 2)
    await sup.settle()
    assert [w.starts for w in work] == [1, 2, 2]  # c0 (started before) untouched
    assert [e.data["child"] for e in k.sink.of(TkiEventType.PROCESS_RESTARTED)] == ["c1", "c2"]
    await sup.shutdown()


async def test_one_for_one_leaves_siblings_alone() -> None:
    k = make_kernel()
    sup, work = await three(k, Strategy.ONE_FOR_ONE)
    await until(lambda: work[1].starts == 2)
    await sup.settle()
    assert [w.starts for w in work] == [1, 2, 1]
    await sup.shutdown()


async def test_group_restart_skips_siblings_that_already_terminated() -> None:
    k = make_kernel()
    _, sup = await boot(k, SupervisorConfig(strategy=Strategy.ONE_FOR_ALL, max_children=5))
    done = Counter(ExitReason.COMPLETED)
    fail = Counter(ExitReason.FAILED, None)
    sup.start_child(child("done", done))
    pid = sup.start_child(child("fail", fail, restart=RestartPolicy.ON_FAILURE, max_restarts=2))
    await k.sched.wait(pid)
    await until(lambda: fail.starts == 2)
    await sup.settle()
    assert done.starts == 1  # already finished: not resurrected
    await sup.shutdown()


async def test_supervisor_wide_intensity_gives_up_and_stops_everything() -> None:
    k = make_kernel()
    cfg = SupervisorConfig(max_children=5, max_total_restarts=2, strategy=Strategy.ONE_FOR_ONE)
    _, sup = await boot(k, cfg)
    a = Counter(*[ExitReason.FAILED] * 10)
    b = Counter()
    sup.start_child(child("a", a, restart=RestartPolicy.ALWAYS, max_restarts=100))
    pb = sup.start_child(child("b", b))
    await k.sched.wait(pb)  # killed by "supervisor gave up"
    await sup.settle()
    assert a.starts == 3 and k.sched.get(pb).exit_reason is ExitReason.KILLED
    assert all(c.state is ProcessState.TERMINATED for c in sup.children())
    esc = k.sink.of(TkiEventType.SUPERVISOR_ESCALATED)
    assert any("supervisor restart intensity" in e.data["reason"] for e in esc)
    with pytest.raises(Exception, match="stopped"):
        sup.start_child(child("late", Counter()))


# ---- limits, lifecycle ---------------------------------------------------------------------------


async def test_max_children_bounds_live_children_not_lifetime_starts() -> None:
    k = make_kernel()
    _, sup = await boot(k, SupervisorConfig(max_children=1))
    first = Counter()
    pid = sup.start_child(child("one", first))
    with pytest.raises(ChildLimitError):
        sup.start_child(child("two", Counter()))
    with pytest.raises(DuplicateChildError):
        sup.start_child(child("one", Counter()))
    first.gate.set()
    await k.sched.wait(pid)
    sup.start_child(child("three", Counter()))  # slot freed by the exited child
    await sup.shutdown()


async def test_max_children_zero_forbids_spawning() -> None:
    k = make_kernel()
    _, sup = await boot(k, SupervisorConfig(max_children=0))
    with pytest.raises(ChildLimitError):
        sup.start_child(child("x", Counter()))
    with pytest.raises(KeyError):
        sup.pid_of("x")
    await sup.shutdown()


async def test_parent_termination_kills_supervised_children_without_restart() -> None:
    k = make_kernel()
    parent, sup = await boot(k, CFG)
    work = Counter()
    pid = sup.start_child(child("c", work, restart=RestartPolicy.ALWAYS, max_restarts=9))
    await until(lambda: work.starts == 1)
    k.sched.signal(parent, Signal.KILL)
    v = await k.sched.wait(pid)
    await sup.settle()
    assert v.exit_reason is ExitReason.PARENT_TERMINATED and work.starts == 1


async def test_restart_refused_when_parent_is_going_away() -> None:
    k = make_kernel()
    parent, sup = await boot(k, CFG)
    go = asyncio.Event()
    starts = {"n": 0}

    async def fail_on_cue(_c: ProcessContext) -> None:
        starts["n"] += 1
        await go.wait()
        raise RuntimeError("late crash")

    sup.start_child(child("c", fail_on_cue, restart=RestartPolicy.ON_FAILURE, max_restarts=5))
    await until(lambda: starts["n"] == 1)
    # the parent is mid-termination when the child fails: the restart must be refused
    k.sched._procs[parent].finishing = True  # noqa: SLF001
    go.set()
    await until(lambda: k.sink.of(TkiEventType.SUPERVISOR_ESCALATED) != [])
    await sup.settle()
    assert starts["n"] == 1
    esc = k.sink.of(TkiEventType.SUPERVISOR_ESCALATED)
    assert "restart refused" in esc[0].data["reason"]
    k.sched._procs[parent].finishing = False  # noqa: SLF001
    await sup.shutdown()


async def test_children_inherit_tenant_and_run_and_unknown_parent_is_rejected() -> None:
    k = make_kernel()
    parent, sup = await boot(k, CFG)
    pid = sup.start_child(child("c", Counter()))
    v = k.sched.get(pid)
    assert v.tenant_id == k.sched.get(parent).tenant_id and v.run_id == k.sched.get(parent).run_id
    with pytest.raises(Exception):  # noqa: B017
        Supervisor(k.sched, "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV", CFG)
    await sup.shutdown()


# ---- review: a restart must not reset the child's budget ----------------------------------------------


async def test_review_restarts_share_one_budget_so_the_child_cap_is_never_exceeded_in_total() -> (
    None
):
    """A child with tokens hard=100 that crashes after spending 60 used to get a FRESH 100 on every
    restart (new process account), i.e. 60 x (1 + max_restarts) tokens against a cap of 100."""
    k = make_kernel()
    _pid, sup = await boot(k, CFG)
    attempts: list[str] = []

    async def spender(ctx: ProcessContext) -> WorkloadResult | None:
        attempts.append(ctx.pid)
        res = ctx.reserve({Resource.TOKENS: 60})  # BudgetExceededError ends the attempt
        ctx.commit(res)
        raise RuntimeError("crash after spending")

    sup.start_child(
        child(
            "c",
            spender,
            restart=RestartPolicy.ON_FAILURE,
            max_restarts=5,
            limits={Resource.TOKENS: Limit(hard=100)},
        )
    )
    await until(lambda: len(attempts) >= 2)
    await asyncio.sleep(0.2)  # let every restart the policy allows play out
    await sup.settle()
    total = sum(
        e.data["granted"].get("tokens", 0) for e in k.sink.of(TkiEventType.BUDGET_COMMITTED)
    )
    assert total <= 100, f"child cap 100 exceeded across restarts: {total}"
    assert len(attempts) == 2  # 60 fits; the restart is left with 40 and is refused
    assert sup.children()[0].exit_reason is ExitReason.BUDGET_EXCEEDED
    k.gate.set()  # type: ignore[attr-defined]


def test_review_remaining_limits_never_go_negative_and_do_not_rearm_a_crossed_soft_cap() -> None:
    from axis_runtime.tki.supervisor import remaining_limits

    lim = {
        Resource.TOKENS: Limit(soft=50, hard=100),
        Resource.TOOL_CALLS: Limit(soft=2, hard=3),
        Resource.RUNTIME_MS: Limit(),
    }
    out = remaining_limits(lim, {Resource.TOKENS: 60, Resource.TOOL_CALLS: 5})
    assert out[Resource.TOKENS] == Limit(soft=None, hard=40)  # soft was crossed: not re-armed
    assert out[Resource.TOOL_CALLS] == Limit(soft=None, hard=0)  # overspent: refuse everything
    assert out[Resource.RUNTIME_MS] == Limit()
    assert remaining_limits(lim, {Resource.TOKENS: 10})[Resource.TOKENS] == Limit(40, 90)
