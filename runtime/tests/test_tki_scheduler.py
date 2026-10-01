"""TKI scheduler: lifecycle, priority/fairness/limits, cancellation, cascade, budgets, IPC."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from axis_runtime.process import ExitReason, ProcessState, Signal
from axis_runtime.tki import (
    Limit,
    Priority,
    ProcessCancelled,
    ProcessContext,
    Resource,
    SchedulerConfig,
    TkiEventType,
    WorkloadResult,
)
from axis_runtime.tki.budget import BudgetExceededError
from axis_runtime.tki.ipc import IpcDeniedError, Kind
from axis_runtime.tki.scheduler import SchedulerError, SpawnError
from tki_helpers import T1, T2, Kernel, lifecycle, make_kernel, spec, until

TOK = Resource.TOKENS


async def quick(_ctx: ProcessContext) -> None:
    return None


def blocker(release: asyncio.Event) -> Any:
    async def run(ctx: ProcessContext) -> None:
        await ctx.checkpoint()
        await release.wait()

    return run


async def finish_all(k: Kernel) -> None:
    await k.sched.shutdown()


# ---- lifecycle -----------------------------------------------------------------------------------


async def test_process_runs_through_the_frozen_state_machine() -> None:
    k = make_kernel()
    pid = k.sched.spawn(spec(), quick)
    view = await k.sched.wait(pid)
    assert view.state is ProcessState.TERMINATED and view.exit_reason is ExitReason.COMPLETED
    assert lifecycle(k, pid) == [
        ("init_complete", "ready"),
        ("scheduled", "running"),
        ("exit", "terminated"),
    ]
    assert k.sched.running_count == 0 and k.sched.tenant_running(T1) == 0
    spawned = k.sink.of(TkiEventType.PROCESS_SPAWNED)[0]
    assert spawned.pid == pid and spawned.data["agent"] == "agent-a"


async def test_workload_result_and_exceptions_map_to_exit_reasons() -> None:
    k = make_kernel()

    async def denied(_c: ProcessContext) -> WorkloadResult:
        return WorkloadResult(ExitReason.POLICY_DENIED, "no")

    async def boom(_c: ProcessContext) -> None:
        raise ValueError("kaput")

    async def budget(_c: ProcessContext) -> None:
        raise BudgetExceededError(
            __import__("axis_runtime.tki.budget", fromlist=["x"]).AccountKey(
                T1, __import__("axis_runtime.tki.budget", fromlist=["x"]).ScopeKind.TENANT, "t"
            ),
            TOK,
            1,
            0,
        )

    a = k.sched.spawn(spec(), denied)
    b = k.sched.spawn(spec(), boom)
    c = k.sched.spawn(spec(), budget)
    views = [await k.sched.wait(p) for p in (a, b, c)]
    assert [v.exit_reason for v in views] == [
        ExitReason.POLICY_DENIED,
        ExitReason.FAILED,
        ExitReason.BUDGET_EXCEEDED,
    ]
    assert "ValueError: kaput" in views[1].detail


async def test_spawn_validation_and_listing() -> None:
    k = make_kernel()
    for bad in (
        spec(priority=-1),
        spec(tenant=""),
        spec(agent=""),
        spec(run=""),
        spec(ppid="axp_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
    ):
        with pytest.raises(SpawnError):
            k.sched.spawn(bad, quick)
    pid = k.sched.spawn(spec(), quick)
    await k.sched.wait(pid)
    assert [v.pid for v in k.sched.processes()] == [pid]
    assert k.sched.processes(T2) == []
    with pytest.raises(SchedulerError):
        k.sched.get("axp_01ARZ3NDEKTSV4RRFFQ69G5FAV")


def test_config_validation() -> None:
    for kw in ({"max_running": 0}, {"default_tenant_limit": 0}, {"aging_interval": 0},
               {"tenant_limits": {"t": 0}}):  # fmt: skip
        with pytest.raises(ValueError):
            SchedulerConfig(**kw)
    assert SchedulerConfig(tenant_limits={"a": 7}).limit_for("a") == 7


async def test_audit_failure_at_spawn_means_the_process_never_existed() -> None:
    k = make_kernel()
    real = k.sink.emit

    def emit(e: Any) -> None:
        if e.type is TkiEventType.PROCESS_SPAWNED:
            raise RuntimeError("audit down")
        real(e)

    k.sink.emit = emit  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        k.sched.spawn(spec(), quick)
    assert k.sched.processes() == [] and k.router.mailbox is not None
    assert k.sched.running_count == 0 and not k.sched.queued()


async def test_a_reused_pid_is_refused_without_touching_the_existing_process() -> None:
    k = make_kernel()
    gate = asyncio.Event()
    pid = k.sched.spawn(spec(), blocker(gate))
    k.sched._pid_factory = lambda: pid  # type: ignore[method-assign]  # noqa: SLF001
    with pytest.raises(SpawnError, match="duplicate pid"):
        k.sched.spawn(spec(), quick)
    assert k.sched.get(pid).state is ProcessState.RUNNING
    gate.set()
    await k.sched.wait(pid)
    with pytest.raises(SpawnError):  # still refused after exit: PIDs are never reused
        k.sched.spawn(spec(), quick)


# ---- priority, fairness, limits ------------------------------------------------------------------


async def test_priority_orders_the_ready_queue() -> None:
    k = make_kernel(SchedulerConfig(max_running=1))
    order: list[str] = []
    gate = asyncio.Event()

    def tag(name: str) -> Any:
        async def run(_c: ProcessContext) -> None:
            order.append(name)

        return run

    first = k.sched.spawn(spec(run="r0"), blocker(gate))
    k.sched.spawn(spec(priority=Priority.LOW), tag("low"))
    k.sched.spawn(spec(priority=Priority.NORMAL), tag("normal"))
    k.sched.spawn(spec(priority=Priority.HIGH), tag("high"))
    assert k.sched.get(first).state is ProcessState.RUNNING and len(k.sched.queued()) == 3
    gate.set()
    await until(lambda: len(order) == 3)
    assert order == ["high", "normal", "low"]


async def test_tenants_are_served_round_robin_not_by_flooding() -> None:
    k = make_kernel(SchedulerConfig(max_running=1, default_tenant_limit=1, aging_interval=10_000))
    order: list[str] = []
    gate = asyncio.Event()

    def tag(name: str) -> Any:
        async def run(_c: ProcessContext) -> None:
            order.append(name)

        return run

    k.sched.spawn(spec(T1, run="r0"), blocker(gate))
    for i in range(4):
        k.sched.spawn(spec(T1), tag(f"a{i}"))
    k.sched.spawn(spec(T2, agent="b"), tag("b0"))
    gate.set()
    await until(lambda: len(order) == 5)
    # b0 was queued last but tenant 2 had never been served: it jumps ahead of the whole flood.
    assert order == ["b0", "a0", "a1", "a2", "a3"]


async def test_aging_prevents_starvation_of_low_priority_work() -> None:
    k = make_kernel(SchedulerConfig(max_running=1, default_tenant_limit=1, aging_interval=2))
    order: list[str] = []
    gate = asyncio.Event()

    def tag(name: str) -> Any:
        async def run(_c: ProcessContext) -> None:
            order.append(name)
            await asyncio.sleep(0)

        return run

    k.sched.spawn(spec(run="r0"), blocker(gate))
    k.sched.spawn(spec(priority=Priority.LOW), tag("low"))
    for i in range(8):
        k.sched.spawn(spec(priority=Priority.HIGH), tag(f"h{i}"))
    gate.set()
    await until(lambda: len(order) == 9)
    assert order.index("low") < 8  # without aging it would be last (index 8)


async def test_tenant_concurrency_limit_is_enforced_while_other_tenants_proceed() -> None:
    k = make_kernel(SchedulerConfig(max_running=4, default_tenant_limit=1, tenant_limits={T2: 2}))
    gate = asyncio.Event()
    a1 = k.sched.spawn(spec(T1, run="r1"), blocker(gate))
    a2 = k.sched.spawn(spec(T1, run="r2"), blocker(gate))
    b1 = k.sched.spawn(spec(T2, run="r3", agent="b"), blocker(gate))
    b2 = k.sched.spawn(spec(T2, run="r4", agent="b"), blocker(gate))
    b3 = k.sched.spawn(spec(T2, run="r5", agent="b"), blocker(gate))
    await asyncio.sleep(0.01)
    assert k.sched.get(a1).state is ProcessState.RUNNING
    assert k.sched.get(a2).state is ProcessState.READY  # free slots exist, tenant limit blocks it
    assert k.sched.tenant_running(T1) == 1 and k.sched.tenant_running(T2) == 2
    assert [k.sched.get(p).state for p in (b1, b2, b3)] == [
        ProcessState.RUNNING,
        ProcessState.RUNNING,
        ProcessState.READY,
    ]
    gate.set()
    await asyncio.gather(*(k.sched.wait(p) for p in (a1, a2, b1, b2, b3)))
    assert k.sched.running_count == 0


async def test_running_never_exceeds_limits_under_churn() -> None:
    k = make_kernel(SchedulerConfig(max_running=3, default_tenant_limit=2))
    peak = {"all": 0, "t1": 0}

    async def work(ctx: ProcessContext) -> None:
        for _ in range(3):
            peak["all"] = max(peak["all"], k.sched.running_count)
            peak["t1"] = max(peak["t1"], k.sched.tenant_running(T1))
            await ctx.yield_()

    pids = [k.sched.spawn(spec(T1 if i % 2 else T2, run=f"r{i}"), work) for i in range(12)]
    await asyncio.gather(*(k.sched.wait(p) for p in pids))
    assert peak["all"] <= 3 and peak["t1"] <= 2
    assert all(k.sched.get(p).exit_reason is ExitReason.COMPLETED for p in pids)


async def test_yield_requeues_behind_better_ranked_work() -> None:
    k = make_kernel(SchedulerConfig(max_running=1, default_tenant_limit=1))
    order: list[str] = []

    def loop(name: str) -> Any:
        async def run(ctx: ProcessContext) -> None:
            for i in range(2):
                order.append(f"{name}{i}")
                await ctx.yield_()

        return run

    a = k.sched.spawn(spec(run="r1"), loop("a"))
    b = k.sched.spawn(spec(run="r2"), loop("b"))
    await asyncio.gather(k.sched.wait(a), k.sched.wait(b))
    assert order == ["a0", "b0", "a1", "b1"]
    assert ("yield", "ready") in lifecycle(k, a)


async def test_waiting_releases_the_slot() -> None:
    k = make_kernel(SchedulerConfig(max_running=1, default_tenant_limit=1))
    io = asyncio.Event()
    ran = asyncio.Event()

    async def waiter(ctx: ProcessContext) -> None:
        async with ctx.waiting():
            await io.wait()

    async def other(_c: ProcessContext) -> None:
        ran.set()

    w = k.sched.spawn(spec(run="r1"), waiter)
    o = k.sched.spawn(spec(run="r2"), other)
    await asyncio.wait_for(ran.wait(), 2)  # other ran while waiter was waiting
    assert k.sched.get(w).state is ProcessState.WAITING
    io.set()
    await asyncio.gather(k.sched.wait(w), k.sched.wait(o))
    assert [t for t, _ in lifecycle(k, w)] == [
        "init_complete", "scheduled", "await", "wake", "exit",
    ]  # fmt: skip


async def test_exception_inside_waiting_block_terminates_from_waiting() -> None:
    k = make_kernel()

    async def bad(ctx: ProcessContext) -> None:
        async with ctx.waiting():
            raise RuntimeError("io failed")

    pid = k.sched.spawn(spec(), bad)
    v = await k.sched.wait(pid)
    assert v.exit_reason is ExitReason.FAILED
    assert lifecycle(k, pid)[-1] == ("KILL", "terminated")


# ---- cancellation and signals --------------------------------------------------------------------


async def test_term_is_cooperative_and_exits_via_the_term_transition() -> None:
    k = make_kernel(SchedulerConfig(term_grace_seconds=5))
    saw: list[str] = []

    began = asyncio.Event()

    async def polite(ctx: ProcessContext) -> None:
        began.set()
        try:
            while True:
                await ctx.checkpoint()
                await asyncio.sleep(0.001)
        except ProcessCancelled:
            saw.append("cleanup")
            raise

    pid = k.sched.spawn(spec(), polite)
    await asyncio.wait_for(began.wait(), 2)
    k.sched.signal(pid, Signal.TERM)
    k.sched.signal(pid, Signal.TERM)  # idempotent
    v = await k.sched.wait(pid)
    assert v.exit_reason is ExitReason.KILLED and saw == ["cleanup"]
    assert lifecycle(k, pid)[-1] == ("TERM", "terminated")
    sigs = [e.data["signal"] for e in k.sink.of(TkiEventType.SIGNAL_DELIVERED)]
    assert sigs.count("TERM") == 2 and "KILL" not in sigs


async def test_term_escalates_to_kill_when_the_workload_ignores_it() -> None:
    k = make_kernel(SchedulerConfig(term_grace_seconds=0.02))

    began = asyncio.Event()

    async def stubborn(_c: ProcessContext) -> None:
        began.set()
        await asyncio.sleep(60)

    pid = k.sched.spawn(spec(), stubborn)
    await asyncio.wait_for(began.wait(), 2)
    k.sched.signal(pid, Signal.TERM)
    v = await k.sched.wait(pid)
    assert v.exit_reason is ExitReason.KILLED
    assert any(e.data.get("escalated") for e in k.sink.of(TkiEventType.SIGNAL_DELIVERED))


async def test_kill_is_immediate_from_every_non_terminal_state() -> None:
    k = make_kernel(SchedulerConfig(max_running=1, default_tenant_limit=1))
    gate = asyncio.Event()
    running = k.sched.spawn(spec(run="r1"), blocker(gate))
    ready = k.sched.spawn(spec(run="r2"), quick)
    suspended = k.sched.spawn(spec(run="r3"), quick)
    k.sched.signal(suspended, Signal.PAUSE)
    assert k.sched.get(suspended).state is ProcessState.SUSPENDED
    for pid in (running, ready, suspended):
        k.sched.signal(pid, Signal.KILL)
    views = [await k.sched.wait(p) for p in (running, ready, suspended)]
    assert all(v.exit_reason is ExitReason.KILLED for v in views)
    k.sched.signal(running, Signal.KILL)  # terminal: no-op
    assert k.sched.running_count == 0 and not k.sched.queued()


async def test_term_on_queued_and_suspended_processes_is_immediate() -> None:
    k = make_kernel(SchedulerConfig(max_running=1, default_tenant_limit=1))
    gate = asyncio.Event()
    k.sched.spawn(spec(run="r1"), blocker(gate))
    queued = k.sched.spawn(spec(run="r2"), quick)
    paused = k.sched.spawn(spec(run="r3"), quick)
    k.sched.signal(paused, Signal.PAUSE)
    for pid in (queued, paused):
        k.sched.signal(pid, Signal.TERM)
    assert [(await k.sched.wait(p)).exit_reason for p in (queued, paused)] == [
        ExitReason.KILLED
    ] * 2
    assert lifecycle(k, queued)[-1] == ("TERM", "terminated")
    gate.set()


async def test_term_after_kill_decision_is_ignored_and_terminate_api() -> None:
    k = make_kernel()
    gate = asyncio.Event()
    pid = k.sched.spawn(spec(), blocker(gate))
    await until(lambda: k.sched.get(pid).state is ProcessState.RUNNING)
    k.sched.terminate(pid, ExitReason.POLICY_DENIED, "kill switch")
    k.sched.signal(pid, Signal.TERM)
    v = await k.sched.wait(pid)
    assert v.exit_reason is ExitReason.POLICY_DENIED and v.detail == "kill switch"
    k.sched.terminate(pid, ExitReason.KILLED)  # already terminal: no-op


async def test_pause_resume_at_checkpoint_and_while_queued() -> None:
    k = make_kernel(SchedulerConfig(max_running=1, default_tenant_limit=1))
    progress: list[int] = []

    async def stepper(ctx: ProcessContext) -> None:
        for i in range(3):
            await ctx.checkpoint()
            progress.append(i)
            await asyncio.sleep(0.005)

    pid = k.sched.spawn(spec(), stepper)
    await until(lambda: len(progress) >= 1)
    k.sched.signal(pid, Signal.PAUSE)
    await until(lambda: k.sched.get(pid).state is ProcessState.SUSPENDED)
    frozen = len(progress)
    await asyncio.sleep(0.03)
    assert len(progress) == frozen and k.sched.running_count == 0
    k.sched.signal(pid, Signal.RESUME)
    v = await k.sched.wait(pid)
    assert v.exit_reason is ExitReason.COMPLETED and progress == [0, 1, 2]
    tr = [t for t, _ in lifecycle(k, pid)]
    assert tr[:3] == ["init_complete", "scheduled", "PAUSE"] and "RESUME" in tr

    gate = asyncio.Event()
    k.sched.spawn(spec(run="r1"), blocker(gate))
    queued = k.sched.spawn(spec(run="r2"), quick)
    k.sched.signal(queued, Signal.PAUSE)
    assert k.sched.get(queued).state is ProcessState.SUSPENDED and not k.sched.queued()
    gate.set()
    await asyncio.sleep(0.02)
    assert k.sched.get(queued).state is ProcessState.SUSPENDED
    k.sched.signal(queued, Signal.RESUME)
    assert (await k.sched.wait(queued)).exit_reason is ExitReason.COMPLETED


async def test_resume_before_the_pause_is_honoured_cancels_it_and_pause_of_waiting() -> None:
    k = make_kernel()
    io = asyncio.Event()
    hits: list[str] = []

    async def w(ctx: ProcessContext) -> None:
        async with ctx.waiting():
            await io.wait()
        await ctx.checkpoint()  # honours the pause requested while waiting
        hits.append("after")

    pid = k.sched.spawn(spec(), w)
    await until(lambda: k.sched.get(pid).state is ProcessState.WAITING)
    k.sched.signal(pid, Signal.PAUSE)
    io.set()
    await until(lambda: k.sched.get(pid).state is ProcessState.SUSPENDED)
    k.sched.signal(pid, Signal.RESUME)
    await k.sched.wait(pid)
    assert hits == ["after"]
    k.sched.signal(pid, Signal.PAUSE)  # terminal: ignored


async def test_interrupt_delivers_a_message_without_state_change() -> None:
    k = make_kernel()
    gate = asyncio.Event()
    got: list[list[str]] = []

    async def w(ctx: ProcessContext) -> None:
        await gate.wait()
        got.append(ctx.take_interrupts())
        got.append(ctx.take_interrupts())

    pid = k.sched.spawn(spec(), w)
    await until(lambda: k.sched.get(pid).state is ProcessState.RUNNING)
    k.sched.signal(pid, Signal.INTERRUPT, "human takeover")
    assert k.sched.get(pid).state is ProcessState.RUNNING
    gate.set()
    await k.sched.wait(pid)
    assert got == [["human takeover"], []]


async def test_shutdown_kills_everything() -> None:
    k = make_kernel()
    gate = asyncio.Event()
    parent = k.sched.spawn(spec(), blocker(gate))
    child = k.sched.spawn(spec(ppid=parent), blocker(gate))
    await k.sched.shutdown()
    assert k.sched.get(parent).exit_reason is ExitReason.KILLED
    assert k.sched.get(child).exit_reason is ExitReason.PARENT_TERMINATED


# ---- trees ---------------------------------------------------------------------------------------


async def test_parent_termination_cascades_term_then_kill_to_all_descendants() -> None:
    k = make_kernel()
    gate = asyncio.Event()
    parent = k.sched.spawn(spec(), blocker(gate))
    c1 = k.sched.spawn(spec(ppid=parent), blocker(gate))
    c2 = k.sched.spawn(spec(ppid=parent), blocker(gate))
    gc = k.sched.spawn(spec(ppid=c1), blocker(gate))
    await until(lambda: all(s is ProcessState.RUNNING for s in
                            [k.sched.get(p).state for p in (parent, c1, c2, gc)]))  # fmt: skip
    assert [v.pid for v in k.sched.children_of(parent)] == [c1, c2]
    k.sched.signal(parent, Signal.KILL)
    for p in (c1, c2, gc):
        v = await k.sched.wait(p)
        assert v.exit_reason is ExitReason.PARENT_TERMINATED
    assert (await k.sched.wait(parent)).exit_reason is ExitReason.KILLED
    seq = [
        (e.pid, e.data.get("signal") or e.data.get("to"))
        for e in k.sink.events
        if e.type in (TkiEventType.SIGNAL_DELIVERED, TkiEventType.PROCESS_TRANSITION)
        and e.pid in (parent, c1)
        and (e.data.get("signal") in ("TERM", "KILL") or e.data.get("to") == "terminated")
    ]
    assert seq.index((c1, "TERM")) < seq.index((c1, "KILL")) < seq.index((c1, "terminated"))
    assert seq.index((c1, "terminated")) < seq.index((parent, "terminated"))  # children first
    for p in (parent, c1, c2, gc):
        lifecycle(k, p)  # legal chains
    assert k.sched.running_count == 0


async def test_natural_parent_exit_also_terminates_live_children() -> None:
    k = make_kernel()
    gate = asyncio.Event()
    child_ids: list[str] = []

    async def parent_work(ctx: ProcessContext) -> None:
        child_ids.append(k.sched.spawn(spec(ppid=ctx.pid), blocker(gate)))
        await asyncio.sleep(0.01)

    p = k.sched.spawn(spec(), parent_work)
    assert (await k.sched.wait(p)).exit_reason is ExitReason.COMPLETED
    assert k.sched.get(child_ids[0]).exit_reason is ExitReason.PARENT_TERMINATED


async def test_child_that_ignores_kill_is_forced_terminated_after_the_wait() -> None:
    k = make_kernel(SchedulerConfig(child_kill_wait_seconds=0.02))
    release = asyncio.Event()

    async def immortal(_c: ProcessContext) -> None:
        while not release.is_set():
            try:
                await asyncio.sleep(0.005)
            except asyncio.CancelledError:
                continue  # swallows cancellation

    parent = k.sched.spawn(spec(), blocker(asyncio.Event()))
    child = k.sched.spawn(spec(ppid=parent), immortal)
    await until(lambda: k.sched.get(child).state is ProcessState.RUNNING)
    k.sched.signal(parent, Signal.KILL)
    assert (await k.sched.wait(parent)).state is ProcessState.TERMINATED
    assert k.sched.get(child).exit_reason is ExitReason.PARENT_TERMINATED
    release.set()


async def test_spawn_parent_checks_are_tenant_scoped() -> None:
    k = make_kernel()
    gate = asyncio.Event()
    parent = k.sched.spawn(spec(T1), blocker(gate))
    with pytest.raises(SpawnError, match="unknown parent"):
        k.sched.spawn(spec(T2, ppid=parent), quick)  # cross-tenant parent looks like a missing one
    k.sched.signal(parent, Signal.KILL)
    await k.sched.wait(parent)
    with pytest.raises(SpawnError, match="terminating"):
        k.sched.spawn(spec(T1, ppid=parent), quick)


# ---- budgets -------------------------------------------------------------------------------------


async def test_reserve_over_hard_cap_terminates_with_budget_exceeded_and_cascades() -> None:
    k = make_kernel()
    gate = asyncio.Event()
    holder: list[str] = []

    async def spender(ctx: ProcessContext) -> None:
        holder.append(k.sched.spawn(spec(ppid=ctx.pid), blocker(gate)))
        ctx.commit(ctx.reserve({TOK: 80}))
        ctx.reserve({TOK: 30})  # 110 > 100: refused, process must die

    pid = k.sched.spawn(spec(limits={TOK: Limit(soft=50, hard=100)}), spender)
    v = await k.sched.wait(pid)
    assert v.exit_reason is ExitReason.BUDGET_EXCEEDED and "hard cap" in v.detail
    assert k.sched.get(holder[0]).exit_reason is ExitReason.PARENT_TERMINATED
    assert k.sink.of(TkiEventType.BUDGET_SOFT_CAP) and k.sink.of(TkiEventType.BUDGET_DENIED)
    run_acct = next(a for a in k.ledger._accounts.values() if a.key.id == "run-1")  # noqa: SLF001
    assert run_acct.committed[TOK] == 80 and run_acct.reserved.get(TOK, 0) == 0


async def test_a_workload_that_swallows_the_budget_error_is_still_stopped() -> None:
    k = make_kernel()
    after: list[str] = []

    async def sneaky(ctx: ProcessContext) -> None:
        try:
            ctx.reserve({TOK: 999})
        except BudgetExceededError:
            pass
        await asyncio.sleep(0)  # the pending cancellation lands here
        after.append("kept running")

    pid = k.sched.spawn(spec(limits={TOK: Limit(hard=10)}), sneaky)
    v = await k.sched.wait(pid)
    assert v.exit_reason is ExitReason.BUDGET_EXCEEDED and after == []


async def test_returning_completed_cannot_mask_a_budget_trip() -> None:
    k = make_kernel()

    async def sneaky(ctx: ProcessContext) -> WorkloadResult:
        try:
            ctx.reserve({TOK: 999})
        except BudgetExceededError:
            pass
        return WorkloadResult(ExitReason.COMPLETED)  # no await: cancellation never delivered

    pid = k.sched.spawn(spec(limits={TOK: Limit(hard=10)}), sneaky)
    assert (await k.sched.wait(pid)).exit_reason is ExitReason.BUDGET_EXCEEDED


async def test_commit_overrun_trips_the_budget() -> None:
    k = make_kernel()

    async def over(ctx: ProcessContext) -> None:
        res = ctx.reserve({TOK: 5})
        ctx.commit(res, {TOK: 500})
        await asyncio.sleep(1)

    pid = k.sched.spawn(spec(limits={TOK: Limit(hard=50)}), over)
    v = await k.sched.wait(pid)
    assert v.exit_reason is ExitReason.BUDGET_EXCEEDED
    assert k.sink.of(TkiEventType.BUDGET_HARD_CAP)


async def test_child_spend_counts_against_parent_run_agent_and_tenant() -> None:
    k = make_kernel()
    k.ledger.ensure_account(  # tenant-level cap configured by the operator
        __import__("axis_runtime.tki.budget", fromlist=["x"]).AccountKey(
            T1, __import__("axis_runtime.tki.budget", fromlist=["x"]).ScopeKind.TENANT, T1
        )
    )
    from axis_runtime.tki.budget import AccountKey, ScopeKind

    k.ledger.set_limits(AccountKey(T1, ScopeKind.TENANT, T1), {TOK: Limit(hard=100)})
    results: dict[str, Any] = {}

    async def child(ctx: ProcessContext) -> None:
        ctx.commit(ctx.reserve({TOK: 60}))

    async def parent(ctx: ProcessContext) -> None:
        ctx.commit(ctx.reserve({TOK: 30}))
        c = k.sched.spawn(spec(ppid=ctx.pid), child)
        results["child"] = await k.sched.wait(c)
        ctx.reserve({TOK: 20})  # parent 30 + child 60 + 20 > 100 tenant cap

    pid = k.sched.spawn(spec(limits={TOK: Limit(hard=1000)}), parent)
    v = await k.sched.wait(pid)
    assert results["child"].exit_reason is ExitReason.COMPLETED
    assert v.exit_reason is ExitReason.BUDGET_EXCEEDED
    assert k.ledger.usage(AccountKey(T1, ScopeKind.TENANT, T1)).committed[TOK] == 90


async def test_child_is_bounded_by_the_parents_own_cap() -> None:
    k = make_kernel()

    async def child(ctx: ProcessContext) -> None:
        ctx.reserve({TOK: 40})

    async def parent(ctx: ProcessContext) -> None:
        c = k.sched.spawn(spec(ppid=ctx.pid, limits={TOK: Limit(hard=1_000_000)}), child)
        assert (await k.sched.wait(c)).exit_reason is ExitReason.BUDGET_EXCEEDED
        # parent itself survives its child's trip: the child's own death is the consequence

    pid = k.sched.spawn(spec(limits={TOK: Limit(hard=30)}), parent)
    assert (await k.sched.wait(pid)).exit_reason is ExitReason.COMPLETED


async def test_open_reservations_are_released_when_the_process_dies() -> None:
    k = make_kernel()

    async def leaky(ctx: ProcessContext) -> None:
        ctx.reserve({TOK: 10})
        res = ctx.reserve({TOK: 5})
        ctx.release(res)
        raise RuntimeError("crash with a reservation open")

    pid = k.sched.spawn(spec(limits={TOK: Limit(hard=100)}), leaky)
    assert (await k.sched.wait(pid)).exit_reason is ExitReason.FAILED
    run_acct = next(a for a in k.ledger._accounts.values() if a.key.id == "run-1")  # noqa: SLF001
    assert run_acct.reserved.get(TOK, 0) == 0 and run_acct.committed.get(TOK, 0) == 0


async def test_a_cancelled_process_cannot_start_new_spend_or_messages() -> None:
    k = make_kernel()
    outcomes: list[str] = []

    began = asyncio.Event()

    async def late(ctx: ProcessContext) -> None:
        began.set()
        await ctx.token.wait()
        for what, op in (
            ("reserve", lambda: ctx.reserve({TOK: 1})),
        ):  # fmt: skip
            try:
                op()
            except ProcessCancelled:
                outcomes.append(what)
        for what, coro in (("send", ctx.send(ctx.pid, {})), ("recv", ctx.receive(0.01))):
            try:
                await coro
            except ProcessCancelled:
                outcomes.append(what)

    pid = k.sched.spawn(spec(), late)
    await asyncio.wait_for(began.wait(), 2)
    k.sched.signal(pid, Signal.TERM)
    await k.sched.wait(pid)
    assert outcomes == ["reserve", "send", "recv"]


async def test_runtime_hard_cap_watchdog_kills_with_budget_exceeded() -> None:
    k = make_kernel()
    pid = k.sched.spawn(
        spec(limits={Resource.RUNTIME_MS: Limit(hard=40)}),
        lambda c: asyncio.sleep(60),  # type: ignore[arg-type, return-value]
    )
    v = await k.sched.wait(pid)
    assert v.exit_reason is ExitReason.BUDGET_EXCEEDED and "runtime_ms" in v.detail
    run_acct = next(a for a in k.ledger._accounts.values() if a.key.id == "run-1")  # noqa: SLF001
    assert 0 < run_acct.committed[Resource.RUNTIME_MS] <= 400  # charged, bounded by wall time


async def test_process_timeout_watchdog() -> None:
    k = make_kernel()
    pid = k.sched.spawn(spec(timeout_seconds=0.03), lambda c: asyncio.sleep(60))  # type: ignore[arg-type, return-value]
    v = await k.sched.wait(pid)
    assert v.exit_reason is ExitReason.TIMEOUT


async def test_elapsed_runtime_is_charged_on_exit_with_injected_clock() -> None:
    ticks = iter([1.0, 1.25])
    k = make_kernel(monotonic=lambda: next(ticks))
    pid = k.sched.spawn(spec(limits={Resource.RUNTIME_MS: Limit(hard=10_000)}), quick)
    await k.sched.wait(pid)
    run_acct = next(a for a in k.ledger._accounts.values() if a.key.id == "run-1")  # noqa: SLF001
    assert run_acct.committed[Resource.RUNTIME_MS] == 250


# ---- IPC through the context ---------------------------------------------------------------------


async def test_processes_exchange_messages_and_cross_tenant_send_is_refused() -> None:
    k = make_kernel()
    ready = asyncio.Event()
    pids: dict[str, str] = {}
    got: list[Any] = []
    errors: list[str] = []

    async def receiver(ctx: ProcessContext) -> None:
        pids["rx"] = ctx.pid
        ready.set()
        got.append(await ctx.receive(2))

    async def sender(ctx: ProcessContext) -> None:
        await ready.wait()
        assert await ctx.send(pids["rx"], {"hello": "world"}, kind=Kind.REQUEST) == 1

    async def foreign(ctx: ProcessContext) -> None:
        await ready.wait()
        try:
            await ctx.send(pids["rx"], {"x": 1})
        except IpcDeniedError as exc:
            errors.append(str(exc))

    # foreign tenant first: it must be refused even though the receiver exists
    rx = k.sched.spawn(spec(T1, run="r1"), receiver)
    f = k.sched.spawn(spec(T2, agent="b", run="r2"), foreign)
    await k.sched.wait(f)
    s = k.sched.spawn(spec(T1, run="r1"), sender)
    await asyncio.gather(k.sched.wait(rx), k.sched.wait(s))
    assert errors == ["recipient unavailable"]
    assert len(got) == 1 and got[0].payload == {"hello": "world"} and got[0].tenant_id == T1
    assert got[0].sender == s and got[0].kind is Kind.REQUEST
    assert len(k.sink.of(TkiEventType.IPC_SENT)) == 1


async def test_mailbox_is_unregistered_when_the_process_ends() -> None:
    k = make_kernel()
    pid = k.sched.spawn(spec(), quick)
    await k.sched.wait(pid)
    assert k.router.mailbox(pid) is None


async def test_a_run_belongs_to_one_agent_but_children_may_be_other_agents() -> None:
    k = make_kernel()
    gate = asyncio.Event()
    root = k.sched.spawn(spec(agent="planner", run="r9"), blocker(gate))
    with pytest.raises(SpawnError, match="different agent"):
        k.sched.spawn(spec(agent="other", run="r9"), quick)
    child = k.sched.spawn(spec(agent="worker", run="r9", ppid=root), blocker(gate))
    assert k.sched.get(child).agent == "worker"
    gate.set()
    await asyncio.gather(k.sched.wait(root), k.sched.wait(child))


async def test_context_exposes_identity_and_a_failed_mailbox_registration_rolls_back() -> None:
    k = make_kernel()
    seen: dict[str, Any] = {}

    async def look(ctx: ProcessContext) -> None:
        seen.update(
            tenant=ctx.tenant_id, run=ctx.run_id, acct=ctx.account, box=ctx.mailbox, pid=ctx.pid
        )

    pid = k.sched.spawn(spec(), look)
    await k.sched.wait(pid)
    assert seen["tenant"] == T1 and seen["run"] == "run-1" and seen["pid"] == pid
    assert seen["acct"].id == pid and seen["box"].pid == pid

    taken = "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV"
    k.router.register(taken, T2)  # the router already knows this PID
    k.sched._pid_factory = lambda: taken  # type: ignore[method-assign]  # noqa: SLF001
    with pytest.raises(Exception, match="already registered"):
        k.sched.spawn(spec(), quick)
    from axis_runtime.tki.budget import AccountKey, ScopeKind, UnknownAccountError

    with pytest.raises(UnknownAccountError):  # the half-made process account was closed
        k.ledger.usage(AccountKey(T1, ScopeKind.PROCESS, taken))


async def test_the_first_termination_decision_wins() -> None:
    k = make_kernel()
    gate = asyncio.Event()
    pid = k.sched.spawn(spec(), blocker(gate))
    k.sched.terminate(pid, ExitReason.POLICY_DENIED, "kill switch")
    k.sched.terminate(pid, ExitReason.KILLED, "operator")  # arrives before the task unwinds
    k.sched.signal(pid, Signal.KILL)
    v = await k.sched.wait(pid)
    assert v.exit_reason is ExitReason.POLICY_DENIED and v.detail == "kill switch"
