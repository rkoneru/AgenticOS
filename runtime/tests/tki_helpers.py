"""Shared builders for the TKI tests."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from axis_runtime.process import ProcessState, new_pid
from axis_runtime.tki import (
    Envelope,
    InMemoryLedger,
    Kind,
    ListSink,
    MessageRouter,
    Scheduler,
    SchedulerConfig,
)
from conftest import FakeClock

T1 = "11111111-1111-4111-8111-111111111111"
T2 = "22222222-2222-4222-8222-222222222222"
TRACE = "a" * 32


async def allow_all(_env: Envelope) -> bool:
    return True


@dataclass
class Kernel:
    sched: Scheduler
    ledger: InMemoryLedger
    router: MessageRouter
    sink: ListSink
    clock: FakeClock


def make_kernel(
    config: SchedulerConfig | None = None,
    *,
    authorize: Callable[[Envelope], Any] = allow_all,
    monotonic: Callable[[], float] | None = None,
) -> Kernel:
    sink = ListSink()
    clock = FakeClock()
    ledger = InMemoryLedger(sink)
    router = MessageRouter(sink=sink, authorize=authorize, clock=clock)
    kw: dict[str, Any] = {}
    if monotonic is not None:
        kw["monotonic"] = monotonic
    sched = Scheduler(
        ledger=ledger,
        router=router,
        sink=sink,
        clock=clock,
        config=config or SchedulerConfig(),
        pid_factory=new_pid,
        **kw,
    )
    return Kernel(sched, ledger, router, sink, clock)


def env(
    sender: str,
    to: str,
    *,
    tenant: str = T1,
    kind: Kind = Kind.MESSAGE,
    payload: dict[str, Any] | None = None,
    **kw: Any,
) -> Envelope:
    return Envelope.new(
        tenant_id=tenant,
        trace_id=TRACE,
        sender=sender,
        to=to,
        kind=kind,
        payload=payload or {"x": 1},
        clock=FakeClock(),
        **kw,
    )


async def until(pred: Callable[[], bool], timeout: float = 3.0) -> None:
    async def poll() -> None:
        while not pred():
            await asyncio.sleep(0.001)

    await asyncio.wait_for(poll(), timeout)


def states(k: Kernel, *pids: str) -> list[ProcessState]:
    return [k.sched.get(p).state for p in pids]


def lifecycle(k: Kernel, pid: str) -> list[tuple[str, str]]:
    """(trigger, to) pairs of a process, after checking the chain against the frozen model."""
    from axis_runtime.process import next_state
    from axis_runtime.tki import TkiEventType

    cur = "spawn"
    out: list[tuple[str, str]] = []
    for e in k.sink.events:
        if e.type is TkiEventType.PROCESS_TRANSITION and e.pid == pid:
            assert e.data["from"] == cur
            assert next_state(ProcessState(cur), e.data["trigger"]).value == e.data["to"]
            cur = e.data["to"]
            out.append((e.data["trigger"], cur))
            assert (cur == "terminated") == ("exit_reason" in e.data)
    return out


def spec(tenant: str = T1, agent: str = "agent-a", run: str = "run-1", **kw: Any) -> Any:
    from axis_runtime.tki import SpawnSpec

    return SpawnSpec(tenant_id=tenant, agent=agent, run_id=run, **kw)
