"""Supervisor trees on top of the scheduler (Erlang-style, driven by the ABL ``spec.process``).

* strategies ``one-for-one`` | ``one-for-all`` | ``rest-for-one`` (``rest-for-one`` restarts the
  failed child and every child started AFTER it, in start order);
* per-child ``restart_policy`` (``never`` | ``on-failure`` | ``always``) and ``max_restarts``
  inside a sliding intensity window (``window_seconds``; ``None`` = lifetime);
* an optional supervisor-wide ``max_total_restarts`` in the same window: exceeding it shuts every
  child down and records ``supervisor_escalated`` (a restart storm must not run forever);
* ``max_children`` bounds LIVE children.

Restart eligibility is deliberately narrow and fail-closed.  Only these exits are ever restarted:
``failed`` and ``timeout`` (``on-failure``), plus ``completed`` (``always``).  ``budget_exceeded``,
``policy_denied``, ``killed`` and ``parent_terminated`` are NEVER restarted: a restart must not be a
way around a budget cap, a policy denial or a kill switch.  A restarted child is a NEW process
(new PID, new budget account under the same parent) so ledger totals up the tree keep counting.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

from axis_runtime.manifest import ProcessConfig, RuntimeManifest
from axis_runtime.process import ExitReason, ProcessState, is_terminal
from axis_runtime.tki.budget import Limit, Limits, Resource
from axis_runtime.tki.events import TkiEvent, TkiEventType
from axis_runtime.tki.scheduler import (
    Priority,
    ProcessView,
    Scheduler,
    SchedulerError,
    SpawnError,
    SpawnSpec,
    Workload,
)


class Strategy(StrEnum):
    ONE_FOR_ONE = "one-for-one"
    ONE_FOR_ALL = "one-for-all"
    REST_FOR_ONE = "rest-for-one"


class RestartPolicy(StrEnum):
    NEVER = "never"
    ON_FAILURE = "on-failure"
    ALWAYS = "always"

    @classmethod
    def parse(cls, raw: str) -> RestartPolicy:
        """Accepts the ABL spelling (``on-failure``) and the runtime manifest's (``on_failure``)."""
        return cls(raw.replace("_", "-"))


_RESTARTABLE: dict[RestartPolicy, frozenset[ExitReason]] = {
    RestartPolicy.NEVER: frozenset(),
    RestartPolicy.ON_FAILURE: frozenset({ExitReason.FAILED, ExitReason.TIMEOUT}),
    RestartPolicy.ALWAYS: frozenset({ExitReason.COMPLETED, ExitReason.FAILED, ExitReason.TIMEOUT}),
}


def should_restart(policy: RestartPolicy, reason: ExitReason) -> bool:
    return reason in _RESTARTABLE[policy]


class ChildLimitError(SchedulerError):
    pass


class DuplicateChildError(SchedulerError):
    pass


@dataclass(frozen=True)
class SupervisorConfig:
    strategy: Strategy = Strategy.ONE_FOR_ONE
    max_children: int = 0
    window_seconds: float | None = 60.0
    max_total_restarts: int | None = None

    @classmethod
    def from_process_config(
        cls,
        pc: ProcessConfig,
        *,
        window_seconds: float | None = 60.0,
        max_total_restarts: int | None = None,
    ) -> SupervisorConfig:
        return cls(Strategy(pc.supervisor), pc.max_children, window_seconds, max_total_restarts)


def limits_from_manifest(manifest: RuntimeManifest) -> Limits:
    """ABL budgets -> ledger limits (cost USD -> micro-USD, seconds -> ms)."""
    b = manifest.budgets

    def conv(budget_soft: float | None, budget_hard: float | None, scale: int) -> Limit:
        return Limit(
            None if budget_soft is None else int(budget_soft * scale),
            None if budget_hard is None else int(budget_hard * scale),
        )

    out: dict[Resource, Limit] = {}
    for res, budget, scale in (
        (Resource.TOKENS, b.tokens, 1),
        (Resource.COST_MICRO_USD, b.cost_usd, 1_000_000),
        (Resource.RUNTIME_MS, b.runtime_seconds, 1000),
        (Resource.TOOL_CALLS, b.tool_calls, 1),
    ):
        if budget.soft is not None or budget.hard is not None:
            out[res] = conv(budget.soft, budget.hard, scale)
    return out


@dataclass(frozen=True)
class ChildSpec:
    name: str
    agent: str
    workload: Workload
    restart: RestartPolicy = RestartPolicy.NEVER
    max_restarts: int = 0
    priority: int = Priority.NORMAL
    limits: Limits = field(default_factory=dict)
    timeout_seconds: float | None = None

    @classmethod
    def from_manifest(cls, name: str, manifest: RuntimeManifest, workload: Workload) -> ChildSpec:
        pc = manifest.process
        return cls(
            name=name,
            agent=f"{manifest.name}@{manifest.version}",
            workload=workload,
            restart=RestartPolicy.parse(pc.restart_policy),
            max_restarts=pc.max_restarts,
            limits=limits_from_manifest(manifest),
            timeout_seconds=pc.timeout_seconds,
        )


@dataclass
class _Slot:
    spec: ChildSpec
    pid: str
    restarts: list[float] = field(default_factory=list)
    total_restarts: int = 0


@dataclass(frozen=True)
class ChildInfo:
    name: str
    pid: str
    state: ProcessState
    restarts: int
    exit_reason: ExitReason | None


class Supervisor:
    def __init__(
        self,
        scheduler: Scheduler,
        parent_pid: str,
        config: SupervisorConfig,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        parent = scheduler.get(parent_pid)  # raises for an unknown parent
        self._sched = scheduler
        self._parent = parent_pid
        self._tenant = parent.tenant_id
        self._run_id = parent.run_id
        self._config = config
        self._monotonic = monotonic
        self._slots: list[_Slot] = []  # start order
        self._by_pid: dict[str, _Slot] = {}
        self._bouncing: set[str] = set()
        self._lock = asyncio.Lock()
        self._tasks: set[asyncio.Task[None]] = set()
        self._stopped = False
        self._window_events: list[float] = []
        scheduler.on_exit(self._on_exit)

    # ---- public ----------------------------------------------------------------------------
    def start_child(self, spec: ChildSpec) -> str:
        if self._stopped:
            raise SchedulerError("supervisor is stopped")
        if any(s.spec.name == spec.name for s in self._slots):
            raise DuplicateChildError(f"child name {spec.name!r} already supervised")
        live = sum(1 for s in self._slots if not is_terminal(self._sched.get(s.pid).state))
        if live >= self._config.max_children:
            raise ChildLimitError(f"max_children ({self._config.max_children}) reached")
        slot = _Slot(spec, self._spawn(spec))
        self._slots.append(slot)
        self._by_pid[slot.pid] = slot
        return slot.pid

    def children(self) -> list[ChildInfo]:
        out = []
        for s in self._slots:
            v = self._sched.get(s.pid)
            out.append(ChildInfo(s.spec.name, s.pid, v.state, s.total_restarts, v.exit_reason))
        return out

    def pid_of(self, name: str) -> str:
        for s in self._slots:
            if s.spec.name == name:
                return s.pid
        raise KeyError(name)

    async def settle(self) -> None:
        """Wait until no restart handling is in flight."""
        while self._tasks:
            await asyncio.gather(*list(self._tasks))
            # gather() over already-finished tasks does not yield; give their done-callbacks (which
            # drop them from ``_tasks``) a loop turn or this spins forever.
            await asyncio.sleep(0)

    async def shutdown(self) -> None:
        """Stop supervising and terminate every live child (no restarts)."""
        self._stopped = True
        await self.settle()
        live = [s.pid for s in self._slots if not is_terminal(self._sched.get(s.pid).state)]
        for pid in live:
            self._sched.terminate(pid, ExitReason.KILLED, "supervisor shutdown")
        await asyncio.gather(*(self._sched.wait(p) for p in live))

    # ---- internals -------------------------------------------------------------------------
    def _spawn(self, spec: ChildSpec) -> str:
        return self._sched.spawn(
            SpawnSpec(
                tenant_id=self._tenant,
                agent=spec.agent,
                run_id=self._run_id,
                ppid=self._parent,
                priority=spec.priority,
                limits=spec.limits,
                timeout_seconds=spec.timeout_seconds,
            ),
            spec.workload,
        )

    def _on_exit(self, view: ProcessView) -> None:
        slot = self._by_pid.get(view.pid)
        if slot is None or self._stopped or view.pid in self._bouncing:
            return
        reason = view.exit_reason
        if reason is None or not should_restart(slot.spec.restart, reason):
            return
        if is_terminal(self._sched.get(self._parent).state):
            return
        task = asyncio.create_task(self._handle(slot, reason))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _within_window(self, times: list[float]) -> int:
        if self._config.window_seconds is None:
            return len(times)
        cutoff = self._monotonic() - self._config.window_seconds
        times[:] = [t for t in times if t > cutoff]
        return len(times)

    def _escalate(self, slot: _Slot, why: str) -> None:
        self._sched.sink.emit(
            TkiEvent(
                TkiEventType.SUPERVISOR_ESCALATED,
                self._tenant,
                self._parent,
                {"child": slot.spec.name, "reason": why, "strategy": self._config.strategy.value},
            )
        )

    async def _handle(self, failed: _Slot, reason: ExitReason) -> None:
        async with self._lock:
            if self._stopped or is_terminal(self._sched.get(self._parent).state):
                return
            if self._within_window(failed.restarts) >= failed.spec.max_restarts:
                self._escalate(failed, "child restart intensity exceeded")
                return
            cfg = self._config
            if (
                cfg.max_total_restarts is not None
                and self._within_window(self._window_events) >= cfg.max_total_restarts
            ):
                self._escalate(failed, "supervisor restart intensity exceeded")
                self._stopped = True
                for s in self._slots:
                    live = not is_terminal(self._sched.get(s.pid).state)
                    if live:
                        self._sched.terminate(s.pid, ExitReason.KILLED, "supervisor gave up")
                return
            now = self._monotonic()
            failed.restarts.append(now)
            self._window_events.append(now)
            group = self._group(failed)
            others = [s for s in group if s is not failed]
            bounced = [s for s in others if not is_terminal(self._sched.get(s.pid).state)]
            for s in bounced:
                self._bouncing.add(s.pid)
                self._sched.terminate(s.pid, ExitReason.KILLED, f"supervisor {cfg.strategy.value}")
            await asyncio.gather(*(self._sched.wait(s.pid) for s in bounced))
            for s in group:
                if s is failed or s in bounced:
                    try:
                        self._restart(s, reason if s is failed else None)
                    except SpawnError as exc:  # parent is going away: stop, never half-restart
                        self._escalate(failed, f"restart refused: {exc}")
                        return

    def _group(self, failed: _Slot) -> list[_Slot]:
        strategy = self._config.strategy
        if strategy is Strategy.ONE_FOR_ONE:
            return [failed]
        if strategy is Strategy.ONE_FOR_ALL:
            return list(self._slots)
        return self._slots[self._slots.index(failed) :]

    def _restart(self, slot: _Slot, reason: ExitReason | None) -> None:
        old = slot.pid
        del self._by_pid[old]
        self._bouncing.discard(old)
        slot.pid = self._spawn(slot.spec)
        slot.total_restarts += 1
        self._by_pid[slot.pid] = slot
        self._sched.sink.emit(
            TkiEvent(
                TkiEventType.PROCESS_RESTARTED,
                self._tenant,
                slot.pid,
                {
                    "child": slot.spec.name,
                    "previous_pid": old,
                    "cause": None if reason is None else reason.value,
                    "strategy": self._config.strategy.value,
                    "restart_count": slot.total_restarts,
                },
            )
        )
