"""TKI scheduler: priority + tenant-fair queue over agent processes, per-tenant concurrency limits,
cooperative cancellation, parent-termination cascade, budget accounts per process.

Process states and legal transitions come ONLY from ``axis_runtime.process`` (the frozen contract):
every state change goes through ``next_state`` and is announced to the injected ``EventSink``.

Scheduling
    A process holds a *slot* only while RUNNING.  ``ready`` processes wait in one queue; on every
    slot release the dispatcher picks the entry with the best key
    ``(effective_priority, tenant_last_served, enqueue_seq)``:

    * lower priority number runs first (``Priority.HIGH`` = 0);
    * aging: each ``aging_interval`` dispatches an entry has waited improves its effective priority
      by one level, so low priority work cannot starve;
    * among equal priority the tenant served least recently goes first (round-robin fairness: a
      tenant that floods the queue cannot push another tenant's work behind its own);
    * a tenant at its concurrency limit is skipped (not blocked on) until one of its processes
      leaves RUNNING.

Cancellation is cooperative (``TERM`` sets a token the workload polls via
``ctx.checkpoint()``) with escalation to ``KILL`` (task cancellation) after
``term_grace_seconds``.  Terminating a process first
terminates its live children (TERM then KILL signal events, exit reason ``parent_terminated``).
Budget hard-cap trips, runtime/timeout watchdogs and supervisor actions use the same machinery.

Every external action of a TKI-supervised *agent* still goes through the gate/executor: this module
runs opaque ``Workload`` callables and never performs actions (see ``adapter.py``).
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from axis_runtime.events import Clock, SystemClock
from axis_runtime.process import (
    ExitReason,
    Lifecycle,
    ProcessState,
    Signal,
    is_terminal,
    new_pid,
    next_state,
)
from axis_runtime.tki.budget import (
    AccountConfigError,
    AccountKey,
    Amounts,
    BudgetExceededError,
    BudgetLedger,
    CommitResult,
    Limit,
    Limits,
    Reservation,
    Resource,
    ScopeKind,
)
from axis_runtime.tki.events import EventSink, TkiEvent, TkiEventType
from axis_runtime.tki.ipc import Envelope, Kind, Mailbox, MessageRouter


class Priority(IntEnum):
    HIGH = 0
    NORMAL = 1
    LOW = 2


class SchedulerError(Exception):
    pass


class SpawnError(SchedulerError):
    pass


class ProcessCancelled(Exception):  # noqa: N818 - control-flow signal, not an error condition
    """Raised inside a workload at a checkpoint after TERM/KILL/budget trip/parent termination."""


@dataclass(frozen=True)
class SchedulerConfig:
    max_running: int = 8
    default_tenant_limit: int = 4
    tenant_limits: Mapping[str, int] = field(default_factory=dict)
    term_grace_seconds: float = 5.0
    aging_interval: int = 8
    child_kill_wait_seconds: float = 5.0

    def __post_init__(self) -> None:
        if self.max_running < 1 or self.default_tenant_limit < 1 or self.aging_interval < 1:
            raise ValueError("max_running, default_tenant_limit, aging_interval must be >= 1")
        if any(v < 1 for v in self.tenant_limits.values()):
            raise ValueError("tenant limits must be >= 1")

    def limit_for(self, tenant_id: str) -> int:
        return self.tenant_limits.get(tenant_id, self.default_tenant_limit)


@dataclass(frozen=True)
class WorkloadResult:
    exit_reason: ExitReason = ExitReason.COMPLETED
    detail: str = ""


@dataclass(frozen=True)
class SpawnSpec:
    tenant_id: str
    agent: str
    run_id: str
    ppid: str | None = None
    priority: int = Priority.NORMAL
    limits: Limits = field(default_factory=dict)
    timeout_seconds: float | None = None
    trace_id: str | None = None


@dataclass(frozen=True)
class ProcessView:
    pid: str
    ppid: str | None
    tenant_id: str
    agent: str
    run_id: str
    state: ProcessState
    priority: int
    exit_reason: ExitReason | None = None
    detail: str = ""


class CancelToken:
    def __init__(self) -> None:
        self._event = asyncio.Event()
        self.reason: ExitReason | None = None
        self.detail = ""

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self, reason: ExitReason, detail: str = "") -> None:
        if not self._event.is_set():
            self.reason, self.detail = reason, detail
            self._event.set()

    async def wait(self) -> None:
        await self._event.wait()


Workload = Callable[["ProcessContext"], Awaitable["WorkloadResult | None"]]
ExitListener = Callable[[ProcessView], None]


@dataclass
class _Outcome:
    reason: ExitReason
    detail: str = ""
    trigger: str | None = None  # None: EXIT when running, else KILL


@dataclass
class _Entry:
    proc: _Proc
    seq: int
    enq_tick: int
    trigger: Lifecycle


@dataclass
class _Proc:
    pid: str
    spec: SpawnSpec
    account: AccountKey
    mailbox: Mailbox
    token: CancelToken = field(default_factory=CancelToken)
    state: ProcessState = ProcessState.SPAWN
    exit_reason: ExitReason | None = None
    detail: str = ""
    task: asyncio.Task[None] | None = None
    grant: asyncio.Future[None] | None = None
    holds_slot: bool = False
    pause_requested: bool = False
    finishing: bool = False
    outcome: _Outcome | None = None
    children: list[str] = field(default_factory=list)
    done: asyncio.Event = field(default_factory=asyncio.Event)
    reservations: dict[str, Reservation] = field(default_factory=dict)
    interrupts: list[str] = field(default_factory=list)
    timers: list[asyncio.Task[None]] = field(default_factory=list)
    started_at: float | None = None
    entered: bool = False  # the task body has begun (a task cancelled earlier never runs at all)

    def view(self) -> ProcessView:
        return ProcessView(
            self.pid,
            self.spec.ppid,
            self.spec.tenant_id,
            self.spec.agent,
            self.spec.run_id,
            self.state,
            self.spec.priority,
            self.exit_reason,
            self.detail,
        )


class ProcessContext:
    """The only handle a workload gets: cancellation, yielding, budgets and IPC for ITS process."""

    def __init__(self, sched: Scheduler, proc: _Proc) -> None:
        self._sched = sched
        self._proc = proc

    @property
    def pid(self) -> str:
        return self._proc.pid

    @property
    def tenant_id(self) -> str:
        return self._proc.spec.tenant_id

    @property
    def run_id(self) -> str:
        return self._proc.spec.run_id

    @property
    def account(self) -> AccountKey:
        return self._proc.account

    @property
    def token(self) -> CancelToken:
        return self._proc.token

    @property
    def mailbox(self) -> Mailbox:
        return self._proc.mailbox

    def _live(self) -> None:
        if self._proc.token.cancelled or is_terminal(self._proc.state):
            raise ProcessCancelled(self._proc.token.detail or "process is terminating")

    async def checkpoint(self) -> None:
        """Safe point: raise if cancelled, suspend here if PAUSE was requested."""
        self._live()
        if self._proc.pause_requested:
            await self._sched._suspend(self._proc)  # noqa: SLF001
            self._live()

    async def yield_(self) -> None:
        """Give up the slot (running -> ready) and queue again behind better-ranked work."""
        await self.checkpoint()
        await self._sched._yield(self._proc)  # noqa: SLF001
        self._live()

    @asynccontextmanager
    async def waiting(self) -> AsyncIterator[None]:
        """``async with ctx.waiting(): await io`` : state ``waiting``, slot released meanwhile."""
        self._live()
        self._sched._begin_wait(self._proc)  # noqa: SLF001
        yield
        await self._sched._end_wait(self._proc)  # noqa: SLF001
        self._live()

    def take_interrupts(self) -> list[str]:
        out, self._proc.interrupts = self._proc.interrupts, []
        return out

    # ---- budgets (reserve-before-spend) ----------------------------------------------------
    def reserve(self, amounts: Amounts) -> Reservation:
        self._live()
        try:
            res = self._sched.ledger.reserve(self._proc.account, amounts)
        except BudgetExceededError as exc:
            self._sched._trip(self._proc, str(exc))  # noqa: SLF001
            raise
        self._proc.reservations[res.id] = res
        return res

    def commit(self, res: Reservation, actual: Amounts | None = None) -> CommitResult:
        result = self._sched.ledger.commit(res, actual)
        self._proc.reservations.pop(res.id, None)
        if result.tripped:
            self._sched._trip(self._proc, f"hard cap overrun {dict(result.overrun)}")  # noqa: SLF001
        return result

    def release(self, res: Reservation) -> None:
        self._sched.ledger.release(res)
        self._proc.reservations.pop(res.id, None)

    # ---- IPC -------------------------------------------------------------------------------
    async def send(
        self,
        to: str,
        payload: Mapping[str, Any],
        *,
        kind: Kind = Kind.MESSAGE,
        correlation_id: str | None = None,
        ttl_seconds: int | None = None,
    ) -> int:
        self._live()
        env = Envelope.new(
            tenant_id=self.tenant_id,
            trace_id=self._proc.spec.trace_id or "0" * 32,
            sender=self.pid,
            to=to,
            kind=kind,
            payload=payload,
            clock=self._sched.clock,
            correlation_id=correlation_id,
            ttl_seconds=ttl_seconds,
        )
        return await self._sched.router.send(env)

    async def receive(self, within: float | None = None) -> Envelope:
        self._live()
        return await self._proc.mailbox.receive(within)


class Scheduler:
    def __init__(
        self,
        *,
        ledger: BudgetLedger,
        router: MessageRouter,
        sink: EventSink,
        clock: Clock | None = None,
        config: SchedulerConfig | None = None,
        pid_factory: Callable[[], str] = new_pid,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.ledger = ledger
        self.router = router
        self.sink = sink
        self.clock: Clock = clock or SystemClock()
        self.config = config or SchedulerConfig()
        self._pid_factory = pid_factory
        self._monotonic = monotonic
        self._procs: dict[str, _Proc] = {}
        self._queue: list[_Entry] = []
        self._seq = 0
        self._tick = 0
        self._running = 0
        self._tenant_running: dict[str, int] = {}
        self._tenant_served: dict[str, int] = {}
        self._listeners: list[ExitListener] = []

    # ---- public API ------------------------------------------------------------------------
    def on_exit(self, listener: ExitListener) -> None:
        self._listeners.append(listener)

    def get(self, pid: str) -> ProcessView:
        return self._proc(pid).view()

    def children_of(self, pid: str) -> list[ProcessView]:
        return [self._procs[c].view() for c in self._proc(pid).children]

    def processes(self, tenant_id: str | None = None) -> list[ProcessView]:
        return [p.view() for p in self._procs.values() if tenant_id in (None, p.spec.tenant_id)]

    @property
    def running_count(self) -> int:
        return self._running

    def tenant_running(self, tenant_id: str) -> int:
        return self._tenant_running.get(tenant_id, 0)

    def queued(self) -> list[str]:
        return [e.proc.pid for e in self._queue]

    def spawn(self, spec: SpawnSpec, workload: Workload) -> str:
        if spec.priority < 0:
            raise SpawnError("priority must be >= 0")
        if not spec.tenant_id or not spec.agent or not spec.run_id:
            raise SpawnError("tenant_id, agent and run_id are required")
        parent: _Proc | None = None
        if spec.ppid is not None:
            parent = self._procs.get(spec.ppid)
            # Unknown and cross-tenant parents are reported identically.
            if parent is None or parent.spec.tenant_id != spec.tenant_id:
                raise SpawnError("unknown parent process")
            if is_terminal(parent.state) or parent.finishing:
                raise SpawnError("parent is terminating")
        tid = spec.tenant_id
        tenant_key = AccountKey(tid, ScopeKind.TENANT, tid)
        agent_key = AccountKey(tid, ScopeKind.AGENT, spec.agent)
        run_key = AccountKey(tid, ScopeKind.RUN, spec.run_id)
        if parent is None:
            # Roots hang under tenant -> agent -> run.  Children hang under their parent's process
            # account, so a child of another agent still counts against the run it belongs to.
            try:
                self.ledger.ensure_account(tenant_key)
                self.ledger.ensure_account(agent_key, tenant_key)
                self.ledger.ensure_account(run_key, agent_key)
            except AccountConfigError as exc:
                raise SpawnError(f"run {spec.run_id!r} belongs to a different agent") from exc
        pid = self._pid_factory()
        if pid in self._procs:
            raise SpawnError("duplicate pid")
        key = AccountKey(tid, ScopeKind.PROCESS, pid)
        self.ledger.open_account(key, parent.account if parent else run_key, spec.limits)
        try:
            box = self.router.register(pid, tid)
        except Exception:
            self.ledger.close_account(key)
            raise
        proc = _Proc(pid=pid, spec=spec, account=key, mailbox=box)
        try:
            self._event(
                TkiEventType.PROCESS_SPAWNED,
                proc,
                ppid=spec.ppid,
                agent=spec.agent,
                run_id=spec.run_id,
                priority=int(spec.priority),
            )
            self._go(proc, Lifecycle.INIT_COMPLETE)
        except Exception:  # audit failure: the process never existed (fail-closed)
            self.router.unregister(pid)
            self.ledger.close_account(key)
            raise
        self._procs[pid] = proc
        if parent is not None:
            parent.children.append(pid)
        self._enqueue(proc, Lifecycle.SCHEDULED)
        proc.task = asyncio.create_task(self._main(proc, workload))
        self._dispatch()
        return pid

    async def wait(self, pid: str) -> ProcessView:
        proc = self._proc(pid)
        await proc.done.wait()
        return proc.view()

    def signal(self, pid: str, sig: Signal, message: str | None = None) -> None:
        proc = self._proc(pid)
        if is_terminal(proc.state):
            return
        data: dict[str, Any] = {"signal": sig.value}
        if message:
            data["message"] = message
        self._event(TkiEventType.SIGNAL_DELIVERED, proc, **data)
        if sig is Signal.PAUSE:
            self._pause(proc)
        elif sig is Signal.RESUME:
            proc.pause_requested = False
            if proc.state is ProcessState.SUSPENDED:
                self._go(proc, Signal.RESUME)
                self._enqueue(proc, Lifecycle.SCHEDULED)
                self._dispatch()
        elif sig is Signal.INTERRUPT:
            proc.interrupts.append(message or "")
        elif sig is Signal.TERM:
            self._term(proc)
        else:
            self._kill(proc, ExitReason.KILLED, "KILL", Signal.KILL)

    def terminate(self, pid: str, reason: ExitReason, detail: str = "") -> None:
        """Immediate, supervisor/operator-driven termination with an explicit exit reason."""
        proc = self._proc(pid)
        if not is_terminal(proc.state):
            self._kill(proc, reason, detail, Signal.KILL)

    async def shutdown(self) -> None:
        for proc in list(self._procs.values()):
            if proc.spec.ppid is None and not is_terminal(proc.state):
                self._kill(proc, ExitReason.KILLED, "scheduler shutdown", Signal.KILL)
        await asyncio.gather(*(p.done.wait() for p in self._procs.values()))

    # ---- internals: bookkeeping ------------------------------------------------------------
    def _proc(self, pid: str) -> _Proc:
        proc = self._procs.get(pid)
        if proc is None:
            raise SchedulerError(f"unknown process {pid}")
        return proc

    def _event(self, kind: TkiEventType, proc: _Proc, **data: object) -> None:
        self.sink.emit(TkiEvent(kind, proc.spec.tenant_id, proc.pid, data))

    def _go(
        self,
        proc: _Proc,
        trigger: str,
        *,
        reason: ExitReason | None = None,
        detail: str = "",
    ) -> None:
        target = next_state(proc.state, trigger)
        data: dict[str, Any] = {
            "from": proc.state.value,
            "to": target.value,
            "trigger": str(trigger),
        }
        if reason is not None:
            data["exit_reason"] = reason.value
            if detail:
                data["detail"] = detail[:300]
        self._event(TkiEventType.PROCESS_TRANSITION, proc, **data)  # audit first, then apply
        proc.state = target

    # ---- internals: queue ------------------------------------------------------------------
    def _enqueue(self, proc: _Proc, trigger: Lifecycle) -> None:
        if proc.grant is None or proc.grant.done():
            proc.grant = asyncio.get_running_loop().create_future()
        self._seq += 1
        self._queue.append(_Entry(proc, self._seq, self._tick, trigger))

    def _rank(self, e: _Entry) -> tuple[int, int, int]:
        aged = (self._tick - e.enq_tick) // self.config.aging_interval
        eff = max(0, int(e.proc.spec.priority) - aged)
        return (eff, self._tenant_served.get(e.proc.spec.tenant_id, -1), e.seq)

    def _dispatch(self) -> None:
        while self._running < self.config.max_running:
            eligible = [
                e
                for e in self._queue
                if self.tenant_running(e.proc.spec.tenant_id)
                < self.config.limit_for(e.proc.spec.tenant_id)
            ]
            if not eligible:
                return
            entry = min(eligible, key=self._rank)
            self._queue.remove(entry)
            proc = entry.proc
            if proc.pause_requested:
                self._go(proc, Signal.PAUSE)  # ready -> suspended; RESUME re-queues it
                continue
            self._tick += 1
            tid = proc.spec.tenant_id
            self._tenant_served[tid] = self._tick
            self._running += 1
            self._tenant_running[tid] = self.tenant_running(tid) + 1
            proc.holds_slot = True
            self._go(proc, entry.trigger)
            if proc.started_at is None:
                proc.started_at = self._monotonic()
                self._arm_watchdogs(proc)
            if proc.grant is not None and not proc.grant.done():
                proc.grant.set_result(None)

    def _release_slot(self, proc: _Proc) -> None:
        if proc.holds_slot:
            proc.holds_slot = False
            self._running -= 1
            self._tenant_running[proc.spec.tenant_id] -= 1

    def _unqueue(self, proc: _Proc) -> None:
        self._queue = [e for e in self._queue if e.proc is not proc]

    # ---- internals: cooperative points -----------------------------------------------------
    async def _await_slot(self, proc: _Proc) -> None:
        grant = proc.grant
        if grant is not None:
            await grant

    async def _yield(self, proc: _Proc) -> None:
        self._go(proc, Lifecycle.YIELD)
        self._release_slot(proc)
        self._enqueue(proc, Lifecycle.SCHEDULED)
        self._dispatch()
        await self._await_slot(proc)

    async def _suspend(self, proc: _Proc) -> None:
        self._go(proc, Signal.PAUSE)
        self._release_slot(proc)
        proc.grant = asyncio.get_running_loop().create_future()
        self._dispatch()
        await self._await_slot(proc)

    def _begin_wait(self, proc: _Proc) -> None:
        self._go(proc, Lifecycle.AWAIT)
        self._release_slot(proc)
        self._dispatch()

    async def _end_wait(self, proc: _Proc) -> None:
        self._enqueue(proc, Lifecycle.WAKE)
        self._dispatch()
        await self._await_slot(proc)

    def _pause(self, proc: _Proc) -> None:
        proc.pause_requested = True
        if proc.state is ProcessState.READY:
            self._unqueue(proc)
            self._go(proc, Signal.PAUSE)
        # A WAITING process honours the flag after it wakes (it suspends at its next checkpoint).

    # ---- internals: termination ------------------------------------------------------------
    def _kill(
        self, proc: _Proc, reason: ExitReason, detail: str, trigger: str | None = Signal.KILL
    ) -> None:
        if proc.finishing or is_terminal(proc.state):
            return
        if proc.outcome is None:
            proc.outcome = _Outcome(reason, detail, trigger)
        proc.token.cancel(proc.outcome.reason, proc.outcome.detail)
        if proc.entered and proc.task is not None and not proc.task.done():
            if proc.task is asyncio.current_task():
                # Never cancel the running task from inside itself: on Python 3.12 a cancel that
                # is raised through instead of delivered at an await poisons the next await.
                # Deliver it on the next loop step instead (a no-op if already finishing).
                asyncio.get_running_loop().call_soon(self._deliver_cancel, proc)
            else:
                proc.task.cancel()

    def _deliver_cancel(self, proc: _Proc) -> None:
        if not proc.finishing and proc.task is not None and not proc.task.done():
            proc.task.cancel()

    def _trip(self, proc: _Proc, detail: str) -> None:
        self._kill(proc, ExitReason.BUDGET_EXCEEDED, detail, None)

    def _term(self, proc: _Proc) -> None:
        if proc.finishing or proc.outcome is not None:
            return
        proc.outcome = _Outcome(ExitReason.KILLED, "TERM", Signal.TERM)
        if proc.state in (ProcessState.READY, ProcessState.SUSPENDED, ProcessState.SPAWN):
            self._kill(proc, ExitReason.KILLED, "TERM", Signal.TERM)
            return
        proc.token.cancel(ExitReason.KILLED, "TERM")
        proc.timers.append(asyncio.create_task(self._escalate(proc)))

    async def _escalate(self, proc: _Proc) -> None:
        await asyncio.sleep(self.config.term_grace_seconds)
        if not proc.finishing and not is_terminal(proc.state):
            self._event(TkiEventType.SIGNAL_DELIVERED, proc, signal="KILL", escalated=True)
            if proc.task is not None and not proc.task.done():
                proc.task.cancel()

    def _arm_watchdogs(self, proc: _Proc) -> None:
        if proc.spec.timeout_seconds is not None:
            proc.timers.append(
                asyncio.create_task(
                    self._watch(
                        proc, proc.spec.timeout_seconds, ExitReason.TIMEOUT, "process timeout"
                    )
                )
            )
        room = self.ledger.headroom(proc.account, Resource.RUNTIME_MS)
        if room is not None:
            proc.timers.append(
                asyncio.create_task(
                    self._watch(
                        proc, room / 1000, ExitReason.BUDGET_EXCEEDED, "runtime_ms hard cap"
                    )
                )
            )

    async def _watch(self, proc: _Proc, seconds: float, reason: ExitReason, detail: str) -> None:
        await asyncio.sleep(seconds)
        self._kill(proc, reason, detail, None)

    async def _main(self, proc: _Proc, workload: Workload) -> None:
        outcome: _Outcome
        try:
            proc.entered = True
            if proc.token.cancelled:  # killed before the first scheduling step
                raise ProcessCancelled(proc.token.detail)
            await self._await_slot(proc)
            res = await workload(ProcessContext(self, proc))
            outcome = (
                _Outcome(res.exit_reason, res.detail) if res else _Outcome(ExitReason.COMPLETED)
            )
        except asyncio.CancelledError:
            outcome = proc.outcome or _Outcome(ExitReason.KILLED, "cancelled", Signal.KILL)
        except ProcessCancelled:
            outcome = proc.outcome or _Outcome(ExitReason.KILLED, "cancelled", Signal.KILL)
        except BudgetExceededError as exc:
            outcome = proc.outcome or _Outcome(ExitReason.BUDGET_EXCEEDED, str(exc))
        except Exception as exc:
            outcome = proc.outcome or _Outcome(
                ExitReason.FAILED, f"{type(exc).__name__}: {str(exc)[:200]}"
            )
        task = asyncio.current_task()
        while task is not None and task.cancelling():
            task.uncancel()
        if proc.outcome is not None and proc.outcome.reason is not ExitReason.COMPLETED:
            # A kill/trip/term decided earlier wins over whatever the workload returned.
            outcome = proc.outcome
        await self._finish(proc, outcome)

    async def _finish(self, proc: _Proc, outcome: _Outcome) -> None:
        proc.finishing = True
        for t in proc.timers:
            t.cancel()
        # Children first: TERM then KILL, exit reason parent_terminated, no grace.
        live = [self._procs[c] for c in proc.children if not is_terminal(self._procs[c].state)]
        for child in live:
            self._event(TkiEventType.SIGNAL_DELIVERED, child, signal="TERM", by_parent=proc.pid)
            self._event(TkiEventType.SIGNAL_DELIVERED, child, signal="KILL", by_parent=proc.pid)
            self._kill(child, ExitReason.PARENT_TERMINATED, f"parent {proc.pid} terminated")
        for child in live:
            try:
                await asyncio.wait_for(child.done.wait(), self.config.child_kill_wait_seconds)
            except TimeoutError:
                self._force(child, ExitReason.PARENT_TERMINATED, "child ignored KILL")
        if proc.started_at is not None:
            elapsed = int((self._monotonic() - proc.started_at) * 1000)
            with contextlib.suppress(Exception):
                self.ledger.charge(proc.account, {Resource.RUNTIME_MS: elapsed})
        self._force(proc, outcome.reason, outcome.detail, outcome.trigger)

    def _force(
        self, proc: _Proc, reason: ExitReason, detail: str, trigger: str | None = Signal.KILL
    ) -> None:
        """Record termination (idempotent), release resources, notify listeners."""
        if is_terminal(proc.state):
            return
        self._unqueue(proc)
        self._release_slot(proc)
        if trigger is None:
            trigger = Lifecycle.EXIT if proc.state is ProcessState.RUNNING else Signal.KILL
        self._go(proc, trigger, reason=reason, detail=detail)
        proc.exit_reason, proc.detail = reason, detail
        proc.pause_requested = False
        for res in list(proc.reservations.values()):
            self.ledger.release(res)
        proc.reservations.clear()
        self.router.unregister(proc.pid)
        self.ledger.close_account(proc.account)
        if proc.grant is not None and not proc.grant.done():
            proc.grant.cancel()
        proc.done.set()
        for listener in list(self._listeners):
            listener(proc.view())
        self._dispatch()


__all__ = [
    "CancelToken",
    "Limit",
    "Priority",
    "ProcessCancelled",
    "ProcessContext",
    "ProcessView",
    "Scheduler",
    "SchedulerConfig",
    "SchedulerError",
    "SpawnError",
    "SpawnSpec",
    "Workload",
    "WorkloadResult",
]
