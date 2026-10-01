"""AgentProcess and ``run_agent``: drives one agent from a RuntimeManifest.

All process state lives in the event log (see ``events``): this module only *appends* lifecycle
events through ``RunRecorder`` and reads state back from the fold.  Every external action goes
through an ``ActionRunner`` (the ``ActionExecutor``, or a Temporal activity proxy).

Supervision (one-for-one): a failed child is restarted on its own, per the CHILD's
``restart_policy``/``max_restarts``; siblings are untouched.  Terminating a parent delivers TERM
then KILL to its children (exit reason ``parent_terminated``) without a grace period.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import hashlib
import json
import secrets
from collections.abc import Awaitable, Callable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from axis_runtime.actions import (
    Action,
    Backends,
    BrowserExec,
    CodeExec,
    McpCall,
    MessageSend,
    ModelCall,
    ToolCall,
    to_jsonable,
)
from axis_runtime.approvals import ApprovalResolver
from axis_runtime.events import (
    Clock,
    EventType,
    InMemoryRunEventLog,
    RunEventLog,
    RunRecorder,
    RunState,
    SystemClock,
)
from axis_runtime.executor import (
    ActionExecutor,
    ActionOutcome,
    ActionRunner,
    Completed,
    Denied,
    Failed,
    PendingApproval,
    RunIdentity,
)
from axis_runtime.gate import GateClient
from axis_runtime.manifest import ManifestError, RuntimeManifest, ToolSpec
from axis_runtime.models.gateway import ModelGateway
from axis_runtime.models.types import (
    CacheHints,
    Message,
    ModelRequest,
    ModelTarget,
    ToolCallRequest,
    ToolDefinition,
)
from axis_runtime.nexus.router import NexusRouter
from axis_runtime.nexus.types import RouteRequest, RouteResult
from axis_runtime.process import (
    ExitReason,
    Lifecycle,
    ProcessState,
    Signal,
    is_terminal,
    new_pid,
    next_state,
)
from axis_runtime.tools import ToolRegistry

ACTING_PID: ContextVar[str | None] = ContextVar("axis_acting_pid", default=None)


class ChildError(RuntimeError):
    """A child process did not complete (surfaced to the parent as a failed tool call)."""


#: ``(run context, child ref, tool args) -> child output``; raises ``ChildError`` if the child did
#: not complete. TKI supplies one (``tki.adapter.TkiChildSpawner``) so children run under a
#: supervisor with budgets; the child's actions still go through the same gate and executor.
ChildSpawner = Callable[["RunContext", str, Mapping[str, Any]], Awaitable[Any]]


@dataclass
class RunDeps:
    tenant_id: str
    gate: GateClient
    models: ModelGateway
    tools: ToolRegistry = field(default_factory=ToolRegistry)
    log: RunEventLog = field(default_factory=InMemoryRunEventLog)
    clock: Clock = field(default_factory=SystemClock)
    backends: Backends | None = None
    child_manifests: Mapping[str, RuntimeManifest] = field(default_factory=dict)
    run_id: str | None = None
    trace_id: str | None = None
    pid_factory: Callable[[], str] = new_pid
    runner_factory: Callable[[RunContext], ActionRunner] | None = None
    max_steps: int = 32
    exit_on_deny: bool = False
    term_grace_seconds: float = 5.0
    gate_timeout: float = 5.0
    #: When set, a REQUIRE_APPROVAL is resolved inline and the approved action is RE-GATED
    #: (executor.py); when absent the run parks with ``awaiting_approval`` as before.
    approvals: ApprovalResolver | None = None
    #: Builds the run's NEXUS router (``ctx.runner`` is the gated executor its LLM stage calls;
    #: ``ctx.nexus_event_sink()`` appends stage events to the run log). When set, every model
    #: step of every agent in the run is routed cache -> rules -> ... -> llm instead of calling
    #: the model directly. The LLM stage is still a gated ``ModelCall``; cache and rule hits are
    #: not actions.
    nexus_factory: Callable[[RunContext], NexusRouter] | None = None
    #: Replaces the built-in one-for-one child loop of ``AgentProcess.spawn_child`` (see TKI).
    child_spawner: ChildSpawner | None = None


class _Exit(Exception):
    def __init__(self, reason: ExitReason, detail: str = "") -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class _ModelAnswer:
    text: str
    tool_calls: tuple[ToolCallRequest, ...]


class _Parked(Exception):
    """The process is waiting on a human approval; the run is parked, not terminated."""

    def __init__(self, approval_id: str) -> None:
        super().__init__(approval_id)
        self.approval_id = approval_id


@dataclass
class RunContext:
    deps: RunDeps
    recorder: RunRecorder
    identity: RunIdentity
    runner: ActionRunner
    processes: dict[str, AgentProcess] = field(default_factory=dict)
    nexus: NexusRouter | None = None

    def nexus_event_sink(self) -> NexusRunSink:
        """An ``EventSink`` for ``NexusRouter`` that appends ``nexus_stage`` / ``nexus_route``
        events to THIS run's log, attributed to the process that is routing."""
        return NexusRunSink(self)

    async def spawn_child(self, ref: str, args: Mapping[str, Any]) -> Any:
        """``Backends.spawn``: called by an ``agent``-kind ToolCall performed for ACTING_PID."""
        pid = ACTING_PID.get()
        parent = self.processes.get(pid or "")
        if parent is None:
            raise ChildError("no acting process")
        return await parent.spawn_child(ref, args)


class NexusRunSink:
    """Appends NEXUS telemetry to the run log (the run's own hash-chained, replayable record)."""

    def __init__(self, ctx: RunContext) -> None:
        self._ctx = ctx

    async def emit(self, event_type: str, data: Mapping[str, Any]) -> None:
        pid = ACTING_PID.get()
        if pid is None or pid not in self._ctx.processes:
            return  # telemetry only: nothing is routing on behalf of a process of this run
        await self._ctx.recorder.record(event_type, pid, data)


@dataclass(frozen=True)
class ProcessResult:
    pid: str
    exit_reason: ExitReason | None
    output: str | None
    approval_id: str | None = None


@dataclass(frozen=True)
class RunResult:
    run_id: str
    pid: str
    status: str  # an ExitReason value, or "awaiting_approval"
    exit_reason: ExitReason | None
    output: str | None
    approval_id: str | None
    state: RunState


class AgentProcess:
    def __init__(
        self, manifest: RuntimeManifest, ctx: RunContext, *, ppid: str | None = None
    ) -> None:
        self.manifest = manifest
        self.ctx = ctx
        self.ppid = ppid
        self.pid = ctx.deps.pid_factory()
        self.children: list[AgentProcess] = []
        self._task: asyncio.Task[ProcessResult] | None = None
        self._pause_requested = False
        self._term_requested = False
        self._kill_requested = False
        self._parent_killed = False
        self._resume = asyncio.Event()
        self._interrupts: list[str] = []
        self._escalation: asyncio.Task[None] | None = None
        self._started = ctx.deps.clock.now()
        self._spawned_children = 0
        ctx.processes[self.pid] = self

    # ---- state (always derived from the log) ---------------------------------------------
    @property
    def state(self) -> ProcessState:
        return self.ctx.recorder.state.processes[self.pid].state

    async def spawn(self) -> None:
        await self.ctx.recorder.record(
            EventType.PROCESS_SPAWNED,
            self.pid,
            {"ppid": self.ppid, "agent": f"{self.manifest.name}@{self.manifest.version}"},
        )

    async def _go(
        self, trigger: str, *, reason: ExitReason | None = None, detail: str = ""
    ) -> None:
        cur = self.state
        to = next_state(cur, trigger)
        data: dict[str, Any] = {"from": cur.value, "to": to.value, "trigger": str(trigger)}
        if reason is not None:
            data["exit_reason"] = reason.value
            if detail:
                data["detail"] = detail[:300]
        await self.ctx.recorder.record(EventType.PROCESS_TRANSITION, self.pid, data)

    # ---- signals --------------------------------------------------------------------------
    async def deliver(
        self, sig: Signal, message: str | None = None, *, by_parent: bool = False
    ) -> None:
        if is_terminal(self.state):
            return
        data: dict[str, Any] = {"signal": sig.value}
        if message:
            data["message"] = message
        await self.ctx.recorder.record(EventType.SIGNAL_DELIVERED, self.pid, data)
        if sig is Signal.PAUSE:
            self._pause_requested = True
        elif sig is Signal.RESUME:
            self._pause_requested = False
            self._resume.set()
        elif sig is Signal.INTERRUPT:
            self._interrupts.append(message or "")
        elif sig is Signal.TERM:
            self._term_requested = True
            self._resume.set()
            if not by_parent and self._escalation is None:
                self._escalation = asyncio.create_task(self._escalate())
        elif sig is Signal.KILL:
            self._kill_requested = True
            self._resume.set()
            if self._task is not None:
                self._task.cancel()

    async def _escalate(self) -> None:
        await asyncio.sleep(self.ctx.deps.term_grace_seconds)
        await self.deliver(Signal.KILL)

    # ---- main -----------------------------------------------------------------------------
    async def run(self, input_text: str) -> ProcessResult:
        self._task = asyncio.current_task()
        reason: ExitReason | None = None
        detail = ""
        parked: str | None = None
        reraise: asyncio.CancelledError | None = None
        output: str | None = None
        timeout_cm = asyncio.timeout(self.manifest.process.timeout_seconds)
        try:
            async with timeout_cm:
                output = await self._lifecycle(input_text)
                reason = ExitReason.COMPLETED
        except _Exit as exc:
            reason, detail = exc.reason, exc.detail
        except _Parked as exc:
            parked = exc.approval_id
        except asyncio.CancelledError as exc:
            if self._kill_requested and not self._parent_killed:
                reason, detail = ExitReason.KILLED, "KILL"
                if self._task is not None:
                    self._task.uncancel()
            else:
                reason, detail, reraise = ExitReason.PARENT_TERMINATED, "", exc
        except TimeoutError as exc:
            if timeout_cm.expired():
                reason, detail = ExitReason.TIMEOUT, "process timeout"
            else:
                reason, detail = ExitReason.FAILED, f"TimeoutError: {str(exc)[:200]}"
        except Exception as exc:
            reason, detail = ExitReason.FAILED, f"{type(exc).__name__}: {str(exc)[:200]}"

        if reason is not None:
            if reason is ExitReason.COMPLETED and output is not None:
                await self.ctx.recorder.record(
                    EventType.PROCESS_OUTPUT, self.pid, {"output": output}
                )
            await self._terminate(reason, detail)
        if self._escalation is not None:
            self._escalation.cancel()
        if reraise is not None:
            raise reraise
        st = self.ctx.recorder.state.processes[self.pid]
        return ProcessResult(
            self.pid, st.exit_reason, self.ctx.recorder.state.outputs.get(self.pid), parked
        )

    async def _terminate(self, reason: ExitReason, detail: str) -> None:
        cur = self.state
        if is_terminal(cur):
            return
        if cur is ProcessState.RUNNING:
            trigger: str = Lifecycle.EXIT
        elif cur is ProcessState.SPAWN:
            trigger = Lifecycle.INIT_FAILED if reason is ExitReason.FAILED else Signal.KILL
        elif reason is ExitReason.KILLED and self._term_requested and not self._kill_requested:
            trigger = Signal.TERM
        else:
            trigger = Signal.KILL
        await self._go(trigger, reason=reason, detail=detail)

    async def _lifecycle(self, input_text: str) -> str:
        try:
            self.manifest.validate_supported()
        except ManifestError as exc:
            raise _Exit(ExitReason.FAILED, f"init: {exc}") from exc
        await self._go(Lifecycle.INIT_COMPLETE)
        await self._go(Lifecycle.SCHEDULED)
        return await self._agent_loop(input_text)

    # ---- safe points and budgets ---------------------------------------------------------
    async def _safe_point(self) -> None:
        if self._term_requested:
            raise _Exit(ExitReason.KILLED, "TERM")
        if self._pause_requested:
            self._resume.clear()
            await self._go(Signal.PAUSE)
            while self._pause_requested and not self._term_requested:
                await self._resume.wait()
                self._resume.clear()
            if self._term_requested:
                raise _Exit(ExitReason.KILLED, "TERM")
            await self._go(Signal.RESUME)
            await self._go(Lifecycle.SCHEDULED)

    def _usage(self) -> dict[str, float]:
        st = self.ctx.recorder.state
        mine = [m for m in st.model_calls if m.pid == self.pid]
        elapsed = (self.ctx.deps.clock.now() - self._started).total_seconds()
        return {
            "tokens": float(sum(m.input_tokens + m.output_tokens for m in mine)),
            "cost_usd": sum(m.cost_micro_usd or 0 for m in mine) / 1_000_000,
            "runtime_seconds": elapsed,
            "tool_calls": float(sum(1 for t in st.tool_calls if t.pid == self.pid)),
        }

    async def _check_budgets(
        self, *, extra_tool_call: bool = False, before_model: bool = False
    ) -> None:
        usage = self._usage()
        if extra_tool_call:
            usage["tool_calls"] += 1
        b = self.manifest.budgets
        for name, budget in (
            ("tokens", b.tokens),
            ("cost_usd", b.cost_usd),
            ("runtime_seconds", b.runtime_seconds),
            ("tool_calls", b.tool_calls),
        ):
            used = usage[name]
            key = f"{self.pid}:{name}"
            if (
                budget.soft is not None
                and used >= budget.soft
                and key not in self.ctx.recorder.state.warnings
            ):
                await self.ctx.recorder.record(EventType.BUDGET_WARNING, self.pid, {"budget": key})
            if budget.hard is not None and (
                used > budget.hard or (before_model and name == "tokens" and used >= budget.hard)
            ):
                raise _Exit(ExitReason.BUDGET_EXCEEDED, f"{name} hard cap {budget.hard} exceeded")

    # ---- actions --------------------------------------------------------------------------
    async def _act(self, action: Action) -> ActionOutcome:
        await self._go(Lifecycle.AWAIT)
        marker = ACTING_PID.set(self.pid)
        try:
            outcome = await self.ctx.runner.run(action, pid=self.pid)
        finally:
            ACTING_PID.reset(marker)
        if isinstance(outcome, PendingApproval):
            raise _Parked(outcome.approval_id)  # stays in `waiting`
        await self._go(Lifecycle.WAKE)
        return outcome

    def _action_for(self, spec: ToolSpec, args: Mapping[str, Any]) -> Action:
        common: dict[str, Any] = {"name": spec.name, "args": dict(args)}
        if spec.kind == "mcp":
            return McpCall(
                **common, mcp_server=spec.mcp_server or "", side_effects=spec.side_effects
            )
        if spec.kind == "code":
            return CodeExec(
                **common, side_effects=spec.side_effects, timeout_seconds=spec.timeout_seconds
            )
        if spec.kind == "browser":
            return BrowserExec(**common, side_effects=spec.side_effects)
        if spec.kind == "channel":
            return MessageSend(
                **common, channel=spec.ref or spec.name, side_effects=spec.side_effects
            )
        return ToolCall(**common, kind=spec.kind, side_effects=spec.side_effects, ref=spec.ref)

    def _tool_definitions(self) -> tuple[ToolDefinition, ...]:
        registry = self.ctx.deps.tools
        defs = []
        for spec in self.manifest.tools:
            reg = registry.get(spec.ref or spec.name)
            defs.append(
                ToolDefinition(
                    spec.name,
                    reg.description if reg else "",
                    reg.input_schema if reg else {"type": "object"},
                )
            )
        return tuple(defs)

    def _model_request(self, messages: list[Message]) -> ModelRequest:
        m = self.manifest
        return ModelRequest(
            tenant_id=self.ctx.deps.tenant_id,
            messages=tuple(messages),
            target=ModelTarget(
                m.primary.provider, m.primary.model, m.primary.endpoint, m.primary.params
            ),
            tools=self._tool_definitions(),
            fallbacks=tuple(
                ModelTarget(f.provider, f.model, f.endpoint, f.params) for f in m.fallbacks
            ),
            cache=CacheHints(system=True),
        )

    async def _agent_loop(self, input_text: str) -> str:
        messages: list[Message] = []
        if self.manifest.system_prompt:
            messages.append(Message("system", self.manifest.system_prompt))
        messages.append(Message("user", input_text))
        for _ in range(self.ctx.deps.max_steps):
            await self._safe_point()
            while self._interrupts:
                messages.append(Message("user", f"[interrupt] {self._interrupts.pop(0)}"))
            await self._check_budgets(before_model=True)
            response = await self._model_step(messages)
            await self._check_budgets()
            if not response.tool_calls:
                return str(response.text)
            messages.append(Message("assistant", response.text, tuple(response.tool_calls)))
            for call in response.tool_calls:
                await self._safe_point()
                messages.append(await self._run_tool(call))
        raise _Exit(ExitReason.FAILED, f"max_steps ({self.ctx.deps.max_steps}) reached")

    async def _model_step(self, messages: list[Message]) -> _ModelAnswer:
        """One model turn: a gated ``ModelCall``, or (NEXUS configured) a routed one."""
        if self.ctx.nexus is not None:
            return await self._routed_model_step(self.ctx.nexus, messages)
        primary = self.manifest.primary
        outcome = await self._act(
            ModelCall(
                name=f"{primary.provider}/{primary.model}",
                request=self._model_request(messages),
            )
        )
        if isinstance(outcome, Denied):
            raise _Exit(ExitReason.POLICY_DENIED, f"model call denied: {outcome.reason}")
        if isinstance(outcome, Failed):
            raise _Exit(ExitReason.FAILED, f"model call failed: {outcome.error}")
        if not isinstance(outcome, Completed):
            raise _Exit(ExitReason.FAILED, "unexpected action outcome")
        return _ModelAnswer(str(outcome.result.text), tuple(outcome.result.tool_calls))

    async def _routed_model_step(
        self, router: NexusRouter, messages: list[Message]
    ) -> _ModelAnswer:
        """Same transitions and failure mapping as ``_act``, with NEXUS deciding the answer."""
        m = self.manifest
        last_user = next((x.content for x in reversed(messages) if x.role == "user"), "")
        request = RouteRequest(
            tenant_id=self.ctx.deps.tenant_id,
            prompt=last_user,
            pid=self.pid,
            agent=m.name,
            agent_version=m.version,
            phi=m.phi,
            trace_id=self.ctx.identity.trace_id,
            system_prompt=m.system_prompt,
            messages=tuple(messages),
            tools=self._tool_definitions(),
        )
        await self._go(Lifecycle.AWAIT)
        marker = ACTING_PID.set(self.pid)
        try:
            route: RouteResult = await router.route(request)
        finally:
            ACTING_PID.reset(marker)
        if route.status == "blocked":
            reason = route.blocked_reason
            if reason.startswith("approval_pending:"):
                raise _Parked(reason.removeprefix("approval_pending:"))  # stays `waiting`
            raise _Exit(
                ExitReason.POLICY_DENIED, f"model call denied: {reason.removeprefix('denied:')}"
            )
        if route.status != "hit" or route.answer is None:
            raise _Exit(ExitReason.FAILED, "model call failed: no routing stage produced an answer")
        await self._go(Lifecycle.WAKE)
        return _ModelAnswer(route.answer, tuple(route.tool_calls))

    async def _run_tool(self, call: ToolCallRequest) -> Message:
        def reply(content: str, *, error: bool = False) -> Message:
            return Message("tool", content, tool_call_id=call.id, name=call.name, is_error=error)

        spec = self.manifest.tool(call.name)
        if spec is None:
            return reply(f"unknown tool {call.name!r}", error=True)
        await self._check_budgets(extra_tool_call=True)
        outcome = await self._act(self._action_for(spec, call.arguments))
        if isinstance(outcome, Completed):
            return reply(json.dumps(to_jsonable(outcome.result)))
        if isinstance(outcome, Denied):
            if self.ctx.deps.exit_on_deny:
                raise _Exit(ExitReason.POLICY_DENIED, f"{call.name} denied: {outcome.reason}")
            return reply(f"denied by policy: {outcome.reason}", error=True)
        return reply(
            outcome.error if isinstance(outcome, Failed) else "unexpected outcome", error=True
        )

    # ---- children (supervisor: one-for-one, or TKI via ``RunDeps.child_spawner``) ----------
    async def spawn_child(self, ref: str, args: Mapping[str, Any]) -> Any:
        child_manifest = self.ctx.deps.child_manifests.get(ref)
        if child_manifest is None:
            raise ChildError(f"unknown child agent {ref!r}")
        if self._spawned_children >= self.manifest.process.max_children:
            raise ChildError(f"max_children ({self.manifest.process.max_children}) reached")
        self._spawned_children += 1
        if self.ctx.deps.child_spawner is not None:
            return await self.ctx.deps.child_spawner(self.ctx, ref, args)
        input_text = str(args.get("input") or json.dumps(to_jsonable(args)))
        restarts = 0
        while True:
            child = AgentProcess(child_manifest, self.ctx, ppid=self.pid)
            self.children.append(child)
            await child.spawn()
            task = asyncio.create_task(child.run(input_text))
            try:
                result = await task
            except asyncio.CancelledError:
                # Parent is being terminated: TERM then KILL, reason parent_terminated.
                child._parent_killed = True  # noqa: SLF001
                await child.deliver(Signal.TERM, by_parent=True)
                await child.deliver(Signal.KILL, by_parent=True)
                with contextlib.suppress(asyncio.CancelledError):
                    await task
                raise
            if result.exit_reason is ExitReason.COMPLETED:
                return result.output
            failed = result.exit_reason in (ExitReason.FAILED, ExitReason.TIMEOUT)
            cp = child_manifest.process
            if failed and cp.restart_policy == "on_failure" and restarts < cp.max_restarts:
                restarts += 1
                continue
            raise ChildError(f"child {ref!r} exited: {result.exit_reason}")


# --------------------------------------------------------------------------------------


class RunHandle:
    def __init__(
        self, ctx: RunContext, root: AgentProcess, task: asyncio.Task[ProcessResult]
    ) -> None:
        self.ctx = ctx
        self.root = root
        self._task = task

    @property
    def run_id(self) -> str:
        return self.ctx.recorder.run_id

    @property
    def pid(self) -> str:
        return self.root.pid

    @property
    def state(self) -> RunState:
        return self.ctx.recorder.state

    async def signal(
        self, sig: Signal, message: str | None = None, *, pid: str | None = None
    ) -> None:
        target = self.ctx.processes[pid] if pid else self.root
        await target.deliver(sig, message)

    async def result(self) -> RunResult:
        pr = await self._task
        status = pr.exit_reason.value if pr.exit_reason else "awaiting_approval"
        return RunResult(
            run_id=self.run_id,
            pid=self.root.pid,
            status=status,
            exit_reason=pr.exit_reason,
            output=pr.output,
            approval_id=pr.approval_id,
            state=self.ctx.recorder.state,
        )


async def start_agent(manifest: RuntimeManifest, input_text: str, deps: RunDeps) -> RunHandle:
    run_id = deps.run_id or f"run_{secrets.token_hex(12)}"
    trace_id = deps.trace_id or secrets.token_hex(16)
    recorder = await RunRecorder.start(
        deps.log,
        deps.clock,
        run_id=run_id,
        tenant_id=deps.tenant_id,
        meta={
            "blueprint": manifest.name,
            "version": manifest.version,
            "content_hash": manifest.content_hash,
            "input_hash": hashlib.sha256(input_text.encode("utf-8")).hexdigest(),
            "trace_id": trace_id,
        },
    )
    identity = RunIdentity(
        tenant_id=deps.tenant_id,
        run_id=run_id,
        trace_id=trace_id,
        span_id=hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:16],  # deterministic (Temporal)
        blueprint_name=manifest.name,
        blueprint_version=manifest.version,
        phi=manifest.phi,
    )
    backends = dataclasses.replace(
        deps.backends or Backends(), tools=deps.tools, models=deps.models
    )
    placeholder: Any = None
    ctx = RunContext(deps, recorder, identity, placeholder)
    backends.spawn = ctx.spawn_child
    ctx.runner = (
        deps.runner_factory(ctx)
        if deps.runner_factory
        else ActionExecutor(
            gate=deps.gate,
            recorder=recorder,
            identity=identity,
            backends=backends,
            gate_timeout=deps.gate_timeout,
            approvals=deps.approvals,
        )
    )
    if deps.nexus_factory is not None:
        ctx.nexus = deps.nexus_factory(ctx)
    root = AgentProcess(manifest, ctx)
    await root.spawn()
    task = asyncio.create_task(root.run(input_text))
    return RunHandle(ctx, root, task)


async def run_agent(manifest: RuntimeManifest, input_text: str, deps: RunDeps) -> RunResult:
    return await (await start_agent(manifest, input_text, deps)).result()
