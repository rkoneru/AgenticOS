"""Temporal integration (Prototype): each agent run is a durable ``AgentRunWorkflow``.

Split of responsibilities
  * The WORKFLOW runs the very same ``AgentProcess`` loop as ``run_agent`` but with three
    substitutions, so it stays deterministic: the clock is ``workflow.now()``, PIDs come from
    ``workflow.random()``, and all I/O goes through activities.
  * ``ActivityRunner`` (an ``ActionRunner``) turns every Action into an ``axis.run_action``
    activity.  The activity worker holds the real gate, backends and event store: it resumes the
    run from the event log, runs ``ActionExecutor.run`` and returns the events it appended, which
    the workflow folds into its own state.  Activity results ARE the event-log entries.
  * Lifecycle events sealed by the workflow are persisted through ``axis.append_run_event``
    (idempotent, so safe to retry).
  * ``axis.run_action`` is at-most-once (``maximum_attempts=1``): a retried side-effecting activity
    could repeat an action.  If it fails, the workflow re-syncs from the log and reports a failed
    action instead of guessing.

Not supported under Temporal yet: ``agent``-kind tools (child processes), streaming, approval
resume (a REQUIRE_APPROVAL run parks in ``waiting``).  See docs/spec/runtime.md.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from temporalio import activity, workflow
from temporalio.client import Client
from temporalio.common import RetryPolicy as TemporalRetryPolicy
from temporalio.exceptions import ActivityError, ApplicationError
from temporalio.exceptions import CancelledError as TemporalCancelledError
from temporalio.worker import Worker

with workflow.unsafe.imports_passed_through():
    from axis_runtime._decision import Decision
    from axis_runtime.actions import (
        Action,
        Backends,
        ModelCall,
        action_from_spec,
        to_jsonable,
    )
    from axis_runtime.events import (
        RunEvent,
        RunEventLog,
        RunRecorder,
        SequenceConflictError,
        SystemClock,
    )
    from axis_runtime.executor import (
        ActionExecutor,
        ActionOutcome,
        Completed,
        Denied,
        Failed,
        PendingApproval,
        RunIdentity,
    )
    from axis_runtime.gate import EvaluateRequest, GateClient, GateDecision, deny
    from axis_runtime.manifest import ManifestError, RuntimeManifest
    from axis_runtime.models.types import ModelResponse
    from axis_runtime.process import Signal, new_pid
    from axis_runtime.run import RunContext, RunDeps, start_agent
    from axis_runtime.tools import ToolRegistry

APPEND_ACTIVITY = "axis.append_run_event"
RUN_ACTION_ACTIVITY = "axis.run_action"
READ_EVENTS_ACTIVITY = "axis.read_run_events"


@dataclass
class AgentRunInput:
    manifest: dict[str, Any]
    input: str
    tenant_id: str
    run_id: str
    trace_id: str
    tool_schemas: dict[str, dict[str, Any]] = field(default_factory=dict)
    max_steps: int = 32
    exit_on_deny: bool = False
    action_timeout_seconds: int = 300


@dataclass
class AgentRunOutput:
    run_id: str
    pid: str
    status: str
    exit_reason: str | None
    output: str | None
    approval_id: str | None
    last_seq: int
    last_hash: str


@dataclass
class RunActionInput:
    run_id: str
    pid: str
    identity: dict[str, Any]
    action: dict[str, Any]


@dataclass
class RunActionOutput:
    events: list[dict[str, Any]]
    outcome: dict[str, Any]


# ---- (de)serialisation of outcomes -----------------------------------------------------------


def _decision_to_dict(d: GateDecision) -> dict[str, Any]:
    return {
        "decision": d.decision.value,
        "reason": d.reason,
        "policy_version": d.policy_version,
        "matched_rule_ids": list(d.matched_rule_ids),
        "redact_fields": list(d.redact_fields),
        "approval_id": d.approval_id,
        "audit_event_id": d.audit_event_id,
    }


def _decision_from_dict(raw: dict[str, Any]) -> GateDecision:
    return GateDecision(
        decision=Decision(raw["decision"]),
        reason=raw["reason"],
        policy_version=raw["policy_version"],
        matched_rule_ids=tuple(raw["matched_rule_ids"]),
        redact_fields=tuple(raw["redact_fields"]),
        approval_id=raw["approval_id"],
        audit_event_id=raw["audit_event_id"],
    )


def outcome_to_dict(outcome: ActionOutcome) -> dict[str, Any]:
    base = {"decision": _decision_to_dict(outcome.decision)}
    if isinstance(outcome, Completed):
        result = outcome.result
        return {
            **base,
            "kind": "completed",
            "result": result.to_dict()
            if isinstance(result, ModelResponse)
            else to_jsonable(result),
        }
    if isinstance(outcome, Denied):
        return {**base, "kind": "denied", "reason": outcome.reason}
    if isinstance(outcome, PendingApproval):
        return {
            **base,
            "kind": "pending",
            "approval_id": outcome.approval_id,
            "reason": outcome.reason,
        }
    return {**base, "kind": "failed", "error": outcome.error}


def outcome_from_dict(raw: dict[str, Any], action: Action) -> ActionOutcome:
    decision = _decision_from_dict(raw["decision"])
    kind = raw["kind"]
    if kind == "completed":
        result = raw["result"]
        if isinstance(action, ModelCall):
            result = ModelResponse.from_dict(result)
        return Completed(result, decision)
    if kind == "denied":
        return Denied(raw["reason"], decision)
    if kind == "pending":
        return PendingApproval(raw["approval_id"], raw["reason"], decision)
    return Failed(raw["error"], decision)


# ---- activities (worker side: real gate, backends, event store) ------------------------------


class AgentActivities:
    def __init__(
        self,
        *,
        log: RunEventLog,
        gate: GateClient,
        backends: Backends,
        gate_timeout: float = 5.0,
    ) -> None:
        self._log = log
        self._gate = gate
        self._backends = backends
        self._gate_timeout = gate_timeout

    @activity.defn(name=APPEND_ACTIVITY)
    async def append_run_event(self, event: dict[str, Any]) -> None:
        try:
            await self._log.append(RunEvent.from_dict(event))
        except SequenceConflictError as exc:
            # A retried sealed event cannot succeed; the workflow rebuilds it on the new head.
            raise ApplicationError(
                str(exc), type="SequenceConflictError", non_retryable=True
            ) from exc

    @activity.defn(name=READ_EVENTS_ACTIVITY)
    async def read_run_events(self, run_id: str, after_seq: int) -> list[dict[str, Any]]:
        return [e.to_dict() for e in (await self._log.read(run_id))[after_seq:]]

    @activity.defn(name=RUN_ACTION_ACTIVITY)
    async def run_action(self, inp: RunActionInput) -> RunActionOutput:
        recorder = await RunRecorder.resume(self._log, SystemClock(), inp.run_id)
        before = recorder.state.last_seq
        executor = ActionExecutor(
            gate=self._gate,
            recorder=recorder,
            identity=RunIdentity(**inp.identity),
            backends=self._backends,
            gate_timeout=self._gate_timeout,
        )
        outcome = await executor.run(action_from_spec(inp.action), pid=inp.pid)
        new = (await self._log.read(inp.run_id))[before:]
        return RunActionOutput([e.to_dict() for e in new], outcome_to_dict(outcome))

    def all(self) -> list[Any]:
        return [self.append_run_event, self.read_run_events, self.run_action]


# ---- workflow-side substitutions -------------------------------------------------------------


class WorkflowClock:
    def now(self) -> datetime:
        return workflow.now()


class ActivityLog:
    """RunEventLog whose appends are activities (durable, idempotent)."""

    def __init__(self, timeout: timedelta = timedelta(seconds=30)) -> None:
        self._timeout = timeout

    async def append(self, event: RunEvent) -> None:
        try:
            await workflow.execute_activity(
                APPEND_ACTIVITY,
                event.to_dict(),
                start_to_close_timeout=self._timeout,
                retry_policy=TemporalRetryPolicy(maximum_attempts=5),
            )
        except ActivityError as exc:
            if (
                isinstance(exc.cause, ApplicationError)
                and exc.cause.type == "SequenceConflictError"
            ):
                raise SequenceConflictError(str(exc.cause.message)) from exc
            raise

    async def read_after(self, run_id: str, after_seq: int) -> list[RunEvent]:
        raw: list[dict[str, Any]] = await workflow.execute_activity(
            READ_EVENTS_ACTIVITY,
            args=[run_id, after_seq],
            start_to_close_timeout=self._timeout,
            retry_policy=TemporalRetryPolicy(maximum_attempts=5),
        )
        return [RunEvent.from_dict(e) for e in raw]

    async def read(
        self, run_id: str
    ) -> list[RunEvent]:  # pragma: no cover - never used in-workflow
        raise NotImplementedError("the workflow never reads the store; it folds activity results")


class _NoGate:
    """The workflow holds no gate: every evaluation happens inside the activity (fail-closed)."""

    async def evaluate(self, request: EvaluateRequest) -> GateDecision:  # pragma: no cover
        return deny("gate_not_available_in_workflow")


class ActivityRunner:
    """ActionRunner that performs actions by executing ``axis.run_action`` activities."""

    def __init__(self, ctx: RunContext, timeout_seconds: int) -> None:
        self._ctx = ctx
        self._timeout = timedelta(seconds=timeout_seconds)

    async def run(self, action: Action, *, pid: str) -> ActionOutcome:
        ident = self._ctx.identity
        inp = RunActionInput(
            run_id=ident.run_id,
            pid=pid,
            identity={
                "tenant_id": ident.tenant_id,
                "run_id": ident.run_id,
                "trace_id": ident.trace_id,
                "span_id": ident.span_id,
                "blueprint_name": ident.blueprint_name,
                "blueprint_version": ident.blueprint_version,
                "phi": ident.phi,
            },
            action=action.to_spec(),
        )
        try:
            out: RunActionOutput = await workflow.execute_activity(
                RUN_ACTION_ACTIVITY,
                inp,
                result_type=RunActionOutput,
                start_to_close_timeout=self._timeout,
                retry_policy=TemporalRetryPolicy(maximum_attempts=1),  # at-most-once side effects
            )
        except ActivityError as exc:
            if isinstance(exc.cause, TemporalCancelledError):
                # Killed/terminated while the action was in flight: propagate the cancellation so
                # the process exits `killed`, not `failed`. The orphaned activity may still append;
                # the recorder folds such events on its next append.
                raise asyncio.CancelledError from exc
            await self._resync()
            cause = type(exc.cause).__name__ if exc.cause else type(exc).__name__
            return Failed(f"activity_failed:{cause}", deny("activity_failed"))
        self._ctx.recorder.ingest(RunEvent.from_dict(e) for e in out.events)
        return outcome_from_dict(out.outcome, action)

    async def _resync(self) -> None:
        """Fold events an activity appended before it failed, so the next append is not a fork."""
        rec = self._ctx.recorder
        raw: list[dict[str, Any]] = await workflow.execute_activity(
            READ_EVENTS_ACTIVITY,
            args=[rec.run_id, rec.state.last_seq],
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=TemporalRetryPolicy(maximum_attempts=5),
        )
        rec.ingest(RunEvent.from_dict(e) for e in raw)


def _never(args: Any) -> Any:  # pragma: no cover - schema-only stub, real tools run in the activity
    raise RuntimeError("tools never run inside the workflow")


@workflow.defn(name="AgentRunWorkflow")
class AgentRunWorkflow:
    def __init__(self) -> None:
        self._handle: Any = None

    @workflow.signal
    async def send_signal(self, signal: str, message: str | None = None) -> None:
        await workflow.wait_condition(lambda: self._handle is not None)
        await self._handle.signal(Signal(signal), message)

    @workflow.query
    def process_states(self) -> dict[str, str]:
        if self._handle is None:
            return {}
        return {pid: p.state.value for pid, p in self._handle.state.processes.items()}

    @workflow.run
    async def run(self, inp: AgentRunInput) -> AgentRunOutput:
        try:
            manifest = RuntimeManifest.from_dict(inp.manifest)
        except ManifestError as exc:
            # A plain exception fails the workflow *task* and retries forever; fail the execution.
            raise ApplicationError(str(exc), type="ManifestError", non_retryable=True) from exc
        registry = ToolRegistry()
        for spec in manifest.tools:
            schema = inp.tool_schemas.get(spec.ref or spec.name, {})
            registry.register(
                spec.ref or spec.name,
                _never,
                description=schema.get("description", ""),
                input_schema=schema.get("input_schema"),
            )
        deps = RunDeps(
            tenant_id=inp.tenant_id,
            gate=_NoGate(),
            models=None,  # type: ignore[arg-type]  # model calls run in activities
            tools=registry,
            log=ActivityLog(),
            clock=WorkflowClock(),
            run_id=inp.run_id,
            trace_id=inp.trace_id,
            pid_factory=lambda: new_pid(
                now_ms=int(workflow.now().timestamp() * 1000),
                randbytes=workflow.random().randbytes,
            ),
            runner_factory=lambda ctx: ActivityRunner(ctx, inp.action_timeout_seconds),
            max_steps=inp.max_steps,
            exit_on_deny=inp.exit_on_deny,
        )
        self._handle = await start_agent(manifest, inp.input, deps)
        result = await self._handle.result()
        return AgentRunOutput(
            run_id=result.run_id,
            pid=result.pid,
            status=result.status,
            exit_reason=result.exit_reason.value if result.exit_reason else None,
            output=result.output,
            approval_id=result.approval_id,
            last_seq=result.state.last_seq,
            last_hash=result.state.last_hash,
        )


def build_worker(
    client: Client, *, task_queue: str, activities: AgentActivities, **kwargs: Any
) -> Worker:
    return Worker(
        client,
        task_queue=task_queue,
        workflows=[AgentRunWorkflow],
        activities=activities.all(),
        **kwargs,
    )
