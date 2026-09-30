"""ActionExecutor: the ONLY way an Action is performed.

``run(action)`` = build gate request -> gate (fail-closed) -> append ``gate_decision`` event ->
perform iff ALLOW / ALLOW_WITH_REDACTION.  DENY and REQUIRE_APPROVAL perform nothing.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Protocol

from axis_runtime._decision import Decision
from axis_runtime.actions import (
    Action,
    Backends,
    ExecutionToken,
    bind_executor_token,
    to_jsonable,
)
from axis_runtime.events import EventType, RunRecorder
from axis_runtime.gate import (
    ActorType,
    EvaluateRequest,
    FailClosedGate,
    GateClient,
    GateDecision,
    deny,
    validate_decision,
)
from axis_runtime.process import ProcessState
from axis_runtime.redaction import RedactionPathError, redact_paths, split_scope

_TOKEN = ExecutionToken()
bind_executor_token(_TOKEN)

_RUNNABLE = {ProcessState.RUNNING, ProcessState.WAITING}


@dataclass(frozen=True)
class RunIdentity:
    tenant_id: str
    run_id: str
    trace_id: str
    span_id: str
    blueprint_name: str
    blueprint_version: str
    phi: bool = False
    actor_type: ActorType = ActorType.AGENT
    actor_id: str = ""


@dataclass(frozen=True)
class Completed:
    result: Any
    decision: GateDecision


@dataclass(frozen=True)
class Denied:
    reason: str
    decision: GateDecision


@dataclass(frozen=True)
class PendingApproval:
    approval_id: str
    reason: str
    decision: GateDecision


@dataclass(frozen=True)
class Failed:
    """The gate allowed the action but performing it raised."""

    error: str
    decision: GateDecision


ActionOutcome = Completed | Denied | PendingApproval | Failed


class ActionRunner(Protocol):
    async def run(self, action: Action, *, pid: str) -> ActionOutcome: ...


class ActionExecutor:
    def __init__(
        self,
        *,
        gate: GateClient,
        recorder: RunRecorder,
        identity: RunIdentity,
        backends: Backends,
        gate_timeout: float = 5.0,
    ) -> None:
        self._gate: GateClient = (
            gate if isinstance(gate, FailClosedGate) else FailClosedGate(gate, gate_timeout)
        )
        self._recorder = recorder
        self._identity = identity
        self._backends = backends
        st = recorder.state
        self._counter = len(st.gate_decisions) + st.blocked_actions

    def _next_action_id(self) -> str:
        self._counter += 1
        return f"act_{self._counter:06d}"

    def _request(self, action: Action, pid: str) -> EvaluateRequest:
        ident = self._identity
        ep = action.enforcement_point
        context = {
            "tool": action.tool_descriptor(),
            "args": to_jsonable(action.gate_args()),
            "data": {"phi": ident.phi},
            "tenant": {"id": ident.tenant_id},
            "agent": {"name": ident.blueprint_name, "version": ident.blueprint_version},
            "run": {"id": ident.run_id},
            "actor": {"type": ident.actor_type.value, "id": ident.actor_id or pid},
            "enforcement_point": ep.value,
        }
        return EvaluateRequest(
            tenant_id=ident.tenant_id,
            trace_id=ident.trace_id,
            span_id=ident.span_id,
            actor_type=ident.actor_type,
            actor_id=ident.actor_id or pid,
            pid=pid,
            blueprint_name=ident.blueprint_name,
            blueprint_version=ident.blueprint_version,
            enforcement_point=ep,
            action=action.name,
            context=context,
        )

    def _runnable(self, pid: str) -> bool:
        info = self._recorder.state.processes.get(pid)
        return info is not None and info.state in _RUNNABLE

    async def _block(self, pid: str, action_id: str, action: Action, reason: str) -> Denied:
        await self._recorder.record(
            EventType.ACTION_BLOCKED,
            pid,
            {
                "action_id": action_id,
                "enforcement_point": action.enforcement_point.value,
                "action": action.name,
                "reason": reason,
            },
        )
        return Denied(reason, deny(reason))

    async def run(self, action: Action, *, pid: str) -> ActionOutcome:
        if pid not in self._recorder.state.processes:
            raise KeyError(f"unknown pid {pid!r}")
        action_id = self._next_action_id()
        if not self._runnable(pid):
            state = self._recorder.state.processes[pid].state.value
            return await self._block(pid, action_id, action, f"process_not_runnable:{state}")

        try:
            decision = validate_decision(await self._gate.evaluate(self._request(action, pid)))
        except Exception as exc:  # FailClosedGate should prevent this; never trust it
            decision = deny(f"gate_error:{type(exc).__name__}")

        if not self._runnable(pid):  # killed/paused while the gate was thinking
            return await self._block(pid, action_id, action, "process_terminated_during_gate")

        await self._recorder.record(
            EventType.GATE_DECISION,
            pid,
            {
                "action_id": action_id,
                "enforcement_point": action.enforcement_point.value,
                "action": action.name,
                "decision": decision.decision.value,
                "reason": decision.reason,
                "policy_version": decision.policy_version,
                "redact_fields": list(decision.redact_fields),
                "approval_id": decision.approval_id,
                "audit_event_id": decision.audit_event_id,
            },
        )

        if decision.decision is Decision.DENY:
            return Denied(decision.reason or "denied", decision)
        if decision.decision is Decision.REQUIRE_APPROVAL:
            return PendingApproval(decision.approval_id, decision.reason, decision)
        if decision.decision not in (Decision.ALLOW, Decision.ALLOW_WITH_REDACTION):
            return Denied("unknown_decision", decision)  # defence in depth

        to_perform = action
        result_paths: list[str] = []
        if decision.decision is Decision.ALLOW_WITH_REDACTION:
            try:
                arg_paths, result_paths = split_scope(decision.redact_fields)
                to_perform = action.with_args(redact_paths(action.gate_args(), arg_paths))
            except (RedactionPathError, ValueError, KeyError, TypeError):
                return await self._block(pid, action_id, action, "redaction_failed")

        try:
            result = await to_perform.perform(_TOKEN, self._backends)
            if decision.decision is Decision.ALLOW_WITH_REDACTION:
                result = action.redact_result(result, result_paths)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            error = f"{type(exc).__name__}: {str(exc)[:300]}"
            etype, data = action.failure_event(error)
            await self._recorder.record(etype, pid, {"action_id": action_id, **data})
            return Failed(error, decision)

        etype, data = action.result_event(result)
        await self._recorder.record(etype, pid, {"action_id": action_id, **data})
        return Completed(result, decision)


__all__ = [
    "ActionExecutor",
    "ActionOutcome",
    "ActionRunner",
    "Completed",
    "Denied",
    "Failed",
    "PendingApproval",
    "RunIdentity",
]
