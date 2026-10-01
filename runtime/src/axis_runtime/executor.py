"""ActionExecutor: the ONLY way an Action is performed.

``run(action)`` = build gate request -> gate (fail-closed) -> append ``gate_decision`` event ->
perform iff ALLOW / ALLOW_WITH_REDACTION.  DENY and REQUIRE_APPROVAL perform nothing.

With an ``ApprovalResolver`` configured, REQUIRE_APPROVAL does not end the call: the executor waits
for the human decision and, if (and only if) it is APPROVED, RE-SUBMITS the same action to the gate
carrying the signed decision record.  The kernel verifies the record for exactly that
tenant/run/tool/arguments, applies every DENY policy and cap again and consumes the approval; only
that second ALLOW performs the action.  Denied, expired, unresolvable or unaccepted approvals
perform nothing.  There is no loop: a second REQUIRE_APPROVAL is a DENY."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
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
from axis_runtime.approvals import ApprovalResolver
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
        approvals: ApprovalResolver | None = None,
    ) -> None:
        self._approvals = approvals
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

    def _request(
        self, action: Action, pid: str, approval: Mapping[str, Any] | None = None
    ) -> EvaluateRequest:
        ident = self._identity
        ep = action.enforcement_point
        context: dict[str, Any] = {
            "tool": action.tool_descriptor(),
            "args": to_jsonable(action.gate_args()),
            "data": {"phi": ident.phi},
            "tenant": {"id": ident.tenant_id},
            "agent": {"name": ident.blueprint_name, "version": ident.blueprint_version},
            "run": {"id": ident.run_id},
            "actor": {"type": ident.actor_type.value, "id": ident.actor_id or pid},
            "enforcement_point": ep.value,
        }
        if approval is not None:
            context["approval"] = dict(approval)  # evidence for the kernel's own verification
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

    async def _gate_once(self, request: EvaluateRequest) -> GateDecision:
        try:
            return validate_decision(await self._gate.evaluate(request))
        except Exception as exc:  # FailClosedGate should prevent this; never trust it
            return deny(f"gate_error:{type(exc).__name__}")

    async def _record_decision(
        self, pid: str, action_id: str, action: Action, decision: GateDecision
    ) -> None:
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

    async def _resume_after_approval(
        self, action: Action, pid: str, action_id: str, pending: GateDecision
    ) -> GateDecision | Denied:
        """Wait for the human decision, then re-gate the SAME action with the signed record."""
        assert self._approvals is not None  # noqa: S101 - narrowed by the caller
        ident = self._identity
        try:
            record = await self._approvals.resolve(ident.tenant_id, pending.approval_id)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # unresolvable approval is a DENY; type name only
            reason = f"approval_unavailable:{type(exc).__name__}"
            return await self._block(pid, action_id, action, reason)
        if not self._runnable(pid):
            return await self._block(pid, action_id, action, "process_terminated_during_approval")
        outcome = record.get("outcome")
        if outcome != "APPROVED":
            label = outcome.lower() if isinstance(outcome, str) else "malformed"
            return await self._block(pid, action_id, action, f"approval_{label}")
        if (
            record.get("request_id") != pending.approval_id
            or record.get("tenant_id") != ident.tenant_id
            or record.get("run_id") != ident.run_id
        ):
            return await self._block(pid, action_id, action, "approval_mismatch")
        regated = await self._gate_once(self._request(action, pid, approval=record))
        if not self._runnable(pid):
            return await self._block(pid, action_id, action, "process_terminated_during_gate")
        await self._record_decision(pid, action_id, action, regated)
        if regated.decision is Decision.REQUIRE_APPROVAL:  # not accepted by the kernel: no loop
            return Denied("approval_not_accepted", regated)
        if regated.decision is Decision.DENY:
            return Denied(regated.reason or "denied", regated)
        return regated

    async def run(self, action: Action, *, pid: str) -> ActionOutcome:
        if pid not in self._recorder.state.processes:
            raise KeyError(f"unknown pid {pid!r}")
        action_id = self._next_action_id()
        if not self._runnable(pid):
            state = self._recorder.state.processes[pid].state.value
            return await self._block(pid, action_id, action, f"process_not_runnable:{state}")

        decision = await self._gate_once(self._request(action, pid))
        if not self._runnable(pid):  # killed/paused while the gate was thinking
            return await self._block(pid, action_id, action, "process_terminated_during_gate")
        await self._record_decision(pid, action_id, action, decision)

        if decision.decision is Decision.REQUIRE_APPROVAL:
            if self._approvals is None:
                return PendingApproval(decision.approval_id, decision.reason, decision)
            resumed = await self._resume_after_approval(action, pid, action_id, decision)
            if isinstance(resumed, Denied):
                return resumed
            decision = resumed
        if decision.decision is Decision.DENY:
            return Denied(decision.reason or "denied", decision)
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
