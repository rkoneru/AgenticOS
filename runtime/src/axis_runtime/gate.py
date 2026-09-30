"""Gate client: the runtime holds NO policy logic, it only asks the Risk Kernel (ADR-0009).

Client rule (gate.proto): transport error, deadline, malformed response or DECISION_UNSPECIFIED
is DENY.  ``FailClosedGate`` enforces that for any ``GateClient``; ``GrpcGateClient`` is also
fail-closed on its own (defence in depth) and the executor always wraps whatever it is given.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol, cast

import grpc
import grpc.aio
from google.protobuf import json_format, struct_pb2

from axis_runtime._decision import Decision
from axis_runtime._gen.axis.runtime.v1 import common_pb2, gate_pb2, gate_pb2_grpc

log = logging.getLogger("axis_runtime.gate")


class EnforcementPoint(StrEnum):
    TOOL_CALL = "tool_call"
    MCP_CALL = "mcp_call"
    MODEL_CALL = "model_call"
    MEMORY_WRITE = "memory_write"
    MESSAGE_SEND = "message_send"
    CODE_EXEC = "code_exec"
    BROWSER_EXEC = "browser_exec"


class ActorType(StrEnum):
    HUMAN = "human"
    AGENT = "agent"
    SYSTEM = "system"


@dataclass(frozen=True)
class EvaluateRequest:
    tenant_id: str
    trace_id: str
    span_id: str
    actor_type: ActorType
    actor_id: str
    pid: str
    blueprint_name: str
    blueprint_version: str
    enforcement_point: EnforcementPoint
    action: str
    context: Mapping[str, Any]


@dataclass(frozen=True)
class GateDecision:
    decision: Decision
    reason: str = ""
    policy_version: str = ""
    matched_rule_ids: tuple[str, ...] = ()
    redact_fields: tuple[str, ...] = ()
    approval_id: str = ""
    audit_event_id: str = ""


def deny(reason: str) -> GateDecision:
    return GateDecision(decision=Decision.DENY, reason=reason)


class GateClient(Protocol):
    async def evaluate(self, request: EvaluateRequest) -> GateDecision: ...


def validate_decision(value: object) -> GateDecision:
    """Return ``value`` if it is a well-formed GateDecision, otherwise a DENY."""
    if not isinstance(value, GateDecision):
        return deny("gate_malformed_response")
    if not isinstance(value.decision, Decision):
        return deny("gate_unknown_decision")
    if value.decision is Decision.ALLOW_WITH_REDACTION and not value.redact_fields:
        return deny("gate_malformed_response: redaction without fields")
    if value.decision is Decision.REQUIRE_APPROVAL and not value.approval_id:
        return deny("gate_malformed_response: approval without approval_id")
    if not isinstance(value.reason, str) or not isinstance(value.redact_fields, tuple):
        return deny("gate_malformed_response")
    return value


class FailClosedGate:
    """Wraps any GateClient: exception, timeout or malformed/unknown decision becomes DENY."""

    def __init__(self, inner: GateClient, timeout: float = 5.0) -> None:
        self._inner = inner
        self.timeout = timeout

    async def evaluate(self, request: EvaluateRequest) -> GateDecision:
        try:
            result = await asyncio.wait_for(self._inner.evaluate(request), timeout=self.timeout)
        except TimeoutError:
            return deny("gate_timeout")
        except Exception as exc:
            # Type name only: exception text could contain request data or credentials.
            return deny(f"gate_error:{type(exc).__name__}")
        return validate_decision(result)


_EP_TO_PROTO: dict[EnforcementPoint, common_pb2.EnforcementPoint] = {
    ep: cast(
        common_pb2.EnforcementPoint,
        common_pb2.EnforcementPoint.Value(f"ENFORCEMENT_POINT_{ep.name}"),
    )
    for ep in EnforcementPoint
}
_ACTOR_TO_PROTO = {
    ActorType.HUMAN: common_pb2.Actor.TYPE_HUMAN,
    ActorType.AGENT: common_pb2.Actor.TYPE_AGENT,
    ActorType.SYSTEM: common_pb2.Actor.TYPE_SYSTEM,
}
_DECISION_FROM_PROTO = {
    common_pb2.DECISION_ALLOW: Decision.ALLOW,
    common_pb2.DECISION_DENY: Decision.DENY,
    common_pb2.DECISION_REQUIRE_APPROVAL: Decision.REQUIRE_APPROVAL,
    common_pb2.DECISION_ALLOW_WITH_REDACTION: Decision.ALLOW_WITH_REDACTION,
}


def to_proto_request(request: EvaluateRequest) -> gate_pb2.EvaluateRequest:
    context = struct_pb2.Struct()
    # Round-trip through JSON so non-JSON values fail here (-> DENY) instead of mid-wire.
    json_format.ParseDict(json.loads(json.dumps(request.context)), context)
    return gate_pb2.EvaluateRequest(
        tenant_id=request.tenant_id,
        trace=common_pb2.TraceContext(trace_id=request.trace_id, span_id=request.span_id),
        actor=common_pb2.Actor(
            type=_ACTOR_TO_PROTO[request.actor_type], id=request.actor_id, pid=request.pid
        ),
        blueprint=common_pb2.BlueprintRef(
            name=request.blueprint_name, version=request.blueprint_version
        ),
        enforcement_point=_EP_TO_PROTO[request.enforcement_point],
        action=request.action,
        context=context,
    )


def from_proto_response(resp: gate_pb2.EvaluateResponse) -> GateDecision:
    decision = _DECISION_FROM_PROTO.get(resp.decision)
    if decision is None:  # DECISION_UNSPECIFIED or a value this client does not know
        return deny("gate_unspecified_decision")
    return validate_decision(
        GateDecision(
            decision=decision,
            reason=resp.reason,
            policy_version=resp.policy_version,
            matched_rule_ids=tuple(resp.matched_rule_ids),
            redact_fields=tuple(resp.redact_fields),
            approval_id=resp.approval_id,
            audit_event_id=resp.audit_event_id,
        )
    )


class GrpcGateClient:
    """``GateService.Evaluate`` over gRPC.  Pass ``credentials`` for mTLS (required in prod)."""

    def __init__(
        self,
        target: str | None = None,
        *,
        timeout: float = 2.0,
        credentials: grpc.ChannelCredentials | None = None,
        channel: grpc.aio.Channel | None = None,
        token: str | None = None,
    ) -> None:
        if channel is None:
            if target is None:
                raise ValueError("target or channel is required")
            channel = (
                grpc.aio.secure_channel(target, credentials)
                if credentials is not None
                else grpc.aio.insecure_channel(target)
            )
        self._channel = channel
        self._stub = gate_pb2_grpc.GateServiceStub(channel)  # type: ignore[no-untyped-call]
        self.timeout = timeout
        # The kernel derives the tenant from this credential, never from the request alone.
        self._metadata: tuple[tuple[str, str], ...] = (
            (("authorization", f"Bearer {token}"),) if token else ()
        )

    async def evaluate(self, request: EvaluateRequest) -> GateDecision:
        try:
            resp = await self._stub.Evaluate(
                to_proto_request(request), timeout=self.timeout, metadata=self._metadata or None
            )
        except grpc.aio.AioRpcError as exc:
            log.warning("gate rpc failed: %s", exc.code().name)
            return deny(f"gate_rpc_error:{exc.code().name}")
        except Exception as exc:
            log.warning("gate client error: %s", type(exc).__name__)
            return deny(f"gate_error:{type(exc).__name__}")
        return from_proto_response(resp)

    async def close(self) -> None:
        await self._channel.close()
