"""Gate clients are fail-closed; the gRPC client is tested against an in-process fake server."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import grpc
import grpc.aio
import pytest
from axis_runtime import Decision
from axis_runtime._gen.axis.runtime.v1 import common_pb2, gate_pb2, gate_pb2_grpc
from axis_runtime.gate import (
    ActorType,
    EnforcementPoint,
    EvaluateRequest,
    FailClosedGate,
    GateDecision,
    GrpcGateClient,
    deny,
    from_proto_response,
    to_proto_request,
    validate_decision,
)

REQ = EvaluateRequest(
    tenant_id="t-1",
    trace_id="a" * 32,
    span_id="b" * 16,
    actor_type=ActorType.AGENT,
    actor_id="agent-1",
    pid="axp_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    blueprint_name="bp",
    blueprint_version="1.0.0",
    enforcement_point=EnforcementPoint.TOOL_CALL,
    action="lookup",
    context={"tool": {"name": "lookup"}, "args": {"n": 3, "ssn": "123"}, "data": {"phi": True}},
)


class _Inner:
    def __init__(self, fn: Callable[[], Awaitable[Any]]) -> None:
        self.fn = fn

    async def evaluate(self, request: EvaluateRequest) -> GateDecision:
        return await self.fn()  # type: ignore[no-any-return]


# ---- FailClosedGate -------------------------------------------------------------------------


async def _eval(fn: Callable[[], Awaitable[Any]], timeout: float = 1.0) -> GateDecision:
    return await FailClosedGate(_Inner(fn), timeout).evaluate(REQ)


async def test_passes_well_formed_decisions_through() -> None:
    for d in (
        GateDecision(Decision.ALLOW, "ok"),
        GateDecision(Decision.DENY, "no"),
        GateDecision(Decision.REQUIRE_APPROVAL, "ask", approval_id="ap_1"),
        GateDecision(Decision.ALLOW_WITH_REDACTION, "r", redact_fields=("args.ssn",)),
    ):

        async def fn(d: GateDecision = d) -> GateDecision:
            return d

        assert await _eval(fn) == d


async def test_exception_is_deny_without_leaking_message() -> None:
    async def boom() -> GateDecision:
        raise RuntimeError("secret-token-abc leaked in message")

    out = await _eval(boom)
    assert out.decision is Decision.DENY
    assert out.reason == "gate_error:RuntimeError"
    assert "secret" not in out.reason


async def test_timeout_is_deny() -> None:
    async def slow() -> GateDecision:
        await asyncio.sleep(5)
        return GateDecision(Decision.ALLOW)

    out = await _eval(slow, timeout=0.02)
    assert out.decision is Decision.DENY and out.reason == "gate_timeout"


@pytest.mark.parametrize(
    "bad",
    [
        None,
        "ALLOW",
        {"decision": "ALLOW"},
        GateDecision("ALLOW"),  # type: ignore[arg-type]  # a str, not the enum
        GateDecision("MAYBE"),  # type: ignore[arg-type]
        GateDecision(Decision.ALLOW_WITH_REDACTION),  # redaction without fields
        GateDecision(Decision.REQUIRE_APPROVAL),  # approval without id
        GateDecision(Decision.ALLOW, reason=None),  # type: ignore[arg-type]
        GateDecision(Decision.ALLOW, redact_fields=["x"]),  # type: ignore[arg-type]
    ],
)
async def test_malformed_or_unknown_decisions_are_deny(bad: object) -> None:
    async def fn() -> Any:
        return bad

    out = await _eval(fn)
    assert out.decision is Decision.DENY
    assert out.reason.startswith("gate_")


async def test_cancellation_is_not_swallowed() -> None:
    started = asyncio.Event()

    async def hang() -> GateDecision:
        started.set()
        await asyncio.sleep(10)
        return GateDecision(Decision.ALLOW)

    task = asyncio.create_task(_eval(hang, timeout=30))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


def test_validate_decision_returns_same_object_when_valid() -> None:
    d = GateDecision(Decision.ALLOW)
    assert validate_decision(d) is d
    assert deny("x").decision is Decision.DENY


# ---- gRPC against an in-process fake GateService --------------------------------------------


class FakeGate(gate_pb2_grpc.GateServiceServicer):  # type: ignore[misc]
    def __init__(self) -> None:
        self.handler: Callable[
            [gate_pb2.EvaluateRequest, Any], Awaitable[gate_pb2.EvaluateResponse]
        ] = self._default
        self.seen: list[gate_pb2.EvaluateRequest] = []
        self.metadata: list[dict[str, str]] = []

    @staticmethod
    async def _default(req: gate_pb2.EvaluateRequest, ctx: Any) -> gate_pb2.EvaluateResponse:
        return gate_pb2.EvaluateResponse(decision=common_pb2.DECISION_ALLOW, reason="fine")

    async def Evaluate(
        self, request: gate_pb2.EvaluateRequest, context: Any
    ) -> gate_pb2.EvaluateResponse:
        self.seen.append(request)
        self.metadata.append({m.key: m.value for m in context.invocation_metadata()})
        return await self.handler(request, context)


@pytest.fixture
async def server() -> AsyncIterator[tuple[FakeGate, str]]:
    servicer = FakeGate()
    srv = grpc.aio.server()
    gate_pb2_grpc.add_GateServiceServicer_to_server(servicer, srv)
    port = srv.add_insecure_port("127.0.0.1:0")
    await srv.start()
    yield servicer, f"127.0.0.1:{port}"
    await srv.stop(None)


async def test_grpc_allow_and_request_mapping(server: tuple[FakeGate, str]) -> None:
    fake, target = server
    client = GrpcGateClient(target, timeout=2)
    try:
        out = await client.evaluate(REQ)
    finally:
        await client.close()
    assert out.decision is Decision.ALLOW and out.reason == "fine"
    seen = fake.seen[0]
    assert seen.tenant_id == "t-1"
    assert seen.trace.trace_id == "a" * 32 and seen.trace.span_id == "b" * 16
    assert seen.actor.type == common_pb2.Actor.TYPE_AGENT and seen.actor.pid == REQ.pid
    assert seen.blueprint.name == "bp" and seen.blueprint.version == "1.0.0"
    assert seen.enforcement_point == common_pb2.ENFORCEMENT_POINT_TOOL_CALL
    assert seen.action == "lookup"
    assert seen.context["args"]["ssn"] == "123" and seen.context["data"]["phi"] is True


async def test_grpc_sends_the_bearer_token_only_when_configured(
    server: tuple[FakeGate, str],
) -> None:
    fake, target = server
    with_token = GrpcGateClient(target, timeout=2, token="s3cret")
    without = GrpcGateClient(target, timeout=2)
    try:
        await with_token.evaluate(REQ)
        await without.evaluate(REQ)
    finally:
        await with_token.close()
        await without.close()
    assert fake.metadata[0]["authorization"] == "Bearer s3cret"
    assert "authorization" not in fake.metadata[1]


async def test_grpc_maps_all_decisions(server: tuple[FakeGate, str]) -> None:
    fake, target = server
    client = GrpcGateClient(target, timeout=2)
    cases = [
        (gate_pb2.EvaluateResponse(decision=common_pb2.DECISION_DENY, reason="r"), Decision.DENY),
        (
            gate_pb2.EvaluateResponse(
                decision=common_pb2.DECISION_REQUIRE_APPROVAL, approval_id="ap"
            ),
            Decision.REQUIRE_APPROVAL,
        ),
        (
            gate_pb2.EvaluateResponse(
                decision=common_pb2.DECISION_ALLOW_WITH_REDACTION,
                redact_fields=["args.ssn"],
                matched_rule_ids=["r1"],
                policy_version="p9",
                audit_event_id="ae",
            ),
            Decision.ALLOW_WITH_REDACTION,
        ),
    ]
    try:
        for resp, expected in cases:

            async def handler(_r: Any, _c: Any, resp: gate_pb2.EvaluateResponse = resp) -> Any:
                return resp

            fake.handler = handler
            out = await client.evaluate(REQ)
            assert out.decision is expected
        assert (
            out.redact_fields,
            out.matched_rule_ids,
            out.policy_version,
            out.audit_event_id,
        ) == (
            ("args.ssn",),
            ("r1",),
            "p9",
            "ae",
        )
    finally:
        await client.close()


async def test_grpc_unspecified_decision_is_deny(server: tuple[FakeGate, str]) -> None:
    fake, target = server

    async def handler(_r: Any, _c: Any) -> gate_pb2.EvaluateResponse:
        return gate_pb2.EvaluateResponse(decision=common_pb2.DECISION_UNSPECIFIED, reason="x")

    fake.handler = handler
    client = GrpcGateClient(target, timeout=2)
    try:
        out = await client.evaluate(REQ)
    finally:
        await client.close()
    assert out.decision is Decision.DENY and out.reason == "gate_unspecified_decision"


async def test_grpc_unknown_enum_value_is_deny(server: tuple[FakeGate, str]) -> None:
    fake, target = server

    async def handler(_r: Any, _c: Any) -> gate_pb2.EvaluateResponse:
        return gate_pb2.EvaluateResponse(decision=99)

    fake.handler = handler
    client = GrpcGateClient(target, timeout=2)
    try:
        assert (await client.evaluate(REQ)).decision is Decision.DENY
    finally:
        await client.close()


async def test_grpc_deadline_exceeded_is_deny(server: tuple[FakeGate, str]) -> None:
    fake, target = server

    async def slow(_r: Any, _c: Any) -> gate_pb2.EvaluateResponse:
        await asyncio.sleep(2)
        return gate_pb2.EvaluateResponse(decision=common_pb2.DECISION_ALLOW)

    fake.handler = slow
    client = GrpcGateClient(target, timeout=0.1)
    try:
        out = await client.evaluate(REQ)
    finally:
        await client.close()
    assert out.decision is Decision.DENY and out.reason == "gate_rpc_error:DEADLINE_EXCEEDED"


async def test_grpc_unavailable_server_is_deny(server: tuple[FakeGate, str]) -> None:
    fake, target = server

    async def unavailable(_r: Any, ctx: Any) -> gate_pb2.EvaluateResponse:
        await ctx.abort(grpc.StatusCode.UNAVAILABLE, "kernel restarting")
        raise AssertionError  # pragma: no cover

    fake.handler = unavailable
    client = GrpcGateClient(target, timeout=2)
    try:
        out = await client.evaluate(REQ)
    finally:
        await client.close()
    assert out.decision is Decision.DENY and out.reason == "gate_rpc_error:UNAVAILABLE"


async def test_grpc_no_server_at_all_is_deny() -> None:
    client = GrpcGateClient("127.0.0.1:1", timeout=0.5)
    try:
        out = await client.evaluate(REQ)
    finally:
        await client.close()
    assert out.decision is Decision.DENY and out.reason.startswith("gate_rpc_error:")


async def test_grpc_unserializable_context_is_deny() -> None:
    client = GrpcGateClient("127.0.0.1:1", timeout=0.5)
    bad = EvaluateRequest(**{**REQ.__dict__, "context": {"x": object()}})
    try:
        out = await client.evaluate(bad)
    finally:
        await client.close()
    assert out.decision is Decision.DENY and out.reason == "gate_error:TypeError"


async def test_grpc_redaction_without_fields_is_deny(server: tuple[FakeGate, str]) -> None:
    fake, target = server

    async def handler(_r: Any, _c: Any) -> gate_pb2.EvaluateResponse:
        return gate_pb2.EvaluateResponse(decision=common_pb2.DECISION_ALLOW_WITH_REDACTION)

    fake.handler = handler
    client = GrpcGateClient(target, timeout=2)
    try:
        assert (await client.evaluate(REQ)).decision is Decision.DENY
    finally:
        await client.close()


async def test_grpc_composes_with_fail_closed_wrapper(server: tuple[FakeGate, str]) -> None:
    _, target = server
    client = GrpcGateClient(target, timeout=2)
    try:
        assert (await FailClosedGate(client, 2).evaluate(REQ)).decision is Decision.ALLOW
    finally:
        await client.close()


async def test_grpc_constructor_variants() -> None:
    with pytest.raises(ValueError, match="target or channel"):
        GrpcGateClient()
    secure = GrpcGateClient("127.0.0.1:1", credentials=grpc.ssl_channel_credentials(), timeout=0.3)
    assert (await secure.evaluate(REQ)).decision is Decision.DENY  # TLS to nothing: still DENY
    await secure.close()
    channel = grpc.aio.insecure_channel("127.0.0.1:1")
    wrapped = GrpcGateClient(channel=channel, timeout=0.3)
    assert (await wrapped.evaluate(REQ)).decision is Decision.DENY
    await wrapped.close()


def test_only_an_agent_actor_carries_a_pid_on_the_wire() -> None:
    """The audit table rejects a pid on a non-agent actor, which would deny every inbound MCP call."""
    for actor in ActorType:
        pid = to_proto_request(EvaluateRequest(**{**REQ.__dict__, "actor_type": actor})).actor.pid
        assert (pid != "") is (actor is ActorType.AGENT), actor


def test_proto_mappings_cover_every_enforcement_point() -> None:
    for ep in EnforcementPoint:
        msg = to_proto_request(EvaluateRequest(**{**REQ.__dict__, "enforcement_point": ep}))
        assert msg.enforcement_point == getattr(common_pb2, f"ENFORCEMENT_POINT_{ep.name}")
    for actor in ActorType:
        assert (
            to_proto_request(EvaluateRequest(**{**REQ.__dict__, "actor_type": actor})).actor.type
            > 0
        )
    assert (
        from_proto_response(gate_pb2.EvaluateResponse(decision=common_pb2.DECISION_ALLOW)).decision
        is Decision.ALLOW
    )
