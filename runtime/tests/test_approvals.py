"""Approval round-trip in the executor (resume = RE-GATE) and the HTTP resolver client."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from typing import Any

import httpx
import pytest
from axis_runtime import Decision
from axis_runtime.actions import ToolCall
from axis_runtime.approvals import ApprovalUnavailable, HttpApprovalResolver
from axis_runtime.events import EventType
from axis_runtime.executor import ActionExecutor, Completed, Denied, PendingApproval
from axis_runtime.gate import EvaluateRequest, GateDecision
from conftest import TENANT, FakeClock, ScriptedGate, allow, deny
from helpers import PID, Effects, identity, recording_backends, running_recorder

AP = "ap_1"


def record(**over: Any) -> dict[str, Any]:
    base = {
        "request_id": AP,
        "tenant_id": TENANT,
        "run_id": "run_1",
        "tool": "lookup",
        "args_hash": "a" * 64,
        "outcome": "APPROVED",
        "decision": "ALLOW",
        "signature": "sig",
    }
    base.update(over)
    return base


class Resolver:
    def __init__(self, result: Any = None, exc: BaseException | None = None) -> None:
        self.result = record() if result is None else result
        self.exc = exc
        self.calls: list[tuple[str, str]] = []

    async def resolve(self, tenant_id: str, approval_id: str) -> Mapping[str, Any]:
        self.calls.append((tenant_id, approval_id))
        if self.exc is not None:
            raise self.exc
        return self.result  # type: ignore[no-any-return]


def kernel_like(second: GateDecision | None = None) -> ScriptedGate:
    """First call: REQUIRE_APPROVAL. A call carrying an approval record: ``second`` (default ALLOW)."""

    def fn(r: EvaluateRequest) -> GateDecision:
        if "approval" in r.context:
            return second or allow("approved")
        return GateDecision(Decision.REQUIRE_APPROVAL, "needs a human", approval_id=AP)

    return ScriptedGate(fn)


async def make(gate: Any, resolver: Any, *, to_state: str = "running") -> Any:
    effects = Effects()
    rec = await running_recorder(FakeClock(), to_state=to_state)
    ex = ActionExecutor(
        gate=gate,
        recorder=rec,
        identity=identity(),
        backends=recording_backends(effects),
        gate_timeout=0.5,
        approvals=resolver,
    )
    return ex, rec, effects


async def blocked_reasons(rec: Any) -> list[str]:
    return [e.data["reason"] for e in await rec.log.read("run_1") if e.type == "action_blocked"]


async def test_approved_action_is_regated_with_the_record_and_runs_exactly_once() -> None:
    gate, resolver = kernel_like(), Resolver()
    ex, rec, effects = await make(gate, resolver)
    out = await ex.run(ToolCall(name="lookup", args={"q": "x"}), pid=PID)
    assert isinstance(out, Completed)
    assert effects.total() == 1  # performed once, after the SECOND allow
    assert resolver.calls == [(TENANT, AP)]
    first, second = gate.requests
    assert "approval" not in first.context and second.context["approval"] == record()
    assert {k: v for k, v in second.context.items() if k != "approval"} == first.context
    assert [(g.decision, g.reason) for g in rec.state.gate_decisions] == [
        (Decision.REQUIRE_APPROVAL, "needs a human"),
        (Decision.ALLOW, "approved"),
    ]
    assert len(rec.state.tool_calls) == 1


@pytest.mark.parametrize("outcome", ["DENIED", "EXPIRED"])
async def test_denied_or_expired_approval_performs_nothing_and_does_not_regate(
    outcome: str,
) -> None:
    gate = kernel_like()
    ex, rec, effects = await make(gate, Resolver(record(outcome=outcome, decision="DENY")))
    out = await ex.run(ToolCall(name="lookup"), pid=PID)
    assert isinstance(out, Denied) and out.reason == f"approval_{outcome.lower()}"
    assert effects.total() == 0 and len(gate.requests) == 1
    assert await blocked_reasons(rec) == [f"approval_{outcome.lower()}"]


@pytest.mark.parametrize("bad", [record(outcome=None), record(outcome=5), {"outcome": []}])
async def test_malformed_outcome_is_a_denial(bad: Any) -> None:
    ex, _, effects = await make(kernel_like(), Resolver(bad))
    out = await ex.run(ToolCall(name="lookup"), pid=PID)
    assert isinstance(out, Denied) and out.reason in ("approval_malformed", "approval_mismatch")
    assert effects.total() == 0


@pytest.mark.parametrize(
    "bad",
    [
        record(request_id="other"),
        record(tenant_id="22222222-2222-4222-8222-222222222222"),
        record(run_id="run_other"),
    ],
)
async def test_a_record_for_another_request_tenant_or_run_is_never_forwarded(bad: Any) -> None:
    gate = kernel_like()
    ex, _, effects = await make(gate, Resolver(bad))
    out = await ex.run(ToolCall(name="lookup"), pid=PID)
    assert isinstance(out, Denied) and out.reason == "approval_mismatch"
    assert effects.total() == 0 and len(gate.requests) == 1


@pytest.mark.parametrize("exc", [ApprovalUnavailable("http_500"), RuntimeError("boom"), OSError()])
async def test_an_unresolvable_approval_is_a_denial_with_the_type_name_only(exc: Exception) -> None:
    ex, rec, effects = await make(kernel_like(), Resolver(exc=exc))
    out = await ex.run(ToolCall(name="lookup"), pid=PID)
    assert isinstance(out, Denied) and out.reason == f"approval_unavailable:{type(exc).__name__}"
    assert "boom" not in out.reason and effects.total() == 0
    assert len(await blocked_reasons(rec)) == 1


async def test_cancellation_while_waiting_propagates() -> None:
    ex, _, effects = await make(kernel_like(), Resolver(exc=asyncio.CancelledError()))
    with pytest.raises(asyncio.CancelledError):
        await ex.run(ToolCall(name="lookup"), pid=PID)
    assert effects.total() == 0


async def test_a_process_killed_while_waiting_never_runs_the_action() -> None:
    holder: dict[str, Any] = {}

    class Killer:
        async def resolve(self, tenant_id: str, approval_id: str) -> Mapping[str, Any]:
            await holder["rec"].record(
                EventType.PROCESS_TRANSITION,
                PID,
                {"from": "running", "to": "terminated", "trigger": "KILL", "exit_reason": "killed"},
            )
            return record()

    gate = kernel_like()
    ex, rec, effects = await make(gate, Killer())
    holder["rec"] = rec
    out = await ex.run(ToolCall(name="lookup"), pid=PID)
    assert isinstance(out, Denied) and out.reason == "process_terminated_during_approval"
    assert effects.total() == 0 and len(gate.requests) == 1


async def test_a_process_killed_during_the_regate_never_runs_the_action() -> None:
    holder: dict[str, Any] = {}

    def fn(r: EvaluateRequest) -> GateDecision:
        if "approval" in r.context:
            holder["kill"] = True
            return allow()
        return GateDecision(Decision.REQUIRE_APPROVAL, "x", approval_id=AP)

    class KillOnSecond(ScriptedGate):
        async def evaluate(self, request: EvaluateRequest) -> GateDecision:
            d = await super().evaluate(request)
            if "approval" in request.context:
                await holder["rec"].record(
                    EventType.PROCESS_TRANSITION,
                    PID,
                    {
                        "from": "running",
                        "to": "terminated",
                        "trigger": "KILL",
                        "exit_reason": "killed",
                    },
                )
            return d

    ex, rec, effects = await make(KillOnSecond(fn), Resolver())
    holder["rec"] = rec
    out = await ex.run(ToolCall(name="lookup"), pid=PID)
    assert isinstance(out, Denied) and out.reason == "process_terminated_during_gate"
    assert effects.total() == 0


async def test_the_kernel_can_still_deny_an_approved_action() -> None:
    """An approval is evidence, not authority: DENY on the re-gate (a cap, a kill-switch) wins."""
    ex, rec, effects = await make(kernel_like(deny("kill-switch engaged (tenant)")), Resolver())
    out = await ex.run(ToolCall(name="lookup"), pid=PID)
    assert isinstance(out, Denied) and out.reason == "kill-switch engaged (tenant)"
    assert effects.total() == 0
    assert [g.decision for g in rec.state.gate_decisions] == [
        Decision.REQUIRE_APPROVAL,
        Decision.DENY,
    ]


async def test_a_second_require_approval_is_a_denial_not_a_loop() -> None:
    gate = ScriptedGate(GateDecision(Decision.REQUIRE_APPROVAL, "again", approval_id=AP))
    resolver = Resolver()
    ex, _, effects = await make(gate, resolver)
    out = await ex.run(ToolCall(name="lookup"), pid=PID)
    assert isinstance(out, Denied) and out.reason == "approval_not_accepted"
    assert effects.total() == 0 and len(gate.requests) == 2 and len(resolver.calls) == 1


async def test_a_gate_failure_on_the_regate_is_a_denial() -> None:
    def fn(r: EvaluateRequest) -> GateDecision:
        if "approval" in r.context:
            raise RuntimeError("kernel down")
        return GateDecision(Decision.REQUIRE_APPROVAL, "x", approval_id=AP)

    ex, _, effects = await make(ScriptedGate(fn), Resolver())
    out = await ex.run(ToolCall(name="lookup"), pid=PID)
    assert isinstance(out, Denied) and out.reason == "gate_error:RuntimeError"
    assert effects.total() == 0


async def test_without_a_resolver_the_action_parks_as_before() -> None:
    ex, rec, effects = await make(kernel_like(), None)
    out = await ex.run(ToolCall(name="lookup"), pid=PID)
    assert isinstance(out, PendingApproval) and out.approval_id == AP
    assert effects.total() == 0 and len(rec.state.gate_decisions) == 1


async def test_decision_without_approval_is_unaffected_by_a_resolver() -> None:
    resolver = Resolver()
    ex, _, effects = await make(ScriptedGate(), resolver)
    assert isinstance(await ex.run(ToolCall(name="lookup"), pid=PID), Completed)
    assert resolver.calls == [] and effects.total() == 1


# ---- HttpApprovalResolver -------------------------------------------------------------------------


def http_resolver(
    handler: Callable[[httpx.Request], httpx.Response], **kw: Any
) -> HttpApprovalResolver:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return HttpApprovalResolver("http://127.0.0.1:9/", token="tok", client=client, **kw)


async def test_http_resolver_posts_the_request_id_with_the_bearer_token() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json={"record": record()})

    rec = await http_resolver(handler, poll_seconds=2.0).resolve(TENANT, AP)
    assert rec["outcome"] == "APPROVED"
    (req,) = seen
    assert str(req.url) == "http://127.0.0.1:9/v1/approvals/resolve"
    assert req.headers["authorization"] == "Bearer tok"
    assert req.read() == b'{"request_id":"ap_1","wait_ms":2000}'


async def test_http_resolver_keeps_polling_while_pending() -> None:
    n = {"i": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        n["i"] += 1
        if n["i"] < 3:
            return httpx.Response(202, json={"status": "pending"})
        return httpx.Response(200, json={"record": record(outcome="DENIED", decision="DENY")})

    rec = await http_resolver(handler).resolve(TENANT, AP)
    assert rec["outcome"] == "DENIED" and n["i"] == 3


async def test_http_resolver_gives_up_when_still_pending_past_max_wait() -> None:
    r = http_resolver(lambda _r: httpx.Response(202, json={}), max_wait_seconds=0.05)
    with pytest.raises(ApprovalUnavailable, match="still_pending"):
        await r.resolve(TENANT, AP)


@pytest.mark.parametrize(
    ("response", "why"),
    [
        (httpx.Response(404, json={"error": {"code": "NOT_FOUND"}}), "http_404"),
        (httpx.Response(401, json={}), "http_401"),
        (httpx.Response(500, text="boom"), "http_500"),
        (httpx.Response(200, text="not json"), "malformed_response"),
        (httpx.Response(200, json={"nope": 1}), "malformed_response"),
        (httpx.Response(200, json=[1]), "malformed_response"),
        (httpx.Response(200, json={"record": "x"}), "malformed_record"),
        (httpx.Response(200, json={"record": record(outcome=None)}), "malformed_record"),
        (httpx.Response(200, json={"record": {"request_id": AP}}), "malformed_record"),
        (
            httpx.Response(200, json={"record": record(request_id="x")}),
            "record_for_another_request",
        ),
        (
            httpx.Response(
                200, json={"record": record(tenant_id="22222222-2222-4222-8222-222222222222")}
            ),
            "record_for_another_request",
        ),
    ],
)
async def test_http_resolver_rejects_anything_but_a_well_formed_record(
    response: httpx.Response, why: str
) -> None:
    with pytest.raises(ApprovalUnavailable, match=why):
        await http_resolver(lambda _r: response).resolve(TENANT, AP)


async def test_http_resolver_maps_transport_errors_without_leaking_details() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("http://secret-host refused")

    with pytest.raises(ApprovalUnavailable) as ei:
        await http_resolver(handler).resolve(TENANT, AP)
    assert str(ei.value) == "transport:ConnectError"


async def test_http_resolver_validates_its_configuration_and_closes() -> None:
    with pytest.raises(ValueError):
        HttpApprovalResolver("http://x", token="t", poll_seconds=0)
    with pytest.raises(ValueError):
        HttpApprovalResolver("http://x", token="t", max_wait_seconds=-1)
    r = HttpApprovalResolver("http://127.0.0.1:9", token="t")
    await r.close()
