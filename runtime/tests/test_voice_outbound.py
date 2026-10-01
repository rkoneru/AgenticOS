"""Outbound calls: pre-gate caps and prefixes, the gate on the call, dialer, and agent-facing safety."""

from __future__ import annotations

import pytest
from axis_runtime.actions import Backends
from axis_runtime.executor import ActionExecutor
from axis_runtime.voice.clock import ManualVoiceClock
from axis_runtime.voice.gateway import LoopbackGateway
from axis_runtime.voice.outbound import (
    CallRefusedError,
    GatewayDialer,
    OutboundCaller,
    OutboundCallPolicy,
    OutboundLimiter,
    country_prefix,
)
from conftest import TENANT, FakeClock, ScriptedGate, allow, deny
from helpers import PID, identity, running_recorder

POLICY = OutboundCallPolicy(
    allowed_prefixes=("+1", "+44"),
    max_concurrent=2,
    max_per_window=3,
    max_per_destination=1,
    window_ms=60_000,
)


async def rig(gate: ScriptedGate | None = None, policy: OutboundCallPolicy | None = POLICY):  # type: ignore[no-untyped-def]
    clock = ManualVoiceClock()
    gw = LoopbackGateway(clock)
    rec = await running_recorder(FakeClock())
    gate = gate or ScriptedGate()
    ex = ActionExecutor(
        gate=gate, recorder=rec, identity=identity(), backends=Backends(voice=GatewayDialer(gw))
    )
    limiter = OutboundLimiter({TENANT: policy} if policy else {}, clock)
    return OutboundCaller(ex, rec, PID, limiter, TENANT), gw, gate, rec, clock, limiter


def test_country_prefix_longest_match() -> None:
    assert country_prefix("+14155550100", ("+1", "+141")) == "+141"
    assert country_prefix("+33123456789", ("+1",)) == ""


async def test_allowed_call_goes_through_the_gate_then_the_dialer() -> None:
    caller, gw, gate, rec, *_ = await rig()
    placed = await caller.place("+14155550100", purpose="appointment reminder")
    assert placed.status == "ringing" and gw.originated[0].to_number == "+14155550100"
    req = gate.requests[0]
    assert req.enforcement_point.value == "message_send"
    assert req.context["tool"] == {
        "name": "place_call",
        "kind": "voice",
        "side_effects": "external",
    }
    args = req.context["args"]
    assert args["country_prefix"] == "+1" and args["calls_in_window"] == 1
    assert args["to_masked"] != "+14155550100" and "+14155550100" not in str(req.context)
    assert len(args["to_sha256"]) == 64
    assert rec.state.tool_calls[-1].ok


async def test_gate_deny_places_no_call_and_frees_the_slot() -> None:
    caller, gw, _, _, _, limiter = await rig(ScriptedGate(deny("no outbound")))
    with pytest.raises(CallRefusedError) as ei:
        await caller.place("+14155550100")
    assert ei.value.reason == "gate_denied:no outbound" and gw.originated == []
    assert limiter._usage[TENANT].active == 0  # noqa: SLF001


async def test_gate_error_fails_closed() -> None:
    class Boom:
        async def evaluate(self, r):  # type: ignore[no-untyped-def]
            raise RuntimeError("kernel down")

    caller, gw, *_ = await rig()
    caller._runner._gate = __import__(
        "axis_runtime.gate", fromlist=["FailClosedGate"]
    ).FailClosedGate(Boom(), 0.5)  # noqa: SLF001
    with pytest.raises(CallRefusedError):
        await caller.place("+14155550100")
    assert gw.originated == []


@pytest.mark.parametrize(
    ("to", "reason"),
    [
        ("+33123456789", "country_not_allowed"),
        ("+19005551234", "destination_denied"),
        ("+442079460000", "destination_allowed_placeholder"),
        ("+882123456789", "destination_denied"),
        ("4155550100", "invalid_number"),
        ("+1415", "invalid_number"),
        ("+1415555010099999", "invalid_number"),
        ("+14155550100; DROP", "invalid_number"),
        ("", "invalid_number"),
    ],
)
async def test_pre_gate_refusals_never_reach_the_gate_or_dialer(to: str, reason: str) -> None:
    caller, gw, gate, rec, *_ = await rig()
    if reason == "destination_allowed_placeholder":
        await caller.place(to)  # +44 20... is allowed (premium +449 only is denied)
        return
    with pytest.raises(CallRefusedError) as ei:
        await caller.place(to)
    assert ei.value.reason == reason
    assert gate.requests == [] and gw.originated == []
    assert rec.state.blocked_actions == 1


async def test_uk_premium_range_is_denied_even_though_the_country_is_allowed() -> None:
    caller, gw, gate, *_ = await rig()
    with pytest.raises(CallRefusedError) as ei:
        await caller.place("+449012345678")
    assert ei.value.reason == "destination_denied" and gate.requests == []


async def test_empty_allow_list_and_missing_policy_deny_everything() -> None:
    for policy in (OutboundCallPolicy(), None):
        caller, gw, gate, *_ = await rig(policy=policy)
        with pytest.raises(CallRefusedError):
            await caller.place("+14155550100")
        assert gate.requests == [] and gw.originated == []


async def test_concurrency_rate_and_destination_caps() -> None:
    caller, gw, gate, rec, clock, limiter = await rig()
    await caller.place("+14155550101")
    with pytest.raises(CallRefusedError) as ei:
        await caller.place("+14155550101")
    assert ei.value.reason == "destination_cooldown"
    await caller.place("+14155550102")
    with pytest.raises(CallRefusedError) as ei:
        await caller.place("+14155550103")
    assert ei.value.reason == "concurrent_cap"
    caller.call_ended()
    await caller.place("+14155550103")
    caller.call_ended()
    caller.call_ended()
    with pytest.raises(CallRefusedError) as ei:
        await caller.place("+14155550104")
    assert ei.value.reason == "rate_cap"
    await clock.advance(61_000)  # window rolls over
    await caller.place("+14155550104")
    assert len(gw.originated) == 4


async def test_caps_are_per_tenant() -> None:
    clock = ManualVoiceClock()
    lim = OutboundLimiter({"a": POLICY, "b": POLICY}, clock)
    lim.check_and_reserve("a", "+14155550101")
    lim.check_and_reserve("a", "+14155550102")
    with pytest.raises(CallRefusedError):
        lim.check_and_reserve("a", "+14155550103")
    lim.check_and_reserve("b", "+14155550103")
    lim.release("zzz")


async def test_gate_args_carry_cap_state_for_policy() -> None:
    caller, _, gate, *_ = await rig()
    await caller.place("+14155550100")
    a = gate.requests[0].context["args"]
    assert (a["max_per_window"], a["max_concurrent"], a["max_duration_ms"]) == (3, 2, 600_000)


async def test_dial_failure_and_pending_approval() -> None:
    from axis_runtime import Decision
    from axis_runtime.gate import GateDecision

    caller, gw, *_ = await rig(
        ScriptedGate(GateDecision(Decision.REQUIRE_APPROVAL, "ask", approval_id="a"))
    )
    with pytest.raises(CallRefusedError) as ei:
        await caller.place("+14155550100")
    assert ei.value.reason == "approval_pending"

    caller, gw, *_ = await rig()

    async def boom(req):  # type: ignore[no-untyped-def]
        raise RuntimeError("trunk down")

    gw.originate = boom  # type: ignore[method-assign]
    with pytest.raises(CallRefusedError) as ei:
        await caller.place("+14155550100")
    assert ei.value.reason == "dial_failed"


async def test_originated_call_becomes_a_transport_once_answered() -> None:
    caller, gw, *_ = await rig()
    placed = await caller.place("+14155550100")
    gw.answer(placed.call_id)
    transport = await gw.transport_for(placed.call_id)
    assert (
        transport.info.to_number == "+14155550100" and transport.info.direction.value == "outbound"
    )
    with pytest.raises(KeyError):
        await gw.transport_for("nope")
    _ = allow
