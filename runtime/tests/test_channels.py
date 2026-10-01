"""Channel sender: gating through the executor, wire contract, tenant binding, no body leakage."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from axis_runtime import Decision
from axis_runtime.actions import Backends, MessageSend
from axis_runtime.channels import CHANNELS, ChannelUnavailable, ChannelWiring, HttpChannelSender
from axis_runtime.executor import ActionExecutor, Completed, Denied, Failed
from axis_runtime.gate import GateDecision
from conftest import TENANT, FakeClock, ScriptedGate, allow, deny
from helpers import PID, identity, running_recorder

ROOT = Path(__file__).resolve().parents[2]
WIRE = json.loads((ROOT / "services/channels/contract/wire-v1.json").read_text())

Handler = Callable[[httpx.Request], httpx.Response]


class Wire:
    def __init__(self, handler: Handler | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self._handler = handler

    def client(self) -> httpx.AsyncClient:
        def respond(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            if self._handler is not None:
                return self._handler(request)
            return httpx.Response(
                200, json={"conversation_id": "c1", "parts": 1, "message_ids": ["m1"]}
            )

        return httpx.AsyncClient(transport=httpx.MockTransport(respond))

    def bodies(self) -> list[dict[str, Any]]:
        return [json.loads(r.content) for r in self.requests]


def sender(wire: Wire, **kw: Any) -> HttpChannelSender:
    kw.setdefault("run_id", "run_1")
    kw.setdefault("trace_id", "0123456789abcdef0123456789abcdef")
    return HttpChannelSender(
        "http://chan", token="tok", tenant_id=TENANT, client=wire.client(), **kw
    )


async def _executor(gate: ScriptedGate, s: HttpChannelSender) -> ActionExecutor:
    return ActionExecutor(
        gate=gate,
        recorder=await running_recorder(FakeClock()),
        identity=identity(),
        backends=Backends(channels=s),
        gate_timeout=0.2,
    )


def _send(channel: str = "slack", **args: Any) -> MessageSend:  # the manifest tool: kind "channel"
    args.setdefault("body", "hello")
    args.setdefault("conversation_id", "c1")
    return MessageSend(name="notify", channel=channel, args=args)


# ---- gating: a message is an Action, so the gate decides --------------------------------------
async def test_allowed_send_reaches_the_service_as_a_gated_action() -> None:
    wire = Wire()
    gate = ScriptedGate(allow())
    ex = await _executor(gate, sender(wire))
    out = await ex.run(_send(), pid=PID)
    assert isinstance(out, Completed)
    assert out.result == {"conversation_id": "c1", "parts": 1, "message_ids": ["m1"]}
    assert [r.enforcement_point for r in gate.requests] == ["message_send"]
    req = wire.requests[0]
    assert str(req.url) == "http://chan/v1/channels/send"
    assert req.headers["authorization"] == "Bearer tok"
    assert wire.bodies()[0]["tenant_id"] == TENANT


async def test_denied_send_never_calls_the_service() -> None:
    wire = Wire()
    ex = await _executor(ScriptedGate(deny()), sender(wire))
    out = await ex.run(_send(), pid=PID)
    assert isinstance(out, Denied)
    assert wire.requests == []


async def test_gate_error_or_timeout_never_sends() -> None:
    wire = Wire()

    def boom(_r: Any) -> GateDecision:
        raise RuntimeError("kernel down")

    ex = await _executor(ScriptedGate(boom), sender(wire))
    out = await ex.run(_send(), pid=PID)
    assert not isinstance(out, Completed)
    assert wire.requests == []


async def test_gate_redaction_is_applied_before_the_service_sees_the_message() -> None:
    wire = Wire()
    gate = ScriptedGate(
        GateDecision(Decision.ALLOW_WITH_REDACTION, "phi", redact_fields=("args.body",))
    )
    ex = await _executor(gate, sender(wire))
    out = await ex.run(_send(body="patient SSN 111-22-3333"), pid=PID)
    assert isinstance(out, Completed)
    assert "111-22-3333" not in json.dumps(wire.bodies())


async def test_service_failure_is_a_failed_result_without_the_response_body() -> None:
    wire = Wire(lambda _r: httpx.Response(403, json={"error": "FORBIDDEN", "message": "secret"}))
    ex = await _executor(ScriptedGate(allow()), sender(wire))
    out = await ex.run(_send(), pid=PID)
    assert isinstance(out, Failed)
    assert "FORBIDDEN" in out.error and "secret" not in out.error


# ---- wire contract shared with the real server -------------------------------------------------
@pytest.mark.parametrize("case", WIRE["send"], ids=[c["name"] for c in WIRE["send"]])
async def test_requests_match_the_shared_wire_contract(case: dict[str, Any]) -> None:
    def sub(v: Any) -> Any:
        return json.loads(
            json.dumps(v).replace("{tenant}", TENANT).replace("{conversation}", "conv-1")
        )

    resp = sub(case["response"])
    wire = Wire(lambda _r: httpx.Response(200, json=resp))
    out = await sender(wire).send(case["channel"], sub(case["args"]))
    assert wire.bodies() == [sub(case["request"])]
    assert out == {k: v for k, v in resp.items() if k != "audit_hashes"}


# ---- validation --------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("channel", "args", "msg"),
    [
        ("fax", {"body": "x", "to": "1"}, "unknown channel"),
        ("sms", {"to": "+1555"}, "non-empty string 'body'"),
        ("sms", {"body": "", "to": "+1555"}, "non-empty string 'body'"),
        ("sms", {"body": 5, "to": "+1555"}, "non-empty string 'body'"),
        ("sms", {"body": "x"}, "'conversation_id' or 'to'"),
        ("sms", {"body": "x", "to": ""}, "non-empty string"),
        ("sms", {"body": "x", "to": 5}, "non-empty string"),
    ],
)
async def test_invalid_messages_are_rejected_before_any_request(
    channel: str, args: dict[str, Any], msg: str
) -> None:
    wire = Wire()
    with pytest.raises(ValueError, match=msg):
        await sender(wire).send(channel, args)
    assert wire.requests == []


async def test_text_is_an_alias_for_body_and_optional_fields_pass_through() -> None:
    wire = Wire()
    await sender(wire).send(
        "email", {"text": "hi", "to": "a@b.co", "subject": "S", "from": "support@x.co"}
    )
    body = wire.bodies()[0]
    assert body["text"] == "hi" and body["subject"] == "S" and body["from"] == "support@x.co"


async def test_every_known_channel_is_accepted() -> None:
    wire = Wire()
    s = sender(wire)
    for ch in sorted(CHANNELS):
        await s.send(ch, {"body": "x", "to": "t"})
    assert len(wire.requests) == len(CHANNELS)


async def test_run_and_trace_ids_are_optional() -> None:
    wire = Wire()
    s = HttpChannelSender("http://chan/", token="t", tenant_id=TENANT, client=wire.client())
    await s.send("sms", {"body": "x", "to": "+1"})
    assert "run_id" not in wire.bodies()[0] and "trace_id" not in wire.bodies()[0]
    assert str(wire.requests[0].url) == "http://chan/v1/channels/send"


# ---- failure modes -----------------------------------------------------------------------------
async def test_transport_errors_never_leak_details() -> None:
    def boom(_r: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connect to secret-host failed")

    with pytest.raises(ChannelUnavailable) as e:
        await sender(Wire(boom)).send("sms", {"body": "x", "to": "+1"})
    assert "secret-host" not in str(e.value) and "ConnectError" in str(e.value)


@pytest.mark.parametrize(
    ("resp", "expect"),
    [
        (httpx.Response(500, content=b"<html>secret</html>"), "500 (error)"),
        (httpx.Response(404, json={"error": "NOT_FOUND"}), "404 (NOT_FOUND)"),
        (httpx.Response(429, json={"error": "made-up"}), "429 (error)"),
        (httpx.Response(502, json=["x"]), "502 (error)"),
        (httpx.Response(200, content=b"not json"), "invalid JSON"),
        (httpx.Response(200, json=["x"]), "invalid response"),
    ],
)
async def test_bad_responses_become_channel_unavailable(resp: httpx.Response, expect: str) -> None:
    with pytest.raises(ChannelUnavailable, match=expect.replace("(", r"\(").replace(")", r"\)")):
        await sender(Wire(lambda _r: resp)).send("sms", {"body": "x", "to": "+1"})


def test_construction_requires_tenant_and_token() -> None:
    with pytest.raises(ValueError, match="tenant_id"):
        HttpChannelSender("http://c", token="t", tenant_id="")
    with pytest.raises(ValueError, match="token"):
        HttpChannelSender("http://c", token="", tenant_id=TENANT)


async def test_wiring_builds_a_tenant_bound_sender_and_does_not_print_the_token() -> None:
    wire = Wire()
    wiring = ChannelWiring(
        "http://chan",
        token="s3cret",
        transport=httpx.MockTransport(
            lambda r: (wire.requests.append(r), httpx.Response(200, json={"parts": 1}))[1]
        ),
    )
    assert "s3cret" not in repr(wiring)
    s = wiring.sender(tenant_id=TENANT, run_id="r1")
    assert (await s.send("sms", {"body": "x", "to": "+1"})) == {"parts": 1}
    assert wire.bodies()[0]["tenant_id"] == TENANT and wire.bodies()[0]["run_id"] == "r1"
    await s.aclose()
