"""Usage emitter: a whitelisted projection of the run log, idempotent sends, failure handling."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import httpx
import pytest
from axis_runtime.actions import Backends, MemoryWrite
from axis_runtime.events import EventType, InMemoryRunEventLog
from axis_runtime.executor import ActionExecutor, Completed, Denied
from axis_runtime.usage import BILLING_FIELDS, HttpUsageEmitter, UsageUnavailable, project_event
from conftest import FakeClock, ScriptedGate, allow, deny
from helpers import PID, identity, running_recorder

_FIXTURE = (
    Path(__file__).resolve().parents[2] / "services/billing/test/fixtures/run-projection.json"
)


class _Mem:
    async def write(self, scope: str, args: Mapping[str, Any], *, agent: str | None = None) -> Any:
        return {"id": "m1"}

    async def search(self, *a: Any, **k: Any) -> Sequence[Any]:  # pragma: no cover
        return []

    async def recall(self, *a: Any, **k: Any) -> Sequence[Any]:  # pragma: no cover
        return []


async def _log_with_actions() -> tuple[InMemoryRunEventLog, str]:
    rec = await running_recorder(FakeClock())
    log: InMemoryRunEventLog = rec.log  # type: ignore[assignment]
    allowed = ActionExecutor(
        gate=ScriptedGate(allow()),
        recorder=rec,
        identity=identity(),
        backends=Backends(memory=_Mem()),
        gate_timeout=0.2,
    )
    out = await allowed.run(
        MemoryWrite(name="w", scope="long_term", args={"content": "SECRET"}), pid=PID
    )
    assert isinstance(out, Completed)
    denied = ActionExecutor(
        gate=ScriptedGate(deny()),
        recorder=rec,
        identity=identity(),
        backends=Backends(memory=_Mem()),
        gate_timeout=0.2,
    )
    assert isinstance(
        await denied.run(MemoryWrite(name="w", scope="long_term", args={"content": "X"}), pid=PID),
        Denied,
    )
    await rec.record(
        EventType.GATE_DECISION,
        PID,
        {
            "action_id": "a-model",
            "enforcement_point": "model_call",
            "action": "model.complete",
            "decision": "ALLOW",
            "reason": "ok",
            "policy_version": "v1",
            "redact_fields": [],
            "approval_id": "",
            "audit_event_id": "",
        },
    )
    await rec.record(
        EventType.MODEL_CALL,
        PID,
        {
            "action_id": "a-model",
            "provider": "anthropic",
            "model": "m",
            "input_tokens": 10,
            "output_tokens": 5,
            "cached_tokens": 0,
            "cost_micro_usd": 7,
            "finish_reason": "stop",
            "latency_ms": 3,
            "attempts": ["x"],
        },
    )
    return log, "run_1"


def _client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


_OK = {"records": 1, "inserted": 1, "duplicates": 0, "conflicts": 0, "skipped": []}


async def test_projection_keeps_only_billing_fields_and_drops_unbilled_events() -> None:
    log, run_id = await _log_with_actions()
    events = await log.read(run_id)
    projected = [p for e in events if (p := project_event(e)) is not None]
    assert {p["type"] for p in projected} <= set(BILLING_FIELDS)
    text = json.dumps(projected)
    assert "SECRET" not in text and "cost_micro_usd" not in text and "latency_ms" not in text
    kinds = [p["type"] for p in projected]
    assert "action_blocked" not in kinds and "run_started" in kinds and "model_call" in kinds
    # a DENY is forwarded as a decision, so the service can refuse to bill it
    assert [p["data"]["decision"] for p in projected if p["type"] == "gate_decision"] == [
        "ALLOW",
        "DENY",
        "ALLOW",
    ]
    assert project_event(events[0]) is not None and project_event(events[0])["pid"] is None  # type: ignore[index]


async def test_emit_run_posts_the_projection_with_the_bearer_token() -> None:
    log, run_id = await _log_with_actions()
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json=_OK)

    emitter = HttpUsageEmitter("http://billing/", token="tok", client=_client(handler))
    assert await emitter.emit_run(log, run_id) == _OK
    req = seen[0]
    assert str(req.url) == "http://billing/v1/usage/run-events"
    assert req.headers["authorization"] == "Bearer tok"
    body = json.loads(req.content)
    assert body["run_id"] == run_id and body["events"][0]["type"] == "run_started"
    assert "tenant_id" not in {k for k in body}  # the tenant comes from the token, not the body
    await emitter.aclose()


async def test_nothing_billable_sends_nothing() -> None:
    called = False

    def handler(req: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json=_OK)

    emitter = HttpUsageEmitter("http://billing", token="t", client=_client(handler))
    out = await emitter.emit_events("run_1", [])
    assert out["records"] == 0 and not called
    await emitter.aclose()


@pytest.mark.parametrize(
    "respond",
    [
        lambda r: httpx.Response(500, json={}),
        lambda r: httpx.Response(403, json={"error": {"code": "FORBIDDEN"}}),
        lambda r: httpx.Response(200, content=b"not json"),
        lambda r: httpx.Response(200, json=["x"]),
        lambda r: httpx.Response(200, json={"nope": 1}),
    ],
)
async def test_failures_raise_usage_unavailable_without_leaking_bodies(
    respond: Callable[[httpx.Request], httpx.Response],
) -> None:
    log, run_id = await _log_with_actions()
    emitter = HttpUsageEmitter("http://billing", token="t", client=_client(respond))
    with pytest.raises(UsageUnavailable) as exc:
        await emitter.emit_run(log, run_id)
    assert "SECRET" not in str(exc.value)
    await emitter.aclose()


async def test_transport_errors_raise_usage_unavailable() -> None:
    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=req)

    log, run_id = await _log_with_actions()
    emitter = HttpUsageEmitter("http://billing", token="t", client=_client(boom))
    with pytest.raises(UsageUnavailable, match="transport:ConnectError"):
        await emitter.emit_run(log, run_id)
    await emitter.aclose()


async def test_default_client_is_created() -> None:
    emitter = HttpUsageEmitter("http://billing", token="t")
    await emitter.aclose()


async def test_projection_matches_the_golden_contract_fixture_the_billing_service_consumes() -> (
    None
):
    """services/billing/test/fixtures/run-projection.json is read by the TS mapper tests: both sides pin the same wire."""
    fixture = _FIXTURE
    log, run_id = await _log_with_actions()
    projected = [p for e in await log.read(run_id) if (p := project_event(e)) is not None]
    if not fixture.exists():  # first run writes it; afterwards it is a regression pin
        fixture.write_text(json.dumps(projected, indent=2, sort_keys=True) + "\n")
    assert json.loads(fixture.read_text()) == json.loads(json.dumps(projected))
