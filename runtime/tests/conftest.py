"""Shared test helpers: fake clock, scripted gate, scripted HTTP transport, manifest builder."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from axis_runtime import Decision
from axis_runtime.events import InMemoryRunEventLog, RunRecorder
from axis_runtime.gate import EvaluateRequest, GateDecision
from axis_runtime.manifest import RuntimeManifest
from axis_runtime.models import (
    InMemorySecretStore,
    ModelGateway,
    RetryPolicy,
)
from axis_runtime.models.adapters.base import HttpCall, HttpResponse, StreamHandle
from axis_runtime.run import RunDeps
from axis_runtime.tools import ToolRegistry

TENANT = "11111111-1111-4111-8111-111111111111"


class FakeClock:
    """Deterministic clock usable as events.Clock and models ModelClock (sleep records, no wait)."""

    def __init__(self) -> None:
        self.t = datetime(2026, 1, 1, tzinfo=UTC)
        self.mono = 0.0
        self.slept: list[float] = []

    def now(self) -> datetime:
        self.t += timedelta(milliseconds=1)
        return self.t

    def monotonic(self) -> float:
        return self.mono

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.mono += seconds

    def advance(self, seconds: float) -> None:
        self.mono += seconds
        self.t += timedelta(seconds=seconds)


class FixedRng:
    """rng.uniform(a, b) -> b (the ceiling), so delays are predictable."""

    def uniform(self, a: float, b: float) -> float:
        return b


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


def allow(reason: str = "ok") -> GateDecision:
    return GateDecision(Decision.ALLOW, reason, policy_version="v1")


def deny(reason: str = "nope") -> GateDecision:
    return GateDecision(Decision.DENY, reason, policy_version="v1")


class ScriptedGate:
    """GateClient driven by a function; records every request."""

    def __init__(
        self, fn: Callable[[EvaluateRequest], GateDecision] | GateDecision | None = None
    ) -> None:
        if fn is None:
            fn = allow()
        self._fn = fn if callable(fn) else (lambda _r: fn)  # type: ignore[misc, return-value]
        self.requests: list[EvaluateRequest] = []

    async def evaluate(self, request: EvaluateRequest) -> GateDecision:
        self.requests.append(request)
        return self._fn(request)  # type: ignore[no-any-return]


def manifest_dict(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "manifest_version": 1,
        "blueprint": {"name": "claims-triage", "version": "1.0.0", "content_hash": "a" * 64},
        "risk": {
            "level": "limited",
            "human_oversight_required": False,
            "approver_roles": [],
            "transparency_notice": "You are talking to an AI.",
        },
        "models": {
            "primary": {
                "provider": "openai",
                "model": "gpt-4o",
                "endpoint": None,
                "params": {"temperature": 0},
            },
            "fallbacks": [],
        },
        "routing": {"stages": ["llm"]},
        "system_prompt": "You triage claims.",
        "tools": [
            {
                "name": "lookup_claim",
                "kind": "function",
                "ref": None,
                "mcp_server": None,
                "side_effects": "read",
                "timeout_seconds": 60,
            }
        ],
        "memory": {"run": True, "session": False, "long_term": False, "knowledge_bases": []},
        "budgets": {
            "tokens": {"soft": None, "hard": None},
            "cost_usd": {"soft": None, "hard": None},
            "runtime_seconds": {"soft": None, "hard": None},
            "tool_calls": {"soft": None, "hard": None},
        },
        "process": {
            "restart_policy": "never",
            "max_restarts": 0,
            "max_children": 0,
            "timeout_seconds": None,
            "supervisor": "one-for-one",
        },
        "policy_packs": [],
        "channels": [],
        "data": {"phi": False, "residency": None},
        "evals": [],
    }
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            base[k] = {**base[k], **v}
        else:
            base[k] = v
    return base


def make_manifest(**over: Any) -> RuntimeManifest:
    return RuntimeManifest.from_dict(manifest_dict(**over))


# ---- scripted HTTP (OpenAI chat-completions format) ----------------------------------------


def openai_body(
    text: str | None = "done",
    tool_calls: list[tuple[str, str, dict[str, Any]]] | None = None,
    prompt: int = 10,
    completion: int = 5,
    finish: str | None = None,
) -> dict[str, Any]:
    msg: dict[str, Any] = {"role": "assistant", "content": text}
    if tool_calls:
        msg["tool_calls"] = [
            {"id": i, "type": "function", "function": {"name": n, "arguments": json.dumps(a)}}
            for i, n, a in tool_calls
        ]
    return {
        "id": "chatcmpl-1",
        "model": "gpt-4o-2024-08-06",
        "choices": [
            {
                "index": 0,
                "message": msg,
                "finish_reason": finish or ("tool_calls" if tool_calls else "stop"),
            }
        ],
        "usage": {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "prompt_tokens_details": {"cached_tokens": 0},
        },
    }


def final_body(text: str = "done", **kw: Any) -> dict[str, Any]:
    """A plain assistant answer (no tool calls)."""
    return openai_body(text, **kw)


def tool_turn_body(*calls: tuple[str, dict[str, Any]], **kw: Any) -> dict[str, Any]:
    """An assistant turn that requests the given (tool_name, arguments) calls."""
    return openai_body(None, [(f"call_{i}", n, a) for i, (n, a) in enumerate(calls)], **kw)


@dataclass
class ScriptedTransport:
    """Transport returning queued (status, body) pairs; records calls. Sleeps never happen."""

    responses: list[tuple[int, Any]] = field(default_factory=list)
    calls: list[HttpCall] = field(default_factory=list)
    delay: Callable[[], Any] | None = None

    def queue(self, status: int, body: Any) -> None:
        self.responses.append((status, body))

    async def send(self, call: HttpCall) -> HttpResponse:
        self.calls.append(call)
        if self.delay is not None:
            await self.delay()
        status, body = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        return HttpResponse(status, {}, raw)

    @asynccontextmanager
    async def stream(self, call: HttpCall) -> AsyncIterator[StreamHandle]:  # pragma: no cover
        raise NotImplementedError
        yield


async def _public_resolver(host: str, port: int) -> list[str]:
    return ["93.184.216.34"]


def make_gateway(
    transport: ScriptedTransport,
    clock: FakeClock,
    *,
    secrets: InMemorySecretStore | None = None,
    **kw: Any,
) -> ModelGateway:
    return ModelGateway(
        secrets or _store_with_keys(),
        transport=transport,
        clock=clock,
        rng=FixedRng(),
        resolver=_public_resolver,
        retry=RetryPolicy(max_attempts=3, base_delay=1.0, max_delay=8.0),
        **kw,
    )


def _store_with_keys() -> InMemorySecretStore:
    return InMemorySecretStore({(TENANT, "openai", "default"): "sk-test-secret-123"})


def make_deps(
    *,
    gate: Any = None,
    transport: ScriptedTransport | None = None,
    clock: FakeClock | None = None,
    tools: ToolRegistry | None = None,
    **kw: Any,
) -> RunDeps:
    clock = clock or FakeClock()
    transport = transport or ScriptedTransport([(200, openai_body())])
    return RunDeps(
        tenant_id=TENANT,
        gate=gate or ScriptedGate(),
        models=make_gateway(transport, clock),
        tools=tools or ToolRegistry(),
        log=InMemoryRunEventLog(),
        clock=clock,
        **kw,
    )


async def started_recorder(clock: FakeClock | None = None) -> RunRecorder:
    return await RunRecorder.start(
        InMemoryRunEventLog(), clock or FakeClock(), run_id="run_1", tenant_id=TENANT, meta={}
    )
