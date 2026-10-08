"""Shared fixtures of the eval tests: a scripted model provider, a scripted gate, manifests, and an
in-memory Eval Hub."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from axis_runtime.evals.hubclient import EvalHubClient, HubError
from axis_runtime.evals.types import Dataset, EvalCase, GraderSpec, OnlineConfig, QueuedRun, Suite
from axis_runtime.events import InMemoryRunEventLog
from axis_runtime.gate import EvaluateRequest, GateDecision
from axis_runtime.manifest import RuntimeManifest
from axis_runtime.models.adapters.base import HttpCall, HttpResponse, StreamHandle
from axis_runtime.run import RunDeps
from conftest import (
    TENANT,
    FakeClock,
    ScriptedGate,
    allow,
    make_gateway,
    manifest_dict,
    openai_body,
)

__all__ = ["TENANT"]


class FnTransport:
    """Scripted model provider: ``fn(messages, n) -> response body | (status, body)``, where
    ``messages`` is the request's chat history and ``n`` the 0-based number of calls so far."""

    def __init__(
        self,
        fn: Callable[[list[dict[str, Any]], int], Any],
        delay: Callable[[list[dict[str, Any]]], Awaitable[None]] | None = None,
    ) -> None:
        self.fn = fn
        self.delay = delay
        self.calls: list[list[dict[str, Any]]] = []
        self.bodies: list[dict[str, Any]] = []

    async def send(self, call: HttpCall) -> HttpResponse:
        body = json.loads(call.body)
        messages = body["messages"]
        self.bodies.append(body)
        self.calls.append(messages)
        if self.delay is not None:
            await self.delay(messages)
        out = self.fn(messages, len(self.calls) - 1)
        status, payload = out if isinstance(out, tuple) else (200, out)
        return HttpResponse(status, {}, json.dumps(payload).encode())

    @asynccontextmanager
    async def stream(self, call: HttpCall) -> AsyncIterator[StreamHandle]:  # pragma: no cover
        raise NotImplementedError
        yield


def user_text(messages: Sequence[Mapping[str, Any]]) -> str:
    return "\n".join(str(m.get("content")) for m in messages if m.get("role") == "user")


def text_body(text: str) -> dict[str, Any]:
    return openai_body(text)


def make_manifest(**over: Any) -> RuntimeManifest:
    over.setdefault("tools", [])
    over.setdefault("memory", {"run": False, "session": False, "long_term": False, "knowledge_bases": []})
    return RuntimeManifest.from_dict(manifest_dict(**over))


def make_base_deps(
    transport: FnTransport,
    gate: ScriptedGate | None = None,
    *,
    tenant: str = TENANT,
) -> Callable[[], RunDeps]:
    clock = FakeClock()
    gw = make_gateway(transport, clock)  # type: ignore[arg-type]
    g = gate or ScriptedGate(allow())

    def factory() -> RunDeps:
        return RunDeps(tenant_id=tenant, gate=g, models=gw, log=InMemoryRunEventLog(), clock=clock)

    return factory


def policy_gate(fn: Callable[[EvaluateRequest], GateDecision]) -> ScriptedGate:
    return ScriptedGate(fn)


class SeqIds:
    """Deterministic ids for assertions."""

    def __init__(self) -> None:
        self.n = 0

    def run_id(self) -> str:
        self.n += 1
        return f"run_eval{self.n:04d}"

    def trace_id(self) -> str:
        return f"{self.n:032x}"


def cases(*pairs: tuple[str, Any]) -> tuple[EvalCase, ...]:
    return tuple(EvalCase(id=i, input=inp, expected=None) for i, inp in pairs)


def det(id_: str, type_: str, weight: float = 1.0, **cfg: Any) -> GraderSpec:
    return GraderSpec(id_, "deterministic", weight, {"type": type_, **cfg})


# ---- in-memory hub ---------------------------------------------------------------------------


@dataclass
class FakeHub(EvalHubClient):  # type: ignore[misc]
    queue: list[QueuedRun] = field(default_factory=list)
    suites: dict[str, Suite] = field(default_factory=dict)
    datasets: dict[str, Dataset] = field(default_factory=dict)
    submissions: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    tasks: list[tuple[str, list[dict[str, Any]]]] = field(default_factory=list)
    online: list[OnlineConfig] = field(default_factory=list)
    online_results: list[dict[str, Any]] = field(default_factory=list)
    fail_submits: int = 0
    fail_online: bool = False

    async def claim_run(self) -> QueuedRun | None:
        return self.queue.pop(0) if self.queue else None

    async def get_suite(self, ref: str) -> Suite:
        if ref not in self.suites:
            raise HubError("http_404")
        return self.suites[ref]

    async def get_dataset(self, ref: str) -> Dataset:
        if ref not in self.datasets:
            raise HubError("http_404")
        return self.datasets[ref]

    async def submit_results(self, run_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        if self.fail_submits:
            self.fail_submits -= 1
            raise HubError("http_503")
        self.submissions.append((run_id, dict(payload)))
        return {"ok": True}

    async def create_review_tasks(
        self, run_id: str, tasks: Sequence[Mapping[str, Any]]
    ) -> Mapping[str, Any]:
        self.tasks.append((run_id, [dict(t) for t in tasks]))
        return {"created": len(tasks)}

    async def online_configs(self) -> list[OnlineConfig]:
        return list(self.online)

    async def post_online_results(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        if self.fail_online:
            raise HubError("http_503")
        self.online_results.append(dict(payload))
        return {"ok": True}

    async def aclose(self) -> None:
        return None
