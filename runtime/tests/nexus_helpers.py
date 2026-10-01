"""Shared NEXUS test fixtures: scripted stages and request builders."""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal

from axis_runtime.nexus import Hit, Miss, RouteRequest, RouteState
from axis_runtime.nexus.types import StageOutcome
from conftest import TENANT

T1 = TENANT
T2 = "22222222-2222-4222-8222-222222222222"
PID = "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV"


def req(prompt: str = "What is my deductible?", **kw: object) -> RouteRequest:
    base: dict[str, object] = {
        "tenant_id": T1,
        "prompt": prompt,
        "pid": PID,
        "principal": "user-1",
        "agent": "claims",
        "agent_version": "1.0.0",
        "trace_id": "c" * 32,
    }
    base.update(kw)
    return RouteRequest(**base)  # type: ignore[arg-type]


class ScriptedStage:
    """Stage whose behaviour is a function; records the order calls were made in."""

    def __init__(
        self,
        name: str,
        fn: Callable[[RouteRequest, RouteState], StageOutcome] | StageOutcome | None = None,
        log: list[str] | None = None,
    ) -> None:
        self.name = name
        self._fn = fn
        self.calls = 0
        self.log = log if log is not None else []

    async def run(self, request: RouteRequest, state: RouteState) -> StageOutcome:
        self.calls += 1
        self.log.append(self.name)
        if self._fn is None:
            return Miss("scripted_miss")
        if callable(self._fn):
            return self._fn(request, state)
        return self._fn


def hit(answer: str = "ans", cost: str = "0", **kw: object) -> Hit:
    return Hit(answer, cost=Decimal(cost), **kw)  # type: ignore[arg-type]
