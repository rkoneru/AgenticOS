"""NEXUS core types: request, Hit/Miss stage outcomes, per-stage records and the RouteResult."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Protocol, runtime_checkable

from axis_runtime.models.types import ToolCallRequest

STAGE_NAMES = ("cache", "rules", "mpm", "rag", "llm")
ZERO = Decimal(0)


def hash_text(value: str, *, length: int = 16) -> str:
    """Short SHA-256 digest for any prompt-derived value that must be logged (never the prompt)."""
    return hashlib.sha256(value.encode()).hexdigest()[:length]


@dataclass(frozen=True)
class RouteRequest:
    """One routing decision.  ``tenant_id`` and ``principal`` scope every stage that stores or reads
    data; ``phi`` forbids caching.  ``pid`` is the process on whose behalf the LLM stage acts."""

    tenant_id: str
    prompt: str
    pid: str
    principal: str = ""
    agent: str = ""
    agent_version: str = ""
    phi: bool = False
    intent: str | None = None
    capability: str | None = None
    trace_id: str = ""
    system_prompt: str = ""


@dataclass(frozen=True)
class Passage:
    """A retrieved passage with its owning tenant and the principals allowed to read it."""

    id: str
    tenant_id: str
    text: str
    score: float = 0.0
    allowed_principals: frozenset[str] = frozenset()  # empty = any principal of the tenant


@dataclass(frozen=True)
class Hit:
    """A stage resolved the request.  The first Hit short-circuits the pipeline."""

    answer: str
    cost: Decimal = ZERO
    confidence: float = 1.0
    tokens: int = 0
    cacheable: bool = True
    tool_calls: tuple[ToolCallRequest, ...] = ()
    cache_key_hash: str | None = None
    meta: Mapping[str, Any] = field(default_factory=dict)

    def problem(self) -> str | None:
        if not 0.0 <= self.confidence <= 1.0:
            return "confidence_out_of_range"
        if self.cost < 0 or self.tokens < 0:
            return "negative_cost_or_tokens"
        return None


@dataclass(frozen=True)
class Miss:
    """A stage did not resolve the request.  ``blocked`` marks a terminal refusal (gate DENY or
    approval pending) that must NOT be retried elsewhere; ``context`` carries passages (RAG) for the
    stages after it."""

    reason: str = ""
    cost: Decimal = ZERO
    tokens: int = 0
    blocked: bool = False
    cache_key_hash: str | None = None
    context: tuple[Passage, ...] = ()


StageOutcome = Hit | Miss


@dataclass
class RouteState:
    """Mutable, per-route scratch space shared by the stages of ONE route."""

    retrieved: list[Passage] = field(default_factory=list)


class Stage(Protocol):
    name: str

    async def run(self, request: RouteRequest, state: RouteState) -> StageOutcome: ...


@runtime_checkable
class WriteBackStage(Protocol):
    """A stage that learns from a later stage's Hit (the cache)."""

    name: str

    async def write_back(self, request: RouteRequest, hit: Hit, source_stage: str) -> None: ...


@dataclass(frozen=True)
class StageRecord:
    stage: str
    outcome: str  # "hit" | "miss"
    reason: str
    latency_ms: float
    tokens: int
    cost_usd: Decimal
    cache_key_hash: str | None = None
    confidence: float | None = None


@dataclass(frozen=True)
class RouteResult:
    status: str  # "hit" | "blocked" | "exhausted"
    answer: str | None
    hit_stage: str | None
    stages: tuple[StageRecord, ...]
    tool_calls: tuple[ToolCallRequest, ...] = ()
    confidence: float | None = None
    total_latency_ms: float = 0.0
    sink_errors: int = 0
    blocked_reason: str = ""

    @property
    def total_cost_usd(self) -> Decimal:
        return sum((s.cost_usd for s in self.stages), ZERO)

    @property
    def total_tokens(self) -> int:
        return sum(s.tokens for s in self.stages)

    @property
    def cost_by_stage(self) -> dict[str, Decimal]:
        out: dict[str, Decimal] = {}
        for s in self.stages:
            out[s.stage] = out.get(s.stage, ZERO) + s.cost_usd
        return out
