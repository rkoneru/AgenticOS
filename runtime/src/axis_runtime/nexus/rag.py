"""RAG stage: retrieval interface plus an in-memory fake (the real memory service is Phase 4).

Every retrieval carries ``tenant_id`` AND the requesting principal; a retriever must never return a
passage of another tenant or one the principal may not read.  The stage re-checks both (defence in
depth: a buggy or malicious retriever cannot widen access).  A confident passage answers directly
(extractive); otherwise the passages ride along on the Miss as context for the LLM stage.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from axis_runtime.nexus.types import Hit, Miss, Passage, RouteRequest, RouteState, StageOutcome


class Retriever(Protocol):
    async def retrieve(
        self, *, tenant_id: str, principal: str, query: str, limit: int
    ) -> Sequence[Passage]: ...


def _tokens(text: str) -> set[str]:
    return {w for w in "".join(c.lower() if c.isalnum() else " " for c in text).split() if w}


class InMemoryRetriever:
    """Deterministic lexical-overlap retriever.  A test fake, not a vector store."""

    def __init__(self, passages: Sequence[Passage] = ()) -> None:
        self._passages = list(passages)

    def add(self, passage: Passage) -> None:
        self._passages.append(passage)

    async def retrieve(
        self, *, tenant_id: str, principal: str, query: str, limit: int
    ) -> Sequence[Passage]:
        if not tenant_id:
            raise ValueError("tenant_id required")
        q = _tokens(query)
        scored: list[Passage] = []
        for p in self._passages:
            if p.tenant_id != tenant_id:
                continue
            if p.allowed_principals and principal not in p.allowed_principals:
                continue
            t = _tokens(p.text)
            score = len(q & t) / len(q) if q else 0.0
            if score > 0:
                scored.append(Passage(p.id, p.tenant_id, p.text, score, p.allowed_principals))
        scored.sort(key=lambda p: (-p.score, p.id))
        return scored[:limit]


class RagStage:
    name = "rag"

    def __init__(
        self, retriever: Retriever, *, limit: int = 3, answer_threshold: float = 0.9
    ) -> None:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        self._retriever = retriever
        self._limit = limit
        self._threshold = answer_threshold

    async def run(self, request: RouteRequest, state: RouteState) -> StageOutcome:
        found = await self._retriever.retrieve(
            tenant_id=request.tenant_id,
            principal=request.principal,
            query=request.prompt,
            limit=self._limit,
        )
        usable = tuple(
            p
            for p in found
            if p.tenant_id == request.tenant_id
            and (not p.allowed_principals or request.principal in p.allowed_principals)
        )[: self._limit]
        if not usable:
            return Miss("no_passages")
        best = usable[0]
        if best.score >= self._threshold:
            return Hit(
                best.text,
                confidence=min(1.0, best.score),
                meta={"passage_ids": [p.id for p in usable]},
            )
        return Miss("low_score", context=usable)
