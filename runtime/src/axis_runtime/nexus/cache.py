"""Cache stage: tenant-scoped, TTL-bound, never used for PHI or uncacheable responses.

Isolation is structural, not by convention: the store is a ``tenant_id -> entries`` map and its API
cannot read without a tenant; the key digest additionally includes the tenant (and, by default, the
principal and agent identity), so even a shared backend keyed by digest alone could not collide
across tenants.  Telemetry only ever sees a truncated digest, never the prompt.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Protocol

from axis_runtime.nexus.types import Hit, Miss, RouteRequest, RouteState, StageOutcome

_WS = re.compile(r"\s+")


class CacheClock(Protocol):
    def monotonic(self) -> float: ...


@dataclass(frozen=True)
class CacheEntry:
    answer: str
    confidence: float
    expires_at: float
    source_stage: str
    tokens_saved: int = 0
    cost_saved: Decimal = Decimal(0)


class CacheStore(Protocol):
    async def get(self, tenant_id: str, key: str) -> CacheEntry | None: ...
    async def put(self, tenant_id: str, key: str, entry: CacheEntry) -> None: ...


class InMemoryCache:
    """Per-tenant LRU with TTL.  Each tenant has its own bounded map, so one tenant cannot evict or
    observe another's entries."""

    def __init__(self, clock: CacheClock, *, max_entries_per_tenant: int = 1024) -> None:
        if max_entries_per_tenant < 1:
            raise ValueError("max_entries_per_tenant must be >= 1")
        self._clock = clock
        self._max = max_entries_per_tenant
        self._data: dict[str, dict[str, CacheEntry]] = {}

    async def get(self, tenant_id: str, key: str) -> CacheEntry | None:
        if not tenant_id:
            raise ValueError("tenant_id required")
        bucket = self._data.get(tenant_id)
        entry = bucket.get(key) if bucket else None
        if bucket is None or entry is None:
            return None
        if entry.expires_at <= self._clock.monotonic():
            del bucket[key]
            return None
        del bucket[key]  # re-insert: dicts keep insertion order, so the head is least recent
        bucket[key] = entry
        return entry

    async def put(self, tenant_id: str, key: str, entry: CacheEntry) -> None:
        if not tenant_id:
            raise ValueError("tenant_id required")
        bucket = self._data.setdefault(tenant_id, {})
        bucket.pop(key, None)
        bucket[key] = entry
        while len(bucket) > self._max:
            del bucket[next(iter(bucket))]

    def size(self, tenant_id: str) -> int:
        return len(self._data.get(tenant_id, ()))


def cache_key(request: RouteRequest, *, scope_principal: bool = True) -> str:
    """SHA-256 hex digest of the canonical (tenant, principal, agent, system prompt, prompt)."""
    material = json.dumps(
        [
            request.tenant_id,
            request.principal if scope_principal else "",
            request.agent,
            request.agent_version,
            hashlib.sha256(request.system_prompt.encode()).hexdigest(),
            _WS.sub(" ", request.prompt).strip(),
        ],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(material.encode()).hexdigest()


class CacheStage:
    name = "cache"

    def __init__(
        self,
        store: CacheStore,
        clock: CacheClock,
        *,
        ttl_seconds: float = 300.0,
        scope_principal: bool = True,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        self._store = store
        self._clock = clock
        self._ttl = ttl_seconds
        self._scope_principal = scope_principal

    async def run(self, request: RouteRequest, state: RouteState) -> StageOutcome:
        if request.phi:
            return Miss("phi")
        key = cache_key(request, scope_principal=self._scope_principal)
        digest = key[:16]
        entry = await self._store.get(request.tenant_id, key)
        if entry is None:
            return Miss("not_cached", cache_key_hash=digest)
        return Hit(
            entry.answer,
            confidence=entry.confidence,
            cacheable=False,  # already cached; do not refresh the TTL from a cache hit
            cache_key_hash=digest,
            meta={"source_stage": entry.source_stage, "cost_saved": str(entry.cost_saved)},
        )

    async def write_back(self, request: RouteRequest, hit: Hit, source_stage: str) -> None:
        if request.phi or not hit.cacheable or hit.tool_calls:
            return
        key = cache_key(request, scope_principal=self._scope_principal)
        await self._store.put(
            request.tenant_id,
            key,
            CacheEntry(
                hit.answer,
                hit.confidence,
                self._clock.monotonic() + self._ttl,
                source_stage,
                hit.tokens,
                hit.cost,
            ),
        )
