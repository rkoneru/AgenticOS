"""Memory backend and RAG retriever over the memory service's HTTP/JSON dev surface.

``HttpMemoryBackend`` implements ``tools.MemoryStore`` (what ``MemoryWrite`` performs). It is
reachable only through ``ActionExecutor`` (gate -> audit -> perform), so every long-term write is a
gated action. ``MemoryRagRetriever`` implements ``nexus.rag.Retriever``: it is read-only and
carries ``tenant_id`` and the requesting principal on every call; the service returns ONLY passages
that principal may read, and the stage re-checks tenant and principal on top.

The tenant is bound by the bearer token (the service derives it from the token and rejects a
different ``tenant_id`` in the body), so a client built for tenant A cannot address tenant B. The
principal is supplied by this trusted runtime. The wire format is
``services/memory/contract/wire-v1.json``; the service is a loopback dev bridge, not a production
surface (docs/NEEDS.md). Any failure raises ``MemoryUnavailable``: the executor turns an action
failure into a failed result and the NEXUS router turns a stage failure into a miss.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import httpx

from axis_runtime.nexus.types import Passage

#: ABL/runtime scope names -> service scopes.
_SCOPES = {
    "run": "run",
    "session": "session",
    "long_term": "agent",
    "longTerm": "agent",
    "agent": "agent",
    "tenant": "tenant",
}
_PASSTHROUGH = ("metadata", "acl", "subject", "ttl_seconds", "phi")


class MemoryUnavailable(RuntimeError):  # noqa: N818 - a condition, not a failure class hierarchy
    """The memory service could not answer.  Never carries response bodies (they may hold
    content)."""


class _Client:
    def __init__(
        self,
        base_url: str,
        *,
        token: str,
        tenant_id: str,
        client: httpx.AsyncClient | None,
        timeout: float,
    ) -> None:
        if not tenant_id:
            raise ValueError("tenant_id required")
        self._base = base_url.rstrip("/") + "/v1/memory/"
        self._headers = {"authorization": f"Bearer {token}"}
        self.tenant_id = tenant_id
        self._client = client or httpx.AsyncClient(timeout=timeout)

    async def post(self, route: str, body: Mapping[str, Any]) -> dict[str, Any]:
        payload = {"tenant_id": self.tenant_id, **body}
        try:
            resp = await self._client.post(self._base + route, json=payload, headers=self._headers)
        except httpx.HTTPError as exc:
            raise MemoryUnavailable(f"transport error: {type(exc).__name__}") from exc
        if resp.status_code != 200:
            raise MemoryUnavailable(f"memory service returned {resp.status_code}")
        try:
            out = resp.json()
        except ValueError as exc:
            raise MemoryUnavailable("invalid JSON from memory service") from exc
        if not isinstance(out, dict):
            raise MemoryUnavailable("invalid response from memory service")
        return out

    async def aclose(self) -> None:
        await self._client.aclose()


def _principal(principal: str, groups: Sequence[str]) -> dict[str, Any]:
    return {"id": principal, "groups": list(groups)}


class HttpMemoryBackend:
    """``MemoryStore`` for one agent process: ``write(scope, args)`` and ``recall`` / ``search``.

    ``owner_refs`` maps a service scope to its owner (``{"run": run_id, "session": sid, "agent":
    name}``).
    ``args`` of a ``MemoryWrite``: ``content`` (required) and optionally ``metadata``, ``acl``,
    ``subject``,
    ``ttl_seconds``, ``phi``.  Redaction paths are NOT forwarded: the executor has already applied
    the
    gate's redaction to ``args`` before ``perform``; the service additionally redacts in PHI mode.
    """

    def __init__(
        self,
        base_url: str,
        *,
        token: str,
        tenant_id: str,
        principal: str,
        groups: Sequence[str] = (),
        owner_refs: Mapping[str, str] | None = None,
        kbs: Sequence[str] = (),
        client: httpx.AsyncClient | None = None,
        timeout: float = 30.0,
    ) -> None:
        if not principal:
            raise ValueError("principal required")
        self._c = _Client(
            base_url, token=token, tenant_id=tenant_id, client=client, timeout=timeout
        )
        self._principal = _principal(principal, groups)
        self._owners = dict(owner_refs or {})
        self._kbs = list(kbs)

    def _owner(self, scope: str) -> str | None:
        if scope == "tenant":
            return None
        owner = self._owners.get(scope)
        if not owner:
            raise ValueError(f"no owner configured for {scope!r} memory")
        return owner

    async def write(self, scope: str, args: Mapping[str, Any]) -> Any:
        svc_scope = _SCOPES.get(scope)
        if svc_scope is None:
            raise ValueError(f"unknown memory scope {scope!r}")
        content = args.get("content")
        if not isinstance(content, str) or not content:
            raise ValueError("memory write needs a non-empty string 'content'")
        body: dict[str, Any] = {
            "scope": svc_scope,
            "content": content,
            "principal": self._principal,
        }
        owner = self._owner(svc_scope)
        if owner is not None:
            body["owner_ref"] = owner
        for key in _PASSTHROUGH:
            if key in args:
                body[key] = args[key]
        return await self._c.post("write", body)

    async def search(self, query: str, *, scopes: Sequence[str], limit: int = 5) -> dict[str, Any]:
        """ACL-aware similarity search over ``scopes`` (agent-facing names plus ``kb``), as THIS
        principal. One service call per scope (the owner filter is per scope); hits are merged by
        score. The service filters unreadable rows in SQL: nothing here widens access."""
        if not isinstance(query, str) or not query:
            raise ValueError("memory search needs a non-empty string 'query'")
        limit = max(1, min(int(limit), 20))
        hits: list[dict[str, Any]] = []
        for scope in dict.fromkeys(scopes):
            body: dict[str, Any] = {
                "query": query,
                "limit": limit,
                "principal": self._principal,
            }
            if scope == "kb":
                if not self._kbs:
                    continue
                body.update(scopes=["kb"], kbs=self._kbs)
            else:
                svc_scope = _SCOPES.get(scope)
                if svc_scope is None:
                    raise ValueError(f"unknown memory scope {scope!r}")
                body["scopes"] = [svc_scope]
                owner = self._owner(svc_scope)
                if owner is not None:
                    body["owner_ref"] = owner
            out = await self._c.post("search", body)
            found = out.get("hits")
            if not isinstance(found, list):
                raise MemoryUnavailable("invalid response from memory service")
            for h in found:
                try:
                    hits.append(
                        {
                            "id": str(h["id"]),
                            "scope": str(h["scope"]),
                            "kb": h.get("kb"),
                            "content": str(h["content"]),
                            "score": float(h["score"]),
                        }
                    )
                except (KeyError, TypeError, ValueError, AttributeError) as exc:
                    raise MemoryUnavailable("invalid response from memory service") from exc
        hits.sort(key=lambda h: (-h["score"], h["id"]))
        return {"hits": hits[:limit]}

    async def recall(self, scope: str, *, limit: int = 20) -> list[dict[str, Any]]:
        svc_scope = _SCOPES.get(scope)
        if svc_scope is None:
            raise ValueError(f"unknown memory scope {scope!r}")
        body: dict[str, Any] = {
            "scope": svc_scope,
            "limit": limit,
            "principal": self._principal,
        }
        owner = self._owner(svc_scope)
        if owner is not None:
            body["owner_ref"] = owner
        out = await self._c.post("recall", body)
        entries = out.get("entries")
        if not isinstance(entries, list):
            raise MemoryUnavailable("invalid response from memory service")
        return [e for e in entries if isinstance(e, dict)]

    async def aclose(self) -> None:
        await self._c.aclose()


class MemoryRagRetriever:
    """``nexus.rag.Retriever`` over the memory service's ACL-aware vector search.

    NEXUS carries the principal as a string; ``groups_for`` (optional) resolves its groups.
    Passages are marked as readable by exactly the requesting principal (the service already
    filtered by ACL).
    Cosine similarity is clamped to [0, 1] for the stage's confidence.
    """

    def __init__(
        self,
        base_url: str,
        *,
        token: str,
        tenant_id: str,
        kbs: Sequence[str] = (),
        groups_for: Callable[[str], Sequence[str]] | None = None,
        client: httpx.AsyncClient | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._c = _Client(
            base_url, token=token, tenant_id=tenant_id, client=client, timeout=timeout
        )
        self._kbs = list(kbs)
        self._groups_for = groups_for

    async def retrieve(
        self, *, tenant_id: str, principal: str, query: str, limit: int
    ) -> Sequence[Passage]:
        if not tenant_id:
            raise ValueError("tenant_id required")
        if tenant_id != self._c.tenant_id:
            raise ValueError("tenant_id does not match this retriever's credential")
        if not principal:
            raise ValueError("principal required")
        groups = self._groups_for(principal) if self._groups_for else ()
        body: dict[str, Any] = {
            "principal": _principal(principal, groups),
            "query": query,
            "limit": limit,
        }
        if self._kbs:
            body["kbs"] = self._kbs
            body["scopes"] = ["kb"]
        out = await self._c.post("search", body)
        hits = out.get("hits")
        if not isinstance(hits, list):
            raise MemoryUnavailable("invalid response from memory service")
        passages: list[Passage] = []
        for h in hits:
            if not isinstance(h, dict):
                raise MemoryUnavailable("invalid response from memory service")
            try:
                score = min(1.0, max(0.0, float(h["score"])))
                passages.append(
                    Passage(
                        id=str(h["id"]),
                        tenant_id=tenant_id,
                        text=str(h["content"]),
                        score=score,
                        allowed_principals=frozenset({principal}),
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise MemoryUnavailable("invalid response from memory service") from exc
        return passages

    async def aclose(self) -> None:
        await self._c.aclose()


@dataclass(frozen=True)
class MemoryWiring:
    """How a run reaches the memory service (the service derives the tenant from ``token``).

    ``transport`` is a test seam (an ``httpx`` mock transport); production leaves it ``None``."""

    base_url: str
    token: str = field(repr=False)
    timeout: float = 30.0
    transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=self.timeout, transport=self.transport)

    def backend(
        self,
        *,
        tenant_id: str,
        principal: str,
        groups: Sequence[str],
        owner_refs: Mapping[str, str],
        kbs: Sequence[str],
    ) -> HttpMemoryBackend:
        return HttpMemoryBackend(
            self.base_url,
            token=self.token,
            tenant_id=tenant_id,
            principal=principal,
            groups=groups,
            owner_refs=owner_refs,
            kbs=kbs,
            client=self._client(),
        )

    def retriever(
        self, *, tenant_id: str, kbs: Sequence[str], groups: Sequence[str]
    ) -> MemoryRagRetriever:
        return MemoryRagRetriever(
            self.base_url,
            token=self.token,
            tenant_id=tenant_id,
            kbs=kbs,
            groups_for=lambda _principal: groups,
            client=self._client(),
        )
