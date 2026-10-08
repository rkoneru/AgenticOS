"""Approval resolution for the runtime: how a REQUIRE_APPROVAL ends, and nothing else.

``ApprovalResolver.resolve`` returns the signed decision record of the approvals service for one
request. The runtime does NOT interpret the signature (it holds no key): it forwards an APPROVED
record to the Risk Kernel with the re-submitted action, and the kernel verifies it for exactly that
tenant, run, tool and arguments, applies every DENY policy and cap again, and consumes it
(docs/spec/approvals.md). An approval therefore never bypasses the gate.

``HttpApprovalResolver`` talks to the approvals service's loopback dev bridge
(``services/approvals/src/dev-bridge.ts``). That bridge is e2e/dev only, not a production surface
(docs/NEEDS.md #62). Any failure (transport, non-200, malformed body, timeout) raises
``ApprovalUnavailable``, which the executor turns into a DENY."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping
from typing import Any, Protocol

import httpx

from axis_runtime._tls import shared_ssl_context


class ApprovalUnavailable(RuntimeError):  # noqa: N818 - a condition, not a failure class hierarchy
    """The approval could not be resolved. Callers MUST treat this as DENY."""


class ApprovalResolver(Protocol):
    async def resolve(self, tenant_id: str, approval_id: str) -> Mapping[str, Any]:
        """Wait until the request is terminal and return its signed decision record."""
        ...


_REQUIRED = ("request_id", "tenant_id", "run_id", "tool", "args_hash", "outcome", "decision")


class HttpApprovalResolver:
    def __init__(
        self,
        base_url: str,
        *,
        token: str,
        poll_seconds: float = 5.0,
        max_wait_seconds: float = 3600.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if poll_seconds <= 0 or max_wait_seconds <= 0:
            raise ValueError("poll_seconds and max_wait_seconds must be positive")
        self._url = base_url.rstrip("/") + "/v1/approvals/resolve"
        self._headers = {"authorization": f"Bearer {token}"}
        self._poll = poll_seconds
        self._max = max_wait_seconds
        self._client = client or httpx.AsyncClient(
            timeout=poll_seconds + 10.0, verify=shared_ssl_context()
        )

    async def resolve(self, tenant_id: str, approval_id: str) -> Mapping[str, Any]:
        deadline = time.monotonic() + self._max
        while True:
            try:
                resp = await self._client.post(
                    self._url,
                    headers=self._headers,
                    json={"request_id": approval_id, "wait_ms": int(self._poll * 1000)},
                )
            except httpx.HTTPError as exc:
                raise ApprovalUnavailable(f"transport:{type(exc).__name__}") from None
            if resp.status_code == 200:
                return self._record(resp, tenant_id, approval_id)
            if resp.status_code != 202:
                raise ApprovalUnavailable(f"http_{resp.status_code}")
            if time.monotonic() >= deadline:
                raise ApprovalUnavailable("still_pending")
            await asyncio.sleep(0)  # still pending: poll again

    @staticmethod
    def _record(resp: httpx.Response, tenant_id: str, approval_id: str) -> Mapping[str, Any]:
        try:
            record = resp.json()["record"]
        except (ValueError, KeyError, TypeError):
            raise ApprovalUnavailable("malformed_response") from None
        if not isinstance(record, dict) or any(
            not isinstance(record.get(k), str) for k in _REQUIRED
        ):
            raise ApprovalUnavailable("malformed_record")
        if record["request_id"] != approval_id or record["tenant_id"] != tenant_id:
            raise ApprovalUnavailable("record_for_another_request")
        return record

    async def close(self) -> None:
        await self._client.aclose()
