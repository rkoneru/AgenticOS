"""Structural types shared by the generated layer and the transports."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from ._generated.operations import OperationSpec
    from .errors import ResponseMeta


@dataclass(frozen=True, slots=True)
class RequestOptions:
    """Per-call overrides."""

    timeout: float | None = None
    max_retries: int | None = None
    #: Extra headers. Credential, tenant and host headers are refused.
    headers: Mapping[str, str] | None = None
    on_response: Callable[[ResponseMeta], None] | None = None


class SyncTransport(Protocol):
    def call(
        self,
        op: OperationSpec,
        *,
        path: Mapping[str, Any],
        query: Mapping[str, Any],
        body: Any,
        idempotency_key: str | None,
        options: RequestOptions | None,
    ) -> Any: ...


class AsyncTransport(Protocol):
    async def call(
        self,
        op: OperationSpec,
        *,
        path: Mapping[str, Any],
        query: Mapping[str, Any],
        body: Any,
        idempotency_key: str | None,
        options: RequestOptions | None,
    ) -> Any: ...
