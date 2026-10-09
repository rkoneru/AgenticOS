"""Adapter base, HTTP transport (the ONLY place the model layer touches httpx), the default DNS
resolver (the only use of socket) and SSE decoding."""

from __future__ import annotations

import asyncio
import json
import socket
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar, Protocol

import httpx

from axis_runtime._tls import shared_ssl_context
from axis_runtime.models.endpoints import Resolver
from axis_runtime.models.secrets import Secret, scrub
from axis_runtime.models.types import (
    ErrorKind,
    FinishReason,
    ModelError,
    ModelRequest,
    ModelTarget,
    StreamEvent,
    ToolCallRequest,
    Usage,
)


@dataclass(frozen=True)
class HttpCall:
    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes
    timeout: float = 120.0


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class StreamHandle(Protocol):
    status: int
    headers: Mapping[str, str]

    async def read(self) -> bytes: ...
    def aiter_bytes(self) -> AsyncIterator[bytes]: ...


class Transport(Protocol):
    async def send(self, call: HttpCall) -> HttpResponse: ...
    def stream(self, call: HttpCall) -> AbstractAsyncContextManager[StreamHandle]: ...


def default_resolver() -> Resolver:
    """Real DNS via the event loop's getaddrinfo (threaded; never called at import time)."""

    async def resolve(host: str, port: int) -> list[str]:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return [str(info[4][0]) for info in infos]

    return resolve


def _map_transport_error(exc: httpx.HTTPError, provider: str) -> ModelError:
    # Only the exception TYPE is used: httpx messages can embed URLs (and thus query-string keys).
    if isinstance(exc, httpx.TimeoutException):
        return ModelError(ErrorKind.TIMEOUT, provider, type(exc).__name__)
    return ModelError(ErrorKind.NETWORK, provider, type(exc).__name__)


class HttpxTransport:
    def __init__(self, client: httpx.AsyncClient | None = None, *, provider_hint: str = "") -> None:
        self._client = client or httpx.AsyncClient(verify=shared_ssl_context())
        self._hint = provider_hint

    async def send(self, call: HttpCall) -> HttpResponse:
        try:
            resp = await self._client.request(
                call.method,
                call.url,
                content=call.body,
                headers=dict(call.headers),
                timeout=call.timeout,
            )
        except httpx.HTTPError as exc:
            raise _map_transport_error(exc, self._hint) from None
        return HttpResponse(resp.status_code, dict(resp.headers), resp.content)

    @asynccontextmanager
    async def stream(self, call: HttpCall) -> AsyncIterator[StreamHandle]:
        try:
            async with self._client.stream(
                call.method,
                call.url,
                content=call.body,
                headers=dict(call.headers),
                timeout=call.timeout,
            ) as resp:
                yield _HttpxStream(resp, self._hint)
        except httpx.HTTPError as exc:
            raise _map_transport_error(exc, self._hint) from None


class _HttpxStream:
    def __init__(self, resp: httpx.Response, provider: str) -> None:
        self._resp = resp
        self._provider = provider
        self.status = resp.status_code
        self.headers: Mapping[str, str] = dict(resp.headers)

    async def read(self) -> bytes:
        return await self._resp.aread()

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        async for chunk in self._resp.aiter_bytes():
            yield chunk


# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ParsedResponse:
    text: str
    tool_calls: tuple[ToolCallRequest, ...]
    usage: Usage
    finish_reason: FinishReason
    model: str


def parse_args(raw: str) -> dict[str, Any]:
    """Tool-call arguments arrive as a JSON string from some providers; never raise on bad JSON."""
    if not raw.strip():
        return {}
    try:
        value = json.loads(raw)
    except ValueError:
        return {"_invalid_json": raw}
    return value if isinstance(value, dict) else {"_value": value}


class SseDecoder:
    """Incremental Server-Sent-Events decoder: ``feed(bytes)`` -> [(event_name, data), ...]."""

    def __init__(self) -> None:
        self._buf = b""
        self._event = ""
        self._data: list[str] = []

    def feed(self, chunk: bytes) -> list[tuple[str, str]]:
        self._buf += chunk
        out: list[tuple[str, str]] = []
        while True:
            nl = self._buf.find(b"\n")
            if nl < 0:
                break
            line = self._buf[:nl].rstrip(b"\r").decode("utf-8", errors="replace")
            self._buf = self._buf[nl + 1 :]
            if line == "":
                if self._data:
                    out.append((self._event or "message", "\n".join(self._data)))
                self._event, self._data = "", []
            elif line.startswith(":"):
                continue
            else:
                name, _, value = line.partition(":")
                value = value[1:] if value.startswith(" ") else value
                if name == "event":
                    self._event = value
                elif name == "data":
                    self._data.append(value)
        return out


class StreamParser(ABC):
    """Feeds raw bytes, yields StreamEvents, then exposes the aggregated ParsedResponse."""

    def __init__(self, provider: str) -> None:
        self.provider = provider
        self.text_parts: list[str] = []
        self.tools: dict[int, dict[str, Any]] = {}
        self.usage = Usage()
        self.finish = FinishReason.OTHER
        self.model = ""

    @abstractmethod
    def feed(self, chunk: bytes) -> list[StreamEvent]: ...

    def _tool_delta(
        self, index: int, call_id: str | None, name: str | None, args: str
    ) -> StreamEvent:
        slot = self.tools.setdefault(index, {"id": "", "name": "", "args": []})
        if call_id:
            slot["id"] = call_id
        if name:
            slot["name"] = name
        slot["args"].append(args)
        return StreamEvent(
            "tool_call_delta",
            index=index,
            tool_call_id=call_id,
            tool_name=name,
            arguments_delta=args,
        )

    def _text(self, text: str) -> StreamEvent:
        self.text_parts.append(text)
        return StreamEvent("text", text=text)

    def result(self) -> ParsedResponse:
        calls = tuple(
            ToolCallRequest(
                id=s["id"] or f"call_{i}", name=s["name"], arguments=parse_args("".join(s["args"]))
            )
            for i, s in sorted(self.tools.items())
        )
        finish = self.finish
        if calls and finish is FinishReason.OTHER:
            finish = FinishReason.TOOL_CALLS
        return ParsedResponse("".join(self.text_parts), calls, self.usage, finish, self.model)


class SseStreamParser(StreamParser):
    def __init__(self, provider: str) -> None:
        super().__init__(provider)
        self._sse = SseDecoder()

    def feed(self, chunk: bytes) -> list[StreamEvent]:
        events: list[StreamEvent] = []
        for name, data in self._sse.feed(chunk):
            if data.strip() == "[DONE]":
                continue
            try:
                payload = json.loads(data)
            except ValueError:
                raise ModelError(
                    ErrorKind.SERVER, self.provider, "malformed stream event"
                ) from None
            if isinstance(payload, dict):
                events.extend(self.handle(name, payload))
        return events

    @abstractmethod
    def handle(self, event: str, payload: dict[str, Any]) -> list[StreamEvent]: ...


# --------------------------------------------------------------------------------------


_STATUS_KIND = {
    400: ErrorKind.INVALID_REQUEST,
    401: ErrorKind.AUTH,
    403: ErrorKind.AUTH,
    404: ErrorKind.INVALID_REQUEST,
    408: ErrorKind.TIMEOUT,
    413: ErrorKind.INVALID_REQUEST,
    422: ErrorKind.INVALID_REQUEST,
    429: ErrorKind.RATE_LIMIT,
}


def _retry_after(headers: Mapping[str, str]) -> float | None:
    for k, v in headers.items():
        if k.lower() == "retry-after":
            try:
                return max(0.0, float(v))
            except ValueError:
                return None
    return None


class Adapter(ABC):
    """Translates the neutral request to ONE provider's real HTTP wire format and back."""

    provider: ClassVar[str]
    auth_optional: ClassVar[bool] = False
    endpoint_required: ClassVar[bool] = False

    @abstractmethod
    def build(
        self,
        req: ModelRequest,
        target: ModelTarget,
        secret: Secret | None,
        *,
        stream: bool,
        now: datetime,
    ) -> HttpCall: ...

    @abstractmethod
    def parse(self, data: Mapping[str, Any]) -> ParsedResponse: ...

    @abstractmethod
    def stream_parser(self) -> StreamParser: ...

    def error_code(self, data: Any) -> str:
        """Best-effort provider error code/type (never free text: it may echo user content)."""
        if isinstance(data, dict):
            err = data.get("error", data)
            if isinstance(err, dict):
                for key in ("type", "code", "status"):
                    if isinstance(err.get(key), str):
                        return str(err[key])[:64]
            for key in ("__type", "type"):
                if isinstance(data.get(key), str):
                    return str(data[key])[:64]
        return ""

    def classify(
        self, status: int, headers: Mapping[str, str], body: bytes, secret: Secret | None
    ) -> ModelError:
        try:
            data = json.loads(body)
        except ValueError:
            data = None
        code = scrub(self.error_code(data), secret)
        if "content_filter" in code or "content_policy" in code:
            kind = ErrorKind.CONTENT_FILTER
        elif status in _STATUS_KIND:
            kind = _STATUS_KIND[status]
        elif status >= 500:
            kind = ErrorKind.SERVER
        else:
            kind = ErrorKind.UNKNOWN
        return ModelError(
            kind,
            self.provider,
            f"http {status}" + (f" {code}" if code else ""),
            status=status,
            retry_after=_retry_after(headers),
        )


@dataclass
class AdapterRegistry:
    adapters: dict[str, Adapter] = field(default_factory=dict)

    def register(self, adapter: Adapter) -> None:
        self.adapters[adapter.provider] = adapter
