"""MCP streamable-HTTP client transport (spec 2025-06-18 / 2025-03-26).

POST every JSON-RPC message to the single MCP endpoint with ``Accept: application/json,
text/event-stream``.  The reply is ``202`` (notification accepted), a JSON body, or an SSE stream
that carries the response (and possibly server notifications/requests first).  The optional
``Mcp-Session-Id`` is echoed back; ``MCP-Protocol-Version`` is sent after initialisation.

Safety: the endpoint is re-validated with the SSRF guard of ``models/endpoints.py`` before EVERY
request, redirects are never followed (a 3xx is an error), bodies are read in a bounded streaming
loop, and the whole exchange has a deadline.  KNOWN LIMIT (same as NEEDS #22): ``httpx`` resolves
again at connect time, so DNS rebinding between check and connect is not closed here either.
Only this file and ``stdio.py`` perform IO for MCP (bypass_scan.py grants httpx to this file).
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Mapping
from typing import Any

import httpx

from axis_runtime.mcp import protocol
from axis_runtime.mcp.config import McpLimits, ServerConfig
from axis_runtime.mcp.errors import (
    McpProtocolError,
    McpResponseTooLarge,
    McpSessionExpired,
    McpTransportError,
)
from axis_runtime.models.endpoints import EndpointError, Resolver, validate_endpoint

_SESSION_ID = re.compile(r"^[\x21-\x7e]{1,128}\Z")


class StreamableHttpTransport:
    def __init__(
        self,
        config: ServerConfig,
        limits: McpLimits,
        *,
        resolver: Resolver,
        client: httpx.AsyncClient | None = None,
        allow_http: bool = False,
        extra_ports: frozenset[int] = frozenset(),
    ) -> None:
        if config.url is None:
            raise McpTransportError("http server has no url")
        self._cfg = config
        self._url = config.url
        self._limits = limits
        self._resolver = resolver
        self._allow_http = allow_http
        self._extra_ports = extra_ports
        self._client = client or httpx.AsyncClient(
            timeout=limits.call_timeout_seconds, follow_redirects=False
        )
        self._owns_client = client is None
        self._session_id: str | None = None
        self._version: str | None = None

    def set_protocol_version(self, version: str) -> None:
        self._version = version

    async def _validate(self) -> None:
        try:
            await validate_endpoint(
                self._url,
                allow_http=self._allow_http,
                allow_private=self._cfg.allow_private,
                extra_ports=self._extra_ports,
                resolver=self._resolver,
            )
        except EndpointError as exc:
            raise McpTransportError(f"endpoint rejected: {exc}") from None

    def _headers(self) -> dict[str, str]:
        headers = {
            **self._cfg.headers,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._version:
            headers["MCP-Protocol-Version"] = self._version
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        return headers

    async def exchange(
        self, message: Mapping[str, Any], expect_id: protocol.RequestId | None
    ) -> dict[str, Any] | None:
        try:
            return await asyncio.wait_for(
                self._exchange(message, expect_id), self._limits.call_timeout_seconds
            )
        except TimeoutError:
            raise McpTransportError("http server timed out") from None
        except httpx.HTTPError as exc:  # type name only: messages can embed URLs
            raise McpTransportError(f"http transport error ({type(exc).__name__})") from None

    async def _post(self, message: Mapping[str, Any]) -> httpx.Response:
        await self._validate()
        body = protocol.dumps(message).encode("ascii")
        req = self._client.build_request("POST", self._url, content=body, headers=self._headers())
        return await self._client.send(req, stream=True, follow_redirects=False)

    async def _exchange(
        self, message: Mapping[str, Any], expect_id: protocol.RequestId | None
    ) -> dict[str, Any] | None:
        resp = await self._post(message)
        try:
            return await self._handle(resp, message, expect_id)
        finally:
            await resp.aclose()

    async def _handle(
        self,
        resp: httpx.Response,
        message: Mapping[str, Any],
        expect_id: protocol.RequestId | None,
    ) -> dict[str, Any] | None:
        if 300 <= resp.status_code < 400:
            raise McpTransportError("http redirect refused")
        if resp.status_code == 404 and self._session_id is not None:
            self._session_id = None
            raise McpSessionExpired("http session expired")
        if resp.status_code == 202 and expect_id is None:
            return None
        if resp.status_code != 200:
            raise McpTransportError(f"http status {resp.status_code}")
        if message.get("method") == "initialize":
            sid = resp.headers.get("mcp-session-id")
            if sid is not None:
                if not _SESSION_ID.match(sid):
                    raise McpProtocolError("invalid session id")
                self._session_id = sid
        if expect_id is None:
            return None  # a notification the server answered with a body: ignore it
        ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype == "application/json":
            raw = await self._read_bounded(resp, self._limits.max_message_bytes)
            return await self._route(raw, expect_id, single=True)
        if ctype == "text/event-stream":
            return await self._read_sse(resp, expect_id)
        raise McpProtocolError("unsupported content type")

    async def _read_bounded(self, resp: httpx.Response, cap: int) -> bytes:
        chunks: list[bytes] = []
        total = 0
        async for chunk in resp.aiter_bytes():
            total += len(chunk)
            if total > cap:
                raise McpResponseTooLarge("http response exceeds the size cap")
            chunks.append(chunk)
        return b"".join(chunks)

    async def _route(
        self, raw: bytes, expect_id: protocol.RequestId, *, single: bool
    ) -> dict[str, Any] | None:
        try:
            obj = protocol.loads_strict(raw, self._limits.max_message_bytes)
            response, reply = protocol.route_incoming(obj, expect_id)
        except protocol.ProtocolError as exc:
            if exc.code == protocol.REQUEST_TOO_LARGE:
                raise McpResponseTooLarge("http message exceeds the size cap") from None
            raise McpProtocolError("malformed message from server") from None
        if reply is not None:
            await self._send_reply(reply)
        if response is None and single:
            raise McpProtocolError("response did not answer the request")
        return response

    async def _send_reply(self, reply: Mapping[str, Any]) -> None:
        """Best effort: tell the server we do not implement the request it sent."""
        try:
            resp = await self._post(reply)
            await resp.aclose()
        except (httpx.HTTPError, McpTransportError):
            return

    async def _read_sse(
        self, resp: httpx.Response, expect_id: protocol.RequestId
    ) -> dict[str, Any]:
        cap = self._limits.max_message_bytes
        stream_cap = cap * 4
        total = 0
        buf = ""
        async for chunk in resp.aiter_bytes():
            total += len(chunk)
            if total > stream_cap:
                raise McpResponseTooLarge("event stream exceeds the size cap")
            buf += chunk.decode("utf-8", errors="replace").replace("\r\n", "\n")
            if len(buf) > cap + 1024 and "\n\n" not in buf:
                raise McpResponseTooLarge("event exceeds the size cap")
            while "\n\n" in buf:
                event, buf = buf.split("\n\n", 1)
                data = "\n".join(
                    line[5:].removeprefix(" ")
                    for line in event.split("\n")
                    if line.startswith("data:")
                )
                if not data:
                    continue  # comment / keep-alive / priming event
                response = await self._route(data.encode("utf-8"), expect_id, single=False)
                if response is not None:
                    return response
        raise McpTransportError("event stream ended without a response")

    async def close(self) -> None:
        sid, self._session_id = self._session_id, None
        if sid is not None:
            try:
                headers = {**self._cfg.headers, "Mcp-Session-Id": sid}
                if self._version:
                    headers["MCP-Protocol-Version"] = self._version
                await self._validate()
                req = self._client.build_request("DELETE", self._url, headers=headers)
                resp = await asyncio.wait_for(
                    self._client.send(req, stream=True, follow_redirects=False), 2.0
                )
                await resp.aclose()
            except (httpx.HTTPError, McpTransportError, TimeoutError):
                pass
        if self._owns_client:
            await self._client.aclose()


__all__ = ["StreamableHttpTransport"]
