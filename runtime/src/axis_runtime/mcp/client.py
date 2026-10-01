"""MCP client session: initialize, tools/list, tools/call over any ``Transport``.

Everything a server sends is DATA.  Concretely:

* tool descriptions are sanitised, truncated and *flagged* (never obeyed); input schemas are
  size/depth-capped; ``annotations`` (readOnlyHint etc.) are ignored: ``side_effects`` comes from
  the manifest, not from the server;
* tool names must match ``TOOL_NAME`` (no ``/``), duplicates within a server are dropped entirely;
* the arguments of ``tools/call`` are exactly the Action's (already gated/redacted) arguments,
  never edited by anything the server said;
* a result is normalised into ``{"untrusted": True, "source", "is_error", "content": [...]}`` with
  size caps; binary parts are replaced by placeholders; nothing in it is interpreted;
* server-to-client requests (sampling, roots, elicitation) are answered ``method not found``.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from axis_runtime.mcp import protocol
from axis_runtime.mcp.config import TOOL_NAME, McpLimits, qualify
from axis_runtime.mcp.errors import McpProtocolError, McpResponseTooLarge

CLIENT_NAME = "axis-runtime"
CLIENT_VERSION = "0.0.0"


class Transport(Protocol):
    async def exchange(
        self, message: Mapping[str, Any], expect_id: protocol.RequestId | None
    ) -> dict[str, Any] | None: ...

    def set_protocol_version(self, version: str) -> None: ...

    async def close(self) -> None: ...


@dataclass(frozen=True)
class RemoteTool:
    """A tool as listed by a server, after sanitising. Display/selection data only."""

    server: str
    name: str
    description: str
    input_schema: Mapping[str, Any]
    flags: tuple[str, ...] = ()
    truncated: bool = False

    @property
    def qualified_name(self) -> str:
        return qualify(self.server, self.name)


@dataclass(frozen=True)
class ToolListing:
    tools: tuple[RemoteTool, ...]
    rejected: int  # entries dropped (bad name, duplicate, oversize schema, wrong shape)


def _json_size(value: Any) -> int:
    return len(json.dumps(value, separators=(",", ":"), default=str))


def parse_tool(server: str, raw: Any, limits: McpLimits) -> RemoteTool | None:
    if not isinstance(raw, dict):
        return None
    name = raw.get("name")
    if not isinstance(name, str) or not TOOL_NAME.match(name):
        return None
    schema = raw.get("inputSchema")
    if schema is None:
        schema = {"type": "object"}
    if not isinstance(schema, dict) or _json_size(schema) > limits.max_schema_bytes:
        return None
    if not protocol.depth_ok(schema):
        return None
    desc = raw.get("description")
    text, truncated = protocol.sanitize_text(
        desc if isinstance(desc, str) else "", limits.max_description_chars
    )
    return RemoteTool(
        server=server,
        name=name,
        description=text,
        input_schema=dict(schema),
        flags=protocol.injection_flags(text),
        truncated=truncated,
    )


def normalise_result(server: str, tool: str, raw: Any, limits: McpLimits) -> dict[str, Any]:
    """Turn a ``tools/call`` result into inert, size-capped data."""
    if not isinstance(raw, dict):
        raise McpProtocolError("invalid tool result")
    content = raw.get("content")
    if content is None:
        content = []
    if not isinstance(content, list):
        raise McpProtocolError("invalid tool result")
    budget = limits.max_result_bytes
    parts: list[dict[str, Any]] = []
    flags: list[str] = []
    truncated = len(content) > limits.max_content_items
    for item in content[: limits.max_content_items]:
        part, spent = _normalise_part(item, budget)
        budget -= spent
        if part is None:
            continue
        if part.get("truncated"):
            truncated = True
        if part["type"] == "text":
            flags.extend(protocol.injection_flags(part["text"]))
        parts.append(part)
        if budget <= 0:
            truncated = True
            break
    out: dict[str, Any] = {
        "untrusted": True,
        "source": f"mcp:{qualify(server, tool)}",
        "is_error": raw.get("isError") is True,
        "content": parts,
        "flags": sorted(set(flags)),
        "truncated": truncated,
    }
    structured = raw.get("structuredContent")
    if isinstance(structured, dict):
        if _json_size(structured) <= max(budget, 0) and protocol.depth_ok(structured):
            out["structured"] = structured
        else:
            out["truncated"] = True
    return out


def _normalise_part(item: Any, budget: int) -> tuple[dict[str, Any] | None, int]:
    if not isinstance(item, dict) or not isinstance(item.get("type"), str):
        return None, 0
    kind = item["type"]
    if kind == "text" and isinstance(item.get("text"), str):
        cap = max(budget, 0)
        text, cut = protocol.sanitize_text(item["text"], cap)
        part: dict[str, Any] = {"type": "text", "text": text}
        if cut:
            part["truncated"] = True
        return part, len(text.encode("utf-8", errors="replace"))
    # image / audio / resource / resource_link: never forward blobs or embedded content
    placeholder: dict[str, Any] = {"type": kind[:32], "omitted": True}
    uri = item.get("uri")
    if isinstance(uri, str):
        placeholder["uri"] = protocol.sanitize_text(uri, 512)[0]
    mime = item.get("mimeType")
    if isinstance(mime, str):
        placeholder["mime_type"] = protocol.sanitize_text(mime, 128)[0]
    return placeholder, 64


class McpSession:
    def __init__(self, server: str, transport: Transport, limits: McpLimits | None = None) -> None:
        self.server = server
        self._transport = transport
        self._limits = limits or McpLimits()
        self._ids = itertools.count(1)
        self._initialized = False
        self.protocol_version: str | None = None

    async def _request(self, method: str, params: Mapping[str, Any] | None) -> dict[str, Any]:
        request_id = next(self._ids)
        response = await self._transport.exchange(
            protocol.request(request_id, method, params), request_id
        )
        if response is None:
            raise McpProtocolError("no response")
        if "error" in response:
            err = response["error"]
            code = err.get("code") if isinstance(err, dict) else None
            raise McpProtocolError(
                "server returned an error", code if isinstance(code, int) else None
            )
        result = response.get("result")
        if not isinstance(result, dict):
            raise McpProtocolError("invalid result")
        return result

    async def initialize(self) -> None:
        result = await self._request(
            "initialize",
            {
                "protocolVersion": protocol.PROTOCOL_VERSIONS[0],
                "capabilities": {},
                "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
            },
        )
        version = result.get("protocolVersion")
        if version not in protocol.PROTOCOL_VERSIONS:
            raise McpProtocolError("unsupported protocol version")
        self.protocol_version = version
        self._transport.set_protocol_version(version)
        await self._transport.exchange(protocol.notification("notifications/initialized"), None)
        self._initialized = True

    def _need_init(self) -> None:
        if not self._initialized:
            raise McpProtocolError("session not initialised")

    async def list_tools(self) -> ToolListing:
        self._need_init()
        limits = self._limits
        tools: dict[str, RemoteTool] = {}
        duplicates: set[str] = set()
        rejected = 0
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for _ in range(limits.max_list_pages):
            result = await self._request("tools/list", {"cursor": cursor} if cursor else None)
            raw_tools = result.get("tools")
            if not isinstance(raw_tools, list):
                raise McpProtocolError("invalid tool list")
            for raw in raw_tools:
                tool = parse_tool(self.server, raw, limits)
                if tool is None:
                    rejected += 1
                elif tool.name in tools or tool.name in duplicates:
                    # a second definition under the same name could swap schema/description
                    # after the first was reviewed: drop BOTH, fail closed
                    rejected += 2 if tool.name in tools else 1  # the first one is lost too
                    tools.pop(tool.name, None)
                    duplicates.add(tool.name)
                else:
                    tools[tool.name] = tool
                if len(tools) > limits.max_tools_per_server:
                    raise McpResponseTooLarge("too many tools")
            nxt = result.get("nextCursor")
            if not isinstance(nxt, str) or not nxt:
                return ToolListing(tuple(tools.values()), rejected)
            if len(nxt) > 512 or nxt in seen_cursors:
                raise McpProtocolError("invalid pagination cursor")
            seen_cursors.add(nxt)
            cursor = nxt
        raise McpResponseTooLarge("too many tool list pages")

    async def invoke_tool(self, name: str, args: Mapping[str, Any]) -> dict[str, Any]:
        self._need_init()
        if not TOOL_NAME.match(name):
            raise McpProtocolError("invalid tool name")
        result = await self._request("tools/call", {"name": name, "arguments": dict(args)})
        return normalise_result(self.server, name, result, self._limits)

    async def close(self) -> None:
        await self._transport.close()
