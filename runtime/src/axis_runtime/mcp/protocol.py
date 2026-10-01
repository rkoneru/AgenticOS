"""JSON-RPC 2.0 / MCP wire helpers.  Pure functions: no IO.

Parsing is strict on purpose.  It rejects oversized input, duplicate object keys (two ``name`` keys
would let a smuggled value win depending on the parser), ``NaN``/``Infinity``, over-deep nesting,
batches (removed from MCP in 2025-06-18) and ids that are not a string or an integer (``true``,
``1.5`` and ``null`` are never valid request ids here).  Response ids must match by TYPE and value,
so ``"1"``, ``1.0`` and ``true`` never satisfy a pending integer id ``1``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

JSONRPC = "2.0"
#: Protocol revisions this implementation speaks (newest first).  2024-11-05 used the legacy
#: HTTP+SSE transport and is not implemented.
PROTOCOL_VERSIONS: tuple[str, ...] = ("2025-06-18", "2025-03-26")

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
UNAUTHORIZED = -32001  # implementation-defined range
REQUEST_TOO_LARGE = -32002
RATE_LIMITED = -32029
CANCELLED = -32800  # MCP / LSP convention

MAX_DEPTH = 32

JsonObject = dict[str, Any]
RequestId = str | int


class ProtocolError(Exception):
    """Raised by the parsers; ``code`` is the JSON-RPC code to answer with (if answerable)."""

    def __init__(self, code: int, message: str, request_id: RequestId | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.request_id = request_id


class Kind(StrEnum):
    REQUEST = "request"
    NOTIFICATION = "notification"
    RESPONSE = "response"


@dataclass(frozen=True)
class Message:
    kind: Kind
    body: JsonObject
    id: RequestId | None = None
    method: str | None = None


def valid_id(value: Any) -> bool:
    return isinstance(value, str | int) and not isinstance(value, bool)


def same_id(a: Any, b: Any) -> bool:
    """Exact id equality: same JSON type and value (``1`` != ``"1"`` != ``1.0`` != ``True``)."""
    return type(a) is type(b) and a == b


def _no_duplicates(pairs: list[tuple[str, Any]]) -> JsonObject:
    out: JsonObject = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _reject_constant(_name: str) -> Any:
    raise ValueError("non-finite number")


def depth_ok(value: Any) -> bool:
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        cur, depth = stack.pop()
        if depth > MAX_DEPTH:
            return False
        if isinstance(cur, dict):
            stack.extend((v, depth + 1) for v in cur.values())
        elif isinstance(cur, list):
            stack.extend((v, depth + 1) for v in cur)
    return True


def loads_strict(raw: bytes | str, max_bytes: int) -> Any:
    """Parse JSON with the restrictions above. Raises ``ProtocolError``."""
    size = len(raw)
    if size > max_bytes:
        raise ProtocolError(REQUEST_TOO_LARGE, "message too large")
    try:
        text = raw.decode("utf-8") if isinstance(raw, bytes | bytearray) else raw
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except (ValueError, RecursionError):  # UnicodeDecodeError and JSONDecodeError are ValueErrors
        raise ProtocolError(PARSE_ERROR, "parse error") from None
    if not depth_ok(value):
        raise ProtocolError(INVALID_REQUEST, "message nested too deeply")
    return value


def classify(obj: Any) -> Message:
    """Classify one decoded JSON-RPC message. Raises ``ProtocolError`` (INVALID_REQUEST)."""
    if isinstance(obj, list):
        raise ProtocolError(INVALID_REQUEST, "batches are not supported")
    if not isinstance(obj, dict):
        raise ProtocolError(INVALID_REQUEST, "message must be an object")
    if obj.get("jsonrpc") != JSONRPC:
        raise ProtocolError(INVALID_REQUEST, "jsonrpc must be '2.0'", _safe_id(obj))
    if "method" in obj:
        method = obj["method"]
        if not isinstance(method, str) or not method or len(method) > 128:
            raise ProtocolError(INVALID_REQUEST, "invalid method", _safe_id(obj))
        if not ({"result", "error"}.isdisjoint(obj)):
            raise ProtocolError(INVALID_REQUEST, "request with result", _safe_id(obj))
        params = obj.get("params")
        if params is not None and not isinstance(params, dict | list):
            raise ProtocolError(INVALID_REQUEST, "params must be structured", _safe_id(obj))
        if "id" not in obj:
            return Message(Kind.NOTIFICATION, obj, None, method)
        if not valid_id(obj["id"]):
            raise ProtocolError(INVALID_REQUEST, "invalid id")
        return Message(Kind.REQUEST, obj, obj["id"], method)
    if "id" in obj and ("result" in obj) != ("error" in obj):
        if not valid_id(obj["id"]):
            raise ProtocolError(INVALID_REQUEST, "invalid id")
        return Message(Kind.RESPONSE, obj, obj["id"], None)
    raise ProtocolError(INVALID_REQUEST, "not a request, notification or response")


def _safe_id(obj: Mapping[str, Any]) -> RequestId | None:
    value = obj.get("id")
    return value if valid_id(value) else None


def request(
    request_id: RequestId, method: str, params: Mapping[str, Any] | None = None
) -> JsonObject:
    msg: JsonObject = {"jsonrpc": JSONRPC, "id": request_id, "method": method}
    if params is not None:
        msg["params"] = dict(params)
    return msg


def notification(method: str, params: Mapping[str, Any] | None = None) -> JsonObject:
    msg: JsonObject = {"jsonrpc": JSONRPC, "method": method}
    if params is not None:
        msg["params"] = dict(params)
    return msg


def result_response(request_id: RequestId, result: Mapping[str, Any]) -> JsonObject:
    return {"jsonrpc": JSONRPC, "id": request_id, "result": dict(result)}


def error_response(request_id: RequestId | None, code: int, message: str) -> JsonObject:
    return {"jsonrpc": JSONRPC, "id": request_id, "error": {"code": code, "message": message}}


def dumps(obj: Mapping[str, Any]) -> str:
    """Compact JSON with no raw newlines (stdio framing relies on that)."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def route_incoming(
    obj: Any, expect_id: RequestId | None
) -> tuple[JsonObject | None, JsonObject | None]:
    """Client side: what to do with one message the server sent while we await ``expect_id``.

    Returns ``(our_response, reply)``.  A server-to-client REQUEST (sampling, roots, elicitation,
    ping...) is never executed: it gets a ``method not found`` reply, because this client declares
    no client capabilities.  Notifications and unsolicited responses are dropped.  A malformed
    message raises ``ProtocolError``.
    """
    msg = classify(obj)
    if msg.kind is Kind.RESPONSE:
        if expect_id is not None and same_id(msg.id, expect_id):
            return msg.body, None
        return None, None
    if msg.kind is Kind.REQUEST:
        assert msg.id is not None  # noqa: S101 - classify guarantees it
        return None, error_response(msg.id, METHOD_NOT_FOUND, "method not found")
    return None, None


# ---- untrusted text ----------------------------------------------------------------------------
# Control characters (except \t \n), zero-width / bidi formatting characters and the Unicode "tag"
# block (used for invisible ASCII smuggling) are removed from anything a server sends as text.
_STRIP = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f­​-‏‪-‮⁠-⁤⁦-⁯﻿￹-￻\U000e0000-\U000e007f]")
# Heuristics that FLAG instruction-like text for operators / UI.  They are informational only: no
# code path may use a flag to grant, widen or skip anything (and none can be relied on to catch an
# attack; see docs/spec/mcp.md, threat model).
_SUSPICIOUS = (
    ("ignore_instructions", re.compile(r"ignore\s+(all\s+|any\s+)?(previous|prior|above)", re.I)),
    ("system_prompt", re.compile(r"system\s+prompt|developer\s+message", re.I)),
    (
        "directive",
        re.compile(r"\b(you\s+must|you\s+should\s+now|always\s+call|do\s+not\s+tell)\b", re.I),
    ),
    ("markup", re.compile(r"</?\s*(important|system|instructions?|tool_call|assistant)\b", re.I)),
    (
        "tool_invocation",
        re.compile(r"\b(call|invoke|use|run)\s+the\s+\w+\s+tool\b|tools/call", re.I),
    ),
    ("exfiltration", re.compile(r"exfiltrat|send\s+(it|this|the\s+\w+)\s+to\s+https?://", re.I)),
)


def sanitize_text(text: str, max_chars: int) -> tuple[str, bool]:
    """Strip invisible/control characters and truncate. Returns ``(text, was_truncated)``."""
    cleaned = _STRIP.sub("", text)
    if len(cleaned) > max_chars:
        return cleaned[:max_chars], True
    return cleaned, False


def injection_flags(text: str) -> tuple[str, ...]:
    return tuple(name for name, pattern in _SUSPICIOUS if pattern.search(text))
