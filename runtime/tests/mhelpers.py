"""Helpers for ModelGateway tests: httpx.MockTransport plumbing, SSE and AWS event-stream encoders."""

from __future__ import annotations

import json
import struct
import zlib
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from typing import Any

import httpx
from axis_runtime.models import (
    InMemorySecretStore,
    Message,
    ModelGateway,
    ModelRequest,
    ModelTarget,
    RetryPolicy,
    ToolCallRequest,
    ToolDefinition,
    UnguardedModelGateway,
)
from axis_runtime.models.adapters import HttpxTransport
from conftest import TENANT, FakeClock, FixedRng

Handler = Callable[[httpx.Request], httpx.Response | Awaitable[httpx.Response]]

KEYS = {
    "anthropic": "sk-ant-SECRET-111",
    "openai": "sk-openai-SECRET-222",
    "google": "AIza-SECRET-333",
    "azure-openai": "azure-SECRET-444",
    "openai-compatible": "compat-SECRET-555",
    "bedrock": json.dumps(
        {
            "access_key_id": "AKIDEXAMPLE",
            "secret_access_key": "bedrock-SECRET-666",
            "region": "us-east-1",
        }
    ),
}
ALL_SECRET_VALUES = [
    "sk-ant-SECRET-111",
    "sk-openai-SECRET-222",
    "AIza-SECRET-333",
    "azure-SECRET-444",
    "compat-SECRET-555",
    "bedrock-SECRET-666",
]


def store(**extra: str) -> InMemorySecretStore:
    data = {(TENANT, p, "default"): v for p, v in KEYS.items()}
    data.update({(TENANT, p, "default"): v for p, v in extra.items()})
    return InMemorySecretStore(data)


def gateway_for(
    handler: Handler,
    *,
    secrets: InMemorySecretStore | None = None,
    clock: FakeClock | None = None,
    **kw: Any,
) -> tuple[ModelGateway, FakeClock]:
    clock = clock or FakeClock()
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    kw.setdefault("retry", RetryPolicy(max_attempts=3, base_delay=1.0, max_delay=8.0))
    gw = ModelGateway(
        secrets or store(), transport=HttpxTransport(client), clock=clock, rng=FixedRng(), **kw
    )
    return gw, clock


def free(gw: ModelGateway) -> UnguardedModelGateway:
    return gw.unguarded_for_tests()


def request(
    provider: str,
    model: str = "model-x",
    *,
    endpoint: str | None = None,
    tools: bool = False,
    **kw: Any,
) -> ModelRequest:
    return ModelRequest(
        tenant_id=kw.pop("tenant_id", TENANT),
        messages=kw.pop("messages", (Message("system", "Be brief."), Message("user", "Hello"))),
        target=ModelTarget(provider, model, endpoint, kw.pop("target_params", {})),
        tools=(
            (
                ToolDefinition(
                    "get_weather",
                    "Get weather",
                    {"type": "object", "properties": {"city": {"type": "string"}}},
                ),
            )
            if tools
            else ()
        ),
        **kw,
    )


def tool_round_trip_messages() -> tuple[Message, ...]:
    """user -> assistant(2 tool calls) -> 2 tool results (one is an error)."""
    return (
        Message("user", "weather in Paris and Rome?"),
        Message(
            "assistant",
            "Checking.",
            (
                ToolCallRequest("c1", "get_weather", {"city": "Paris"}),
                ToolCallRequest("c2", "get_weather", {"city": "Rome"}),
            ),
        ),
        Message("tool", '{"temp": 21}', tool_call_id="c1", name="get_weather"),
        Message("tool", "boom", tool_call_id="c2", name="get_weather", is_error=True),
    )


def json_response(
    body: Any, status: int = 200, headers: dict[str, str] | None = None
) -> httpx.Response:
    return httpx.Response(status, json=body, headers=headers)


def sse(*events: tuple[str | None, Any]) -> bytes:
    out = []
    for name, data in events:
        if name:
            out.append(f"event: {name}")
        out.append("data: " + (data if isinstance(data, str) else json.dumps(data)))
        out.append("")
    return ("\n".join(out) + "\n").encode()


async def chunked(data: bytes, size: int = 7) -> AsyncIterator[bytes]:
    for i in range(0, len(data), size):
        yield data[i : i + size]


def stream_response(data: bytes, size: int = 7, status: int = 200) -> Callable[[], httpx.Response]:
    """A factory (a streamed Response can only be consumed once, and the gateway may retry)."""
    return lambda: httpx.Response(status, content=chunked(data, size))


def event_frame(headers: dict[str, str], payload: bytes, *, bad_crc: bool = False) -> bytes:
    """One AWS event-stream message (prelude + headers + payload + CRCs)."""
    hdr = b""
    for name, value in headers.items():
        n, v = name.encode(), value.encode()
        hdr += bytes([len(n)]) + n + b"\x07" + struct.pack(">H", len(v)) + v
    total = 12 + len(hdr) + len(payload) + 4
    prelude = struct.pack(">II", total, len(hdr))
    prelude += struct.pack(">I", zlib.crc32(prelude))
    body = prelude + hdr + payload
    crc = zlib.crc32(body) ^ (1 if bad_crc else 0)
    return body + struct.pack(">I", crc)


def bedrock_event(event_type: str, payload: dict[str, Any]) -> bytes:
    return event_frame(
        {":event-type": event_type, ":content-type": "application/json", ":message-type": "event"},
        json.dumps(payload).encode(),
    )


async def collect(stream: AsyncIterator[Any]) -> list[Any]:
    return [e async for e in stream]


def find(events: Iterable[Any], kind: str) -> list[Any]:
    return [e for e in events if e.kind == kind]
