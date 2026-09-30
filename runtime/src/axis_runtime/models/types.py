"""Provider-neutral request/response types for the ModelGateway."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from enum import StrEnum
from typing import Any, Literal

Role = Literal["system", "user", "assistant", "tool"]


@dataclass(frozen=True)
class ToolCallRequest:
    id: str
    name: str
    arguments: Mapping[str, Any]


@dataclass(frozen=True)
class Message:
    role: Role
    content: str = ""
    tool_calls: tuple[ToolCallRequest, ...] = ()
    tool_call_id: str | None = None  # for role == "tool"
    name: str | None = None  # tool name for role == "tool" (Gemini needs it)
    is_error: bool = False  # for role == "tool"


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str = ""
    input_schema: Mapping[str, Any] = field(default_factory=lambda: {"type": "object"})


@dataclass(frozen=True)
class ModelTarget:
    provider: str
    model: str  # model id; for azure-openai this is the DEPLOYMENT name
    endpoint: str | None = None
    params: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CacheHints:
    """Prompt-caching hints; honoured by providers that support explicit caching."""

    system: bool = False
    tools: bool = False


@dataclass(frozen=True)
class ModelRequest:
    tenant_id: str
    messages: tuple[Message, ...]
    target: ModelTarget
    tools: tuple[ToolDefinition, ...] = ()
    response_schema: Mapping[str, Any] | None = None  # structured output (JSON Schema)
    params: Mapping[str, Any] = field(default_factory=dict)  # temperature, max_tokens, ...
    fallbacks: tuple[ModelTarget, ...] = ()
    cache: CacheHints = field(default_factory=CacheHints)
    key_label: str = "default"

    def merged_params(self, target: ModelTarget) -> dict[str, Any]:
        return {**target.params, **self.params}

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "messages": [
                {
                    "role": m.role,
                    "content": m.content,
                    "tool_calls": [
                        {"id": c.id, "name": c.name, "arguments": dict(c.arguments)}
                        for c in m.tool_calls
                    ],
                    "tool_call_id": m.tool_call_id,
                    "name": m.name,
                    "is_error": m.is_error,
                }
                for m in self.messages
            ],
            "target": _target_dict(self.target),
            "tools": [
                {"name": t.name, "description": t.description, "input_schema": dict(t.input_schema)}
                for t in self.tools
            ],
            "response_schema": None if self.response_schema is None else dict(self.response_schema),
            "params": dict(self.params),
            "fallbacks": [_target_dict(t) for t in self.fallbacks],
            "cache": {"system": self.cache.system, "tools": self.cache.tools},
            "key_label": self.key_label,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ModelRequest:
        return cls(
            tenant_id=raw["tenant_id"],
            messages=tuple(
                Message(
                    role=m["role"],
                    content=m["content"],
                    tool_calls=tuple(
                        ToolCallRequest(c["id"], c["name"], c["arguments"]) for c in m["tool_calls"]
                    ),
                    tool_call_id=m["tool_call_id"],
                    name=m["name"],
                    is_error=m["is_error"],
                )
                for m in raw["messages"]
            ),
            target=_target_from(raw["target"]),
            tools=tuple(
                ToolDefinition(t["name"], t["description"], t["input_schema"]) for t in raw["tools"]
            ),
            response_schema=raw["response_schema"],
            params=raw["params"],
            fallbacks=tuple(_target_from(t) for t in raw["fallbacks"]),
            cache=CacheHints(**raw["cache"]),
            key_label=raw["key_label"],
        )


def _target_dict(t: ModelTarget) -> dict[str, Any]:
    return {
        "provider": t.provider,
        "model": t.model,
        "endpoint": t.endpoint,
        "params": dict(t.params),
    }


def _target_from(raw: Mapping[str, Any]) -> ModelTarget:
    return ModelTarget(raw["provider"], raw["model"], raw["endpoint"], raw["params"])


@dataclass(frozen=True)
class Usage:
    """``input_tokens`` is the TOTAL prompt size; ``cached_tokens`` and ``cache_write_tokens``
    are subsets of it (billed at different rates)."""

    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    cache_write_tokens: int = 0


class FinishReason(StrEnum):
    STOP = "stop"
    LENGTH = "length"
    TOOL_CALLS = "tool_calls"
    CONTENT_FILTER = "content_filter"
    OTHER = "other"


@dataclass(frozen=True)
class Attempt:
    provider: str
    model: str
    outcome: str  # "ok" or an error kind


@dataclass(frozen=True)
class ModelResponse:
    text: str
    tool_calls: tuple[ToolCallRequest, ...]
    usage: Usage
    finish_reason: FinishReason
    provider: str
    model: str
    latency_ms: int = 0
    cost_usd: Decimal | None = None
    attempts: tuple[Attempt, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "tool_calls": [
                {"id": c.id, "name": c.name, "arguments": dict(c.arguments)}
                for c in self.tool_calls
            ],
            "usage": [
                self.usage.input_tokens,
                self.usage.output_tokens,
                self.usage.cached_tokens,
                self.usage.cache_write_tokens,
            ],
            "finish_reason": self.finish_reason.value,
            "provider": self.provider,
            "model": self.model,
            "latency_ms": self.latency_ms,
            "cost_usd": None if self.cost_usd is None else str(self.cost_usd),
            "attempts": [[a.provider, a.model, a.outcome] for a in self.attempts],
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ModelResponse:
        return cls(
            text=raw["text"],
            tool_calls=tuple(
                ToolCallRequest(c["id"], c["name"], c["arguments"]) for c in raw["tool_calls"]
            ),
            usage=Usage(*raw["usage"]),
            finish_reason=FinishReason(raw["finish_reason"]),
            provider=raw["provider"],
            model=raw["model"],
            latency_ms=raw["latency_ms"],
            cost_usd=None if raw["cost_usd"] is None else Decimal(raw["cost_usd"]),
            attempts=tuple(Attempt(*a) for a in raw["attempts"]),
        )


@dataclass(frozen=True)
class StreamEvent:
    kind: Literal["text", "tool_call_delta", "done"]
    text: str = ""
    index: int = 0
    tool_call_id: str | None = None
    tool_name: str | None = None
    arguments_delta: str = ""
    response: ModelResponse | None = None


class ErrorKind(StrEnum):
    AUTH = "auth"
    RATE_LIMIT = "rate_limit"
    INVALID_REQUEST = "invalid_request"
    SERVER = "server"
    TIMEOUT = "timeout"
    NETWORK = "network"
    CONTENT_FILTER = "content_filter"
    NO_CREDENTIALS = "no_credentials"
    CIRCUIT_OPEN = "circuit_open"
    UNKNOWN = "unknown"


RETRYABLE = frozenset(
    {ErrorKind.RATE_LIMIT, ErrorKind.SERVER, ErrorKind.TIMEOUT, ErrorKind.NETWORK}
)


class ModelError(Exception):
    """Provider-neutral failure.  The message never contains credentials."""

    def __init__(
        self,
        kind: ErrorKind,
        provider: str,
        message: str = "",
        *,
        status: int | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(f"{provider}: {kind.value}" + (f": {message}" if message else ""))
        self.kind = kind
        self.detail = message
        self.provider = provider
        self.status = status
        self.retry_after = retry_after
        self.attempts: tuple[Attempt, ...] = ()

    @property
    def retryable(self) -> bool:
        return self.kind in RETRYABLE
