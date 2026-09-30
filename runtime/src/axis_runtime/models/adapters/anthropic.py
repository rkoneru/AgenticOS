"""Anthropic Messages API (``POST /v1/messages``)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any, ClassVar

from axis_runtime.models.adapters.base import (
    Adapter,
    HttpCall,
    ParsedResponse,
    SseStreamParser,
    StreamParser,
)
from axis_runtime.models.secrets import Secret
from axis_runtime.models.types import (
    ErrorKind,
    FinishReason,
    Message,
    ModelError,
    ModelRequest,
    ModelTarget,
    StreamEvent,
    ToolCallRequest,
    Usage,
)

DEFAULT_ENDPOINT = "https://api.anthropic.com"
API_VERSION = "2023-06-01"
STRUCTURED_TOOL = "structured_output"
_EPHEMERAL = {"type": "ephemeral"}

_FINISH = {
    "end_turn": FinishReason.STOP,
    "stop_sequence": FinishReason.STOP,
    "max_tokens": FinishReason.LENGTH,
    "tool_use": FinishReason.TOOL_CALLS,
    "refusal": FinishReason.CONTENT_FILTER,
}


def _usage(raw: Mapping[str, Any]) -> Usage:
    read = int(raw.get("cache_read_input_tokens") or 0)
    write = int(raw.get("cache_creation_input_tokens") or 0)
    return Usage(
        input_tokens=int(raw.get("input_tokens") or 0) + read + write,
        output_tokens=int(raw.get("output_tokens") or 0),
        cached_tokens=read,
        cache_write_tokens=write,
    )


def _convert_messages(messages: tuple[Message, ...]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in messages:
        if m.role == "system":
            continue
        if m.role == "tool":
            block: dict[str, Any] = {
                "type": "tool_result",
                "tool_use_id": m.tool_call_id,
                "content": m.content,
            }
            if m.is_error:
                block["is_error"] = True
            prev = out[-1] if out else None
            if (
                prev
                and prev["role"] == "user"
                and isinstance(prev["content"], list)
                and all(b.get("type") == "tool_result" for b in prev["content"])
            ):
                prev["content"].append(block)  # tool results must share one user turn
            else:
                out.append({"role": "user", "content": [block]})
        elif m.role == "assistant" and m.tool_calls:
            blocks: list[dict[str, Any]] = []
            if m.content:
                blocks.append({"type": "text", "text": m.content})
            blocks += [
                {"type": "tool_use", "id": c.id, "name": c.name, "input": dict(c.arguments)}
                for c in m.tool_calls
            ]
            out.append({"role": "assistant", "content": blocks})
        else:
            out.append({"role": m.role, "content": m.content})
    return out


class AnthropicAdapter(Adapter):
    provider: ClassVar[str] = "anthropic"

    def build(
        self,
        req: ModelRequest,
        target: ModelTarget,
        secret: Secret | None,
        *,
        stream: bool,
        now: datetime,
    ) -> HttpCall:
        if secret is None:
            raise ModelError(ErrorKind.NO_CREDENTIALS, self.provider)
        params = req.merged_params(target)
        body: dict[str, Any] = {
            "model": target.model,
            "max_tokens": int(params.get("max_tokens", 4096)),
            "messages": _convert_messages(req.messages),
        }
        system = [m.content for m in req.messages if m.role == "system"]
        if system:
            if req.cache.system:
                blocks: list[dict[str, Any]] = [{"type": "text", "text": t} for t in system]
                blocks[-1]["cache_control"] = dict(_EPHEMERAL)
                body["system"] = blocks
            else:
                body["system"] = "\n\n".join(system)
        for key, wire in (("temperature", "temperature"), ("top_p", "top_p"), ("top_k", "top_k")):
            if key in params:
                body[wire] = params[key]
        if "stop" in params:
            body["stop_sequences"] = list(params["stop"])
        tools: list[dict[str, Any]] = [
            {"name": t.name, "description": t.description, "input_schema": dict(t.input_schema)}
            for t in req.tools
        ]
        if tools and req.cache.tools:
            tools[-1]["cache_control"] = dict(_EPHEMERAL)
        if req.response_schema is not None:
            # No native schema parameter on the Messages API: force a tool call with the schema.
            tools.append(
                {
                    "name": STRUCTURED_TOOL,
                    "description": "Return the final answer as structured output.",
                    "input_schema": dict(req.response_schema),
                }
            )
            body["tool_choice"] = (
                {"type": "tool", "name": STRUCTURED_TOOL} if len(tools) == 1 else {"type": "any"}
            )
        if tools:
            body["tools"] = tools
        if stream:
            body["stream"] = True
        return HttpCall(
            "POST",
            (target.endpoint or DEFAULT_ENDPOINT).rstrip("/") + "/v1/messages",
            {
                "x-api-key": secret.reveal(),
                "anthropic-version": API_VERSION,
                "content-type": "application/json",
            },
            json.dumps(body).encode("utf-8"),
        )

    def parse(self, data: Mapping[str, Any]) -> ParsedResponse:
        texts: list[str] = []
        calls: list[ToolCallRequest] = []
        structured: str | None = None
        for block in data.get("content", []):
            if block.get("type") == "text":
                texts.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                if block.get("name") == STRUCTURED_TOOL:
                    structured = json.dumps(block.get("input", {}))
                else:
                    calls.append(
                        ToolCallRequest(block["id"], block["name"], block.get("input", {}))
                    )
        finish = _FINISH.get(str(data.get("stop_reason")), FinishReason.OTHER)
        if structured is not None:
            texts, finish = [structured], FinishReason.STOP
        return ParsedResponse(
            "".join(texts),
            tuple(calls),
            _usage(data.get("usage", {})),
            finish,
            str(data.get("model", "")),
        )

    def stream_parser(self) -> StreamParser:
        return _AnthropicStream(self.provider)


class _AnthropicStream(SseStreamParser):
    def __init__(self, provider: str) -> None:
        super().__init__(provider)
        self._kinds: dict[int, str] = {}
        self._in = Usage()

    def handle(self, event: str, payload: dict[str, Any]) -> list[StreamEvent]:
        kind = payload.get("type", event)
        if kind == "message_start":
            msg = payload.get("message", {})
            self.model = str(msg.get("model", ""))
            self._in = _usage(msg.get("usage", {}))
            self.usage = self._in
        elif kind == "content_block_start":
            idx = int(payload["index"])
            block = payload.get("content_block", {})
            self._kinds[idx] = block.get("type", "")
            if block.get("type") == "tool_use":
                return [self._tool_delta(idx, block.get("id"), block.get("name"), "")]
        elif kind == "content_block_delta":
            idx = int(payload["index"])
            delta = payload.get("delta", {})
            if delta.get("type") == "text_delta":
                return [self._text(delta.get("text", ""))]
            if delta.get("type") == "input_json_delta":
                return [self._tool_delta(idx, None, None, delta.get("partial_json", ""))]
        elif kind == "message_delta":
            self.finish = _FINISH.get(
                str(payload.get("delta", {}).get("stop_reason")), FinishReason.OTHER
            )
            out_tokens = int(payload.get("usage", {}).get("output_tokens") or 0)
            self.usage = Usage(
                self._in.input_tokens,
                out_tokens,
                self._in.cached_tokens,
                self._in.cache_write_tokens,
            )
        elif kind == "error":
            err = payload.get("error", {})
            etype = str(err.get("type", ""))[:64]
            mapped = ErrorKind.RATE_LIMIT if etype == "rate_limit_error" else ErrorKind.SERVER
            raise ModelError(mapped, self.provider, f"stream error {etype}")
        return []

    def result(self) -> ParsedResponse:
        parsed = super().result()
        structured = next((c for c in parsed.tool_calls if c.name == STRUCTURED_TOOL), None)
        if structured is None:
            return parsed
        rest = tuple(c for c in parsed.tool_calls if c.name != STRUCTURED_TOOL)
        return ParsedResponse(
            json.dumps(dict(structured.arguments)),
            rest,
            parsed.usage,
            FinishReason.STOP,
            parsed.model,
        )
