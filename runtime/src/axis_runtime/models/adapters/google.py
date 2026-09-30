"""Google Gemini API (``models/{model}:generateContent`` / ``:streamGenerateContent?alt=sse``).

The key is sent in the ``x-goog-api-key`` header, never in the query string, so it cannot leak
through URLs in logs or exception messages.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any, ClassVar
from urllib.parse import quote

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

DEFAULT_ENDPOINT = "https://generativelanguage.googleapis.com"


def _usage(raw: Mapping[str, Any] | None) -> Usage:
    raw = raw or {}
    return Usage(
        input_tokens=int(raw.get("promptTokenCount") or 0),
        output_tokens=int(raw.get("candidatesTokenCount") or 0)
        + int(raw.get("thoughtsTokenCount") or 0),
        cached_tokens=int(raw.get("cachedContentTokenCount") or 0),
    )


def _finish(reason: str | None, has_calls: bool) -> FinishReason:
    if reason == "MAX_TOKENS":
        return FinishReason.LENGTH
    if reason in {"SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII"}:
        return FinishReason.CONTENT_FILTER
    if reason in {"STOP", None}:
        return FinishReason.TOOL_CALLS if has_calls else FinishReason.STOP
    return FinishReason.OTHER


def _tool_response(m: Message) -> dict[str, Any]:
    try:
        parsed = json.loads(m.content)
        response = parsed if isinstance(parsed, dict) else {"result": parsed}
    except ValueError:
        response = {"result": m.content}
    if m.is_error:
        response = {"error": m.content}
    return {"functionResponse": {"name": m.name or "", "response": response}}


def _convert_messages(messages: tuple[Message, ...]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in messages:
        if m.role == "system":
            continue
        if m.role == "tool":
            part = _tool_response(m)
            if (
                out
                and out[-1]["role"] == "user"
                and all("functionResponse" in p for p in out[-1]["parts"])
            ):
                out[-1]["parts"].append(part)
            else:
                out.append({"role": "user", "parts": [part]})
        elif m.role == "assistant":
            parts: list[dict[str, Any]] = []
            if m.content:
                parts.append({"text": m.content})
            parts += [
                {"functionCall": {"name": c.name, "args": dict(c.arguments)}} for c in m.tool_calls
            ]
            out.append({"role": "model", "parts": parts})
        else:
            out.append({"role": "user", "parts": [{"text": m.content}]})
    return out


def _extract(data: Mapping[str, Any]) -> tuple[list[str], list[ToolCallRequest], str | None]:
    candidates = data.get("candidates") or []
    if not candidates:
        return [], [], None
    cand = candidates[0]
    texts: list[str] = []
    calls: list[ToolCallRequest] = []
    for part in (cand.get("content") or {}).get("parts", []):
        if "text" in part and not part.get("thought"):
            texts.append(part["text"])
        elif "functionCall" in part:
            fc = part["functionCall"]
            calls.append(ToolCallRequest(f"call_{len(calls)}", fc["name"], fc.get("args", {})))
    return texts, calls, cand.get("finishReason")


class GoogleAdapter(Adapter):
    provider: ClassVar[str] = "google"

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
        body: dict[str, Any] = {"contents": _convert_messages(req.messages)}
        system = [m.content for m in req.messages if m.role == "system"]
        if system:
            body["systemInstruction"] = {"parts": [{"text": "\n\n".join(system)}]}
        gen: dict[str, Any] = {}
        for key, wire in (
            ("temperature", "temperature"),
            ("top_p", "topP"),
            ("max_tokens", "maxOutputTokens"),
            ("seed", "seed"),
            ("stop", "stopSequences"),
        ):
            if key in params:
                gen[wire] = params[key]
        if req.response_schema is not None:
            gen["responseMimeType"] = "application/json"
            gen["responseSchema"] = dict(req.response_schema)
        if gen:
            body["generationConfig"] = gen
        if req.tools:
            body["tools"] = [
                {
                    "functionDeclarations": [
                        {
                            "name": t.name,
                            "description": t.description,
                            "parameters": dict(t.input_schema),
                        }
                        for t in req.tools
                    ]
                }
            ]
        method = "streamGenerateContent?alt=sse" if stream else "generateContent"
        base = (target.endpoint or DEFAULT_ENDPOINT).rstrip("/")
        url = f"{base}/v1beta/models/{quote(target.model, safe='')}:{method}"
        return HttpCall(
            "POST",
            url,
            {"x-goog-api-key": secret.reveal(), "content-type": "application/json"},
            json.dumps(body).encode("utf-8"),
        )

    def parse(self, data: Mapping[str, Any]) -> ParsedResponse:
        if not data.get("candidates"):
            block = (data.get("promptFeedback") or {}).get("blockReason")
            if block:
                return ParsedResponse(
                    "",
                    (),
                    _usage(data.get("usageMetadata")),
                    FinishReason.CONTENT_FILTER,
                    str(data.get("modelVersion", "")),
                )
            raise ModelError(ErrorKind.SERVER, self.provider, "response had no candidates")
        texts, calls, reason = _extract(data)
        return ParsedResponse(
            "".join(texts),
            tuple(calls),
            _usage(data.get("usageMetadata")),
            _finish(reason, bool(calls)),
            str(data.get("modelVersion", "")),
        )

    def stream_parser(self) -> StreamParser:
        return _GoogleStream(self.provider)


class _GoogleStream(SseStreamParser):
    def __init__(self, provider: str) -> None:
        super().__init__(provider)
        self._calls = 0
        self._reason: str | None = None

    def handle(self, event: str, payload: dict[str, Any]) -> list[StreamEvent]:
        self.model = str(payload.get("modelVersion", self.model))
        if payload.get("usageMetadata"):
            self.usage = _usage(payload["usageMetadata"])
        texts, calls, reason = _extract(payload)
        out = [self._text(t) for t in texts]
        for c in calls:
            out.append(
                self._tool_delta(
                    self._calls, f"call_{self._calls}", c.name, json.dumps(dict(c.arguments))
                )
            )
            self._calls += 1
        if reason:
            self._reason = reason
        self.finish = _finish(self._reason, self._calls > 0) if self._reason else self.finish
        return out
