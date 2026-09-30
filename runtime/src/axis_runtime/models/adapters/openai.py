"""OpenAI Chat Completions, plus the Azure OpenAI and OpenAI-compatible variants."""

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
    parse_args,
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

DEFAULT_ENDPOINT = "https://api.openai.com"
DEFAULT_AZURE_API_VERSION = "2024-10-21"

_FINISH = {
    "stop": FinishReason.STOP,
    "length": FinishReason.LENGTH,
    "tool_calls": FinishReason.TOOL_CALLS,
    "function_call": FinishReason.TOOL_CALLS,
    "content_filter": FinishReason.CONTENT_FILTER,
}


def _usage(raw: Mapping[str, Any] | None) -> Usage:
    raw = raw or {}
    details = raw.get("prompt_tokens_details") or {}
    return Usage(
        input_tokens=int(raw.get("prompt_tokens") or 0),
        output_tokens=int(raw.get("completion_tokens") or 0),
        cached_tokens=int(details.get("cached_tokens") or 0),
    )


def _convert_messages(messages: tuple[Message, ...]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in messages:
        if m.role == "tool":
            out.append({"role": "tool", "tool_call_id": m.tool_call_id, "content": m.content})
        elif m.role == "assistant" and m.tool_calls:
            out.append(
                {
                    "role": "assistant",
                    "content": m.content or None,
                    "tool_calls": [
                        {
                            "id": c.id,
                            "type": "function",
                            "function": {
                                "name": c.name,
                                "arguments": json.dumps(dict(c.arguments)),
                            },
                        }
                        for c in m.tool_calls
                    ],
                }
            )
        else:
            out.append({"role": m.role, "content": m.content})
    return out


class OpenAIAdapter(Adapter):
    provider: ClassVar[str] = "openai"
    max_tokens_param: ClassVar[str] = "max_completion_tokens"
    include_model_in_body: ClassVar[bool] = True

    def url(self, target: ModelTarget) -> str:
        return (target.endpoint or DEFAULT_ENDPOINT).rstrip("/") + "/v1/chat/completions"

    def headers(self, secret: Secret | None) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        if secret is not None:
            headers["authorization"] = f"Bearer {secret.reveal()}"
        return headers

    def build(
        self,
        req: ModelRequest,
        target: ModelTarget,
        secret: Secret | None,
        *,
        stream: bool,
        now: datetime,
    ) -> HttpCall:
        if secret is None and not self.auth_optional:
            raise ModelError(ErrorKind.NO_CREDENTIALS, self.provider)
        params = req.merged_params(target)
        body: dict[str, Any] = {"messages": _convert_messages(req.messages)}
        if self.include_model_in_body:
            body["model"] = target.model
        if "max_tokens" in params:
            body[self.max_tokens_param] = int(params["max_tokens"])
        for key in ("temperature", "top_p", "seed", "stop"):
            if key in params:
                body[key] = params[key]
        if req.tools:
            body["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": dict(t.input_schema),
                    },
                }
                for t in req.tools
            ]
        if req.response_schema is not None:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "response",
                    "schema": dict(req.response_schema),
                    "strict": True,
                },
            }
        if stream:
            body["stream"] = True
            body["stream_options"] = {"include_usage": True}
        return HttpCall(
            "POST", self.url(target), self.headers(secret), json.dumps(body).encode("utf-8")
        )

    def parse(self, data: Mapping[str, Any]) -> ParsedResponse:
        choices = data.get("choices") or []
        if not choices:
            raise ModelError(ErrorKind.SERVER, self.provider, "response had no choices")
        choice = choices[0]
        msg = choice.get("message", {})
        calls = tuple(
            ToolCallRequest(
                c.get("id", f"call_{i}"),
                c["function"]["name"],
                parse_args(c["function"].get("arguments", "")),
            )
            for i, c in enumerate(msg.get("tool_calls") or [])
        )
        finish = _FINISH.get(str(choice.get("finish_reason")), FinishReason.OTHER)
        return ParsedResponse(
            msg.get("content") or "",
            calls,
            _usage(data.get("usage")),
            finish,
            str(data.get("model", "")),
        )

    def stream_parser(self) -> StreamParser:
        return _OpenAIStream(self.provider)


class _OpenAIStream(SseStreamParser):
    def handle(self, event: str, payload: dict[str, Any]) -> list[StreamEvent]:
        if "error" in payload:
            raise ModelError(ErrorKind.SERVER, self.provider, "stream error")
        self.model = str(payload.get("model", self.model))
        if payload.get("usage"):
            self.usage = _usage(payload["usage"])
        out: list[StreamEvent] = []
        for choice in payload.get("choices") or []:
            delta = choice.get("delta") or {}
            if delta.get("content"):
                out.append(self._text(delta["content"]))
            for call in delta.get("tool_calls") or []:
                fn = call.get("function") or {}
                out.append(
                    self._tool_delta(
                        int(call.get("index", 0)),
                        call.get("id"),
                        fn.get("name"),
                        fn.get("arguments", ""),
                    )
                )
            if choice.get("finish_reason"):
                self.finish = _FINISH.get(str(choice["finish_reason"]), FinishReason.OTHER)
        return out


class OpenAICompatibleAdapter(OpenAIAdapter):
    """Any server speaking the OpenAI chat format (vLLM, Ollama, LiteLLM, ...): custom endpoint."""

    provider: ClassVar[str] = "openai-compatible"
    max_tokens_param: ClassVar[str] = "max_tokens"  # the legacy name is the widely supported one
    auth_optional: ClassVar[bool] = True
    endpoint_required: ClassVar[bool] = True

    def url(self, target: ModelTarget) -> str:
        if not target.endpoint:
            raise ModelError(ErrorKind.INVALID_REQUEST, self.provider, "endpoint is required")
        base = target.endpoint.rstrip("/")
        return base + ("/chat/completions" if base.endswith("/v1") else "/v1/chat/completions")


class AzureOpenAIAdapter(OpenAIAdapter):
    """Azure OpenAI: deployment-scoped URL, ``api-version`` query and ``api-key`` header.

    ``target.model`` is the DEPLOYMENT name; ``target.endpoint`` the resource endpoint
    (https://<resource>.openai.azure.com); ``params["api_version"]`` overrides the default.
    """

    provider: ClassVar[str] = "azure-openai"
    include_model_in_body: ClassVar[bool] = False
    endpoint_required: ClassVar[bool] = True

    def url(self, target: ModelTarget) -> str:
        if not target.endpoint:
            raise ModelError(ErrorKind.INVALID_REQUEST, self.provider, "endpoint is required")
        version = str(target.params.get("api_version", DEFAULT_AZURE_API_VERSION))
        return (
            f"{target.endpoint.rstrip('/')}/openai/deployments/{quote(target.model, safe='')}"
            f"/chat/completions?api-version={quote(version, safe='')}"
        )

    def headers(self, secret: Secret | None) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        if secret is not None:
            headers["api-key"] = secret.reveal()
        return headers
