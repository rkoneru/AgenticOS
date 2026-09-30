"""AWS Bedrock Converse / ConverseStream with hand-written SigV4 (no boto3).

Credentials are stored as a JSON secret::

    {"access_key_id": "..", "secret_access_key": "..", "session_token": null, "region": "us-east-1"}
"""

from __future__ import annotations

import json
import struct
import zlib
from collections.abc import Mapping
from datetime import datetime
from typing import Any, ClassVar
from urllib.parse import quote

from axis_runtime.models.adapters.base import (
    Adapter,
    HttpCall,
    ParsedResponse,
    StreamParser,
)
from axis_runtime.models.adapters.sigv4 import sign_request
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

STRUCTURED_TOOL = "structured_output"
SERVICE = "bedrock"  # SigV4 signing name of bedrock-runtime

_FINISH = {
    "end_turn": FinishReason.STOP,
    "stop_sequence": FinishReason.STOP,
    "max_tokens": FinishReason.LENGTH,
    "tool_use": FinishReason.TOOL_CALLS,
    "guardrail_intervened": FinishReason.CONTENT_FILTER,
    "content_filtered": FinishReason.CONTENT_FILTER,
}


def _usage(raw: Mapping[str, Any] | None) -> Usage:
    raw = raw or {}
    read = int(raw.get("cacheReadInputTokens") or 0)
    write = int(raw.get("cacheWriteInputTokens") or 0)
    return Usage(
        input_tokens=int(raw.get("inputTokens") or 0) + read + write,
        output_tokens=int(raw.get("outputTokens") or 0),
        cached_tokens=read,
        cache_write_tokens=write,
    )


def _convert_messages(messages: tuple[Message, ...]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in messages:
        if m.role == "system":
            continue
        if m.role == "tool":
            block = {
                "toolResult": {
                    "toolUseId": m.tool_call_id,
                    "content": [{"text": m.content}],
                    "status": "error" if m.is_error else "success",
                }
            }
            if (
                out
                and out[-1]["role"] == "user"
                and all("toolResult" in b for b in out[-1]["content"])
            ):
                out[-1]["content"].append(block)
            else:
                out.append({"role": "user", "content": [block]})
        elif m.role == "assistant":
            blocks: list[dict[str, Any]] = []
            if m.content:
                blocks.append({"text": m.content})
            blocks += [
                {"toolUse": {"toolUseId": c.id, "name": c.name, "input": dict(c.arguments)}}
                for c in m.tool_calls
            ]
            out.append({"role": "assistant", "content": blocks})
        else:
            out.append({"role": "user", "content": [{"text": m.content}]})
    return out


def parse_credentials(secret: Secret) -> dict[str, Any]:
    try:
        creds = json.loads(secret.reveal())
        if not isinstance(creds, dict):
            raise ValueError
        for key in ("access_key_id", "secret_access_key", "region"):
            if not isinstance(creds.get(key), str) or not creds[key]:
                raise ValueError
    except ValueError:
        # Never include the secret (or a slice of it) in the message.
        raise ModelError(
            ErrorKind.AUTH,
            "bedrock",
            "credentials must be JSON with access_key_id, secret_access_key, region",
        ) from None
    return creds


class BedrockAdapter(Adapter):
    provider: ClassVar[str] = "bedrock"

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
        creds = parse_credentials(secret)
        params = req.merged_params(target)
        body: dict[str, Any] = {"messages": _convert_messages(req.messages)}
        system: list[dict[str, Any]] = [
            {"text": m.content} for m in req.messages if m.role == "system"
        ]
        if system:
            if req.cache.system:
                system.append({"cachePoint": {"type": "default"}})
            body["system"] = system
        inference: dict[str, Any] = {}
        for key, wire in (
            ("max_tokens", "maxTokens"),
            ("temperature", "temperature"),
            ("top_p", "topP"),
            ("stop", "stopSequences"),
        ):
            if key in params:
                inference[wire] = params[key]
        if inference:
            body["inferenceConfig"] = inference
        specs: list[dict[str, Any]] = [
            {
                "toolSpec": {
                    "name": t.name,
                    "description": t.description or t.name,
                    "inputSchema": {"json": dict(t.input_schema)},
                }
            }
            for t in req.tools
        ]
        if specs and req.cache.tools:
            specs.append({"cachePoint": {"type": "default"}})
        tool_config: dict[str, Any] = {}
        if req.response_schema is not None:
            specs.append(
                {
                    "toolSpec": {
                        "name": STRUCTURED_TOOL,
                        "description": "Return the final answer as structured output.",
                        "inputSchema": {"json": dict(req.response_schema)},
                    }
                }
            )
            only = sum(1 for s in specs if "toolSpec" in s) == 1
            tool_config["toolChoice"] = {"tool": {"name": STRUCTURED_TOOL}} if only else {"any": {}}
        if specs:
            tool_config["tools"] = specs
            body["toolConfig"] = tool_config

        host_base = target.endpoint or f"https://bedrock-runtime.{creds['region']}.amazonaws.com"
        path = (
            f"/model/{quote(target.model, safe='')}/{'converse-stream' if stream else 'converse'}"
        )
        url = host_base.rstrip("/") + path
        payload = json.dumps(body).encode("utf-8")
        headers = sign_request(
            method="POST",
            url=url,
            headers={"content-type": "application/json"},
            body=payload,
            access_key=creds["access_key_id"],
            secret_key=creds["secret_access_key"],
            region=creds["region"],
            service=SERVICE,
            now=now,
            session_token=creds.get("session_token") or None,
        )
        return HttpCall("POST", url, headers, payload)

    def parse(self, data: Mapping[str, Any]) -> ParsedResponse:
        message = (data.get("output") or {}).get("message")
        if not message:
            raise ModelError(ErrorKind.SERVER, self.provider, "response had no output message")
        texts: list[str] = []
        calls: list[ToolCallRequest] = []
        structured: str | None = None
        for block in message.get("content", []):
            if "text" in block:
                texts.append(block["text"])
            elif "toolUse" in block:
                tu = block["toolUse"]
                if tu["name"] == STRUCTURED_TOOL:
                    structured = json.dumps(tu.get("input", {}))
                else:
                    calls.append(ToolCallRequest(tu["toolUseId"], tu["name"], tu.get("input", {})))
        finish = _FINISH.get(str(data.get("stopReason")), FinishReason.OTHER)
        if structured is not None:
            texts, finish = [structured], FinishReason.STOP
        return ParsedResponse("".join(texts), tuple(calls), _usage(data.get("usage")), finish, "")

    def stream_parser(self) -> StreamParser:
        return _BedrockStream(self.provider)

    def error_code(self, data: Any) -> str:
        if isinstance(data, dict):
            for key in ("__type", "type", "code"):
                if isinstance(data.get(key), str):
                    return str(data[key]).split("#")[-1][:64]
        return ""


# --- AWS event-stream framing (application/vnd.amazon.eventstream) ---------------------


class EventStreamDecoder:
    """Decodes binary event-stream messages, verifying both CRC32s."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, chunk: bytes) -> list[tuple[dict[str, str], bytes]]:
        self._buf += chunk
        out: list[tuple[dict[str, str], bytes]] = []
        while len(self._buf) >= 12:
            total, hlen = struct.unpack(">II", self._buf[:8])
            (prelude_crc,) = struct.unpack(">I", self._buf[8:12])
            if zlib.crc32(bytes(self._buf[:8])) != prelude_crc:
                raise ModelError(ErrorKind.SERVER, "bedrock", "corrupt event stream (prelude crc)")
            if total < 16 + hlen:
                raise ModelError(ErrorKind.SERVER, "bedrock", "corrupt event stream (length)")
            if len(self._buf) < total:
                break
            message = bytes(self._buf[:total])
            del self._buf[:total]
            (msg_crc,) = struct.unpack(">I", message[-4:])
            if zlib.crc32(message[:-4]) != msg_crc:
                raise ModelError(ErrorKind.SERVER, "bedrock", "corrupt event stream (message crc)")
            out.append((self._headers(message[12 : 12 + hlen]), message[12 + hlen : -4]))
        return out

    @staticmethod
    def _headers(raw: bytes) -> dict[str, str]:
        headers: dict[str, str] = {}
        i = 0
        fixed = {2: 1, 3: 2, 4: 4, 5: 8, 8: 8, 9: 16}
        while i < len(raw):
            nlen = raw[i]
            name = raw[i + 1 : i + 1 + nlen].decode("utf-8")
            i += 1 + nlen
            htype = raw[i]
            i += 1
            if htype in (0, 1):
                headers[name] = "true" if htype == 0 else "false"
            elif htype in fixed:
                i += fixed[htype]
            elif htype in (6, 7):
                (vlen,) = struct.unpack(">H", raw[i : i + 2])
                value = raw[i + 2 : i + 2 + vlen]
                i += 2 + vlen
                if htype == 7:
                    headers[name] = value.decode("utf-8")
            else:
                raise ModelError(ErrorKind.SERVER, "bedrock", "unknown event-stream header type")
        return headers


class _BedrockStream(StreamParser):
    def __init__(self, provider: str) -> None:
        super().__init__(provider)
        self._decoder = EventStreamDecoder()

    def feed(self, chunk: bytes) -> list[StreamEvent]:
        events: list[StreamEvent] = []
        for headers, payload in self._decoder.feed(chunk):
            if headers.get(":message-type") == "exception":
                etype = headers.get(":exception-type", "")[:64]
                kind = ErrorKind.RATE_LIMIT if etype == "throttlingException" else ErrorKind.SERVER
                raise ModelError(kind, self.provider, f"stream exception {etype}")
            try:
                data = json.loads(payload) if payload else {}
            except ValueError:
                raise ModelError(
                    ErrorKind.SERVER, self.provider, "malformed stream event"
                ) from None
            events.extend(self._handle(headers.get(":event-type", ""), data))
        return events

    def _handle(self, event: str, data: dict[str, Any]) -> list[StreamEvent]:
        if event == "contentBlockStart":
            tool = (data.get("start") or {}).get("toolUse")
            if tool:
                return [
                    self._tool_delta(
                        int(data["contentBlockIndex"]), tool.get("toolUseId"), tool.get("name"), ""
                    )
                ]
        elif event == "contentBlockDelta":
            delta = data.get("delta") or {}
            if "text" in delta:
                return [self._text(delta["text"])]
            if "toolUse" in delta:
                return [
                    self._tool_delta(
                        int(data["contentBlockIndex"]),
                        None,
                        None,
                        delta["toolUse"].get("input", ""),
                    )
                ]
        elif event == "messageStop":
            self.finish = _FINISH.get(str(data.get("stopReason")), FinishReason.OTHER)
        elif event == "metadata":
            self.usage = _usage(data.get("usage"))
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
