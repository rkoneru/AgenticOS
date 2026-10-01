"""Outbound channel messages over the channels service's HTTP/JSON dev surface.

``HttpChannelSender`` implements ``tools.ChannelSender`` (what ``MessageSend`` performs). It is
reachable only through ``ActionExecutor`` (gate -> audit -> perform): a DENY, an approval that is
not granted, or a gate error never reaches ``send``, so a denied message is never delivered.
The channels service writes its own transcript audit event (hash, size, channel; never the text)
BEFORE it hands anything to a provider, and refuses the send if that append fails.

The tenant is bound by the bearer token (the service derives it from the token and rejects a
different ``tenant_id`` in the body), so a client built for tenant A cannot address tenant B. The
service additionally refuses a destination that is not a known identity of the tenant unless its
route opts in to unsolicited messages. The wire format is ``docs/spec/channels.md``; the service
is a loopback dev surface, not a production edge (docs/NEEDS.md). Any failure raises
``ChannelUnavailable``, which carries a status code or an error code from a fixed set, never a
response body: the executor turns it into a failed action result.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import httpx

CHANNELS = frozenset({"web", "slack", "teams", "email", "sms", "whatsapp"})

#: Error codes the service may return; anything else is reported as ``error``.
_SERVICE_CODES = frozenset(
    {
        "INVALID",
        "TOO_LARGE",
        "TOO_LONG",
        "RATE_LIMITED",
        "UNKNOWN_ROUTE",
        "TRANSPORT",
        "NOT_FOUND",
        "FORBIDDEN",
        "AUDIT_FAILED",
        "CONFLICT",
    }
)
_OPTIONAL = ("conversation_id", "to", "subject", "from", "idempotency_key")


class ChannelUnavailable(RuntimeError):  # noqa: N818 - a condition, not a failure class hierarchy
    """The channels service could not deliver the message (or refused it)."""


class HttpChannelSender:
    """``ChannelSender`` for one tenant.

    ``args`` of a ``MessageSend``: ``body`` (or ``text``) and either ``conversation_id`` or ``to``;
    optionally ``subject`` (email), ``from`` (which of the tenant's routes to send from) and
    ``idempotency_key``. The executor has already applied the gate's redaction to ``args`` before
    ``send``.
    """

    def __init__(
        self,
        base_url: str,
        *,
        token: str,
        tenant_id: str,
        run_id: str | None = None,
        trace_id: str | None = None,
        client: httpx.AsyncClient | None = None,
        timeout: float = 30.0,
    ) -> None:
        if not tenant_id:
            raise ValueError("tenant_id required")
        if not token:
            raise ValueError("token required")
        self._url = base_url.rstrip("/") + "/v1/channels/send"
        self._headers = {"authorization": f"Bearer {token}"}
        self.tenant_id = tenant_id
        self._run_id = run_id
        self._trace_id = trace_id
        self._client = client or httpx.AsyncClient(timeout=timeout)

    async def send(self, channel: str, args: Mapping[str, Any]) -> Any:
        if channel not in CHANNELS:
            raise ValueError(f"unknown channel {channel!r}")
        text = args.get("body", args.get("text"))
        if not isinstance(text, str) or not text:
            raise ValueError("a message needs a non-empty string 'body'")
        payload: dict[str, Any] = {"tenant_id": self.tenant_id, "channel": channel, "text": text}
        for key in _OPTIONAL:
            value = args.get(key)
            if value is None:
                continue
            if not isinstance(value, str) or not value:
                raise ValueError(f"{key!r} must be a non-empty string")
            payload[key] = value
        if "conversation_id" not in payload and "to" not in payload:
            raise ValueError("a message needs 'conversation_id' or 'to'")
        if self._run_id:
            payload["run_id"] = self._run_id
        if self._trace_id:
            payload["trace_id"] = self._trace_id
        try:
            resp = await self._client.post(self._url, json=payload, headers=self._headers)
        except httpx.HTTPError as exc:
            raise ChannelUnavailable(f"transport error: {type(exc).__name__}") from exc
        if resp.status_code != 200:
            raise ChannelUnavailable(
                f"channels service returned {resp.status_code} ({_error_code(resp)})"
            )
        try:
            out = resp.json()
        except ValueError as exc:
            raise ChannelUnavailable("invalid JSON from channels service") from exc
        if not isinstance(out, dict):
            raise ChannelUnavailable("invalid response from channels service")
        return {
            k: out[k] for k in ("conversation_id", "parts", "message_ids", "duplicate") if k in out
        }

    async def aclose(self) -> None:
        await self._client.aclose()


def _error_code(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return "error"
    code = body.get("error") if isinstance(body, dict) else None
    return code if isinstance(code, str) and code in _SERVICE_CODES else "error"


class ChannelServiceClient:
    """The runtime's side of the channels service dev bridge for ONE tenant (the token fixes it):
    the inbound inbox, the conversation log and the voice transcript relay. A different tenant's id
    in a body is refused by the service, never honoured. Any failure raises ``ChannelUnavailable``
    (status or a fixed error code, never a body)."""

    def __init__(
        self,
        base_url: str,
        *,
        token: str,
        client: httpx.AsyncClient | None = None,
        timeout: float = 30.0,
    ) -> None:
        if not token:
            raise ValueError("token required")
        self._base = base_url.rstrip("/")
        self._headers = {"authorization": f"Bearer {token}"}
        self._client = client or httpx.AsyncClient(timeout=timeout)

    async def _call(
        self, method: str, path: str, body: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        try:
            resp = await self._client.request(
                method, self._base + path, json=body, headers=self._headers
            )
        except httpx.HTTPError as exc:
            raise ChannelUnavailable(f"transport error: {type(exc).__name__}") from exc
        if resp.status_code != 200:
            raise ChannelUnavailable(
                f"channels service returned {resp.status_code} ({_error_code(resp)})"
            )
        try:
            out = resp.json()
        except ValueError as exc:
            raise ChannelUnavailable("invalid JSON from channels service") from exc
        if not isinstance(out, dict):
            raise ChannelUnavailable("invalid response from channels service")
        return out

    async def next_inbound(self, wait_ms: int = 0) -> dict[str, Any] | None:
        """The next verified inbound message queued for this tenant (long poll), or ``None``."""
        out = await self._call("POST", "/v1/channels/inbox/next", {"wait_ms": max(0, wait_ms)})
        item = out.get("item")
        if item is None:
            return None
        if not isinstance(item, dict):
            raise ChannelUnavailable("invalid response from channels service")
        return item

    async def history(self, conversation_id: str) -> list[dict[str, Any]]:
        """The conversation log (oldest first, across every channel the end user is linked on).
        Content is what the tenant's transcript policy stored: a redacted preview by default,
        nothing in ``hash_only`` mode."""
        if not conversation_id:
            raise ValueError("conversation_id required")
        out = await self._call(
            "GET", f"/v1/channels/conversations/{quote(conversation_id, safe='')}/messages"
        )
        msgs = out.get("messages")
        if not isinstance(msgs, list) or not all(isinstance(m, dict) for m in msgs):
            raise ChannelUnavailable("invalid response from channels service")
        return msgs

    async def record_transcript_event(self, event: Mapping[str, Any]) -> None:
        """Append one voice call/turn event to the tenant's audit chain (the service fails
        closed)."""
        await self._call("POST", "/v1/channels/transcript-events", dict(event))

    async def aclose(self) -> None:
        await self._client.aclose()


_TOKEN_CHARS = re.compile(r"[^A-Za-z0-9:_.\-]")


class VoiceTranscriptRelay:
    """``voice.transcript.TranscriptAudit``: mirrors every voice call/turn event of ONE call into
    the audit chain through the channels service, on the call's trace. Hashes and sizes only; the
    (redacted) text stays in the run log."""

    def __init__(
        self,
        client: ChannelServiceClient,
        *,
        trace_id: str,
        agent_name: str,
        agent_version: str,
        run_id: str | None = None,
    ) -> None:
        self._client = client
        self._base: dict[str, Any] = {
            "channel": "voice",
            "trace_id": trace_id,
            "agent": {"name": agent_name, "version": agent_version},
        }
        if run_id:
            self._base["run_id"] = run_id

    async def record(self, event: Mapping[str, Any]) -> None:
        body = {**self._base, **event}
        for key in ("reason",):
            if isinstance(body.get(key), str):
                body[key] = _TOKEN_CHARS.sub("_", body[key])[:64]
        detail = body.get("detail")
        if isinstance(detail, Mapping):
            body["detail"] = {
                k: (_TOKEN_CHARS.sub("_", v)[:64] if isinstance(v, str) else v)
                for k, v in detail.items()
                if v is not None
            }
        await self._client.record_transcript_event(body)


@dataclass(frozen=True)
class ChannelWiring:
    """How a run reaches the channels service (the service derives the tenant from ``token``).

    ``transport`` is a test seam (an ``httpx`` mock transport); production leaves it ``None``.
    The host puts the result in ``Backends(channels=...)``."""

    base_url: str
    token: str = field(repr=False)
    timeout: float = 30.0
    transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)

    def sender(
        self, *, tenant_id: str, run_id: str | None = None, trace_id: str | None = None
    ) -> HttpChannelSender:
        return HttpChannelSender(
            self.base_url,
            token=self.token,
            tenant_id=tenant_id,
            run_id=run_id,
            trace_id=trace_id,
            client=httpx.AsyncClient(timeout=self.timeout, transport=self.transport),
        )

    def client(self) -> ChannelServiceClient:
        return ChannelServiceClient(
            self.base_url,
            token=self.token,
            client=httpx.AsyncClient(timeout=self.timeout, transport=self.transport),
        )
