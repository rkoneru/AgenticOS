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

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

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
