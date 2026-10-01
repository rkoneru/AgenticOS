"""Typed, bounded, tenant-isolated IPC over the frozen IPC envelope (``ipc-envelope-v1``).

* ``Envelope`` mirrors the contract schema; its patterns are READ from the schema file, not copied.
* ``MessageRouter`` owns one bounded ``Mailbox`` per registered process.  A send is checked in this
  order: sender registered and in the envelope's tenant -> ``authorize`` hook (fail-closed: False or
  an exception denies) -> recipient resolved INSIDE the sender's tenant -> audit event -> delivery.
  A recipient that does not exist and one that belongs to another tenant are indistinguishable.
* The ``authorize`` hook is a required constructor argument: the router is the delivery layer, and
  production wiring must supply the Risk Kernel gate there.  Nothing in TKI constructs a router
  that skips it.
* Channels (``chan:<name>``) are keyed by ``(tenant, name)``; subscribers of another tenant can
  never receive, even for an identically named channel.
"""

from __future__ import annotations

import asyncio
import json
import re
import secrets
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from axis_runtime.events import Clock, format_ts
from axis_runtime.tki.events import EventSink, TkiEvent, TkiEventType


def _schema() -> dict[str, Any]:
    path = (
        Path(__file__).resolve().parents[4]
        / "packages"
        / "contracts"
        / "schemas"
        / "ipc-envelope-v1.schema.json"
    )
    return json.loads(path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


_SCHEMA = _schema()
_PROPS = _SCHEMA["properties"]
_TO_RE = re.compile(_PROPS["to"]["pattern"])
_TRACE_RE = re.compile(_PROPS["trace_id"]["pattern"])
_PID_RE = re.compile(_SCHEMA["$defs"]["pid"]["pattern"])
_TTL_MIN = _PROPS["ttl_seconds"]["minimum"]
_TTL_MAX = _PROPS["ttl_seconds"]["maximum"]
SCHEMA_VERSION: int = _PROPS["schema_version"]["const"]


class Kind(StrEnum):
    MESSAGE = "message"
    EVENT = "event"
    REQUEST = "request"
    RESPONSE = "response"


if {k.value for k in Kind} != set(_PROPS["kind"]["enum"]):  # drift guard, like process.py
    raise RuntimeError("tki.ipc.Kind differs from ipc-envelope-v1.schema.json")


class IpcError(Exception):
    pass


class EnvelopeError(IpcError):
    """The envelope violates the IPC contract."""


class IpcDeniedError(IpcError):
    """The send was refused (sender, tenant, recipient or authorizer)."""


class MailboxFullError(IpcError):
    """The recipient's bounded mailbox has no room (back-pressure)."""


class IpcAuditError(IpcError):
    """The audit sink failed; the message was NOT delivered."""


_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _uuid(value: object, what: str) -> str:
    if not isinstance(value, str) or not _UUID_RE.match(value):
        raise EnvelopeError(f"{what} must be a lowercase canonical UUID")
    return value


def new_uuid4() -> str:
    h = secrets.token_hex(16)
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-{'89ab'[int(h[16], 16) & 3]}{h[17:20]}-{h[20:]}"


@dataclass(frozen=True)
class Envelope:
    id: str
    tenant_id: str
    trace_id: str
    sender: str
    to: str
    kind: Kind
    ts: str
    payload: Mapping[str, Any]
    correlation_id: str | None = None
    ttl_seconds: int | None = None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise EnvelopeError("unsupported schema_version")
        _uuid(self.id, "id")
        _uuid(self.tenant_id, "tenant_id")
        if not _TRACE_RE.match(self.trace_id):
            raise EnvelopeError("trace_id must be 32 lowercase hex chars")
        if not _PID_RE.match(self.sender):
            raise EnvelopeError("from must be a PID")
        if not _TO_RE.match(self.to):
            raise EnvelopeError("to must be a PID or chan:<name>")
        if not isinstance(self.kind, Kind):
            raise EnvelopeError("unknown kind")
        if not isinstance(self.payload, Mapping):
            raise EnvelopeError("payload must be an object")
        if self.kind is Kind.RESPONSE and self.correlation_id is None:
            raise EnvelopeError("a response requires correlation_id")
        if self.correlation_id is not None:
            _uuid(self.correlation_id, "correlation_id")
        if self.ttl_seconds is not None and (
            isinstance(self.ttl_seconds, bool)
            or not isinstance(self.ttl_seconds, int)
            or not _TTL_MIN <= self.ttl_seconds <= _TTL_MAX
        ):
            raise EnvelopeError("ttl_seconds out of range")
        try:
            datetime.fromisoformat(self.ts)
        except ValueError as exc:
            raise EnvelopeError("ts must be an RFC 3339 date-time") from exc

    @classmethod
    def new(
        cls,
        *,
        tenant_id: str,
        trace_id: str,
        sender: str,
        to: str,
        kind: Kind,
        payload: Mapping[str, Any],
        clock: Clock,
        correlation_id: str | None = None,
        ttl_seconds: int | None = None,
    ) -> Envelope:
        return cls(
            id=new_uuid4(),
            tenant_id=tenant_id,
            trace_id=trace_id,
            sender=sender,
            to=to,
            kind=kind,
            ts=format_ts(clock.now()),
            payload=payload,
            correlation_id=correlation_id,
            ttl_seconds=ttl_seconds,
        )

    def to_dict(self) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "schema_version": self.schema_version,
            "id": self.id,
            "tenant_id": self.tenant_id,
            "trace_id": self.trace_id,
            "from": self.sender,
            "to": self.to,
            "kind": self.kind.value,
            "ts": self.ts,
            "payload": dict(self.payload),
        }
        if self.correlation_id is not None:
            doc["correlation_id"] = self.correlation_id
        if self.ttl_seconds is not None:
            doc["ttl_seconds"] = self.ttl_seconds
        return doc

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> Envelope:
        allowed = set(_PROPS)
        extra = set(raw) - allowed
        if extra:
            raise EnvelopeError(f"unknown fields: {sorted(extra)}")
        missing = set(_SCHEMA["required"]) - set(raw)
        if missing:
            raise EnvelopeError(f"missing fields: {sorted(missing)}")
        try:
            kind = Kind(raw["kind"])
        except ValueError as exc:
            raise EnvelopeError("unknown kind") from exc
        return cls(
            schema_version=raw["schema_version"],
            id=raw["id"],
            tenant_id=raw["tenant_id"],
            trace_id=raw["trace_id"],
            sender=raw["from"],
            to=raw["to"],
            kind=kind,
            ts=raw["ts"],
            payload=raw["payload"],
            correlation_id=raw.get("correlation_id"),
            ttl_seconds=raw.get("ttl_seconds"),
        )

    def expired(self, now: datetime) -> bool:
        if self.ttl_seconds is None:
            return False
        sent = datetime.fromisoformat(self.ts)
        return now >= sent + timedelta(seconds=self.ttl_seconds)


class Mailbox:
    """A bounded FIFO owned by one process."""

    def __init__(
        self,
        pid: str,
        tenant_id: str,
        capacity: int,
        clock: Clock,
        on_expired: Callable[[Envelope], None],
    ) -> None:
        if capacity < 1:
            raise ValueError("mailbox capacity must be >= 1")
        self.pid = pid
        self.tenant_id = tenant_id
        self.capacity = capacity
        self._clock = clock
        self._on_expired = on_expired
        self._queue: list[Envelope] = []
        self._ready = asyncio.Event()
        self._closed = False

    def __len__(self) -> int:
        return len(self._queue)

    @property
    def full(self) -> bool:
        return len(self._queue) >= self.capacity

    @property
    def closed(self) -> bool:
        return self._closed

    def put_nowait(self, env: Envelope) -> None:
        if self._closed:
            raise IpcDeniedError("recipient unavailable")
        if self.full:
            raise MailboxFullError(f"mailbox of {self.pid} is full ({self.capacity})")
        self._queue.append(env)
        self._ready.set()

    def receive_nowait(self) -> Envelope | None:
        while self._queue:
            env = self._queue.pop(0)
            if env.expired(self._clock.now()):
                self._on_expired(env)
                continue
            if not self._queue:
                self._ready.clear()
            return env
        self._ready.clear()
        return None

    async def receive(self, within: float | None = None) -> Envelope:
        """Next live message; ``TimeoutError`` after ``within`` seconds, ``IpcError`` if closed."""

        async def loop() -> Envelope:
            while True:
                env = self.receive_nowait()
                if env is not None:
                    return env
                if self._closed:
                    raise IpcError("mailbox closed")
                await self._ready.wait()

        return await asyncio.wait_for(loop(), within)

    def close(self) -> None:
        self._closed = True
        self._queue.clear()
        self._ready.set()


Authorizer = Callable[[Envelope], Awaitable[bool]]


class MessageRouter:
    def __init__(
        self,
        *,
        sink: EventSink,
        authorize: Authorizer,
        clock: Clock,
        default_capacity: int = 64,
    ) -> None:
        self._sink = sink
        self._authorize = authorize
        self._clock = clock
        self._default_capacity = default_capacity
        self._boxes: dict[str, Mailbox] = {}
        self._channels: dict[tuple[str, str], list[str]] = {}

    # ---- registry --------------------------------------------------------------------------
    def register(self, pid: str, tenant_id: str, capacity: int | None = None) -> Mailbox:
        if pid in self._boxes:
            raise IpcError(f"pid {pid} is already registered")
        if not _PID_RE.match(pid):
            raise IpcError("invalid pid")
        box = Mailbox(
            pid,
            tenant_id,
            capacity or self._default_capacity,
            self._clock,
            lambda env: self._emit(
                TkiEventType.IPC_DROPPED, env, reason="ttl expired", recipient=pid
            ),
        )
        self._boxes[pid] = box
        return box

    def unregister(self, pid: str) -> None:
        box = self._boxes.pop(pid, None)
        if box is None:
            return
        box.close()
        for key in [k for k, subs in self._channels.items() if pid in subs]:
            self._channels[key].remove(pid)
            if not self._channels[key]:
                del self._channels[key]

    def mailbox(self, pid: str) -> Mailbox | None:
        return self._boxes.get(pid)

    def subscribe(self, pid: str, channel: str) -> None:
        box = self._boxes.get(pid)
        if box is None:
            raise IpcError("unknown pid")
        if not _TO_RE.match(f"chan:{channel}"):
            raise IpcError("invalid channel name")
        subs = self._channels.setdefault((box.tenant_id, channel), [])
        if pid not in subs:
            subs.append(pid)

    def unsubscribe(self, pid: str, channel: str) -> None:
        box = self._boxes.get(pid)
        if box is None:
            return
        subs = self._channels.get((box.tenant_id, channel), [])
        if pid in subs:
            subs.remove(pid)

    # ---- send ------------------------------------------------------------------------------
    def _emit(self, kind: TkiEventType, env: Envelope, **data: object) -> None:
        self._sink.emit(
            TkiEvent(
                kind,
                env.tenant_id,
                env.sender,
                {
                    "message_id": env.id,
                    "trace_id": env.trace_id,
                    "to": env.to,
                    "kind": env.kind.value,
                    **data,
                },
            )
        )

    def _deny(self, env: Envelope, reason: str, public: str = "send denied") -> IpcDeniedError:
        self._emit(TkiEventType.IPC_DENIED, env, reason=reason)
        return IpcDeniedError(public)

    async def send(self, env: Envelope) -> int:
        """Deliver ``env``; returns the number of mailboxes that received it."""
        sender = self._boxes.get(env.sender)
        if sender is None or sender.tenant_id != env.tenant_id:
            raise self._deny(env, "sender not registered in the envelope tenant")
        try:
            allowed = await self._authorize(env)
        except Exception as exc:
            raise self._deny(env, f"authorizer failed: {type(exc).__name__}") from exc
        if allowed is not True:
            raise self._deny(env, "authorizer denied")
        # Everything below is synchronous: state cannot change between resolve and deliver.
        targets = self._resolve(env)
        if not targets:
            raise self._deny(env, "no such recipient in tenant", "recipient unavailable")
        is_channel = env.to.startswith("chan:")
        deliverable = [t for t in targets if not t.full]
        if not is_channel and not deliverable:
            raise self._deny(env, "mailbox full", "mailbox full")
        try:
            self._emit(
                TkiEventType.IPC_SENT,
                env,
                recipients=[t.pid for t in deliverable],
                dropped=[t.pid for t in targets if t.full],
            )
        except Exception as exc:
            raise IpcAuditError("audit sink failed; message not delivered") from exc
        for t in deliverable:
            t.put_nowait(env)
        return len(deliverable)

    def _resolve(self, env: Envelope) -> list[Mailbox]:
        if env.to.startswith("chan:"):
            subs = self._channels.get((env.tenant_id, env.to[len("chan:") :]), [])
            boxes = [self._boxes[p] for p in subs if p in self._boxes]
        else:
            one = self._boxes.get(env.to)
            boxes = [] if one is None else [one]
        return [b for b in boxes if b.tenant_id == env.tenant_id and not b.closed]
