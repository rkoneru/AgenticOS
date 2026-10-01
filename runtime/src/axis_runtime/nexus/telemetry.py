"""NEXUS telemetry: a tiny OpenTelemetry-shaped tracer plus the injected stage-event sink.

``opentelemetry-api`` is not a dependency of the runtime, so spans use an internal ``Tracer``
interface (same vocabulary: name, attributes, start/end, status).  The in-memory exporter is the
only shipped implementation; an OTel adapter is a later, additive implementation of ``Tracer``
(docs/NEEDS.md).  Neither spans nor events ever carry a raw prompt, only a salted hash.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

AttrValue = str | int | float | bool


class Span(Protocol):
    def set_attribute(self, key: str, value: AttrValue) -> None: ...
    def set_status(self, ok: bool, description: str = "") -> None: ...
    def end(self) -> None: ...


class Tracer(Protocol):
    def start_span(
        self,
        name: str,
        *,
        parent: Span | None = None,
        attributes: Mapping[str, AttrValue] | None = None,
    ) -> Span: ...


@dataclass
class RecordedSpan:
    name: str
    parent: RecordedSpan | None = None
    attributes: dict[str, AttrValue] = field(default_factory=dict)
    ok: bool = True
    status_description: str = ""
    ended: bool = False

    def set_attribute(self, key: str, value: AttrValue) -> None:
        self.attributes[key] = value

    def set_status(self, ok: bool, description: str = "") -> None:
        self.ok, self.status_description = ok, description

    def end(self) -> None:
        self.ended = True


class InMemoryTracer:
    """Test/dev tracer: every span is kept in ``spans`` in start order."""

    def __init__(self) -> None:
        self.spans: list[RecordedSpan] = []

    def start_span(
        self,
        name: str,
        *,
        parent: Span | None = None,
        attributes: Mapping[str, AttrValue] | None = None,
    ) -> RecordedSpan:
        span = RecordedSpan(
            name, parent if isinstance(parent, RecordedSpan) else None, dict(attributes or {})
        )
        self.spans.append(span)
        return span

    def named(self, name: str) -> list[RecordedSpan]:
        return [s for s in self.spans if s.name == name]


class _NoopSpan:
    def set_attribute(self, key: str, value: AttrValue) -> None:
        return None

    def set_status(self, ok: bool, description: str = "") -> None:
        return None

    def end(self) -> None:
        return None


class NoopTracer:
    def start_span(
        self,
        name: str,
        *,
        parent: Span | None = None,
        attributes: Mapping[str, AttrValue] | None = None,
    ) -> Span:
        return _NoopSpan()


class EventSink(Protocol):
    """Receives one event per stage (``nexus_stage``) and one per route (``nexus_route``).  The host
    appends them to the audit / run log; the router never reads them back."""

    async def emit(self, event_type: str, data: Mapping[str, Any]) -> None: ...


class InMemoryEventSink:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def emit(self, event_type: str, data: Mapping[str, Any]) -> None:
        self.events.append((event_type, dict(data)))

    def of_type(self, event_type: str) -> list[dict[str, Any]]:
        return [d for t, d in self.events if t == event_type]


class NullEventSink:
    async def emit(self, event_type: str, data: Mapping[str, Any]) -> None:
        return None
