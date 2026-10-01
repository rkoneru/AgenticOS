"""TKI audit events and the injected sink.

TKI never writes to a store itself.  Every state change (process transition, signal, restart, IPC
send, ledger reserve/commit/release, soft/hard cap) is described as a ``TkiEvent`` and handed to an
``EventSink`` *before* the change is applied.  A sink that raises therefore blocks the change
(fail-closed): no message is delivered and no budget is reserved without its audit record.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol


class TkiEventType(StrEnum):
    PROCESS_SPAWNED = "process_spawned"
    PROCESS_TRANSITION = "process_transition"
    SIGNAL_DELIVERED = "signal_delivered"
    PROCESS_RESTARTED = "process_restarted"
    SUPERVISOR_ESCALATED = "supervisor_escalated"
    IPC_SENT = "ipc_sent"
    IPC_DENIED = "ipc_denied"
    IPC_DROPPED = "ipc_dropped"
    BUDGET_RESERVED = "budget_reserved"
    BUDGET_DENIED = "budget_denied"
    BUDGET_COMMITTED = "budget_committed"
    BUDGET_RELEASED = "budget_released"
    BUDGET_SOFT_CAP = "budget_soft_cap"
    BUDGET_HARD_CAP = "budget_hard_cap"


@dataclass(frozen=True)
class TkiEvent:
    type: TkiEventType
    tenant_id: str
    pid: str | None = None
    data: Mapping[str, Any] = field(default_factory=dict)


class EventSink(Protocol):
    """Receives every TKI event.  May raise: the guarded change is then not applied."""

    def emit(self, event: TkiEvent) -> None: ...


class ListSink:
    """In-memory sink (tests, local dev)."""

    def __init__(self) -> None:
        self.events: list[TkiEvent] = []

    def emit(self, event: TkiEvent) -> None:
        self.events.append(event)

    def of(self, *types: TkiEventType) -> list[TkiEvent]:
        return [e for e in self.events if e.type in types]
