"""TKI: the AXIS process kernel (scheduler, supervisor trees, IPC, budget ledger).

See docs/spec/tki.md.  Nothing in this package performs an agent action: actions still go through
the Risk Kernel gate via ``axis_runtime.executor``.
"""

from axis_runtime.tki.budget import (
    AccountKey,
    BudgetExceededError,
    BudgetLedger,
    InMemoryLedger,
    Limit,
    Reservation,
    Resource,
    ScopeKind,
)
from axis_runtime.tki.events import EventSink, ListSink, TkiEvent, TkiEventType

__all__ = [
    "AccountKey",
    "BudgetExceededError",
    "BudgetLedger",
    "EventSink",
    "InMemoryLedger",
    "Limit",
    "ListSink",
    "Reservation",
    "Resource",
    "ScopeKind",
    "TkiEvent",
    "TkiEventType",
]
