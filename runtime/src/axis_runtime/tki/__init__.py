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
from axis_runtime.tki.ipc import Envelope, Kind, MessageRouter
from axis_runtime.tki.scheduler import (
    Priority,
    ProcessCancelled,
    ProcessContext,
    Scheduler,
    SchedulerConfig,
    SpawnSpec,
    WorkloadResult,
)
from axis_runtime.tki.supervisor import (
    ChildSpec,
    RestartPolicy,
    Strategy,
    Supervisor,
    SupervisorConfig,
)

__all__ = [
    "AccountKey",
    "BudgetExceededError",
    "BudgetLedger",
    "ChildSpec",
    "Envelope",
    "EventSink",
    "InMemoryLedger",
    "Kind",
    "Limit",
    "ListSink",
    "MessageRouter",
    "Priority",
    "ProcessCancelled",
    "ProcessContext",
    "Reservation",
    "Resource",
    "RestartPolicy",
    "Scheduler",
    "SchedulerConfig",
    "ScopeKind",
    "SpawnSpec",
    "Strategy",
    "Supervisor",
    "SupervisorConfig",
    "TkiEvent",
    "TkiEventType",
    "WorkloadResult",
]
