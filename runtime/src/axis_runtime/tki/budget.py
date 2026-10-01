"""Hierarchical budget ledger: reserve-before-spend, atomic reserve/commit/release, soft/hard caps.

Accounts form a tree ``tenant -> agent -> run -> process -> child process``.  Every reservation and
every commit applies to the leaf AND all of its ancestors in one synchronous step (no ``await``
inside, so it is atomic under asyncio), or to none of them.

Invariants (property-tested):

* ``committed + reserved <= hard`` for every resource of every account, always (no way to
  exceed a hard cap, including through ``commit`` of more than was reserved: the excess is clamped
  to the remaining headroom and reported as ``overrun``).
* ``committed`` and ``reserved`` are never negative.
* a reservation is settled exactly once (commit XOR release).
* a child's spend is part of every ancestor's totals (conservation up the tree).
* a missing account, a cross-tenant parent or a malformed amount is an error, never a free pass.

Soft caps emit one ``budget_soft_cap`` event the first time ``committed`` reaches them.  A denied
reservation or a clamped commit emits ``budget_denied`` / ``budget_hard_cap``; callers (the
scheduler) turn that into termination with ``ExitReason.BUDGET_EXCEEDED``.

All events are emitted BEFORE state changes, so an audit sink failure leaves the ledger untouched
(except ``release``, which frees budget and is applied first so cleanup can never leak funds).
This implementation is in-memory and single-process; see ``docs/NEEDS.md``.
"""

from __future__ import annotations

import itertools
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Protocol

from axis_runtime.tki.events import EventSink, TkiEvent, TkiEventType


class Resource(StrEnum):
    TOKENS = "tokens"
    COST_MICRO_USD = "cost_micro_usd"
    RUNTIME_MS = "runtime_ms"
    TOOL_CALLS = "tool_calls"


class ScopeKind(IntEnum):
    TENANT = 0
    AGENT = 1
    RUN = 2
    PROCESS = 3


@dataclass(frozen=True)
class AccountKey:
    tenant_id: str
    kind: ScopeKind
    id: str

    def label(self) -> str:
        return f"{self.kind.name.lower()}:{self.id}"


@dataclass(frozen=True)
class Limit:
    soft: int | None = None
    hard: int | None = None

    def __post_init__(self) -> None:
        for name, v in (("soft", self.soft), ("hard", self.hard)):
            if v is not None and (isinstance(v, bool) or not isinstance(v, int) or v < 0):
                raise ValueError(f"limit {name} must be a non-negative int, got {v!r}")
        if self.soft is not None and self.hard is not None and self.soft > self.hard:
            raise ValueError("soft cap must not exceed hard cap")


Limits = Mapping[Resource, Limit]
Amounts = Mapping[Resource, int]


class BudgetError(Exception):
    """Base class for ledger errors."""


class BudgetExceededError(BudgetError):
    """A hard cap would be exceeded (fail-closed: the spend is refused)."""

    def __init__(
        self, account: AccountKey, resource: Resource, requested: int, available: int
    ) -> None:
        super().__init__(
            f"hard cap on {resource.value} at {account.label()}: "
            f"requested {requested}, available {available}"
        )
        self.account = account
        self.resource = resource
        self.requested = requested
        self.available = available


class UnknownAccountError(BudgetError):
    pass


class AccountConfigError(BudgetError):
    pass


class InvalidAmountError(BudgetError):
    pass


class ReservationStateError(BudgetError):
    """The reservation is unknown or was already committed/released."""


@dataclass(frozen=True)
class Reservation:
    id: str
    key: AccountKey
    amounts: Mapping[Resource, int]


@dataclass(frozen=True)
class CommitResult:
    granted: Mapping[Resource, int]
    overrun: Mapping[Resource, int]

    @property
    def tripped(self) -> bool:
        return any(v > 0 for v in self.overrun.values())


@dataclass(frozen=True)
class Usage:
    committed: Mapping[Resource, int]
    reserved: Mapping[Resource, int]


class BudgetLedger(Protocol):
    def open_account(
        self, key: AccountKey, parent: AccountKey | None = None, limits: Limits | None = None
    ) -> None: ...
    def ensure_account(
        self, key: AccountKey, parent: AccountKey | None = None, limits: Limits | None = None
    ) -> None: ...
    def set_limits(self, key: AccountKey, limits: Limits) -> None: ...
    def close_account(self, key: AccountKey) -> None: ...
    def reserve(self, key: AccountKey, amounts: Amounts) -> Reservation: ...
    def commit(self, reservation: Reservation, actual: Amounts | None = None) -> CommitResult: ...
    def release(self, reservation: Reservation) -> None: ...
    def charge(self, key: AccountKey, amounts: Amounts) -> CommitResult: ...
    def usage(self, key: AccountKey) -> Usage: ...
    def headroom(self, key: AccountKey, resource: Resource) -> int | None: ...


@dataclass
class _Account:
    key: AccountKey
    parent: _Account | None
    limits: dict[Resource, Limit] = field(default_factory=dict)
    committed: dict[Resource, int] = field(default_factory=dict)
    reserved: dict[Resource, int] = field(default_factory=dict)
    soft_warned: set[Resource] = field(default_factory=set)
    open_reservations: int = 0

    def used(self, r: Resource) -> int:
        return self.committed.get(r, 0) + self.reserved.get(r, 0)

    def hard(self, r: Resource) -> int | None:
        lim = self.limits.get(r)
        return None if lim is None else lim.hard

    def soft(self, r: Resource) -> int | None:
        lim = self.limits.get(r)
        return None if lim is None else lim.soft

    def chain(self) -> list[_Account]:
        out: list[_Account] = []
        cur: _Account | None = self
        while cur is not None:
            out.append(cur)
            cur = cur.parent
        return out


def _room(chain: list[_Account], r: Resource) -> int | None:
    """Smallest remaining hard-cap headroom along ``chain`` (None: no hard cap anywhere)."""
    best: int | None = None
    for acct in chain:
        hard = acct.hard(r)
        if hard is not None:
            room = max(0, hard - acct.used(r))
            best = room if best is None else min(best, room)
    return best


def _check_amounts(amounts: Amounts) -> dict[Resource, int]:
    out: dict[Resource, int] = {}
    for r, v in amounts.items():
        if not isinstance(r, Resource):
            raise InvalidAmountError(f"unknown resource {r!r}")
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise InvalidAmountError(f"{r.value} amount must be a non-negative int, got {v!r}")
        out[r] = v
    return out


class InMemoryLedger:
    def __init__(self, sink: EventSink) -> None:
        self._sink = sink
        self._accounts: dict[AccountKey, _Account] = {}
        self._open: dict[str, tuple[Reservation, _Account]] = {}
        self._ids = itertools.count(1)

    # ---- accounts --------------------------------------------------------------------------
    def _get(self, key: AccountKey) -> _Account:
        acct = self._accounts.get(key)
        if acct is None:
            raise UnknownAccountError(f"no account {key.label()} for tenant {key.tenant_id}")
        return acct

    def open_account(
        self, key: AccountKey, parent: AccountKey | None = None, limits: Limits | None = None
    ) -> None:
        if key in self._accounts:
            raise AccountConfigError(f"account {key.label()} already exists")
        parent_acct: _Account | None = None
        if key.kind is ScopeKind.TENANT:
            if parent is not None:
                raise AccountConfigError("a tenant account has no parent")
        else:
            if parent is None:
                raise AccountConfigError(f"{key.kind.name.lower()} account needs a parent")
            if parent.tenant_id != key.tenant_id:
                raise AccountConfigError("parent account belongs to another tenant")
            parent_acct = self._get(parent)
            if parent.kind > key.kind or (
                parent.kind == key.kind and key.kind != ScopeKind.PROCESS
            ):
                raise AccountConfigError("parent scope must be broader than the child scope")
        acct = _Account(key=key, parent=parent_acct)
        self._accounts[key] = acct
        if limits:
            try:
                self.set_limits(key, limits)
            except BudgetError:
                del self._accounts[key]
                raise

    def ensure_account(
        self, key: AccountKey, parent: AccountKey | None = None, limits: Limits | None = None
    ) -> None:
        existing = self._accounts.get(key)
        if existing is None:
            self.open_account(key, parent, limits)
            return
        existing_parent = None if existing.parent is None else existing.parent.key
        if existing_parent != parent:
            raise AccountConfigError(f"account {key.label()} exists under a different parent")

    def set_limits(self, key: AccountKey, limits: Limits) -> None:
        acct = self._get(key)
        for r, lim in limits.items():
            if not isinstance(r, Resource):
                raise AccountConfigError(f"unknown resource {r!r}")
            if lim.hard is not None and lim.hard < acct.used(r):
                raise AccountConfigError(
                    f"hard cap {lim.hard} on {r.value} is below current usage {acct.used(r)}"
                )
        acct.limits.update(limits)

    def close_account(self, key: AccountKey) -> None:
        acct = self._get(key)
        if acct.open_reservations:
            raise AccountConfigError(f"account {key.label()} has open reservations")
        if key.kind is ScopeKind.TENANT:
            raise AccountConfigError("tenant accounts are not closed")
        del self._accounts[key]

    # ---- reads -----------------------------------------------------------------------------
    def usage(self, key: AccountKey) -> Usage:
        acct = self._get(key)
        return Usage(dict(acct.committed), dict(acct.reserved))

    def headroom(self, key: AccountKey, resource: Resource) -> int | None:
        return _room(self._get(key).chain(), resource)

    # ---- events ----------------------------------------------------------------------------
    def _emit(self, kind: TkiEventType, key: AccountKey, **data: object) -> None:
        self._sink.emit(TkiEvent(kind, key.tenant_id, None, {"account": key.label(), **data}))

    # ---- spend -----------------------------------------------------------------------------
    def reserve(self, key: AccountKey, amounts: Amounts) -> Reservation:
        want = _check_amounts(amounts)
        leaf = self._get(key)
        chain = leaf.chain()
        for acct in chain:
            for r, v in want.items():
                hard = acct.hard(r)
                if hard is not None and acct.used(r) + v > hard:
                    avail = max(0, hard - acct.used(r))
                    self._emit(
                        TkiEventType.BUDGET_DENIED,
                        key,
                        capped_account=acct.key.label(),
                        resource=r.value,
                        requested=v,
                        available=avail,
                    )
                    raise BudgetExceededError(acct.key, r, v, avail)
        res = Reservation(f"rsv_{next(self._ids)}", key, dict(want))
        self._emit(
            TkiEventType.BUDGET_RESERVED,
            key,
            reservation=res.id,
            amounts={r.value: v for r, v in want.items()},
        )
        for acct in chain:
            for r, v in want.items():
                acct.reserved[r] = acct.reserved.get(r, 0) + v
        leaf.open_reservations += 1
        self._open[res.id] = (res, leaf)
        return res

    def _take(self, reservation: Reservation) -> _Account:
        entry = self._open.get(reservation.id)
        if entry is None or entry[0] != reservation:
            raise ReservationStateError(f"reservation {reservation.id} is not open")
        return entry[1]

    def commit(self, reservation: Reservation, actual: Amounts | None = None) -> CommitResult:
        leaf = self._take(reservation)
        held = reservation.amounts
        spend = _check_amounts(held if actual is None else actual)
        chain = leaf.chain()
        granted: dict[Resource, int] = {}
        overrun: dict[Resource, int] = {}
        for r in set(spend) | set(held):
            have = held.get(r, 0)
            want = spend.get(r, 0)
            room = _room(chain, r)
            # ``have`` is already counted in used(); only the excess needs headroom.
            cap = want if room is None else min(want, have + room)
            granted[r] = cap
            if cap < want:
                overrun[r] = want - cap
        events: list[tuple[TkiEventType, dict[str, object]]] = [
            (
                TkiEventType.BUDGET_COMMITTED,
                {
                    "reservation": reservation.id,
                    "granted": {r.value: v for r, v in granted.items()},
                },
            )
        ]
        for r, over in overrun.items():
            events.append(
                (
                    TkiEventType.BUDGET_HARD_CAP,
                    {"reservation": reservation.id, "resource": r.value, "overrun": over},
                )
            )
        crossed: list[tuple[_Account, Resource]] = []
        for acct in chain:
            for r, g in granted.items():
                soft = acct.soft(r)
                after = acct.committed.get(r, 0) + g
                if soft is not None and after >= soft and r not in acct.soft_warned:
                    crossed.append((acct, r))
                    events.append(
                        (
                            TkiEventType.BUDGET_SOFT_CAP,
                            {
                                "resource": r.value,
                                "soft": soft,
                                "committed": after,
                                "capped_account": acct.key.label(),
                            },
                        )
                    )
        for kind, data in events:
            self._emit(kind, reservation.key, **data)
        for acct in chain:
            for r in held:
                acct.reserved[r] = acct.reserved.get(r, 0) - held[r]
            for r, g in granted.items():
                acct.committed[r] = acct.committed.get(r, 0) + g
        for acct, r in crossed:
            acct.soft_warned.add(r)
        leaf.open_reservations -= 1
        del self._open[reservation.id]
        return CommitResult(granted, overrun)

    def release(self, reservation: Reservation) -> None:
        leaf = self._take(reservation)
        for acct in leaf.chain():
            for r, v in reservation.amounts.items():
                acct.reserved[r] = acct.reserved.get(r, 0) - v
        leaf.open_reservations -= 1
        del self._open[reservation.id]
        self._emit(TkiEventType.BUDGET_RELEASED, reservation.key, reservation=reservation.id)

    def charge(self, key: AccountKey, amounts: Amounts) -> CommitResult:
        """Record spend that already happened (e.g. elapsed time), clamped to the hard caps."""
        want = _check_amounts(amounts)
        clamp: dict[Resource, int] = {}
        for r, v in want.items():
            room = self.headroom(key, r)
            clamp[r] = v if room is None else min(v, room)
        res = self.reserve(key, clamp)
        return self.commit(res, want)
