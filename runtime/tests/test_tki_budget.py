"""TKI budget ledger: caps, atomicity, hierarchy, conservation (seeded property tests)."""

from __future__ import annotations

import asyncio
import random

import pytest
from axis_runtime.tki.budget import (
    AccountConfigError,
    AccountKey,
    BudgetExceededError,
    InMemoryLedger,
    InvalidAmountError,
    Limit,
    ReservationStateError,
    Resource,
    ScopeKind,
    UnknownAccountError,
)
from axis_runtime.tki.events import ListSink, TkiEvent, TkiEventType

T1 = "11111111-1111-4111-8111-111111111111"
T2 = "22222222-2222-4222-8222-222222222222"
TOK = Resource.TOKENS


def k(kind: ScopeKind, ident: str, tenant: str = T1) -> AccountKey:
    return AccountKey(tenant, kind, ident)


def tree(
    sink: ListSink | None = None,
    *,
    tenant: Limit | None = None,
    run: Limit | None = None,
    proc: Limit | None = None,
) -> tuple[InMemoryLedger, ListSink, AccountKey, AccountKey, AccountKey, AccountKey]:
    sink = sink or ListSink()
    led = InMemoryLedger(sink)
    t, a, r, p = (
        k(ScopeKind.TENANT, "t"),
        k(ScopeKind.AGENT, "a"),
        k(ScopeKind.RUN, "r"),
        k(ScopeKind.PROCESS, "p"),
    )
    led.open_account(t, None, {TOK: tenant} if tenant else None)
    led.open_account(a, t)
    led.open_account(r, a, {TOK: run} if run else None)
    led.open_account(p, r, {TOK: proc} if proc else None)
    return led, sink, t, a, r, p


# ---- basics --------------------------------------------------------------------------------------


def test_reserve_commit_moves_reserved_to_committed_up_the_chain() -> None:
    led, _, t, a, r, p = tree()
    res = led.reserve(p, {TOK: 100})
    for key in (t, a, r, p):
        assert led.usage(key).reserved[TOK] == 100 and led.usage(key).committed.get(TOK, 0) == 0
    out = led.commit(res, {TOK: 60})
    assert out.granted[TOK] == 60 and not out.tripped
    for key in (t, a, r, p):
        assert led.usage(key).reserved[TOK] == 0 and led.usage(key).committed[TOK] == 60


def test_commit_defaults_to_reserved_amount() -> None:
    led, *_, p = tree()
    led.commit(led.reserve(p, {TOK: 7}))
    assert led.usage(p).committed[TOK] == 7


def test_release_returns_everything() -> None:
    led, sink, t, *_, p = tree(tenant=Limit(hard=10))
    res = led.reserve(p, {TOK: 10})
    with pytest.raises(BudgetExceededError):
        led.reserve(p, {TOK: 1})
    led.release(res)
    assert led.usage(t).reserved[TOK] == 0 and led.headroom(p, TOK) == 10
    assert sink.of(TkiEventType.BUDGET_RELEASED)
    led.reserve(p, {TOK: 10})  # the whole budget is usable again


def test_hard_cap_denies_and_emits_denied_event() -> None:
    led, sink, *_, p = tree(proc=Limit(hard=50))
    led.reserve(p, {TOK: 50})
    with pytest.raises(BudgetExceededError) as ei:
        led.reserve(p, {TOK: 1})
    assert ei.value.resource is TOK and ei.value.available == 0 and ei.value.requested == 1
    denied = sink.of(TkiEventType.BUDGET_DENIED)
    assert len(denied) == 1 and denied[0].data["capped_account"] == "process:p"


def test_exactly_the_cap_is_allowed() -> None:
    led, *_, p = tree(proc=Limit(hard=5))
    assert led.commit(led.reserve(p, {TOK: 5})).granted[TOK] == 5
    assert led.headroom(p, TOK) == 0


def test_hard_cap_at_ancestor_blocks_child_and_names_the_capped_account() -> None:
    led, sink, *_, p = tree(tenant=Limit(hard=10))
    with pytest.raises(BudgetExceededError) as ei:
        led.reserve(p, {TOK: 11})
    assert ei.value.account.kind is ScopeKind.TENANT
    assert sink.of(TkiEventType.BUDGET_DENIED)[0].data["capped_account"] == "tenant:t"


def test_denied_reserve_changes_nothing_atomic_across_resources_and_chain() -> None:
    led, _, t, a, r, p = tree(tenant=Limit(hard=100))
    led.set_limits(p, {Resource.TOOL_CALLS: Limit(hard=0)})
    with pytest.raises(BudgetExceededError):
        led.reserve(p, {TOK: 10, Resource.TOOL_CALLS: 1})
    for key in (t, a, r, p):
        assert led.usage(key).reserved.get(TOK, 0) == 0


def test_headroom_is_min_over_chain_and_none_without_caps() -> None:
    led, _, *_, p = tree(tenant=Limit(hard=100), run=Limit(hard=40), proc=Limit(hard=90))
    assert led.headroom(p, TOK) == 40
    led.reserve(p, {TOK: 15})
    assert led.headroom(p, TOK) == 25
    assert led.headroom(p, Resource.COST_MICRO_USD) is None


def test_soft_cap_warns_once_when_committed_reaches_it() -> None:
    led, sink, *_, p = tree(proc=Limit(soft=10, hard=100))
    led.commit(led.reserve(p, {TOK: 9}))
    assert not sink.of(TkiEventType.BUDGET_SOFT_CAP)
    led.commit(led.reserve(p, {TOK: 1}))
    led.commit(led.reserve(p, {TOK: 5}))
    soft = sink.of(TkiEventType.BUDGET_SOFT_CAP)
    assert len(soft) == 1 and soft[0].data["soft"] == 10 and soft[0].data["committed"] == 10


def test_soft_cap_at_ancestor_fires_for_child_spend() -> None:
    led, sink, *_, p = tree(run=Limit(soft=5))
    led.commit(led.reserve(p, {TOK: 6}))
    assert sink.of(TkiEventType.BUDGET_SOFT_CAP)[0].data["capped_account"] == "run:r"


def test_commit_over_reservation_is_clamped_to_hard_cap_and_reported() -> None:
    led, sink, t, *_, p = tree(proc=Limit(hard=100))
    res = led.reserve(p, {TOK: 40})
    out = led.commit(res, {TOK: 250})
    assert out.tripped and out.granted[TOK] == 100 and out.overrun[TOK] == 150
    assert led.usage(p).committed[TOK] == 100 and led.usage(t).committed[TOK] == 100
    hard = sink.of(TkiEventType.BUDGET_HARD_CAP)
    assert hard and hard[0].data["overrun"] == 150


def test_commit_over_reservation_within_headroom_is_granted_in_full() -> None:
    led, *_, p = tree(proc=Limit(hard=100))
    out = led.commit(led.reserve(p, {TOK: 40}), {TOK: 70})
    assert out.granted[TOK] == 70 and not out.tripped


def test_commit_clamp_is_bound_by_the_tightest_ancestor() -> None:
    led, *_, p = tree(tenant=Limit(hard=50), proc=Limit(hard=1000))
    out = led.commit(led.reserve(p, {TOK: 10}), {TOK: 500})
    assert out.granted[TOK] == 50 and out.overrun[TOK] == 450


def test_commit_of_unreserved_resource_is_charged_within_headroom() -> None:
    led, *_, p = tree()
    led.set_limits(p, {Resource.TOOL_CALLS: Limit(hard=2)})
    res = led.reserve(p, {TOK: 1})
    out = led.commit(res, {TOK: 1, Resource.TOOL_CALLS: 5})
    assert out.granted[Resource.TOOL_CALLS] == 2 and out.overrun[Resource.TOOL_CALLS] == 3


def test_charge_clamps_and_reports_overrun() -> None:
    led, *_, p = tree(proc=Limit(hard=30))
    assert led.charge(p, {TOK: 10}).granted[TOK] == 10
    out = led.charge(p, {TOK: 100})
    assert out.tripped and out.granted[TOK] == 20
    assert led.usage(p).committed[TOK] == 30


def test_reservation_settles_exactly_once() -> None:
    led, *_, p = tree()
    res = led.reserve(p, {TOK: 1})
    led.commit(res)
    with pytest.raises(ReservationStateError):
        led.commit(res)
    with pytest.raises(ReservationStateError):
        led.release(res)
    res2 = led.reserve(p, {TOK: 1})
    led.release(res2)
    with pytest.raises(ReservationStateError):
        led.commit(res2)


def test_forged_reservation_is_rejected() -> None:
    led, _, _, _, _, p = tree()
    real = led.reserve(p, {TOK: 1})
    forged = type(real)(real.id, real.key, {TOK: 0})
    with pytest.raises(ReservationStateError):
        led.commit(forged)
    with pytest.raises(ReservationStateError):
        led.release(forged)


@pytest.mark.parametrize("bad", [-1, True, 1.5, "3"])
def test_invalid_amounts_are_rejected(bad: object) -> None:
    led, *_, p = tree()
    with pytest.raises(InvalidAmountError):
        led.reserve(p, {TOK: bad})  # type: ignore[dict-item]
    with pytest.raises(InvalidAmountError):
        led.commit(led.reserve(p, {TOK: 1}), {TOK: bad})  # type: ignore[dict-item]


def test_unknown_resource_rejected() -> None:
    led, *_, p = tree()
    with pytest.raises(InvalidAmountError):
        led.reserve(p, {"gpu_hours": 1})  # type: ignore[dict-item]


def test_zero_amount_reserve_is_fine_even_at_cap() -> None:
    led, *_, p = tree(proc=Limit(hard=0))
    led.commit(led.reserve(p, {TOK: 0}))


# ---- accounts ------------------------------------------------------------------------------------


def test_limit_validation() -> None:
    with pytest.raises(ValueError):
        Limit(soft=5, hard=1)
    with pytest.raises(ValueError):
        Limit(hard=-1)
    with pytest.raises(ValueError):
        Limit(soft=True)  # type: ignore[arg-type]


def test_unknown_account_is_an_error_not_a_free_pass() -> None:
    led = InMemoryLedger(ListSink())
    with pytest.raises(UnknownAccountError):
        led.reserve(k(ScopeKind.PROCESS, "ghost"), {TOK: 1})
    with pytest.raises(UnknownAccountError):
        led.usage(k(ScopeKind.PROCESS, "ghost"))


def test_account_tree_shape_is_validated() -> None:
    led = InMemoryLedger(ListSink())
    t = k(ScopeKind.TENANT, "t")
    led.open_account(t)
    with pytest.raises(AccountConfigError):
        led.open_account(t)  # duplicate
    with pytest.raises(AccountConfigError):
        led.open_account(k(ScopeKind.TENANT, "t2"), t)  # tenant with parent
    with pytest.raises(AccountConfigError):
        led.open_account(k(ScopeKind.RUN, "r"))  # no parent
    with pytest.raises(AccountConfigError):  # cross-tenant parent
        led.open_account(k(ScopeKind.AGENT, "a", T2), t)
    led.open_account(k(ScopeKind.AGENT, "a"), t)
    with pytest.raises(AccountConfigError):  # parent narrower than child
        led.open_account(k(ScopeKind.TENANT, "t3", T1), k(ScopeKind.AGENT, "a"))
    with pytest.raises(AccountConfigError):  # same non-process kind
        led.open_account(k(ScopeKind.AGENT, "a2"), k(ScopeKind.AGENT, "a"))
    with pytest.raises(UnknownAccountError):
        led.open_account(k(ScopeKind.RUN, "r"), k(ScopeKind.AGENT, "nope"))
    led.open_account(k(ScopeKind.RUN, "r"), k(ScopeKind.AGENT, "a"))
    led.open_account(k(ScopeKind.PROCESS, "p1"), k(ScopeKind.RUN, "r"))
    led.open_account(k(ScopeKind.PROCESS, "p2"), k(ScopeKind.PROCESS, "p1"))  # child process


def test_bad_limits_at_open_do_not_leave_a_half_account() -> None:
    led = InMemoryLedger(ListSink())
    t = k(ScopeKind.TENANT, "t")
    led.open_account(t)
    led.reserve(t, {TOK: 5})
    led.set_limits(t, {TOK: Limit(hard=5)})
    with pytest.raises(AccountConfigError):
        led.set_limits(t, {TOK: Limit(hard=4)})  # below current usage
    with pytest.raises(AccountConfigError):
        led.set_limits(t, {"x": Limit()})  # type: ignore[dict-item]
    a = k(ScopeKind.AGENT, "a")
    with pytest.raises(AccountConfigError):
        led.open_account(a, t, {"x": Limit()})  # type: ignore[dict-item]
    with pytest.raises(UnknownAccountError):
        led.usage(a)


def test_ensure_account_is_idempotent_and_checks_parent() -> None:
    led = InMemoryLedger(ListSink())
    t = k(ScopeKind.TENANT, "t")
    a = k(ScopeKind.AGENT, "a")
    led.ensure_account(t)
    led.ensure_account(t)
    led.ensure_account(a, t)
    led.ensure_account(a, t)
    t2 = k(ScopeKind.TENANT, "t2")
    led.ensure_account(t2)
    with pytest.raises(AccountConfigError):
        led.ensure_account(a, t2)


def test_close_account_requires_settled_reservations_and_keeps_totals() -> None:
    led, _, t, a, r, p = tree()
    res = led.reserve(p, {TOK: 3})
    with pytest.raises(AccountConfigError):
        led.close_account(p)
    led.commit(res)
    led.close_account(p)
    assert led.usage(r).committed[TOK] == 3 and led.usage(t).committed[TOK] == 3
    with pytest.raises(UnknownAccountError):
        led.usage(p)
    with pytest.raises(AccountConfigError):
        led.close_account(t)


def test_tenant_keys_are_isolated() -> None:
    led = InMemoryLedger(ListSink())
    for tenant in (T1, T2):
        led.open_account(AccountKey(tenant, ScopeKind.TENANT, "t"), None, {TOK: Limit(hard=10)})
    led.reserve(AccountKey(T1, ScopeKind.TENANT, "t"), {TOK: 10})
    led.reserve(AccountKey(T2, ScopeKind.TENANT, "t"), {TOK: 10})  # T1 spending never uses T2 room


# ---- audit ordering ------------------------------------------------------------------------------


class FailingSink:
    def __init__(self, fail_on: set[TkiEventType]) -> None:
        self.fail_on = fail_on
        self.events: list[TkiEvent] = []

    def emit(self, event: TkiEvent) -> None:
        if event.type in self.fail_on:
            raise RuntimeError("audit store down")
        self.events.append(event)


def test_audit_failure_blocks_reserve_and_leaves_ledger_untouched() -> None:
    sink = FailingSink({TkiEventType.BUDGET_RESERVED})
    led, *_ = tree(sink=sink)  # type: ignore[arg-type]
    p = k(ScopeKind.PROCESS, "p")
    with pytest.raises(RuntimeError):
        led.reserve(p, {TOK: 5})
    assert led.usage(p).reserved.get(TOK, 0) == 0


def test_audit_failure_blocks_commit_and_keeps_funds_reserved() -> None:
    sink = FailingSink(set())
    led, *_ = tree(sink=sink, proc=Limit(hard=10))  # type: ignore[arg-type]
    p = k(ScopeKind.PROCESS, "p")
    res = led.reserve(p, {TOK: 4})
    sink.fail_on = {TkiEventType.BUDGET_COMMITTED}
    with pytest.raises(RuntimeError):
        led.commit(res)
    u = led.usage(p)
    assert u.reserved[TOK] == 4 and u.committed.get(TOK, 0) == 0
    sink.fail_on = set()
    led.commit(res)  # still open, can be settled once audit is back


def test_release_is_applied_even_if_audit_fails() -> None:
    sink = FailingSink(set())
    led, *_ = tree(sink=sink)  # type: ignore[arg-type]
    p = k(ScopeKind.PROCESS, "p")
    res = led.reserve(p, {TOK: 4})
    sink.fail_on = {TkiEventType.BUDGET_RELEASED}
    with pytest.raises(RuntimeError):
        led.release(res)
    assert led.usage(p).reserved[TOK] == 0  # cleanup can never leak budget


# ---- property tests (seeded) ---------------------------------------------------------------------


def _assert_invariants(
    led: InMemoryLedger, keys: list[AccountKey], caps: dict[AccountKey, int]
) -> None:
    for key in keys:
        u = led.usage(key)
        c, rsv = u.committed.get(TOK, 0), u.reserved.get(TOK, 0)
        assert c >= 0 and rsv >= 0
        if key in caps:
            assert c <= caps[key] and c + rsv <= caps[key]


@pytest.mark.parametrize("seed", range(40))
def test_property_random_ops_never_break_caps_and_conserve_totals(seed: int) -> None:
    rng = random.Random(seed)
    sink = ListSink()
    led = InMemoryLedger(sink)
    t, a, r = k(ScopeKind.TENANT, "t"), k(ScopeKind.AGENT, "a"), k(ScopeKind.RUN, "r")
    caps = {t: rng.randint(20, 300), r: rng.randint(10, 200)}
    led.open_account(t, None, {TOK: Limit(hard=caps[t])})
    led.open_account(a, t)
    led.open_account(r, a, {TOK: Limit(soft=caps[r] // 2, hard=caps[r])})
    procs = [k(ScopeKind.PROCESS, f"p{i}") for i in range(4)]
    led.open_account(procs[0], r, {TOK: Limit(hard=rng.randint(5, 120))})
    caps[procs[0]] = led._accounts[procs[0]].limits[TOK].hard  # type: ignore[assignment]  # noqa: SLF001
    led.open_account(procs[1], procs[0])
    led.open_account(procs[2], r)
    led.open_account(procs[3], r)
    keys = [t, a, r, *procs]
    open_res = []
    spent: dict[AccountKey, int] = dict.fromkeys(procs, 0)
    for _ in range(300):
        op = rng.choice(["reserve", "reserve", "commit", "release", "charge"])
        p = rng.choice(procs)
        if op == "reserve":
            try:
                open_res.append(led.reserve(p, {TOK: rng.randint(0, 60)}))
            except BudgetExceededError:
                pass
        elif op == "charge":
            out = led.charge(p, {TOK: rng.randint(0, 60)})
            spent[p] += out.granted[TOK]
        elif open_res:
            res = open_res.pop(rng.randrange(len(open_res)))
            if op == "commit":
                out = led.commit(res, {TOK: rng.randint(0, 100)})
                assert out.granted[TOK] + out.overrun.get(TOK, 0) >= 0
                spent[res.key] += out.granted[TOK]
            else:
                led.release(res)
        _assert_invariants(led, keys, caps)
    # conservation: every account's committed == own spend + all descendants' spend
    committed = {key: led.usage(key).committed.get(TOK, 0) for key in keys}
    assert committed[procs[1]] == spent[procs[1]]
    assert committed[procs[0]] == spent[procs[0]] + spent[procs[1]]
    assert committed[procs[2]] == spent[procs[2]] and committed[procs[3]] == spent[procs[3]]
    total = sum(spent.values())
    assert committed[r] == committed[a] == committed[t] == total
    for res in open_res:
        led.release(res)
    for key in keys:
        assert led.usage(key).reserved.get(TOK, 0) == 0


async def test_property_concurrent_reservations_never_oversubscribe() -> None:
    rng = random.Random(1234)
    led = InMemoryLedger(ListSink())
    t, a, r = k(ScopeKind.TENANT, "t"), k(ScopeKind.AGENT, "a"), k(ScopeKind.RUN, "r")
    led.open_account(t, None, {TOK: Limit(hard=1000)})
    led.open_account(a, t)
    led.open_account(r, a)
    procs = [k(ScopeKind.PROCESS, f"p{i}") for i in range(20)]
    for p in procs:
        led.open_account(p, r)
    granted_total = 0

    async def worker(p: AccountKey, seed: int) -> None:
        nonlocal granted_total
        local = random.Random(seed)
        for _ in range(30):
            try:
                res = led.reserve(p, {TOK: local.randint(1, 40)})
            except BudgetExceededError:
                await asyncio.sleep(0)
                continue
            await asyncio.sleep(local.random() * 0.001)  # reservations overlap in time
            assert led.usage(t).committed.get(TOK, 0) + led.usage(t).reserved[TOK] <= 1000
            if local.random() < 0.5:
                out = led.commit(res, {TOK: local.randint(0, 60)})
                granted_total += out.granted[TOK]
            else:
                led.release(res)

    await asyncio.gather(*(worker(p, rng.randrange(10**6)) for p in procs))
    u = led.usage(t)
    assert u.reserved[TOK] == 0
    assert u.committed[TOK] == granted_total <= 1000
    assert led.usage(r).committed[TOK] == u.committed[TOK]
