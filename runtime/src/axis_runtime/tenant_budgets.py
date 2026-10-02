"""The control plane's budgets, as TKI ledger limits (Phase 6 wiring).

``TenantBudgets.from_json`` parses ``GET /internal/v1/budget-config`` (``{tenant: [...], run: [...],
agents: {...}}``, entries ``{metric, period, soft?, hard?}``) and produces:

  * ``tenant_limits()`` - limits for the TENANT account of the TKI ledger (``apply_to_ledger``):
  every spend of
    every run and agent of the tenant counts against them, and a hard cap is never exceeded (a
    commit past it
    is clamped and the process ends ``budget_exceeded``);
  * ``run_limits()``    - limits for each run's root process; ``spawn_limits(manifest_limits)``
  merges them with
    the agent's own ABL budgets (the TIGHTER hard/soft cap per resource wins: a tenant admin can
    lower, never
    raise, what the blueprint declares).

Honest scope (docs/NEEDS.md): the ledger is in-memory and has no time window, so a ``day``/``month``
tenant
budget is enforced over the life of the ledger (one runtime process), not per calendar day; several
periods
for one metric collapse to the tightest. An unknown metric or a malformed entry raises
``BudgetConfigError``:
a cap that cannot be understood must stop the run, not be dropped."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from axis_runtime.tki.budget import AccountKey, BudgetLedger, Limit, Limits, Resource, ScopeKind

_RESOURCE: Mapping[str, tuple[Resource, int]] = {
    "tokens": (Resource.TOKENS, 1),
    "cost_usd": (Resource.COST_MICRO_USD, 1_000_000),
    "tool_calls": (Resource.TOOL_CALLS, 1),
    "runtime_seconds": (Resource.RUNTIME_MS, 1000),
}


#: Largest limit the control plane accepts (and the runtime will read): finite and far below float
#: overflow once scaled (cost_usd is scaled by 1e6). ``json`` also parses NaN/Infinity, which
#: ``int()`` turns into a crash instead of a clear refusal.
MAX_LIMIT = 1e12


class BudgetConfigError(ValueError):
    """The control plane's budget document is not understood. Fail closed."""


@dataclass(frozen=True)
class BudgetEntry:
    metric: str
    period: str
    soft: float | None
    hard: float | None


def _entry(raw: Any) -> BudgetEntry:
    if not isinstance(raw, Mapping):
        raise BudgetConfigError("budget entry must be an object")
    metric = raw.get("metric")
    if metric not in _RESOURCE:
        raise BudgetConfigError(f"unknown budget metric {metric!r}")
    vals: dict[str, float | None] = {}
    for k in ("soft", "hard"):
        v = raw.get(k)
        if v is not None and (isinstance(v, bool) or not isinstance(v, int | float) or v < 0):
            raise BudgetConfigError(f"budget {k} must be a non-negative number")
        if v is not None and (not math.isfinite(v) or v > MAX_LIMIT):
            raise BudgetConfigError(f"budget {k} must be a finite number <= {MAX_LIMIT:g}")
        vals[k] = v
    return BudgetEntry(str(metric), str(raw.get("period", "")), vals["soft"], vals["hard"])


def _limits(entries: tuple[BudgetEntry, ...]) -> Limits:
    softs: dict[Resource, list[int]] = {}
    hards: dict[Resource, list[int]] = {}
    for e in entries:
        res, scale = _RESOURCE[e.metric]
        if e.soft is not None:
            softs.setdefault(res, []).append(int(e.soft * scale))
        if e.hard is not None:
            hards.setdefault(res, []).append(int(e.hard * scale))
    out: dict[Resource, Limit] = {}
    for res in softs.keys() | hards.keys():
        hard = min(hards[res]) if res in hards else None
        soft = min(softs[res]) if res in softs else None
        if soft is not None and hard is not None:
            soft = min(soft, hard)
        out[res] = Limit(soft, hard)
    return out


def tighter(a: Limits, b: Limits) -> Limits:
    """Per resource, the lower hard cap and the lower soft cap (an absent cap never loosens a
    present one)."""
    out: dict[Resource, Limit] = {}
    for res in a.keys() | b.keys():
        softs: list[int] = []
        hards: list[int] = []
        for lim in (a.get(res), b.get(res)):
            if lim is not None and lim.soft is not None:
                softs.append(lim.soft)
            if lim is not None and lim.hard is not None:
                hards.append(lim.hard)
        hard = min(hards) if hards else None
        soft = min(softs) if softs else None
        if soft is not None and hard is not None:
            soft = min(soft, hard)
        out[res] = Limit(soft, hard)
    return out


@dataclass(frozen=True)
class TenantBudgets:
    tenant: tuple[BudgetEntry, ...] = ()
    run: tuple[BudgetEntry, ...] = ()

    @classmethod
    def from_json(cls, doc: Mapping[str, Any]) -> TenantBudgets:
        tenant, run = doc.get("tenant", []), doc.get("run", [])
        if not isinstance(tenant, list) or not isinstance(run, list):
            raise BudgetConfigError("tenant and run must be lists")
        return cls(tuple(_entry(e) for e in tenant), tuple(_entry(e) for e in run))

    def tenant_limits(self) -> Limits:
        return _limits(self.tenant)

    def run_limits(self) -> Limits:
        return _limits(self.run)

    def spawn_limits(self, manifest_limits: Limits) -> Limits:
        return tighter(manifest_limits, self.run_limits())

    def apply_to_ledger(self, ledger: BudgetLedger, tenant_id: str) -> None:
        """Open (or tighten) the tenant account of ``ledger`` with the control plane's tenant
        limits.
        Call before the first spawn: the scheduler's own ``ensure_account`` then finds it."""
        key = AccountKey(tenant_id, ScopeKind.TENANT, tenant_id)
        ledger.ensure_account(key, None, self.tenant_limits())
        ledger.set_limits(
            key, self.tenant_limits()
        )  # the control plane's current config is authoritative
