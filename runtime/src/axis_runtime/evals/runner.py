"""The case runner: one dataset case = one isolated run through the REAL run path.

``start_agent`` with the tenant's kernel gate, wrapped by ``EvalModeGate`` (side effects denied,
fixtures instead of real tools; see ``isolation``). Per case: a fresh run id, trace id and event
log, a timeout and budget caps, a deterministic seed, and no state shared with any other case
unless the case declares a session. Concurrency is bounded; results come back in dataset order.

Retries exist for INFRASTRUCTURE failures only (gate unreachable, provider outage). A low score,
a policy DENY, a budget stop or a timeout is a result, never a reason to run the case again: a
retry that can change the outcome of a graded run is a way to buy a score. ``attempts`` is
recorded so the hub can see when infrastructure was flaky.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import re
import time
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from axis_runtime.actions import Backends
from axis_runtime.evals.isolation import (
    EvalModeGate,
    EvalModePolicy,
    IdSource,
    RandomIds,
    build_tool_registry,
    lockdown_deps,
)
from axis_runtime.evals.trace import trace_from_state
from axis_runtime.evals.types import CaseTrace, EvalCase
from axis_runtime.manifest import Budget, Budgets, ModelSpec, RuntimeManifest
from axis_runtime.process import ExitReason, Signal
from axis_runtime.run import RunDeps, RunHandle, RunResult, start_agent

#: run outcomes that mean "the platform failed", not "the agent failed". Retried a bounded number
#: of times; if they persist the case is an ``error`` (scored 0, flagged), never a pass.
_INFRA_DETAIL = re.compile(
    r"gate_(?:timeout|error|rpc_error|malformed_response|unspecified_decision)"
    r"|ModelError: [\w.-]+: (?:server|network|timeout|rate_limit|circuit_open|unknown)\b"
)

_STATUS = {
    ExitReason.COMPLETED: "completed",
    ExitReason.FAILED: "failed",
    ExitReason.KILLED: "killed",
    ExitReason.BUDGET_EXCEEDED: "budget_exceeded",
    ExitReason.POLICY_DENIED: "policy_denied",
    ExitReason.TIMEOUT: "timeout",
    ExitReason.PARENT_TERMINATED: "killed",
}


@dataclass(frozen=True)
class RunnerConfig:
    concurrency: int = 4
    case_timeout_seconds: float = 120.0
    max_infra_retries: int = 1
    max_tokens: int | None = None
    max_cost_usd: float | None = None
    max_tool_calls: int | None = None
    max_steps: int = 16

    def __post_init__(self) -> None:
        if self.concurrency < 1 or self.case_timeout_seconds <= 0 or self.max_infra_retries < 0:
            raise ValueError("invalid runner configuration")


@dataclass(frozen=True)
class CaseOutcome:
    """``status``: completed | failed | killed | budget_exceeded | policy_denied | timeout |
    approval_required | error. Only ``error`` (infrastructure never recovered) has no trace and is
    not graded."""

    case: EvalCase
    status: str
    attempts: int
    seed: int
    trace: CaseTrace | None = None
    error: str | None = None


def case_seed(run_seed: int, case_id: str) -> int:
    """Deterministic per-case seed: the same (run seed, case id) always yields the same value."""
    digest = hashlib.sha256(f"{run_seed}:{case_id}".encode()).digest()
    return int.from_bytes(digest[:4], "big") & 0x7FFFFFFF


def _cap(current: Budget, cap: float | None) -> Budget:
    if cap is None:
        return current
    hard = cap if current.hard is None else min(current.hard, cap)
    soft = current.soft if current.soft is None or current.soft <= hard else hard
    return Budget(soft, hard)


def prepare_manifest(
    manifest: RuntimeManifest, config: RunnerConfig, case: EvalCase, seed: int
) -> RuntimeManifest:
    """The manifest this case runs: the blueprint's own, tightened (never loosened) by the
    runner/case caps, with the case seed in every model's params."""
    meta = case.metadata
    case_budget = meta.get("budget") if isinstance(meta.get("budget"), Mapping) else {}
    assert isinstance(case_budget, Mapping)  # noqa: S101 - narrowed above

    def cap(runner_value: float | None, key: str) -> float | None:
        values = [v for v in (runner_value, case_budget.get(key)) if isinstance(v, int | float)]
        return min(values) if values else None

    b = manifest.budgets
    timeout = min(
        [config.case_timeout_seconds]
        + [v for v in (meta.get("timeout_seconds"),) if isinstance(v, int | float) and v > 0]
        + ([manifest.process.timeout_seconds] if manifest.process.timeout_seconds else [])
    )

    def seeded(m: ModelSpec) -> ModelSpec:
        return dataclasses.replace(m, params={**m.params, "seed": seed})

    return dataclasses.replace(
        manifest,
        primary=seeded(manifest.primary),
        fallbacks=tuple(seeded(f) for f in manifest.fallbacks),
        budgets=Budgets(
            tokens=_cap(b.tokens, cap(config.max_tokens, "max_tokens")),
            cost_usd=_cap(b.cost_usd, cap(config.max_cost_usd, "max_cost_usd")),
            runtime_seconds=_cap(b.runtime_seconds, timeout),
            tool_calls=_cap(b.tool_calls, cap(config.max_tool_calls, "max_tool_calls")),
        ),
        process=dataclasses.replace(manifest.process, timeout_seconds=timeout),
    )


def is_infra_failure(result: RunResult) -> bool:
    """True when the run ended because the platform (not the agent or the policy) failed."""
    if result.exit_reason not in (ExitReason.FAILED, ExitReason.POLICY_DENIED):
        return False
    info = result.state.processes.get(result.pid)
    detail = info.exit_detail if info is not None and info.exit_detail else ""
    return _INFRA_DETAIL.search(detail) is not None


class CaseRunner:
    def __init__(
        self,
        base_deps: Callable[[], RunDeps],
        *,
        tenant_id: str,
        policy: EvalModePolicy | None = None,
        config: RunnerConfig | None = None,
        ids: IdSource | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        backends: Backends | None = None,
    ) -> None:
        self._base_deps = base_deps
        self._tenant_id = tenant_id
        self._policy = policy or EvalModePolicy()
        self.config = config or RunnerConfig()
        self._ids = ids or RandomIds()
        self._monotonic = monotonic
        self._backends = backends if self._policy.allow_sandboxed else None

    async def _attempt(
        self,
        manifest: RuntimeManifest,
        case: EvalCase,
        seed: int,
        eval_run_id: str,
        session: str | None,
    ) -> tuple[RunResult, RunDeps, str, int]:
        base = self._base_deps()
        run_id, trace_id = self._ids.run_id(), self._ids.trace_id()
        registry, _ = build_tool_registry(manifest, case)
        deps = lockdown_deps(
            base,
            tenant_id=self._tenant_id,
            run_id=run_id,
            trace_id=trace_id,
            tools=registry,
            gate=EvalModeGate(base.gate, self._policy),
            session_id=None if session is None else f"eval-{eval_run_id}-{session}",
            backends=self._backends,
        )
        deps.max_steps = min(deps.max_steps, self.config.max_steps)
        prepared = prepare_manifest(manifest, self.config, case, seed)
        timeout = prepared.process.timeout_seconds or self.config.case_timeout_seconds
        started = self._monotonic()
        handle: RunHandle = await start_agent(prepared, case.input_text, deps)
        try:
            async with asyncio.timeout(timeout + 1.0):  # backstop: the process has its own timeout
                result = await handle.result()
        except TimeoutError:
            await handle.signal(Signal.KILL)
            async with asyncio.timeout(5.0):
                result = await handle.result()
        latency_ms = int((self._monotonic() - started) * 1000)
        return result, deps, trace_id, latency_ms

    async def run_case(
        self,
        manifest: RuntimeManifest,
        case: EvalCase,
        *,
        run_seed: int,
        eval_run_id: str,
        session: str | None = None,
    ) -> CaseOutcome:
        seed = case_seed(run_seed, case.id)
        attempts = 0
        last_error = "infrastructure_failure"
        while attempts <= self.config.max_infra_retries:
            attempts += 1
            try:
                result, deps, trace_id, latency_ms = await self._attempt(
                    manifest, case, seed, eval_run_id, session
                )
            except asyncio.CancelledError:
                raise
            except (OSError, TimeoutError) as exc:  # infra: retry
                last_error = f"{type(exc).__name__}"
                continue
            except Exception as exc:  # noqa: BLE001 - a broken case must not take the run down
                return CaseOutcome(case, "error", attempts, seed, None, f"{type(exc).__name__}")
            if is_infra_failure(result):
                info = result.state.processes.get(result.pid)
                last_error = (info.exit_detail or "infra")[:200] if info else "infra"
                continue
            events = await deps.log.read(result.run_id)
            trace = trace_from_state(
                result.state, trace_id=trace_id, latency_ms=latency_ms, events=events
            )
            status = (
                "approval_required" if result.exit_reason is None else _STATUS[result.exit_reason]
            )
            return CaseOutcome(case, status, attempts, seed, trace)
        return CaseOutcome(case, "error", attempts, seed, None, last_error)

    async def run_all(
        self,
        manifest: RuntimeManifest,
        cases: Sequence[EvalCase],
        *,
        run_seed: int,
        eval_run_id: str,
    ) -> list[CaseOutcome]:
        """All cases, results in dataset order. Cases that declare the same ``metadata.session``
        run one after another (in dataset order); everything else is independent."""
        sem = asyncio.Semaphore(self.config.concurrency)
        results: dict[str, CaseOutcome] = {}
        groups: dict[str | None, list[EvalCase]] = defaultdict(list)
        independent: list[EvalCase] = []
        for c in cases:
            key = c.metadata.get("session")
            if isinstance(key, str) and key:
                groups[key].append(c)
            else:
                independent.append(c)

        async def one(c: EvalCase, session: str | None) -> None:
            async with sem:
                results[c.id] = await self.run_case(
                    manifest, c, run_seed=run_seed, eval_run_id=eval_run_id, session=session
                )

        async def chain(session: str, members: list[EvalCase]) -> None:
            for c in members:
                await one(c, session)

        await asyncio.gather(
            *[one(c, None) for c in independent],
            *[chain(str(s), m) for s, m in groups.items()],
        )
        return [results[c.id] for c in cases]
