"""Run a real AXIS agent (``start_agent``) as a TKI workload, with the budget ledger in its path.

Nothing here performs an action.  ``BudgetedRunner`` WRAPS the one ``ActionExecutor`` the run would
have used anyway (same gate, same recorder, same backends): it adds a reserve-before-spend step in
front of it and a commit/release after it.  It can only make an action less likely to run (a hard
cap refuses it), never route around the Risk Kernel.  Agent-initiated IPC is not exposed here (see
docs/NEEDS.md): when it is, it must be an ``Action`` through the same executor.
"""

from __future__ import annotations

import asyncio
import dataclasses
import itertools
import json
from collections.abc import Callable, Mapping
from typing import Any

from axis_runtime.actions import Action, Backends, ModelCall, to_jsonable
from axis_runtime.executor import ActionExecutor, ActionOutcome, ActionRunner, Completed, Failed
from axis_runtime.manifest import RuntimeManifest
from axis_runtime.models.types import ModelResponse
from axis_runtime.process import ExitReason, Signal
from axis_runtime.run import (
    ChildError,
    ChildSpawner,
    RunContext,
    RunDeps,
    RunResult,
    start_agent,
)
from axis_runtime.tki.budget import Amounts, Limits, Resource
from axis_runtime.tki.scheduler import (
    ProcessCancelled,
    ProcessContext,
    Scheduler,
    Workload,
    WorkloadResult,
)
from axis_runtime.tki.supervisor import ChildSpec, Supervisor, SupervisorConfig

DEFAULT_MAX_OUTPUT_TOKENS = 4096
CostEstimator = Callable[[Action], int]


def estimate_model_tokens(action: ModelCall) -> int:
    """Upper-ish bound reserved BEFORE the call: prompt size (~4 chars/token) + max output."""
    req = action.request
    prompt = sum(len(m.content) for m in req.messages) // 4 + 1
    out = req.merged_params(req.target).get("max_tokens", DEFAULT_MAX_OUTPUT_TOKENS)
    return prompt + (int(out) if isinstance(out, int) and out > 0 else DEFAULT_MAX_OUTPUT_TOKENS)


class BudgetedRunner:
    def __init__(
        self,
        inner: ActionRunner,
        ctx: ProcessContext,
        *,
        cost_estimator: CostEstimator | None = None,
    ) -> None:
        self._inner = inner
        self._ctx = ctx
        self._cost = cost_estimator

    async def run(self, action: Action, *, pid: str) -> ActionOutcome:
        if isinstance(action, ModelCall) and action.replay is not None:
            # A cached answer replayed through the gate has no provider: nothing to reserve.
            # (Charging the prompt estimate could trip a cap a cache hit can never spend.)
            return await self._inner.run(action, pid=pid)
        want: dict[Resource, int] = {}
        if isinstance(action, ModelCall):  # run.py counts tool_calls for tools, not model calls
            want[Resource.TOKENS] = estimate_model_tokens(action)
        else:
            want[Resource.TOOL_CALLS] = 1
        if self._cost is not None:
            want[Resource.COST_MICRO_USD] = self._cost(action)
        res = self._ctx.reserve(want)  # raises BudgetExceededError: the action never starts
        try:
            outcome = await self._inner.run(action, pid=pid)
        except BaseException:
            self._ctx.release(res)
            raise
        actual = self._actual(want, outcome)
        if actual is None:  # denied / parked: nothing was spent
            self._ctx.release(res)
        else:
            self._ctx.commit(res, actual)
        return outcome

    @staticmethod
    def _actual(reserved: Amounts, outcome: ActionOutcome) -> dict[Resource, int] | None:
        if not isinstance(outcome, Completed) and not isinstance(outcome, Failed):
            return None
        actual = dict(reserved)
        if isinstance(outcome, Completed) and isinstance(outcome.result, ModelResponse):
            u = outcome.result.usage
            actual[Resource.TOKENS] = u.input_tokens + u.output_tokens
            if outcome.result.cost_usd is not None:
                actual[Resource.COST_MICRO_USD] = int(
                    (outcome.result.cost_usd * 1_000_000).to_integral_value()
                )
        return actual


def budgeted_deps(deps: RunDeps, ctx: ProcessContext) -> RunDeps:
    """``deps`` whose runner is the normal ``ActionExecutor`` wrapped by ``BudgetedRunner``."""

    def factory(run_ctx: RunContext) -> ActionRunner:
        backends = dataclasses.replace(
            deps.backends or Backends(), tools=deps.tools, models=deps.models
        )
        backends.spawn = run_ctx.spawn_child
        inner = ActionExecutor(
            gate=deps.gate,
            recorder=run_ctx.recorder,
            identity=run_ctx.identity,
            backends=backends,
            gate_timeout=deps.gate_timeout,
            approvals=deps.approvals,
        )
        return BudgetedRunner(inner, ctx)

    return dataclasses.replace(deps, runner_factory=factory)


SpawnerFactory = Callable[[ProcessContext], ChildSpawner]


def agent_workload(
    manifest: RuntimeManifest,
    input_text: str,
    deps: RunDeps,
    *,
    spawner_factory: SpawnerFactory | None = None,
    on_result: Callable[[RunResult], None] | None = None,
) -> Workload:
    """``spawner_factory(ctx)`` (see ``tki_spawner_factory``) routes the agent's ``agent``-kind tool
    calls through a TKI supervisor; ``on_result`` receives the finished run (its output)."""

    async def workload(ctx: ProcessContext) -> WorkloadResult:
        run_deps = budgeted_deps(deps, ctx)
        if spawner_factory is not None:
            run_deps = dataclasses.replace(run_deps, child_spawner=spawner_factory(ctx))
        handle = await start_agent(manifest, input_text, run_deps)
        result = asyncio.ensure_future(handle.result())
        cancelled = asyncio.ensure_future(ctx.token.wait())
        wake = asyncio.Event()
        result.add_done_callback(lambda _f: wake.set())
        cancelled.add_done_callback(lambda _f: wake.set())
        try:
            await wake.wait()
            if not result.done():
                await handle.signal(Signal.TERM, "tki cancel")
                await result
        except asyncio.CancelledError:
            await handle.signal(Signal.KILL, "tki kill")
            raise
        finally:
            cancelled.cancel()
            if not result.done():
                result.cancel()
        if ctx.token.cancelled:
            raise ProcessCancelled(ctx.token.detail)
        out = result.result()
        if on_result is not None:
            on_result(out)
        if out.exit_reason is None:  # parked on a human approval
            return WorkloadResult(ExitReason.COMPLETED, f"awaiting_approval:{out.approval_id}")
        return WorkloadResult(out.exit_reason, out.status)

    return workload


class TkiChildSpawner:
    """Runs the children of ONE parent process under a TKI ``Supervisor``.

    Each child is its own TKI process (own budget account under the parent's, so its spend rolls
    up to the parent, the run and the tenant) running a real agent through the same gate and
    executor, in its own run that shares the parent's trace. A hard-cap trip terminates that child
    with ``budget_exceeded`` (surfaced to the parent as a failed tool call); siblings and the
    parent are unaffected. Restart behaviour is the supervisor's (``budget_exceeded`` is never
    restarted). While a child runs the parent's TKI process is ``waiting`` (its slot is free).
    """

    def __init__(
        self,
        scheduler: Scheduler,
        parent: ProcessContext,
        deps: RunDeps,
        config: SupervisorConfig,
        *,
        child_limits: Mapping[str, Limits] | None = None,
    ) -> None:
        self._sched = scheduler
        self._parent = parent
        self._deps = deps
        self._supervisor = Supervisor(scheduler, parent.pid, config)
        self._config = config
        self._limits = dict(child_limits or {})
        self._seq = itertools.count(1)

    @property
    def supervisor(self) -> Supervisor:
        return self._supervisor

    async def __call__(self, run_ctx: RunContext, ref: str, args: Mapping[str, Any]) -> Any:
        manifest = self._deps.child_manifests.get(ref)
        if manifest is None:
            raise ChildError(f"unknown child agent {ref!r}")
        n = next(self._seq)
        name = f"{ref}#{n}"
        input_text = str(args.get("input") or json.dumps(to_jsonable(args)))
        results: list[RunResult] = []
        base_deps = dataclasses.replace(
            self._deps,
            trace_id=run_ctx.identity.trace_id,  # one trace for the whole multi-agent run
            runner_factory=None,
            child_spawner=None,
        )
        factory = tki_spawner_factory(
            self._sched, self._config, self._deps, child_limits=self._limits
        )
        attempts = itertools.count(1)

        async def workload(ctx: ProcessContext) -> WorkloadResult:
            # A restarted child is a NEW run: a run id is never reused (its log would be corrupt).
            attempt = next(attempts)
            suffix = f".c{n}" if attempt == 1 else f".c{n}r{attempt - 1}"
            child_deps = dataclasses.replace(base_deps, run_id=f"{run_ctx.identity.run_id}{suffix}")
            inner = agent_workload(
                manifest, input_text, child_deps, spawner_factory=factory, on_result=results.append
            )
            return (await inner(ctx)) or WorkloadResult()

        spec = ChildSpec.from_manifest(name, manifest, workload)
        if ref in self._limits:
            spec = dataclasses.replace(spec, limits=self._limits[ref])
        pid = self._supervisor.start_child(spec)
        async with self._parent.waiting():
            while True:
                view = await self._sched.wait(pid)
                await self._supervisor.settle()  # a restart may have replaced the process
                latest = self._supervisor.pid_of(name)
                if latest == pid:
                    break
                pid = latest
        if view.exit_reason is ExitReason.COMPLETED and results and results[-1].output is not None:
            return results[-1].output
        raise ChildError(f"child {ref!r} exited: {view.exit_reason}")


def tki_spawner_factory(
    scheduler: Scheduler,
    config: SupervisorConfig,
    deps: RunDeps,
    *,
    child_limits: Mapping[str, Limits] | None = None,
) -> SpawnerFactory:
    """Factory for ``agent_workload(spawner_factory=...)``: one supervisor per parent process."""

    def make(parent: ProcessContext) -> ChildSpawner:
        return TkiChildSpawner(scheduler, parent, deps, config, child_limits=child_limits)

    return make
