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
from collections.abc import Callable

from axis_runtime.actions import Action, Backends, ModelCall
from axis_runtime.executor import ActionExecutor, ActionOutcome, ActionRunner, Completed, Failed
from axis_runtime.manifest import RuntimeManifest
from axis_runtime.models.types import ModelResponse
from axis_runtime.process import ExitReason, Signal
from axis_runtime.run import RunContext, RunDeps, start_agent
from axis_runtime.tki.budget import Amounts, Resource
from axis_runtime.tki.scheduler import ProcessCancelled, ProcessContext, Workload, WorkloadResult

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


def agent_workload(manifest: RuntimeManifest, input_text: str, deps: RunDeps) -> Workload:
    async def workload(ctx: ProcessContext) -> WorkloadResult:
        handle = await start_agent(manifest, input_text, budgeted_deps(deps, ctx))
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
        if out.exit_reason is None:  # parked on a human approval
            return WorkloadResult(ExitReason.COMPLETED, f"awaiting_approval:{out.approval_id}")
        return WorkloadResult(out.exit_reason, out.status)

    return workload
