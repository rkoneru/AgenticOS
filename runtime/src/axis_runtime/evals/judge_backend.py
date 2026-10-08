"""The judge's transport: a tool-less agent run through the ordinary run path.

``run_agent`` -> a gated ``model_call`` -> the ModelGateway with the tenant's BYO key (the
``SecretStore`` the deps' gateway was built with). The judge therefore obeys the same kernel
policy, kill-switch and audit as any agent action; a DENY or a missing key is ``JudgeUnavailable``
and the grade is ``ungraded`` (0), never a default pass.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from axis_runtime.evals.isolation import IdSource, RandomIds, lockdown_deps
from axis_runtime.evals.judge import JudgeConfig, JudgeReply, JudgeUnavailable, judge_manifest
from axis_runtime.run import RunDeps, run_agent
from axis_runtime.tools import ToolRegistry


class RunPathJudgeBackend:
    def __init__(
        self,
        base_deps: Callable[[], RunDeps],
        *,
        tenant_id: str,
        ids: IdSource | None = None,
    ) -> None:
        self._base_deps = base_deps
        self._tenant_id = tenant_id
        self._ids = ids or RandomIds()

    async def ask(self, *, system: str, user: str, config: JudgeConfig, seed: int) -> JudgeReply:
        base = self._base_deps()
        deps = lockdown_deps(
            base,
            tenant_id=self._tenant_id,
            run_id=self._ids.run_id(),
            trace_id=self._ids.trace_id(),
            tools=ToolRegistry(),  # the judge has no tools at all
            gate=base.gate,
        )
        deps.max_steps = 1
        manifest = judge_manifest(system, config, seed)
        try:
            async with asyncio.timeout(config.timeout_seconds + 5.0):
                result = await run_agent(manifest, user, deps)
        except TimeoutError:
            raise JudgeUnavailable("timeout") from None
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - any failure is "no verdict", never a pass
            raise JudgeUnavailable(type(exc).__name__) from None
        if result.status != "completed" or result.output is None:
            raise JudgeUnavailable(result.status)
        calls = result.state.model_calls
        last = calls[-1] if calls else None
        return JudgeReply(
            text=result.output,
            provider=last.provider if last else config.provider,
            model=last.model if last else config.model,
            tokens=sum(c.input_tokens + c.output_tokens for c in calls),
            cost_micro_usd=sum(c.cost_micro_usd or 0 for c in calls),
        )
