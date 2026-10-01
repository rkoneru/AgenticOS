"""LLM stage: the final fallback.  It never touches a provider; it builds a ``ModelCall`` and
hands it to the ActionExecutor, which gates it through the Risk Kernel and only then reaches the
ModelGateway (invariant 5).  A DENY or approval-pending is TERMINAL for the route (``blocked``)."""

from __future__ import annotations

from collections.abc import Sequence
from decimal import Decimal

from axis_runtime.actions import ModelCall
from axis_runtime.executor import ActionRunner, Completed, Denied, Failed, PendingApproval
from axis_runtime.models.types import (
    CacheHints,
    Message,
    ModelRequest,
    ModelResponse,
    ModelTarget,
)
from axis_runtime.nexus.types import (
    Hit,
    Miss,
    Passage,
    RouteRequest,
    RouteState,
    StageOutcome,
)


def build_context_message(passages: Sequence[Passage]) -> str:
    return "\n".join(f"[{p.id}] {p.text}" for p in passages)


class LlmStage:
    name = "llm"

    def __init__(
        self,
        runner: ActionRunner,
        target: ModelTarget,
        *,
        fallbacks: Sequence[ModelTarget] = (),
        system_prompt: str = "",
    ) -> None:
        self._runner = runner
        self._target = target
        self._fallbacks = tuple(fallbacks)
        self._system = system_prompt

    def _request(self, request: RouteRequest, state: RouteState) -> ModelRequest:
        if request.messages:  # the agent loop's own conversation, tools included
            messages = request.messages
            if state.retrieved:
                # Passages the RAG stage found ride along as extra context, placed right after the
                # leading system messages (they are data for the model, never instructions).
                lead = 0
                while lead < len(messages) and messages[lead].role == "system":
                    lead += 1
                context = Message("system", "Context:\n" + build_context_message(state.retrieved))
                messages = (*messages[:lead], context, *messages[lead:])
            return ModelRequest(
                tenant_id=request.tenant_id,
                messages=messages,
                target=self._target,
                tools=request.tools,
                fallbacks=self._fallbacks,
                cache=CacheHints(system=True),
            )
        msgs: list[Message] = []
        system = request.system_prompt or self._system
        if system:
            msgs.append(Message("system", system))
        if state.retrieved:
            msgs.append(Message("system", "Context:\n" + build_context_message(state.retrieved)))
        msgs.append(Message("user", request.prompt))
        return ModelRequest(
            tenant_id=request.tenant_id,
            messages=tuple(msgs),
            target=self._target,
            fallbacks=self._fallbacks,
        )

    async def run(self, request: RouteRequest, state: RouteState) -> StageOutcome:
        action = ModelCall(
            name=f"{self._target.provider}/{self._target.model}",
            request=self._request(request, state),
        )
        outcome = await self._runner.run(action, pid=request.pid)
        if isinstance(outcome, Denied):
            return Miss(f"denied:{outcome.reason}", blocked=True)
        if isinstance(outcome, PendingApproval):
            return Miss(f"approval_pending:{outcome.approval_id}", blocked=True)
        if isinstance(outcome, Failed):
            return Miss("model_failed")
        res = outcome.result if isinstance(outcome, Completed) else None
        if not isinstance(res, ModelResponse):
            return Miss("unexpected_result")
        return Hit(
            res.text,
            cost=res.cost_usd if res.cost_usd is not None else Decimal(0),
            confidence=1.0,
            tokens=res.usage.input_tokens + res.usage.output_tokens,
            cacheable=not res.tool_calls,
            tool_calls=res.tool_calls,
            meta={"provider": res.provider, "model": res.model},
        )


__all__ = ["LlmStage"]
