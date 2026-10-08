"""Case isolation and eval-mode lockdown: what makes an eval run safe to execute for real.

An eval drives the REAL run path (``start_agent`` with the tenant's kernel gate) so it measures the
agent that production would run, but it must not have production's side effects:

* ``EvalModeGate`` wraps the tenant's gate and can only ADD denials. It denies every action that
  could touch the outside world (MCP, code, browser, memory, outbound messages) unless the suite
  explicitly allows that action name for a sandboxed target; whatever it lets through is still
  decided by the Risk Kernel with a request byte-identical to production's (the eval flag is NOT
  put into the policy context: a policy must not be able to relax itself for evals).
* function tools are served from the case's recorded fixtures (``metadata.tool_fixtures``) or a
  declared dry run; the real tool registry is never reachable.
* ``lockdown_deps`` rebuilds ``RunDeps`` per case: fresh run id, trace id and event log, no
  backends, browser, channels, reply target, NEXUS (a cache would serve one case's answer to the
  next, and would let a score be gamed by caching) or approvals; memory only when a session is
  declared. Nothing is shared between cases except the stateless gate client and model gateway.
"""

from __future__ import annotations

import dataclasses
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from axis_runtime.actions import Backends
from axis_runtime.evals.types import EvalCase
from axis_runtime.events import InMemoryRunEventLog
from axis_runtime.gate import EnforcementPoint, EvaluateRequest, GateClient, GateDecision, deny
from axis_runtime.manifest import RuntimeManifest
from axis_runtime.run import RunDeps
from axis_runtime.tools import ToolRegistry

#: tool kinds whose handlers in an eval are fixtures (``function``) or gated children (``agent``).
SAFE_TOOL_KINDS = frozenset({"function", "agent"})


class IdSource(Protocol):
    def run_id(self) -> str: ...
    def trace_id(self) -> str: ...


class RandomIds:
    """Fresh, unguessable ids: a run id never repeats across cases, attempts or eval runs."""

    def run_id(self) -> str:
        return f"run_{secrets.token_hex(12)}"

    def trace_id(self) -> str:
        return secrets.token_hex(16)


@dataclass(frozen=True)
class EvalModePolicy:
    """``allow_sandboxed``: action names the suite explicitly allows against a sandboxed target."""

    allow_sandboxed: frozenset[str] = frozenset()

    def check(self, request: EvaluateRequest) -> str | None:
        """A denial reason, or ``None`` when the request may go on to the Risk Kernel."""
        point = request.enforcement_point
        if point is EnforcementPoint.MODEL_CALL:
            return None
        tool = request.context.get("tool")
        kind = tool.get("kind") if isinstance(tool, Mapping) else None
        if point is EnforcementPoint.TOOL_CALL and kind in SAFE_TOOL_KINDS:
            return None
        if request.action in self.allow_sandboxed:
            return None
        return f"eval_mode_side_effect_denied:{point.value}"


class EvalModeGate:
    """A GateClient that only ever narrows what ``inner`` (the tenant's gate) would allow."""

    def __init__(self, inner: GateClient, policy: EvalModePolicy) -> None:
        self._inner = inner
        self._policy = policy

    async def evaluate(self, request: EvaluateRequest) -> GateDecision:
        reason = self._policy.check(request)
        if reason is not None:
            return deny(reason)
        return await self._inner.evaluate(request)


# --------------------------------------------------------------------------------------
# Tool fixtures
# --------------------------------------------------------------------------------------


class FixtureMissError(LookupError):
    """The case recorded no response for this tool call (a tool error, never a real call)."""


@dataclass
class FixtureTool:
    name: str
    responses: list[Mapping[str, Any]] = field(default_factory=list)
    dry_run: bool = False
    calls: list[Mapping[str, Any]] = field(default_factory=list)

    def __call__(self, args: Mapping[str, Any]) -> Any:
        self.calls.append(dict(args))
        for entry in self.responses:
            when = entry.get("when")
            if when is None or (
                isinstance(when, Mapping) and all(args.get(k) == v for k, v in when.items())
            ):
                if entry.get("error"):
                    raise FixtureMissError(str(entry["error"])[:200])
                return entry.get("result")
        if self.dry_run:
            return {"dry_run": True, "executed": False}
        raise FixtureMissError(f"no recorded response for {self.name}")


def build_tool_registry(
    manifest: RuntimeManifest, case: EvalCase
) -> tuple[ToolRegistry, dict[str, FixtureTool]]:
    """A registry holding ONLY fixtures for the manifest's function tools."""
    meta = case.metadata
    fixtures = meta.get("tool_fixtures") or {}
    if not isinstance(fixtures, Mapping):
        raise ValueError("metadata.tool_fixtures must be an object")
    dry = bool(meta.get("dry_run", False))
    registry = ToolRegistry()
    tools: dict[str, FixtureTool] = {}
    for spec in manifest.tools:
        if spec.kind != "function":
            continue
        key = spec.ref or spec.name
        fx = fixtures.get(spec.name) or fixtures.get(key) or {}
        responses = fx.get("responses", []) if isinstance(fx, Mapping) else []
        tool = FixtureTool(spec.name, list(responses), dry)
        tools[key] = tool
        registry.register(
            key,
            tool,
            description=str(fx.get("description", "")) if isinstance(fx, Mapping) else "",
            input_schema=fx.get("input_schema") if isinstance(fx, Mapping) else None,
        )
    return registry, tools


def lockdown_deps(
    base: RunDeps,
    *,
    tenant_id: str,
    run_id: str,
    trace_id: str,
    tools: ToolRegistry,
    gate: GateClient,
    session_id: str | None = None,
    backends: Backends | None = None,
) -> RunDeps:
    """``base`` rebuilt for ONE eval run (see the module docstring)."""
    if base.tenant_id != tenant_id:
        raise ValueError("deps belong to another tenant")
    return dataclasses.replace(
        base,
        tenant_id=tenant_id,
        gate=gate,
        tools=tools,
        log=InMemoryRunEventLog(),
        run_id=run_id,
        trace_id=trace_id,
        backends=backends,
        runner_factory=None,
        nexus_factory=None,
        child_spawner=None,
        approvals=None,
        browser=None,
        channels=None,
        reply=None,
        session_id=session_id,
        memory=base.memory if session_id is not None else None,
    )
