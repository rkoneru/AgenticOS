"""NexusRouter: runs the manifest's ``routing.stages`` in order; the first Hit short-circuits.

Robustness rules (docs/spec/nexus.md):
- a stage that raises, times out, or returns a malformed Hit is recorded as a MISS and the pipeline
  falls through (a routing failure never skips anything downstream and never fabricates an answer);
- the router performs no action itself.  Only the LLM stage produces model calls, and it does so by
  handing a ``ModelCall`` to the ActionExecutor, so every one passes the Risk Kernel gate;
- a gate DENY / approval-pending at the LLM stage is terminal (``blocked``), never retried;
- telemetry (spans, events) is best effort: a failing sink is counted, never fatal.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Protocol

from axis_runtime.manifest import RuntimeManifest
from axis_runtime.nexus.telemetry import EventSink, NoopTracer, NullEventSink, Tracer
from axis_runtime.nexus.types import (
    STAGE_NAMES,
    Hit,
    Miss,
    RouteRequest,
    RouteResult,
    RouteState,
    Stage,
    StageRecord,
    WriteBackStage,
)


class MonotonicClock(Protocol):
    def monotonic(self) -> float: ...


class SystemMonotonic:
    def monotonic(self) -> float:
        return time.monotonic()


class NexusConfigError(ValueError):
    """The pipeline is misconfigured (unknown / missing / misordered stage)."""


class NexusRouter:
    def __init__(
        self,
        stages: Sequence[Stage],
        *,
        tracer: Tracer | None = None,
        sink: EventSink | None = None,
        clock: MonotonicClock | None = None,
        stage_timeout_s: float | None = None,
    ) -> None:
        names = [s.name for s in stages]
        if len(set(names)) != len(names):
            raise NexusConfigError("duplicate stage")
        for n in names:
            if n not in STAGE_NAMES:
                raise NexusConfigError(f"unknown stage {n!r}")
        if "llm" in names and names[-1] != "llm":
            raise NexusConfigError("the llm stage is the final fallback and must be last")
        self._stages = tuple(stages)
        self._tracer: Tracer = tracer or NoopTracer()
        self._sink: EventSink = sink or NullEventSink()
        self._clock: MonotonicClock = clock or SystemMonotonic()
        self._timeout = stage_timeout_s

    @classmethod
    def from_manifest(
        cls, manifest: RuntimeManifest, available: Mapping[str, Stage], **kw: object
    ) -> NexusRouter:
        """Build the pipeline in the manifest's ``routing.stages`` order.  A declared stage with no
        implementation is a configuration error (fail closed: never silently dropped)."""
        missing = [n for n in manifest.routing_stages if n not in available]
        if missing:
            raise NexusConfigError(f"no implementation for declared stage(s): {missing}")
        return cls([available[n] for n in manifest.routing_stages], **kw)  # type: ignore[arg-type]

    @property
    def stage_names(self) -> tuple[str, ...]:
        return tuple(s.name for s in self._stages)

    async def route(self, request: RouteRequest) -> RouteResult:
        t0 = self._clock.monotonic()
        root = self._tracer.start_span(
            "nexus.route",
            attributes={
                "nexus.tenant_id": request.tenant_id,
                "nexus.trace_id": request.trace_id,
                "nexus.phi": request.phi,
                "nexus.stages": ",".join(self.stage_names),
            },
        )
        state = RouteState()
        records: list[StageRecord] = []
        sink_errors = 0
        hit: Hit | None = None
        hit_stage: str | None = None
        blocked = ""

        for stage in self._stages:
            outcome, record = await self._run_stage(stage, request, state, root)
            records.append(record)
            sink_errors += await self._emit_stage(request, record)
            if isinstance(outcome, Hit):
                hit, hit_stage = outcome, stage.name
                break
            if outcome.blocked:
                blocked = outcome.reason
                break

        if hit is not None and hit_stage is not None:
            sink_errors += await self._write_back(request, hit, hit_stage)

        result = RouteResult(
            status="hit" if hit else ("blocked" if blocked else "exhausted"),
            answer=hit.answer if hit else None,
            hit_stage=hit_stage,
            stages=tuple(records),
            tool_calls=hit.tool_calls if hit else (),
            confidence=hit.confidence if hit else None,
            total_latency_ms=(self._clock.monotonic() - t0) * 1000.0,
            sink_errors=sink_errors,
            blocked_reason=blocked,
        )
        root.set_attribute("nexus.status", result.status)
        root.set_attribute("nexus.hit_stage", hit_stage or "")
        root.set_attribute("nexus.tokens", result.total_tokens)
        root.set_attribute("nexus.cost_usd", float(result.total_cost_usd))
        root.set_status(result.status != "exhausted", result.blocked_reason)
        root.end()
        sink_errors += await self._emit(
            "nexus_route",
            {
                "tenant_id": request.tenant_id,
                "trace_id": request.trace_id,
                "status": result.status,
                "hit_stage": hit_stage,
                "total_latency_ms": round(result.total_latency_ms, 3),
                "total_tokens": result.total_tokens,
                "total_cost_usd": str(result.total_cost_usd),
                "cost_by_stage": {k: str(v) for k, v in result.cost_by_stage.items()},
            },
        )
        if sink_errors != result.sink_errors:
            result = replace(result, sink_errors=sink_errors)
        return result

    async def _run_stage(
        self, stage: Stage, request: RouteRequest, state: RouteState, root: object
    ) -> tuple[Hit | Miss, StageRecord]:
        span = self._tracer.start_span(
            f"nexus.stage.{stage.name}",
            parent=root,  # type: ignore[arg-type]
            attributes={"nexus.stage": stage.name, "nexus.tenant_id": request.tenant_id},
        )
        started = self._clock.monotonic()
        outcome: Hit | Miss
        try:
            if self._timeout is not None and stage.name != "llm":
                outcome = await asyncio.wait_for(stage.run(request, state), self._timeout)
            else:
                outcome = await stage.run(request, state)
            if not isinstance(outcome, Hit | Miss):
                outcome = Miss("invalid_outcome")
            elif isinstance(outcome, Hit) and (problem := outcome.problem()):
                outcome = Miss(f"invalid_hit:{problem}")
        except TimeoutError:
            outcome = Miss("timeout")
        except Exception as exc:  # a stage failure is a miss, never a crash and never a skip
            outcome = Miss(f"error:{type(exc).__name__}")  # type name only: messages may hold data
        latency_ms = (self._clock.monotonic() - started) * 1000.0

        if isinstance(outcome, Miss):
            state.retrieved.extend(outcome.context)
        is_hit = isinstance(outcome, Hit)
        record = StageRecord(
            stage=stage.name,
            outcome="hit" if is_hit else "miss",
            reason="" if isinstance(outcome, Hit) else outcome.reason,
            latency_ms=latency_ms,
            tokens=outcome.tokens,
            cost_usd=outcome.cost,
            cache_key_hash=outcome.cache_key_hash,
            confidence=outcome.confidence if isinstance(outcome, Hit) else None,
        )
        span.set_attribute("nexus.hit", is_hit)
        span.set_attribute("nexus.latency_ms", latency_ms)
        span.set_attribute("nexus.tokens", record.tokens)
        span.set_attribute("nexus.cost_usd", float(record.cost_usd))
        span.set_attribute("nexus.reason", record.reason)
        if record.cache_key_hash:
            span.set_attribute("nexus.cache_key_hash", record.cache_key_hash)
        span.set_status(not record.reason.startswith(("error:", "timeout")), record.reason)
        span.end()
        return outcome, record

    async def _write_back(self, request: RouteRequest, hit: Hit, source: str) -> int:
        errors = 0
        for stage in self._stages:
            if stage.name == source:
                break  # only stages BEFORE the hit learn from it
            if not isinstance(stage, WriteBackStage):
                continue
            try:
                await stage.write_back(request, hit, source)
            except Exception:
                errors += 1
                await self._emit(
                    "nexus_stage",
                    {
                        "stage": stage.name,
                        "outcome": "write_back_error",
                        "tenant_id": request.tenant_id,
                    },
                )
        return errors

    async def _emit_stage(self, request: RouteRequest, record: StageRecord) -> int:
        return await self._emit(
            "nexus_stage",
            {
                "tenant_id": request.tenant_id,
                "trace_id": request.trace_id,
                "stage": record.stage,
                "outcome": record.outcome,
                "reason": record.reason,
                "latency_ms": round(record.latency_ms, 3),
                "tokens": record.tokens,
                "cost_usd": str(record.cost_usd),
                "cache_key_hash": record.cache_key_hash,
                "confidence": record.confidence,
            },
        )

    async def _emit(self, event_type: str, data: Mapping[str, object]) -> int:
        try:
            await self._sink.emit(event_type, data)
        except Exception:
            return 1
        return 0


__all__ = ["NexusConfigError", "NexusRouter"]
