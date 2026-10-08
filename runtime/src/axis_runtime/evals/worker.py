"""The hub-facing loops: claim queued eval runs and execute them; poll online samplers.

A run the worker cannot or must not execute (stale blueprint hash, altered dataset, an input the
hub refused to serve) is reported as a FAILED run with a reason and no scores: the release gate
treats a failed run like a missing one (blocked), so a refusal can never read as a pass.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol

from axis_runtime.evals.hubclient import EvalHubClient, HubError
from axis_runtime.evals.sampler import OnlineSampler
from axis_runtime.evals.suite import RunRefused, SuiteExecutor
from axis_runtime.evals.types import BlueprintRef, OnlineConfig, QueuedRun
from axis_runtime.events import Clock, SystemClock, format_ts
from axis_runtime.manifest import RuntimeManifest

log = logging.getLogger("axis_runtime.evals.worker")


class ManifestSource(Protocol):
    async def manifest(self, blueprint: BlueprintRef) -> RuntimeManifest:
        """The compiled RuntimeManifest of exactly this blueprint version. Raises if unknown."""
        ...


@dataclass(frozen=True)
class WorkerConfig:
    tenant_id: str
    poll_interval: float = 5.0
    submit_retries: int = 3


class EvalWorker:
    def __init__(
        self,
        hub: EvalHubClient,
        executor: SuiteExecutor,
        manifests: ManifestSource,
        config: WorkerConfig,
        *,
        clock: Clock | None = None,
        sleep: Callable[[float], Any] = asyncio.sleep,
    ) -> None:
        self._hub = hub
        self._executor = executor
        self._manifests = manifests
        self._config = config
        self._clock = clock or SystemClock()
        self._sleep = sleep

    async def _submit(self, run: QueuedRun, payload: dict[str, Any]) -> bool:
        for attempt in range(self._config.submit_retries):
            try:
                await self._hub.submit_results(run.id, payload)
                return True
            except HubError as exc:
                if exc.kind == "conflict":  # already recorded: never submit twice
                    log.warning("hub already holds results for %s", run.id)
                    return False
                log.warning("submit failed (%s), attempt %d", exc.kind, attempt + 1)
                await self._sleep(min(2.0**attempt, 10.0))
        return False

    def _failed(self, run: QueuedRun, reason: str) -> dict[str, Any]:
        return {
            "runner_id": self._executor.runner_id,
            "run_id": run.id,
            "mode": run.mode,
            "status": "failed",
            "reason": reason[:200],
            "suite_ref": run.suite_ref,
            "blueprint": run.blueprint.to_wire(),
            "finished_at": format_ts(self._clock.now()),
        }

    async def run_once(self) -> bool:
        """Claim and execute at most one run. True when a run was handled."""
        try:
            run = await self._hub.claim_run()
        except HubError as exc:
            log.warning("claim failed: %s", exc.kind)
            return False
        if run is None:
            return False
        if run.tenant_id != self._config.tenant_id:
            log.error("hub offered a run of another tenant; refusing")
            return True
        try:
            suite = await self._hub.get_suite(run.suite_ref)
            dataset = await self._hub.get_dataset(suite.dataset_ref)
            manifest = await self._manifests.manifest(run.blueprint)
            execution = await self._executor.execute(run, suite, dataset, manifest)
        except RunRefused as exc:
            await self._submit(run, self._failed(run, f"refused:{exc.reason}"))
            return True
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - report, never crash the loop
            reason = exc.kind if isinstance(exc, HubError) else type(exc).__name__
            await self._submit(run, self._failed(run, f"internal:{reason}"))
            return True
        if await self._submit(run, execution.payload) and execution.review_tasks:
            await self._create_tasks(run, [t.to_wire() for t in execution.review_tasks])
        return True

    async def _create_tasks(self, run: QueuedRun, tasks: list[dict[str, Any]]) -> None:
        for attempt in range(self._config.submit_retries):
            try:
                await self._hub.create_review_tasks(run.id, tasks)
                return
            except HubError as exc:
                if exc.kind == "conflict":
                    return
                log.warning("review task hand-off failed (%s)", exc.kind)
                await self._sleep(min(2.0**attempt, 10.0))

    async def run_forever(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            handled = await self.run_once()
            if not handled:
                try:
                    await asyncio.wait_for(stop.wait(), timeout=self._config.poll_interval)
                except TimeoutError:
                    pass


class OnlineWorker:
    """One sampler per online configuration the hub lists for the tenant."""

    def __init__(
        self,
        hub: EvalHubClient,
        build_sampler: Callable[[OnlineConfig], OnlineSampler | Awaitable[OnlineSampler]],
        *,
        poll_interval: float = 30.0,
    ) -> None:
        self._hub = hub
        self._build = build_sampler
        self._interval = poll_interval
        self._samplers: dict[tuple[str, str], OnlineSampler] = {}

    async def refresh(self) -> None:
        try:
            configs = await self._hub.online_configs()
        except HubError as exc:
            log.warning("online config fetch failed: %s", exc.kind)
            return
        live = {(c.blueprint, c.suite_ref): c for c in configs}
        for key in set(self._samplers) - set(live):
            del self._samplers[key]  # configuration removed: stop sampling
        for key, cfg in live.items():
            current = self._samplers.get(key)
            if current is None or current.config != cfg:
                try:
                    built = self._build(cfg)
                    self._samplers[key] = await built if inspect.isawaitable(built) else built
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 - one bad configuration must not stop the others
                    kind = exc.kind if isinstance(exc, HubError) else type(exc).__name__
                    log.warning("online sampler for %s not built: %s", key, kind)

    def samplers(self) -> list[OnlineSampler]:
        return list(self._samplers.values())

    async def poll_once(self) -> int:
        await self.refresh()
        return sum([await s.poll_once() for s in self._samplers.values()])

    async def run_forever(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            await self.poll_once()
            try:
                await asyncio.wait_for(stop.wait(), timeout=self._interval)
            except TimeoutError:
                pass
        for s in self._samplers.values():
            await s.drain()
