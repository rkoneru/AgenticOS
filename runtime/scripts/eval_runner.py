"""Process launcher of the EVAL RUNNER: polls the Eval Hub for queued runs of ONE tenant and
executes them through the real run path (docs/spec/evals-runner.md); with ``--online`` (or
``"mode": "online"``) it instead grades a deterministic sample of the tenant's finished production
runs, off the decision path.

Lives outside ``src/axis_runtime`` on purpose, like ``run_server.py``: building a ModelGateway,
the gRPC gate client and reading files/environment is deployment wiring, which the bypass scanner
keeps out of the package. Run it as ``uv run python runtime/scripts/eval_runner.py [--online]`` (the
``python -m axis_runtime.evals`` form is deliberately not provided: a module inside the package
could not construct the gateway).

Configuration: ``EVAL_RUNNER_CONFIG`` names a JSON file:
  {"tenant_id": "<uuid>", "hub_url": "http://127.0.0.1:8090",
   "runner_id": "runner-1", "runner_token": "...", "signing_key": null,
   "kernel_target": "127.0.0.1:50051", "kernel_token": "...",
   "control_plane_url": "http://127.0.0.1:8080", "runtime_token": "...",
   "manifest_dir": "/path/to/manifests",     # optional: <name>@<version>.json files
   "poll_interval": 5.0, "once": false, "judge_deps": true,
   "mode": "ci",                             # "online": sample finished production runs
   "run_service_url": "http://127.0.0.1:8081", "run_read_token": "...",   # online only
   "online_poll_interval": 30.0}
Without ``manifest_dir`` the compiled manifest of each queued blueprint version is fetched from the
hub (``GET /v1/evals/runner/manifest``, served only while this runner holds a running run of that
version). Either way the runner refuses a manifest whose content hash is not the queued one. The
tenant's BYO model key comes from the control plane's runtime bridge (``HttpSecretStore``); the
tenant's policies are enforced by the Risk Kernel exactly as for a production run (the judge is a
gated ``model_call`` of blueprint ``eval-judge``: the tenant policy must allow it, NEEDS #309).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from axis_runtime.controlplane import ControlPlaneBridge
from axis_runtime.evals.grading import GradingEngine
from axis_runtime.evals.hubclient import EvalHubClient, HttpEvalHubClient, RunnerIdentity
from axis_runtime.evals.judge import JudgeGrader
from axis_runtime.evals.judge_backend import RunPathJudgeBackend
from axis_runtime.evals.sampler import OnlineSampler
from axis_runtime.evals.sources_http import HttpManifestSource, HttpRunLogReader
from axis_runtime.evals.suite import SuiteExecutor
from axis_runtime.evals.types import BlueprintRef, OnlineConfig
from axis_runtime.evals.worker import EvalWorker, ManifestSource, OnlineWorker, WorkerConfig
from axis_runtime.events import InMemoryRunEventLog
from axis_runtime.gate import GrpcGateClient
from axis_runtime.manifest import RuntimeManifest
from axis_runtime.models import ModelGateway
from axis_runtime.models.adapters.base import Transport
from axis_runtime.models.secrets_http import HttpSecretStore
from axis_runtime.run import RunDeps


class DirManifestSource:
    def __init__(self, directory: Path) -> None:
        self._dir = directory

    async def manifest(self, blueprint: BlueprintRef) -> RuntimeManifest:
        name = f"{blueprint.name}@{blueprint.version}"
        if ".." in name or "\\" in name:
            raise ValueError("invalid blueprint reference")
        path = self._dir / f"{name.replace('/', '__')}.json"
        raw: Any = json.loads(await asyncio.to_thread(path.read_text))
        return RuntimeManifest.from_dict(raw)


async def run(
    cfg: dict[str, Any],
    *,
    online: bool = False,
    transport: Transport | None = None,
    stop: asyncio.Event | None = None,
) -> int:
    """Run the worker until ``stop`` is set (or once when ``cfg["once"]``).

    ``transport`` replaces the model providers' HTTP transport (the e2e passes a scripted one);
    everything else is the real wiring.
    """
    tenant = cfg["tenant_id"]
    online = online or cfg.get("mode") == "online"
    bridge = ControlPlaneBridge(
        cfg["control_plane_url"], tenant_id=tenant, token=cfg["runtime_token"]
    )
    gate = GrpcGateClient(cfg["kernel_target"], token=cfg["kernel_token"])
    models = ModelGateway(HttpSecretStore(bridge), transport=transport)

    def base_deps() -> RunDeps:
        return RunDeps(tenant_id=tenant, gate=gate, models=models, log=InMemoryRunEventLog())

    identity = RunnerIdentity(
        cfg["runner_id"],
        cfg["runner_token"],
        None if cfg.get("signing_key") is None else str(cfg["signing_key"]).encode(),
    )
    hub = HttpEvalHubClient(cfg["hub_url"], identity)
    backend = (
        RunPathJudgeBackend(base_deps, tenant_id=tenant) if cfg.get("judge_deps", True) else None
    )
    closers: list[Any] = []
    stop = stop or asyncio.Event()
    try:
        if online:
            reader = HttpRunLogReader(cfg["run_service_url"], cfg["run_read_token"])
            closers.append(reader.aclose)
            await _run_online(cfg, hub, reader, backend, identity, tenant, stop)
        else:
            manifests: ManifestSource
            if cfg.get("manifest_dir"):
                manifests = DirManifestSource(Path(cfg["manifest_dir"]))
            else:
                source = HttpManifestSource(cfg["hub_url"], identity)
                closers.append(source.aclose)
                manifests = source
            executor = SuiteExecutor(
                base_deps=base_deps, tenant_id=tenant, identity=identity, judge_backend=backend
            )
            worker = EvalWorker(
                hub,
                executor,
                manifests,
                WorkerConfig(tenant_id=tenant, poll_interval=float(cfg.get("poll_interval", 5.0))),
            )
            if cfg.get("once"):
                await worker.run_once()
            else:
                await worker.run_forever(stop)
    finally:
        for close in closers:
            await close()
        await hub.aclose()
        await bridge.aclose()
        await gate.close()
    return 0


async def _run_online(
    cfg: dict[str, Any],
    hub: EvalHubClient,
    reader: HttpRunLogReader,
    backend: RunPathJudgeBackend | None,
    identity: RunnerIdentity,
    tenant: str,
    stop: asyncio.Event,
) -> None:
    grader = GradingEngine(JudgeGrader(backend) if backend is not None else None)

    async def build(conf: OnlineConfig) -> OnlineSampler:
        suite = await hub.get_suite(conf.suite_ref)
        return OnlineSampler(
            config=conf,
            tenant_id=tenant,
            reader=reader,
            grader=grader,
            graders=suite.graders,
            sink=hub,
            runner_id=identity.runner_id,
        )

    worker = OnlineWorker(hub, build, poll_interval=float(cfg.get("online_poll_interval", 30.0)))
    if cfg.get("once"):
        await worker.poll_once()
        for s in worker.samplers():
            await s.drain()
    else:
        await worker.run_forever(stop)


async def main() -> int:
    cfg = json.loads(await asyncio.to_thread(Path(os.environ["EVAL_RUNNER_CONFIG"]).read_text))
    return await run(cfg, online="--online" in sys.argv[1:])


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
