"""Process launcher of the EVAL RUNNER: polls the Eval Hub for queued runs of ONE tenant and
executes them through the real run path (docs/spec/evals-runner.md).

Lives outside ``src/axis_runtime`` on purpose, like ``run_server.py``: building a ModelGateway,
the gRPC gate client and reading files/environment is deployment wiring, which the bypass scanner
keeps out of the package. Run it as ``uv run python runtime/scripts/eval_runner.py`` (the
``python -m axis_runtime.evals`` form is deliberately not provided: a module inside the package
could not construct the gateway).

Configuration: ``EVAL_RUNNER_CONFIG`` names a JSON file:
  {"tenant_id": "<uuid>", "hub_url": "http://127.0.0.1:8090",
   "runner_id": "runner-1", "runner_token": "...", "signing_key": null,
   "kernel_target": "127.0.0.1:50051", "kernel_token": "...",
   "control_plane_url": "http://127.0.0.1:8080", "runtime_token": "...",
   "manifest_dir": "/path/to/manifests", "poll_interval": 5.0, "once": false,
   "judge_deps": true}
``manifest_dir`` holds ``<name>@<version>.json`` (the compiled RuntimeManifest of each blueprint
version the hub may queue; the runner refuses a file whose content hash is not the queued one).
The tenant's BYO model key comes from the control plane's runtime bridge (``HttpSecretStore``);
the tenant's policies are enforced by the Risk Kernel exactly as for a production run.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from axis_runtime.controlplane import ControlPlaneBridge
from axis_runtime.evals.hubclient import HttpEvalHubClient, RunnerIdentity
from axis_runtime.evals.judge_backend import RunPathJudgeBackend
from axis_runtime.evals.suite import SuiteExecutor
from axis_runtime.evals.types import BlueprintRef
from axis_runtime.evals.worker import EvalWorker, WorkerConfig
from axis_runtime.events import InMemoryRunEventLog
from axis_runtime.gate import GrpcGateClient
from axis_runtime.manifest import RuntimeManifest
from axis_runtime.models import ModelGateway
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


async def main() -> int:
    cfg = json.loads(await asyncio.to_thread(Path(os.environ["EVAL_RUNNER_CONFIG"]).read_text))
    tenant = cfg["tenant_id"]
    bridge = ControlPlaneBridge(
        cfg["control_plane_url"], tenant_id=tenant, token=cfg["runtime_token"]
    )
    gate = GrpcGateClient(cfg["kernel_target"], token=cfg["kernel_token"])
    models = ModelGateway(HttpSecretStore(bridge))

    def base_deps() -> RunDeps:
        return RunDeps(tenant_id=tenant, gate=gate, models=models, log=InMemoryRunEventLog())

    identity = RunnerIdentity(
        cfg["runner_id"],
        cfg["runner_token"],
        None if cfg.get("signing_key") is None else str(cfg["signing_key"]).encode(),
    )
    hub = HttpEvalHubClient(cfg["hub_url"], identity)
    executor = SuiteExecutor(
        base_deps=base_deps,
        tenant_id=tenant,
        identity=identity,
        judge_backend=RunPathJudgeBackend(base_deps, tenant_id=tenant)
        if cfg.get("judge_deps", True)
        else None,
    )
    worker = EvalWorker(
        hub,
        executor,
        DirManifestSource(Path(cfg["manifest_dir"])),
        WorkerConfig(tenant_id=tenant, poll_interval=float(cfg.get("poll_interval", 5.0))),
    )
    try:
        if cfg.get("once"):
            await worker.run_once()
        else:
            await worker.run_forever(asyncio.Event())
    finally:
        await hub.aclose()
        await bridge.aclose()
        await gate.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
