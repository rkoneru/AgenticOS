"""Process launcher of the DEV run service (docs/adr/0026).

Lives outside ``src/axis_runtime`` on purpose: constructing a ModelGateway and reading the
environment is deployment wiring, which the bypass scanner keeps out of the package.

Environment (JSON in RUNSERVER_CONFIG, a file path):
  {"port": 0, "tokens": {"<gateway token>": "<tenant uuid>"},
   "kernel_target": "127.0.0.1:50051", "kernel_tokens": {"<tenant>": "<kernel token>"},
   "control_plane_url": "http://127.0.0.1:8080",
   "runtime_tokens": {"<tenant>": "<runtime token>"},
   "billing_url": null, "ingest_tokens": {},
   "approvals_url": null, "approval_tokens": {}}
Prints ``{"port": N}`` when listening.

``approvals_url`` is the approvals service's loopback dev bridge
(``services/approvals/src/dev-bridge.ts``, hosted by the Risk Kernel dev process). With it a
REQUIRE_APPROVAL is resolved inline by a human decision and the approved action is RE-GATED by the
kernel; without it the run parks (``awaiting_approval``). ``wired_factory`` also takes an optional
``model_transport`` and ``tools_factory`` so an e2e can script the model and register deterministic
tools (``e2e/scripts/interfaces_run_server.py``); production wiring passes neither.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from axis_runtime.approvals import HttpApprovalResolver
from axis_runtime.controlplane import ControlPlaneBridge
from axis_runtime.events import InMemoryRunEventLog, SystemClock
from axis_runtime.gate import GrpcGateClient
from axis_runtime.manifest import RuntimeManifest
from axis_runtime.models import ModelGateway
from axis_runtime.models.secrets_http import HttpSecretStore
from axis_runtime.run import RunDeps
from axis_runtime.runserver import (
    DepsFactory,
    HttpError,
    RunServer,
    RunServerConfig,
    RunService,
    RunSetup,
)
from axis_runtime.tenant_budgets import TenantBudgets
from axis_runtime.tki import InMemoryLedger, ListSink, MessageRouter, Scheduler, SchedulerConfig
from axis_runtime.tki.supervisor import limits_from_manifest
from axis_runtime.tools import ToolRegistry
from axis_runtime.usage import HttpUsageEmitter

# ---------------------------------


@dataclass
class Wiring:
    """The real dependencies of a tenant's runs (loopback dev bridges; NEEDS #186 and the Phase
    6 notes)."""

    kernel_target: str
    kernel_tokens: Mapping[str, str]
    control_plane_url: str
    runtime_tokens: Mapping[str, str]
    billing_url: str | None = None
    ingest_tokens: Mapping[str, str] = field(default_factory=dict)
    approvals_url: str | None = None
    approval_tokens: Mapping[str, str] = field(default_factory=dict)
    approval_poll_seconds: float = 1.0
    approval_max_wait_seconds: float = 3600.0
    gate_timeout: float = 5.0
    max_running: int = 4


def wired_factory(
    w: Wiring,
    *,
    model_transport: Any | None = None,
    tools_factory: Callable[[], ToolRegistry] | None = None,
) -> DepsFactory:
    """Kernel gate over gRPC, BYO key and budgets from the control plane, TKI per tenant, usage
    to billing. A tenant with a missing
    credential or an unreachable control plane gets no run (fail closed)."""
    schedulers: dict[str, tuple[Scheduler, Any]] = {}

    async def factory(
        tenant: str, manifest: RuntimeManifest, principal: Mapping[str, Any]
    ) -> RunSetup:
        if tenant not in w.kernel_tokens or tenant not in w.runtime_tokens:
            raise HttpError(503, "this tenant has no run credentials configured")
        bridge = ControlPlaneBridge(
            w.control_plane_url, tenant_id=tenant, token=w.runtime_tokens[tenant]
        )
        emitter = (
            HttpUsageEmitter(w.billing_url, token=w.ingest_tokens[tenant])
            if w.billing_url and tenant in w.ingest_tokens
            else None
        )
        resolver = (
            HttpApprovalResolver(
                w.approvals_url,
                token=w.approval_tokens[tenant],
                poll_seconds=w.approval_poll_seconds,
                max_wait_seconds=w.approval_max_wait_seconds,
            )
            if w.approvals_url and tenant in w.approval_tokens
            else None
        )
        try:
            budgets = TenantBudgets.from_json(await bridge.budget_config())
        except Exception:  # noqa: BLE001
            await bridge.aclose()
            if resolver is not None:
                await resolver.close()
            raise HttpError(503, "tenant budgets are unavailable") from None
        if tenant not in schedulers:
            sink, clock = ListSink(), SystemClock()
            ledger = InMemoryLedger(sink)
            budgets.apply_to_ledger(ledger, tenant)

            async def no_ipc(_env: Any) -> bool:
                return False

            sched = Scheduler(
                ledger=ledger,
                router=MessageRouter(sink=sink, authorize=no_ipc, clock=clock),
                sink=sink,
                clock=clock,
                config=SchedulerConfig(
                    max_running=w.max_running, default_tenant_limit=w.max_running
                ),
            )
            schedulers[tenant] = (sched, budgets)
        sched = schedulers[tenant][0]
        deps = RunDeps(
            tenant_id=tenant,
            gate=GrpcGateClient(
                w.kernel_target, timeout=w.gate_timeout, token=w.kernel_tokens[tenant]
            ),
            models=ModelGateway(HttpSecretStore(bridge), transport=model_transport),
            log=InMemoryRunEventLog(),
            usage=emitter,
            approvals=resolver,
            **({"tools": tools_factory()} if tools_factory is not None else {}),
        )

        async def close() -> None:
            await bridge.aclose()
            if emitter is not None:
                await emitter.aclose()
            if resolver is not None:
                await resolver.close()

        return RunSetup(
            deps=deps,
            scheduler=sched,
            limits=budgets.spawn_limits(limits_from_manifest(manifest)),
            close=close,
        )

    return factory


async def main() -> None:
    cfg = json.loads(await asyncio.to_thread(Path(os.environ["RUNSERVER_CONFIG"]).read_text))
    wiring = Wiring(
        kernel_target=cfg["kernel_target"],
        kernel_tokens=cfg["kernel_tokens"],
        control_plane_url=cfg["control_plane_url"],
        runtime_tokens=cfg["runtime_tokens"],
        billing_url=cfg.get("billing_url"),
        ingest_tokens=cfg.get("ingest_tokens", {}),
        approvals_url=cfg.get("approvals_url"),
        approval_tokens=cfg.get("approval_tokens", {}),
    )
    server = RunServer(RunService(wired_factory(wiring)), RunServerConfig(tokens=cfg["tokens"]))
    port = await server.start(port=int(cfg.get("port", 0)))
    print(json.dumps({"port": port}), flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
