"""Test launcher: the REAL run service with scripted deps (fake gate and model), for the TypeScript gateway's integration test.

usage: python runserver_fake_main.py <token> <tenant-uuid>  -> prints {"port": N}
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Mapping
from typing import Any

from axis_runtime.manifest import RuntimeManifest
from axis_runtime.models import InMemorySecretStore
from axis_runtime.run import RunDeps
from axis_runtime.runserver import RunServer, RunServerConfig, RunService, RunSetup
from conftest import FakeClock, ScriptedGate, ScriptedTransport, final_body, make_gateway


async def factory(tenant: str, manifest: RuntimeManifest, principal: Mapping[str, Any]) -> RunSetup:
    transport = ScriptedTransport([(200, final_body("done by the real run service"))])
    clock = FakeClock()
    store = InMemorySecretStore({(tenant, "openai", "default"): "sk-fake-run-service-test"})
    models = make_gateway(transport, clock, secrets=store)
    return RunSetup(deps=RunDeps(tenant_id=tenant, gate=ScriptedGate(), models=models, clock=clock))


async def main() -> None:
    token, tenant = sys.argv[1], sys.argv[2]
    server = RunServer(RunService(factory), RunServerConfig(tokens={token: tenant}))
    print(json.dumps({"port": await server.start()}), flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
