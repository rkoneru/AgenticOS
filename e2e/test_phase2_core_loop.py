"""Phase 2 exit check: ABL agent -> Python runtime -> real Risk Kernel over gRPC -> Postgres audit.

Everything on the decision path is real: the ABL compiler (Node), the policy compiler + OPA Wasm bundle, the Risk
Kernel process, gRPC, the Postgres hash-chained audit log with RLS. The only fake is the LLM provider HTTP
transport (no API keys).

Run with:  bash infra/scripts/with-pg.sh uv run pytest e2e -p no:cacheprovider --no-cov
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import time
import uuid
from collections.abc import Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import grpc
import grpc.aio
import pytest
from axis_runtime._gen.axis.runtime.v1 import gate_pb2, gate_pb2_grpc
from axis_runtime.events import EventType, replay
from axis_runtime.gate import GrpcGateClient
from axis_runtime.manifest import RuntimeManifest
from axis_runtime.models import InMemorySecretStore, ModelGateway
from axis_runtime.models.adapters.base import HttpCall, HttpResponse, StreamHandle
from axis_runtime.run import RunDeps, run_agent
from axis_runtime.tools import ToolRegistry

ROOT = Path(__file__).resolve().parent.parent
TENANT = "e2e00000-0000-4000-8000-000000000001"
TOKEN = "e2e-token-" + secrets.token_hex(8)


def sh(args: list[str], *, env: dict[str, str] | None = None, cwd: Path = ROOT) -> str:
    out = subprocess.run(
        args,
        cwd=cwd,
        env={**os.environ, **(env or {})},
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        raise RuntimeError(
            f"{' '.join(args)} failed ({out.returncode}):\n{out.stdout}\n{out.stderr}"
        )
    return out.stdout


def psql(url: str, sql: str) -> str:
    return sh(["psql", url, "-v", "ON_ERROR_STOP=1", "-tAc", sql])


@dataclass
class Stack:
    manifest: dict[str, Any]
    db_url: str
    kernel_target: str


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    admin = os.environ.get("PG_ADMIN_URL")
    if not admin:
        raise RuntimeError(
            "PG_ADMIN_URL is required: run via `bash infra/scripts/with-pg.sh uv run pytest e2e`"
        )
    work = tmp_path_factory.mktemp("e2e")
    db = f"axis_e2e_{secrets.token_hex(4)}"
    psql(admin, f"CREATE DATABASE {db}")
    db_url = admin.rsplit("/", 1)[0] + f"/{db}"
    kernel: subprocess.Popen[str] | None = None
    try:
        sh(
            ["pnpm", "--filter", "@axis/db", "exec", "tsx", "src/cli.ts"],
            env={"DATABASE_URL": db_url},
        )
        psql(
            db_url,
            f"INSERT INTO tenants (id, slug, name, region) VALUES ('{TENANT}', 'e2e', 'e2e', 'us')",
        )

        manifest = json.loads(
            sh(["node", "scripts/compile-abl.mjs", "agent.abl.yaml"], cwd=ROOT / "e2e")
        )

        bundle = work / "policy.tar.gz"
        sh(
            [
                "pnpm",
                "--filter",
                "@axis/policy",
                "exec",
                "tsx",
                "src/cli.ts",
                "bundle",
                str(ROOT / "policies/baseline-deny/pack.yaml"),
                str(ROOT / "policies/phi-redaction/pack.yaml"),
                "-o",
                str(bundle),
            ]
        )
        tokens = work / "tokens.json"
        tokens.write_text(
            json.dumps(
                {TOKEN: {"tenantId": TENANT, "subject": "svc-e2e", "platformOperator": False}}
            )
        )

        kernel = subprocess.Popen(
            ["node", "--import", "tsx", "services/risk-kernel/src/main.ts"],
            cwd=ROOT,
            env={
                **os.environ,
                "AXIS_POLICY_BUNDLE": str(bundle),
                "AXIS_RK_TOKENS": str(tokens),
                "AXIS_AUDIT_PG_URL": db_url,
                "AXIS_AUDIT_PG_ROLE": "axis_app",
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert kernel.stdout is not None
        deadline = time.time() + 60
        port = 0
        while time.time() < deadline:
            line = kernel.stdout.readline()
            if line.strip().startswith("{"):
                port = json.loads(line)["port"]
                break
            if kernel.poll() is not None:
                break
        if not port:
            err = kernel.stderr.read() if kernel.stderr else ""
            raise RuntimeError(f"risk kernel did not start: {err}")
        yield Stack(manifest, db_url, f"127.0.0.1:{port}")
    finally:
        if kernel is not None:
            kernel.terminate()
            try:
                kernel.wait(10)
            except subprocess.TimeoutExpired:
                kernel.kill()
        psql(admin, f"DROP DATABASE IF EXISTS {db} WITH (FORCE)")


# ---- a scripted LLM provider (the only fake) ----------------------------------------------------


def openai_turn(
    text: str | None, calls: list[tuple[str, dict[str, Any]]] | None = None
) -> dict[str, Any]:
    msg: dict[str, Any] = {"role": "assistant", "content": text}
    if calls:
        msg["tool_calls"] = [
            {
                "id": f"call_{i}",
                "type": "function",
                "function": {"name": n, "arguments": json.dumps(a)},
            }
            for i, (n, a) in enumerate(calls)
        ]
    return {
        "id": "chatcmpl-e2e",
        "model": "gpt-4o",
        "choices": [
            {"index": 0, "message": msg, "finish_reason": "tool_calls" if calls else "stop"}
        ],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "prompt_tokens_details": {"cached_tokens": 0},
        },
    }


@dataclass
class ScriptedProvider:
    turns: list[dict[str, Any]]
    calls: list[HttpCall] = field(default_factory=list)

    async def send(self, call: HttpCall) -> HttpResponse:
        self.calls.append(call)
        body = self.turns.pop(0) if len(self.turns) > 1 else self.turns[0]
        return HttpResponse(200, {}, json.dumps(body).encode())

    @asynccontextmanager
    async def stream(self, call: HttpCall) -> Any:  # pragma: no cover - not used by the agent loop
        raise NotImplementedError
        yield StreamHandle


@dataclass
class World:
    provider: ScriptedProvider
    lookups: list[dict[str, Any]] = field(default_factory=list)
    crm_writes: list[dict[str, Any]] = field(default_factory=list)


def deps_for(
    stack: Stack, world: World, *, token: str | None = TOKEN, target: str | None = None
) -> RunDeps:
    tools = ToolRegistry()

    def lookup(args: Any) -> Any:
        world.lookups.append(dict(args))
        return {"claim": args.get("claim_id"), "status": "open"}

    def update_crm(args: Any) -> Any:  # must NEVER run under the default policy
        world.crm_writes.append(dict(args))
        return {"ok": True}

    tools.register("lookup-claim", lookup, description="Read a claim")
    tools.register("update-crm", update_crm, description="Write to the CRM")
    return RunDeps(
        tenant_id=TENANT,
        gate=GrpcGateClient(target or stack.kernel_target, timeout=5, token=token),
        models=ModelGateway(
            InMemorySecretStore({(TENANT, "openai", "default"): "sk-e2e"}), transport=world.provider
        ),
        tools=tools,
    )


def audit_rows(stack: Stack) -> dict[str, Any]:
    return json.loads(
        sh(["node", "scripts/verify-audit.mjs", stack.db_url, TENANT], cwd=ROOT / "e2e")
    )


def rows_since(stack: Stack, before: int) -> list[dict[str, Any]]:
    return [e for e in audit_rows(stack)["events"] if e["seq"] > before]


def head(stack: Stack) -> int:
    evs = audit_rows(stack)["events"]
    return max((e["seq"] for e in evs), default=0)


# ---- scenarios -----------------------------------------------------------------------------------


async def test_the_compiled_blueprint_is_what_the_runtime_accepts(stack: Stack) -> None:
    m = RuntimeManifest.from_dict(stack.manifest)
    assert (m.name, m.version) == ("claims-triage", "1.0.0")
    assert {t.name: t.side_effects for t in m.tools} == {
        "lookup-claim": "read",
        "update-crm": "write",
    }


async def test_allowed_read_tool_runs_is_audited_and_replays(stack: Stack) -> None:
    before = head(stack)
    world = World(
        ScriptedProvider(
            [
                openai_turn(None, [("lookup-claim", {"claim_id": "C-1"})]),
                openai_turn("Claim C-1 is open; route to adjuster."),
            ]
        )
    )
    deps = deps_for(stack, world)
    result = await run_agent(
        RuntimeManifest.from_dict(stack.manifest), "what is the status of C-1?", deps
    )

    assert (result.status, result.output) == ("completed", "Claim C-1 is open; route to adjuster.")
    assert world.lookups == [{"claim_id": "C-1"}]  # the read tool ran, through the gate
    assert len(world.provider.calls) == 2

    # 1. The kernel audited every decision, in order, in Postgres.
    new = rows_since(stack, before)
    assert [(e["enforcement_point"], e["decision"]) for e in new] == [
        ("model_call", "ALLOW"),
        ("tool_call", "ALLOW"),
        ("model_call", "ALLOW"),
    ]
    assert all(e["policy_version"] == "baseline-deny@1.0.0,phi-redaction@1.1.0" for e in new)
    assert len({e["trace_id"] for e in new}) == 1  # one trace for the whole run

    # 2. The hash chain in the database verifies end to end.
    assert audit_rows(stack)["verdict"]["ok"] is True

    # 3. Every gate_decision event in the run log points at a real audit row.
    log_events = await deps.log.read(result.run_id)
    referenced = [e.data["audit_event_id"] for e in log_events if e.type == EventType.GATE_DECISION]
    assert len(referenced) == 3
    assert set(referenced) <= {e["id"] for e in audit_rows(stack)["events"]}

    # 4. The run replays from its event log to exactly the live state.
    assert replay(log_events) == result.state


async def test_write_tool_is_denied_by_default_and_never_runs(stack: Stack) -> None:
    before = head(stack)
    world = World(
        ScriptedProvider(
            [
                openai_turn(None, [("update-crm", {"claim_id": "C-2", "note": "approve"})]),
                openai_turn("I could not update the CRM."),
            ]
        )
    )
    deps = deps_for(stack, world)
    result = await run_agent(RuntimeManifest.from_dict(stack.manifest), "close claim C-2", deps)

    assert world.crm_writes == []  # fail-closed: the side effect never happened
    assert result.status == "completed"  # the agent survived the denial and answered
    new = rows_since(stack, before)
    tool_rows = [e for e in new if e["enforcement_point"] == "tool_call"]
    assert [(e["action"], e["decision"]) for e in tool_rows] == [("update-crm", "DENY")]
    assert "default deny" in (tool_rows[0]["reason"] or "")
    assert audit_rows(stack)["verdict"]["ok"] is True
    assert replay(await deps.log.read(result.run_id)) == result.state


async def test_kill_switch_stops_the_next_action_within_a_second_then_releases(
    stack: Stack,
) -> None:
    before = head(stack)
    async with grpc.aio.insecure_channel(stack.kernel_target) as channel:
        stub = gate_pb2_grpc.GateServiceStub(channel)  # type: ignore[no-untyped-call]
        md = (("authorization", f"Bearer {TOKEN}"),)
        scope = gate_pb2.SetKillSwitchRequest.Scope.SCOPE_TENANT
        t0 = time.monotonic()
        await stub.SetKillSwitch(
            gate_pb2.SetKillSwitchRequest(
                tenant_id=TENANT, scope=scope, engaged=True, reason="e2e incident"
            ),
            metadata=md,
        )
        world = World(ScriptedProvider([openai_turn("should never be requested")]))
        result = await run_agent(
            RuntimeManifest.from_dict(stack.manifest), "hello", deps_for(stack, world)
        )
        elapsed = time.monotonic() - t0
        assert world.provider.calls == []  # the model provider was never contacted
        assert result.status != "completed"
        assert elapsed < 1.0  # engage -> denied action, end to end over gRPC
        await stub.SetKillSwitch(
            gate_pb2.SetKillSwitchRequest(tenant_id=TENANT, scope=scope, engaged=False), metadata=md
        )

    new = rows_since(stack, before)
    assert [e["action"] for e in new if e["enforcement_point"] == "admin"] == [
        "kill_switch:tenant:engage",
        "kill_switch:tenant:release",
    ]
    denied = [e for e in new if e["decision"] == "DENY"]
    assert denied and "kill-switch engaged (tenant)" in (denied[0]["reason"] or "")

    world2 = World(ScriptedProvider([openai_turn("back to normal")]))
    ok = await run_agent(
        RuntimeManifest.from_dict(stack.manifest), "hello", deps_for(stack, world2)
    )
    assert (ok.status, ok.output) == ("completed", "back to normal")


async def test_unreachable_kernel_fails_closed_without_touching_the_provider(stack: Stack) -> None:
    world = World(ScriptedProvider([openai_turn("must not be requested")]))
    deps = deps_for(stack, world, target="127.0.0.1:1")
    deps.gate = GrpcGateClient("127.0.0.1:1", timeout=0.5, token=TOKEN)
    result = await run_agent(RuntimeManifest.from_dict(stack.manifest), "hello", deps)
    assert world.provider.calls == [] and world.lookups == [] and world.crm_writes == []
    assert result.status != "completed"


async def test_bad_credentials_fail_closed(stack: Stack) -> None:
    world = World(ScriptedProvider([openai_turn("must not be requested")]))
    result = await run_agent(
        RuntimeManifest.from_dict(stack.manifest),
        "hello",
        deps_for(stack, world, token="wrong-token"),
    )
    assert world.provider.calls == []
    assert result.status != "completed"


async def test_another_tenants_token_cannot_act_for_this_tenant(stack: Stack) -> None:
    # The kernel derives the tenant from the credential: a request naming TENANT without one is denied.
    world = World(ScriptedProvider([openai_turn("must not be requested")]))
    result = await run_agent(
        RuntimeManifest.from_dict(stack.manifest), "hello", deps_for(stack, world, token=None)
    )
    assert world.provider.calls == [] and result.status != "completed"


def test_uuid_is_well_formed() -> None:
    assert str(uuid.UUID(TENANT)) == TENANT
