"""Phase 3 exit check: multi-agent run, budgets, NEXUS stage metrics in the trace, approvals end to end.

Everything on the decision path is real: the ABL compiler (Node), the policy compiler + OPA Wasm bundle, the Risk Kernel
process with the approvals service wired in, gRPC, the Postgres hash-chained audit log with RLS, the Python runtime with its
real executor, TKI scheduler/supervisor/ledger and the NEXUS router. The approvals service is reached over its loopback dev
bridge (docs/NEEDS.md #62), as an approver would and as the runtime's resolver does. The only fake is the LLM provider HTTP
transport (no API keys).

Run with:  make e2e-phase3
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import subprocess
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any

import grpc.aio
import httpx
import pytest
from axis_runtime._gen.axis.runtime.v1 import gate_pb2, gate_pb2_grpc
from axis_runtime.approvals import HttpApprovalResolver
from axis_runtime.events import EventType, SystemClock, replay
from axis_runtime.gate import ActorType, EnforcementPoint, EvaluateRequest, GrpcGateClient
from axis_runtime.manifest import RuntimeManifest
from axis_runtime.models import InMemorySecretStore, ModelGateway, ModelTarget
from axis_runtime.models.adapters.base import HttpCall, HttpResponse, StreamHandle
from axis_runtime.nexus import (
    CacheStage,
    InMemoryCache,
    InMemoryTracer,
    LlmStage,
    NexusRouter,
    RulesStage,
)
from axis_runtime.process import ExitReason, new_pid
from axis_runtime.run import RunContext, RunDeps, RunResult, run_agent
from axis_runtime.tki import (
    InMemoryLedger,
    ListSink,
    MessageRouter,
    Scheduler,
    SchedulerConfig,
    SpawnSpec,
    TkiEventType,
)
from axis_runtime.tki.adapter import agent_workload, tki_spawner_factory
from axis_runtime.tki.budget import AccountKey, ScopeKind
from axis_runtime.tki.supervisor import SupervisorConfig, limits_from_manifest
from axis_runtime.tools import ToolRegistry

ROOT = Path(__file__).resolve().parent.parent
T1 = "e2e00000-0000-4000-8000-0000000000a1"
T2 = "e2e00000-0000-4000-8000-0000000000a2"
TOKEN1 = "e2e-token-1-" + secrets.token_hex(8)
TOKEN2 = "e2e-token-2-" + secrets.token_hex(8)
FINANCE = {"id": "alice", "roles": ["finance-approver"]}
HMAC_KEY = secrets.token_hex(32)


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


# ---- the stack ------------------------------------------------------------------------------------------------


@dataclass
class Kernel:
    target: str
    bridge: str | None
    proc: subprocess.Popen[str]


@dataclass
class Stack:
    manifests: dict[str, dict[str, Any]]
    db_url: str
    kernel: Kernel
    bundle: Path
    tokens: Path
    work: Path
    extra: list[Kernel] = field(default_factory=list)

    @property
    def target(self) -> str:
        return self.kernel.target

    @property
    def bridge(self) -> str:
        assert self.kernel.bridge is not None
        return self.kernel.bridge

    def start_kernel(self, *, approvals: bool) -> Kernel:
        env = {
            **os.environ,
            "AXIS_POLICY_BUNDLE": str(self.bundle),
            "AXIS_RK_TOKENS": str(self.tokens),
            "AXIS_AUDIT_PG_URL": self.db_url,
            "AXIS_AUDIT_PG_ROLE": "axis_app",
        }
        if approvals:
            env["AXIS_APPROVALS_HMAC_KEY"] = HMAC_KEY
            env["AXIS_APPROVALS_DEV_BRIDGE"] = "1"
        err = (self.work / f"kernel-{len(self.extra)}-{approvals}.err").open("w")
        proc = subprocess.Popen(
            ["node", "--import", "tsx", "services/risk-kernel/src/main.ts"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=err,
            text=True,
        )
        assert proc.stdout is not None
        deadline = time.time() + 60
        while time.time() < deadline:
            line = proc.stdout.readline()
            if line.strip().startswith("{"):
                info = json.loads(line)
                k = Kernel(
                    f"127.0.0.1:{info['port']}",
                    f"http://127.0.0.1:{info['approvals_port']}"
                    if info["approvals_port"]
                    else None,
                    proc,
                )
                self.extra.append(k)
                return k
            if proc.poll() is not None:
                break
        raise RuntimeError("risk kernel did not start")


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    admin = os.environ.get("PG_ADMIN_URL")
    if not admin:
        raise RuntimeError("PG_ADMIN_URL is required: run via `make e2e-phase3`")
    work = tmp_path_factory.mktemp("e2e3")
    db = f"axis_e2e3_{secrets.token_hex(4)}"
    psql(admin, f"CREATE DATABASE {db}")
    db_url = admin.rsplit("/", 1)[0] + f"/{db}"
    st: Stack | None = None
    try:
        sh(
            ["pnpm", "--filter", "@axis/db", "exec", "tsx", "src/cli.ts"],
            env={"DATABASE_URL": db_url},
        )
        for tid, slug in ((T1, "e2e3a"), (T2, "e2e3b")):
            psql(
                db_url,
                f"INSERT INTO tenants (id, slug, name, region) VALUES ('{tid}', '{slug}', '{slug}', 'us')",
            )
        manifests = {
            name: json.loads(
                sh(["node", "scripts/compile-abl.mjs", f"agents/{name}.abl.yaml"], cwd=ROOT / "e2e")
            )
            for name in ("lead", "worker-a", "worker-b")
        }
        bundle = work / "policy.tar.gz"
        sh(
            [
                "pnpm", "--filter", "@axis/policy", "exec", "tsx", "src/cli.ts", "bundle",
                str(ROOT / "e2e/policies/phase3-orchestration/pack.yaml"),
                str(ROOT / "policies/phi-redaction/pack.yaml"),
                "-o", str(bundle),
            ]
        )  # fmt: skip
        tokens = work / "tokens.json"
        tokens.write_text(
            json.dumps(
                {
                    TOKEN1: {"tenantId": T1, "subject": "svc-e2e-1", "platformOperator": False},
                    TOKEN2: {"tenantId": T2, "subject": "svc-e2e-2", "platformOperator": False},
                }
            )
        )
        st = Stack(manifests, db_url, Kernel("", None, None), bundle, tokens, work)  # type: ignore[arg-type]
        st.kernel = st.start_kernel(approvals=True)
        yield st
    finally:
        if st is not None:
            for k in st.extra:
                k.proc.terminate()
                try:
                    k.proc.wait(10)
                except subprocess.TimeoutExpired:
                    k.proc.kill()
        psql(admin, f"DROP DATABASE IF EXISTS {db} WITH (FORCE)")


# ---- a scripted LLM provider (the only fake) ------------------------------------------------------------------


def openai_turn(
    text: str | None,
    calls: list[tuple[str, dict[str, Any]]] | None = None,
    *,
    prompt: int = 10,
    completion: int = 5,
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
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "prompt_tokens_details": {"cached_tokens": 0},
        },
    }


@dataclass
class Provider:
    """Answers each request from its content (agents run concurrently, so a fixed order would be fragile)."""

    handler: Callable[[dict[str, Any]], dict[str, Any]]
    calls: list[dict[str, Any]] = field(default_factory=list)

    async def send(self, call: HttpCall) -> HttpResponse:
        body = json.loads(call.body)
        self.calls.append(body)
        return HttpResponse(200, {}, json.dumps(self.handler(body)).encode())

    def stream(self, call: HttpCall) -> Any:  # pragma: no cover - the agent loop does not stream
        raise NotImplementedError
        yield StreamHandle


def tool_results(body: dict[str, Any]) -> list[dict[str, Any]]:
    return [m for m in body["messages"] if m["role"] == "tool"]


def last_user(body: dict[str, Any]) -> str:
    return next(m["content"] for m in reversed(body["messages"]) if m["role"] == "user")


def system_of(body: dict[str, Any]) -> str:
    return body["messages"][0]["content"]


def payer(calls: list[tuple[str, dict[str, Any]]]) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """The lead asks for `calls` once, then reports what the tools said."""

    def handle(body: dict[str, Any]) -> dict[str, Any]:
        done = tool_results(body)
        if not done:
            return openai_turn(None, calls)
        return openai_turn("tool said: " + " | ".join(m["content"][:60] for m in done))

    return handle


# ---- world, deps, audit helpers ---------------------------------------------------------------------------------


@dataclass
class World:
    provider: Provider
    paid: list[dict[str, Any]] = field(default_factory=list)
    wired: list[dict[str, Any]] = field(default_factory=list)
    looked_up: list[dict[str, Any]] = field(default_factory=list)


def make_tools(world: World) -> ToolRegistry:
    tools = ToolRegistry()

    def payments(
        args: Any,
    ) -> Any:  # a side effect that must only ever happen after an approval AND a re-gate
        world.paid.append(dict(args))
        return {"paid": args.get("amount"), "ref": f"PAY-{len(world.paid)}"}

    def wire(args: Any) -> Any:
        world.wired.append(dict(args))
        return {"wired": args.get("amount")}

    def lookup(args: Any) -> Any:
        world.looked_up.append(dict(args))
        return {"claim": args.get("claim_id"), "status": "open"}

    tools.register("payments", payments, description="Pay a vendor")
    tools.register("wire-transfer", wire, description="Wire money")
    tools.register("lookup-claim", lookup, description="Read a claim")
    return tools


class Mono:
    def monotonic(self) -> float:
        return time.monotonic()


def nexus_factory(
    manifest: RuntimeManifest, cache: InMemoryCache, tracer: InMemoryTracer
) -> Callable[[RunContext], NexusRouter]:
    clock = Mono()

    def build(ctx: RunContext) -> NexusRouter:
        p = manifest.primary
        stages = {
            "cache": CacheStage(cache, clock, ttl_seconds=300),
            "rules": RulesStage([]),
            "llm": LlmStage(ctx.runner, ModelTarget(p.provider, p.model, p.endpoint, p.params)),
        }
        return NexusRouter.from_manifest(
            manifest, stages, tracer=tracer, sink=ctx.nexus_event_sink(), clock=clock
        )

    return build


def deps_for(
    stack: Stack,
    world: World,
    *,
    tenant: str = T1,
    token: str = TOKEN1,
    kernel: Kernel | None = None,
    approvals: bool = True,
    nexus: tuple[RuntimeManifest, InMemoryCache, InMemoryTracer] | None = None,
    **kw: Any,
) -> RunDeps:
    k = kernel or stack.kernel
    d = RunDeps(
        tenant_id=tenant,
        gate=GrpcGateClient(k.target, timeout=5, token=token),
        models=ModelGateway(
            InMemorySecretStore({(tenant, "openai", "default"): "sk-e2e"}), transport=world.provider
        ),
        tools=make_tools(world),
        approvals=HttpApprovalResolver(k.bridge, token=token, poll_seconds=2, max_wait_seconds=30)
        if approvals and k.bridge
        else None,
        **kw,
    )
    if nexus is not None:
        d.nexus_factory = nexus_factory(*nexus)
    return d


def audit_dump(stack: Stack, tenant: str = T1) -> dict[str, Any]:
    return json.loads(
        sh(["node", "scripts/verify-audit.mjs", stack.db_url, tenant], cwd=ROOT / "e2e")
    )


def head(stack: Stack, tenant: str = T1) -> int:
    return max((e["seq"] for e in audit_dump(stack, tenant)["events"]), default=0)


def rows_since(stack: Stack, before: int, tenant: str = T1) -> list[dict[str, Any]]:
    return [e for e in audit_dump(stack, tenant)["events"] if e["seq"] > before]


def shape(rows: list[dict[str, Any]]) -> list[tuple[str, str, str]]:
    return [(e["enforcement_point"], e["action"], e["decision"]) for e in rows]


def chain_ok(stack: Stack, tenant: str = T1) -> None:
    verdict = audit_dump(stack, tenant)["verdict"]
    assert verdict["ok"] is True, verdict


class Bridge:
    """The approvals dev bridge as an approver (and as another tenant's service) would call it."""

    def __init__(self, base: str, token: str = TOKEN1) -> None:
        self.http = httpx.AsyncClient(
            base_url=base, headers={"authorization": f"Bearer {token}"}, timeout=10
        )

    async def call(self, route: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        r = await self.http.post(f"/v1/approvals/{route}", json=body)
        return r.status_code, r.json()

    async def pending(
        self, principal: dict[str, Any] = FINANCE, *, n: int = 1, wait_seconds: float = 20
    ) -> list[dict[str, Any]]:
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            _, out = await self.call("list", {"principal": principal, "status": "pending"})
            if len(out["requests"]) >= n:
                return out["requests"]
            await asyncio.sleep(0.02)
        raise AssertionError(f"fewer than {n} pending approvals")

    async def decide(
        self, verb: str, request_id: str, principal: dict[str, Any] = FINANCE
    ) -> tuple[int, dict[str, Any]]:
        return await self.call(verb, {"request_id": request_id, "principal": principal})

    async def close(self) -> None:
        await self.http.aclose()


async def run_lead(stack: Stack, world: World, prompt: str, **kw: Any) -> tuple[RunResult, RunDeps]:
    d = deps_for(stack, world, **kw)
    m = RuntimeManifest.from_dict(stack.manifests["lead"])
    return await run_agent(m, prompt, d), d


async def approve_next(stack: Stack, verb: str = "approve") -> dict[str, Any]:
    b = Bridge(stack.bridge)
    try:
        (req,) = await b.pending()
        status, out = await b.decide(verb, req["id"])
        assert status == 200, out
        return req  # type: ignore[no-any-return]
    finally:
        await b.close()


# ---- compiled blueprints --------------------------------------------------------------------------------------


async def test_the_compiled_blueprints_carry_routing_budgets_and_children(stack: Stack) -> None:
    lead = RuntimeManifest.from_dict(stack.manifests["lead"])
    a = RuntimeManifest.from_dict(stack.manifests["worker-a"])
    assert lead.routing_stages == ("cache", "rules", "llm") == a.routing_stages
    assert {t.name: t.kind for t in lead.tools}["delegate-a"] == "agent"
    assert (a.budgets.tokens.soft, a.budgets.tokens.hard) == (400, 1000)
    assert dict(a.primary.params) == {"max_tokens": 64}  # ABL maxOutputTokens reaches the runtime


# ---- approvals ------------------------------------------------------------------------------------------------


async def test_approval_granted_the_action_runs_once_after_a_re_gate_and_is_audited(
    stack: Stack,
) -> None:
    before = head(stack)
    args = {"amount": 5000, "payee": "acme", "target": "acme-granted"}
    world = World(Provider(payer([("payments", args)])))
    run, approver = await asyncio.gather(run_lead(stack, world, "pay acme"), approve_next(stack))
    result, deps = run
    assert (result.status, result.output) == (
        "completed",
        'tool said: {"paid": 5000, "ref": "PAY-1"}',
    )
    assert world.paid == [args]  # exactly once, with exactly the approved arguments

    rows = rows_since(stack, before)
    assert shape(rows) == [
        ("model_call", "openai/gpt-4o", "ALLOW"),
        (
            "admin",
            "approval.requested",
            "REQUIRE_APPROVAL",
        ),  # the request is opened BEFORE the kernel answers...
        (
            "tool_call",
            "payments",
            "REQUIRE_APPROVAL",
        ),  # ...so its id is in the kernel's own audited decision
        ("admin", "approval.approved", "ALLOW"),
        ("tool_call", "payments", "ALLOW"),  # the gated execution: a second, independent decision
        ("model_call", "openai/gpt-4o", "ALLOW"),
    ]
    request_id = approver["id"]
    assert all(f"request={request_id}" in (r["reason"] or "") for r in rows[1:5])
    assert len({r["trace_id"] for r in rows}) == 1
    assert rows[3]["actor"]["id"] == "alice" and rows[1]["actor"]["type"] == "agent"
    chain_ok(stack)

    # the run log tells the same story and replays to the live state
    log = await deps.log.read(result.run_id)
    decisions = [
        (e.data["decision"], e.data["approval_id"])
        for e in log
        if e.type == EventType.GATE_DECISION and e.data["action"] == "payments"
    ]
    assert decisions == [("REQUIRE_APPROVAL", request_id), ("ALLOW", request_id)]
    assert replay(log) == result.state
    referenced = {e.data["audit_event_id"] for e in log if e.type == EventType.GATE_DECISION}
    assert referenced <= {r["id"] for r in audit_dump(stack)["events"]}


async def test_approval_denied_nothing_executes_and_the_denial_is_audited(stack: Stack) -> None:
    before = head(stack)
    world = World(
        Provider(payer([("payments", {"amount": 4000, "payee": "bob", "target": "bob"})]))
    )
    (result, deps), _ = await asyncio.gather(
        run_lead(stack, world, "pay bob"), approve_next(stack, "deny")
    )
    assert result.status == "completed" and world.paid == []
    rows = rows_since(stack, before)
    assert shape(rows) == [
        ("model_call", "openai/gpt-4o", "ALLOW"),
        ("admin", "approval.requested", "REQUIRE_APPROVAL"),
        ("tool_call", "payments", "REQUIRE_APPROVAL"),
        ("admin", "approval.denied", "DENY"),
        ("model_call", "openai/gpt-4o", "ALLOW"),
    ]  # no tool_call ALLOW: the action never reached the executor's perform
    log = await deps.log.read(result.run_id)
    assert [e.data["reason"] for e in log if e.type == EventType.ACTION_BLOCKED] == [
        "approval_denied"
    ]
    assert "approval_denied" in result.output  # type: ignore[operator]  # the agent was told, and said so
    chain_ok(stack)


async def test_approval_expired_is_fail_closed_and_audited(stack: Stack) -> None:
    before = head(stack)
    world = World(Provider(payer([("wire-transfer", {"amount": 900, "to": "carol"})])))
    t0 = time.monotonic()
    result, deps = await run_lead(
        stack, world, "wire carol"
    )  # nobody approves; the SLA is one second
    assert 0.9 <= time.monotonic() - t0 < 15
    assert result.status == "completed" and world.wired == []
    rows = rows_since(stack, before)
    assert shape(rows) == [
        ("model_call", "openai/gpt-4o", "ALLOW"),
        ("admin", "approval.requested", "REQUIRE_APPROVAL"),
        ("tool_call", "wire-transfer", "REQUIRE_APPROVAL"),
        ("admin", "approval.expired", "DENY"),
        ("model_call", "openai/gpt-4o", "ALLOW"),
    ]
    assert [
        e.data["reason"]
        for e in await deps.log.read(result.run_id)
        if e.type == EventType.ACTION_BLOCKED
    ] == ["approval_expired"]
    chain_ok(stack)


async def test_self_approval_is_rejected_and_the_request_stays_pending(stack: Stack) -> None:
    before = head(stack)
    world = World(
        Provider(payer([("payments", {"amount": 3000, "payee": "dan", "target": "dan"})]))
    )
    b = Bridge(stack.bridge)

    async def attacker_then_approver() -> str:
        (req,) = await b.pending()
        requester = req["requester"]["id"]
        # the agent's own identity, holding the right role, tries to approve its own request
        status, out = await b.decide(
            "approve", req["id"], {"id": requester, "roles": ["finance-approver"]}
        )
        assert (status, out["error"]["code"]) == (403, "SELF_APPROVAL")
        status, out = await b.decide("approve", req["id"], {"id": "mallory", "roles": ["intern"]})
        assert (status, out["error"]["code"]) == (403, "FORBIDDEN_ROLE")
        _, got = await b.call("get", {"request_id": req["id"]})
        assert got["request"]["status"] == "pending"  # neither attempt moved it
        await b.decide("deny", req["id"])  # a real approver ends it (denied)
        return str(req["id"])

    (result, _), request_id = await asyncio.gather(
        run_lead(stack, world, "pay dan"), attacker_then_approver()
    )
    await b.close()
    assert result.status == "completed" and world.paid == []
    rows = rows_since(stack, before)
    assert "approval.approved" not in [r["action"] for r in rows]
    assert [r["action"] for r in rows if r["enforcement_point"] == "admin"] == [
        "approval.requested",
        "approval.denied",
    ]
    assert all(request_id in (r["reason"] or "") for r in rows if r["enforcement_point"] == "admin")
    chain_ok(stack)


async def test_a_cross_tenant_approval_id_is_unusable(stack: Stack) -> None:
    world = World(
        Provider(payer([("payments", {"amount": 2500, "payee": "erin", "target": "erin"})]))
    )
    other = Bridge(stack.bridge, TOKEN2)
    own = Bridge(stack.bridge)

    async def probe_then_approve() -> dict[str, Any]:
        (req,) = await own.pending()
        rid = req["id"]
        # tenant 2's credential: not found, whatever the verb; and a tenant_id in the body changes nothing
        for verb in ("get", "resolve", "approve", "deny", "claim"):
            body = {"request_id": rid, "tenant_id": T1, "principal": {**FINANCE}}
            status, _ = await other.call(verb, body)
            assert status == 404, verb
        assert (await own.call("get", {"request_id": rid}))[1]["request"]["status"] == "pending"
        await own.decide("approve", rid)
        return req  # type: ignore[no-any-return]

    (result, _), req = await asyncio.gather(
        run_lead(stack, world, "pay erin"), probe_then_approve()
    )
    assert world.paid == [
        {"amount": 2500, "payee": "erin", "target": "erin"}
    ]  # the legitimate approval still worked

    # Tenant 2 presents tenant 1's signed, APPROVED record to the kernel for ITS OWN identical action: DENY.
    _, out = await own.call("resolve", {"request_id": req["id"]})
    record = out["record"]
    assert record["outcome"] == "APPROVED" and record["tenant_id"] == T1
    t2 = GrpcGateClient(stack.target, timeout=5, token=TOKEN2)
    d = await t2.evaluate(
        payment_request(
            T2, result.run_id, {"amount": 2500, "payee": "erin", "target": "erin"}, record
        )
    )
    assert d.decision.value == "DENY" and d.reason == "approval record not valid for this action"
    # ...and tenant 2's own chain shows the denial, tenant 1's chain is untouched by it
    assert [e["decision"] for e in audit_dump(stack, T2)["events"]][-1] == "DENY"
    chain_ok(stack, T1)
    chain_ok(stack, T2)
    await other.close()
    await own.close()


def payment_request(
    tenant: str,
    run_id: str,
    args: dict[str, Any],
    approval: dict[str, Any] | None = None,
    *,
    tool: str = "payments",
    trace: str | None = None,
) -> EvaluateRequest:
    ctx: dict[str, Any] = {
        "tool": {"name": tool, "kind": "function", "side_effects": "external"},
        "args": args,
        "run": {"id": run_id},
    }
    if approval is not None:
        ctx["approval"] = approval
    return EvaluateRequest(
        tenant_id=tenant,
        trace_id=trace or secrets.token_hex(16),
        span_id="a" * 16,
        actor_type=ActorType.AGENT,
        actor_id="replayer",
        pid=new_pid(),
        blueprint_name="orchestrator",
        blueprint_version="1.0.0",
        enforcement_point=EnforcementPoint.TOOL_CALL,
        action=tool,
        context=ctx,
    )


async def test_an_approval_is_bound_to_its_action_single_use_and_never_bypasses_the_gate(
    stack: Stack,
) -> None:
    """Driven straight at the kernel: what a replaying or confused client could try with a valid signed record."""
    gate = GrpcGateClient(stack.target, timeout=5, token=TOKEN1)
    b = Bridge(stack.bridge)
    args = {"amount": 1200, "payee": "frank", "target": "frank"}
    run_id = "run_bound_" + secrets.token_hex(4)
    first = await gate.evaluate(payment_request(T1, run_id, args))
    assert first.decision.value == "REQUIRE_APPROVAL" and first.approval_id
    assert (await b.decide("approve", first.approval_id))[0] == 200
    record = (await b.call("resolve", {"request_id": first.approval_id}))[1]["record"]

    async def evaluate(**kw: Any) -> Any:
        base = {"run_id": run_id, "args": args, "approval": record, "tool": "payments"}
        base.update(kw)
        return await gate.evaluate(
            payment_request(T1, base["run_id"], base["args"], base["approval"], tool=base["tool"])
        )

    bad = {
        "other arguments": {"args": {**args, "amount": 1201}},
        "another run": {"run_id": run_id + "-x"},
        "another tool": {"tool": "wire-transfer"},
        "tampered record": {"approval": {**record, "decided_by": "mallory"}},
        "forged outcome": {"approval": {**record, "outcome": "APPROVED", "signature": "AAAA"}},
        "not a record": {"approval": {"request_id": first.approval_id}},
    }
    for name, over in bad.items():
        d = await evaluate(**over)
        assert d.decision.value in ("DENY", "REQUIRE_APPROVAL"), name
        assert d.decision.value != "ALLOW", name

    # kill-switch engaged after the approval: the re-gate denies (an approval is not a bypass)
    async with grpc.aio.insecure_channel(stack.target) as ch:
        stub = gate_pb2_grpc.GateServiceStub(ch)  # type: ignore[no-untyped-call]
        md = (("authorization", f"Bearer {TOKEN1}"),)
        scope = gate_pb2.SetKillSwitchRequest.Scope.SCOPE_TENANT
        await stub.SetKillSwitch(
            gate_pb2.SetKillSwitchRequest(tenant_id=T1, scope=scope, engaged=True, reason="e2e"),
            metadata=md,
        )
        d = await evaluate()
        assert (d.decision.value, d.reason) == ("DENY", "kill-switch engaged (tenant)")
        await stub.SetKillSwitch(
            gate_pb2.SetKillSwitchRequest(tenant_id=T1, scope=scope, engaged=False), metadata=md
        )

    # none of the above consumed it: the exact action is allowed once, and only once
    ok = await evaluate()
    assert ok.decision.value == "ALLOW" and ok.approval_id == first.approval_id
    again = await evaluate()
    assert (again.decision.value, again.reason) == ("DENY", "approval already used")
    chain_ok(stack)
    await b.close()


async def test_caps_still_apply_to_approved_actions_exactly_one_of_two_approved_payments_runs(
    stack: Stack,
) -> None:
    """Two payments of 6000 to one target against a 10000 target cap: both are pending (a pending request reserves nothing),
    both are approved, and the re-gate of the second finds the cap spent."""
    args = {"amount": 6000, "payee": "gina", "target": "gina-cap"}
    w1, w2 = (
        World(Provider(payer([("payments", args)]))),
        World(Provider(payer([("payments", args)]))),
    )
    b = Bridge(stack.bridge)

    # Sequential on purpose: a request holds its gate reservation until the kernel has answered, so two truly
    # simultaneous requests could see each other's transient reservation. Each is pending before the next starts.
    t1 = asyncio.create_task(run_lead(stack, w1, "pay gina 1"))
    await b.pending(n=1)
    t2 = asyncio.create_task(run_lead(stack, w2, "pay gina 2"))
    for r in await b.pending(n=2):
        assert (await b.decide("approve", r["id"]))[0] == 200
    (r1, d1), (r2, d2) = await t1, await t2
    await b.close()
    assert sorted([len(w1.paid), len(w2.paid)]) == [0, 1]  # one ran, one was refused by the re-gate
    refused = d1 if not w1.paid else d2
    loser = r1 if not w1.paid else r2
    log = await refused.log.read(loser.run_id)
    seq = [
        (e.data["decision"], e.data["reason"])
        for e in log
        if e.type == EventType.GATE_DECISION and e.data["action"] == "payments"
    ]
    assert [d for d, _ in seq] == [
        "REQUIRE_APPROVAL",
        "DENY",
    ]  # approved in between, then refused on resume
    assert "target-cap" in seq[1][1], seq[1][1]
    assert [
        e.data["reason"] for e in log if e.type == EventType.ACTION_BLOCKED
    ] == []  # a gate DENY, not a block
    assert world_total(w1, w2) == 6000
    chain_ok(stack)


def world_total(*worlds: World) -> int:
    return sum(int(p["amount"]) for w in worlds for p in w.paid)


async def test_without_an_approvals_service_require_approval_is_denied(stack: Stack) -> None:
    k = stack.start_kernel(approvals=False)
    world = World(
        Provider(payer([("payments", {"amount": 1500, "payee": "hal", "target": "hal"})]))
    )
    before = head(stack)
    result, deps = await run_lead(stack, world, "pay hal", kernel=k, approvals=False)
    assert result.status == "completed" and world.paid == []
    rows = rows_since(stack, before)
    assert ("tool_call", "payments", "REQUIRE_APPROVAL") in shape(
        rows
    )  # the kernel still answered and audited
    assert not [r for r in rows if r["enforcement_point"] == "admin"]  # no request was ever opened
    assert [
        e.data["decision"]
        for e in await deps.log.read(result.run_id)
        if e.type == EventType.GATE_DECISION and e.data["action"] == "payments"
    ] == ["DENY"]
    chain_ok(stack)


# ---- multi-agent run under TKI -----------------------------------------------------------------------------------


def lead_and_worker_handler(body: dict[str, Any]) -> dict[str, Any]:
    sys = system_of(body)
    if "coordinate" in sys:
        if not tool_results(body):
            return openai_turn(
                None, [("delegate-a", {"input": "task A"}), ("delegate-b", {"input": "task B"})]
            )
        return openai_turn(
            "orchestration finished: " + " | ".join(m["content"][:40] for m in tool_results(body))
        )
    if (
        last_user(body) == "task A"
    ):  # worker-a: its provider bill blows through its 1000-token hard cap
        return openai_turn("summary A", prompt=4000, completion=1000)
    return openai_turn("summary B")


@dataclass
class SpyGate:
    inner: GrpcGateClient
    on_request: Callable[[EvaluateRequest], None]

    async def evaluate(self, request: EvaluateRequest) -> Any:
        self.on_request(request)
        return await self.inner.evaluate(request)


async def test_multi_agent_run_budgets_nexus_stage_metrics_and_one_audit_trace(
    stack: Stack,
) -> None:
    before = head(stack)
    trace = secrets.token_hex(16)
    world = World(Provider(lead_and_worker_handler))
    lead = RuntimeManifest.from_dict(stack.manifests["lead"])
    children = {
        "worker-a@^1.0.0": RuntimeManifest.from_dict(stack.manifests["worker-a"]),
        "worker-b@^1.0.0": RuntimeManifest.from_dict(stack.manifests["worker-b"]),
    }
    cache, tracer = InMemoryCache(Mono()), InMemoryTracer()  # type: ignore[arg-type]

    sink, clock = ListSink(), SystemClock()
    ledger = InMemoryLedger(sink)

    async def no_ipc(_env: Any) -> bool:
        return False  # TKI IPC is not exposed to agents (NEEDS #58): deny, never open

    sched = Scheduler(
        ledger=ledger,
        router=MessageRouter(sink=sink, authorize=no_ipc, clock=clock),
        sink=sink,
        clock=clock,
        config=SchedulerConfig(max_running=4, default_tenant_limit=4),
    )
    seen: dict[str, Any] = {}

    def watch(r: EvaluateRequest) -> None:
        # the lead's second model call happens after both children are done and their accounts are closed
        if (
            r.enforcement_point is EnforcementPoint.MODEL_CALL
            and len(world.provider.calls) >= 3
            and "pid" in seen
        ):
            seen["parent_committed"] = dict(
                ledger.usage(AccountKey(T1, ScopeKind.PROCESS, seen["pid"])).committed
            )

    deps = deps_for(
        stack,
        world,
        child_manifests=children,
        trace_id=trace,
        run_id="run-lead",
        nexus=(lead, cache, tracer),
    )
    deps.gate = SpyGate(GrpcGateClient(stack.target, timeout=5, token=TOKEN1), watch)  # type: ignore[assignment]
    factory = tki_spawner_factory(sched, SupervisorConfig(max_children=4), deps)
    pid = sched.spawn(
        SpawnSpec(
            tenant_id=T1,
            agent="orchestrator@1.0.0",
            run_id="run-multi",
            limits=limits_from_manifest(lead),
        ),
        agent_workload(lead, "coordinate the claim review", deps, spawner_factory=factory),
    )
    seen["pid"] = pid
    view = await asyncio.wait_for(sched.wait(pid), 60)

    # -- the parent completed; the offender was stopped alone with budget_exceeded; the sibling was unaffected
    assert view.exit_reason is ExitReason.COMPLETED
    kids = {k.agent: k for k in sched.children_of(pid)}
    assert kids["worker-a@1.0.0"].exit_reason is ExitReason.BUDGET_EXCEEDED
    assert kids["worker-b@1.0.0"].exit_reason is ExitReason.COMPLETED
    assert not sink.of(TkiEventType.PROCESS_RESTARTED)

    def granted(account: str) -> int:
        return sum(
            e.data["granted"].get("tokens", 0)
            for e in sink.of(TkiEventType.BUDGET_COMMITTED)
            if e.data["account"] == account
        )

    a, b = (granted(f"process:{kids[n].pid}") for n in ("worker-a@1.0.0", "worker-b@1.0.0"))
    assert 0 < a <= 1000  # clamped to worker-a's ABL hard cap (5000 were billed)
    assert b == 15
    assert sink.of(TkiEventType.BUDGET_HARD_CAP)
    # -- spend rolled up to the parent: its own first model call + both children's grants
    assert seen["parent_committed"]["tokens"] == 15 + a + b
    assert seen["parent_committed"]["tokens"] <= 60000  # the lead's own ABL hard cap

    # -- the audit chain: every action of every agent, gated, on ONE trace, in order
    rows = rows_since(stack, before)
    assert shape(rows) == [
        ("model_call", "openai/gpt-4o", "ALLOW"),  # lead
        ("tool_call", "delegate-a", "ALLOW"),
        ("model_call", "openai/gpt-4o", "ALLOW"),  # worker-a (then capped)
        ("tool_call", "delegate-b", "ALLOW"),
        ("model_call", "openai/gpt-4o", "ALLOW"),  # worker-b
        ("model_call", "openai/gpt-4o", "ALLOW"),  # lead again
    ]
    assert {r["trace_id"] for r in rows} == {trace}
    chain_ok(stack)

    # -- NEXUS stage metrics are visible in the exported trace (and agree with the audit trace id)
    spans = tracer.export()
    routes = [s for s in spans if s["name"] == "nexus.route"]
    assert len(routes) == 4  # lead x2, worker-a, worker-b
    assert {s["attributes"]["nexus.trace_id"] for s in routes} == {trace}
    stage_spans = [s for s in spans if s["name"].startswith("nexus.stage.")]
    assert [s["name"] for s in stage_spans if s["parent_span_id"] == routes[0]["span_id"]] == [
        "nexus.stage.cache",
        "nexus.stage.rules",
        "nexus.stage.llm",
    ]
    for s in stage_spans:
        assert {
            "nexus.stage",
            "nexus.hit",
            "nexus.cost_usd",
            "nexus.tokens",
            "nexus.latency_ms",
        } <= set(s["attributes"])
    llm_spans = [s for s in stage_spans if s["name"] == "nexus.stage.llm"]
    assert all(
        s["attributes"]["nexus.hit"] is True and s["attributes"]["nexus.cost_usd"] > 0
        for s in llm_spans
    )
    cache_spans = [s for s in stage_spans if s["name"] == "nexus.stage.cache"]
    assert all(
        s["attributes"]["nexus.hit"] is False for s in cache_spans
    )  # first time through: all misses
    # ...and in the run logs (stage name, hit/miss, cost), which replay exactly
    states = {
        rid: replay(await deps.log.read(rid)) for rid in ("run-lead", "run-lead.c1", "run-lead.c2")
    }
    for rid, st in states.items():
        assert [s.stage for s in st.nexus_stages][:3] == ["cache", "rules", "llm"], rid
        assert all(s.outcome == "hit" for s in st.nexus_stages if s.stage == "llm")
        assert all(Decimal(s.cost_usd) >= 0 for s in st.nexus_stages)
    assert len(states["run-lead"].nexus_stages) == 6  # two routed model calls
    cost_a = Decimal(states["run-lead.c1"].nexus_routes[0].total_cost_usd)
    cost_b = Decimal(states["run-lead.c2"].nexus_routes[0].total_cost_usd)
    assert cost_a > cost_b > 0  # the capped worker really was the expensive one


# ---- NEXUS ---------------------------------------------------------------------------------------------------------


async def test_a_cache_hit_second_call_is_cheaper_and_never_reaches_the_gate_or_provider(
    stack: Stack,
) -> None:
    lead = RuntimeManifest.from_dict(stack.manifests["lead"])
    cache, tracer = InMemoryCache(Mono()), InMemoryTracer()  # type: ignore[arg-type]
    prompt = "what is the status of claim C-42? " + secrets.token_hex(4)
    before = head(stack)

    async def one(answer: str) -> tuple[RunResult, World, RunDeps]:
        world = World(Provider(lambda _b: openai_turn(answer, prompt=200, completion=50)))
        d = deps_for(stack, world, nexus=(lead, cache, tracer))
        return await run_agent(lead, prompt, d), world, d

    r1, w1, d1 = await one("claim C-42 is open")
    r2, w2, d2 = await one("MUST NOT BE REQUESTED")
    assert (r1.output, r2.output) == ("claim C-42 is open", "claim C-42 is open")
    assert len(w1.provider.calls) == 1 and len(w2.provider.calls) == 0

    def route_cost(r: RunResult) -> Decimal:
        return Decimal(r.state.nexus_routes[0].total_cost_usd)

    assert route_cost(r1) > 0 and route_cost(r2) == 0  # cheaper
    assert [(s.stage, s.outcome) for s in r1.state.nexus_stages] == [
        ("cache", "miss"),
        ("rules", "miss"),
        ("llm", "hit"),
    ]
    assert [(s.stage, s.outcome, s.cost_usd) for s in r2.state.nexus_stages] == [
        ("cache", "hit", "0")
    ]
    assert r2.state.nexus_routes[0].hit_stage == "cache" and r2.state.model_calls == ()
    # the cache hit is not an external action: exactly one model_call row exists for the two runs
    assert shape(rows_since(stack, before)) == [("model_call", "openai/gpt-4o", "ALLOW")]
    # stage metrics are visible in the exported trace, tied to the run's trace id
    trace_ids = [
        s["attributes"]["nexus.trace_id"] for s in tracer.export() if s["name"] == "nexus.route"
    ]
    assert len(trace_ids) == 2 and trace_ids[0] != trace_ids[1]
    second_route = [s for s in tracer.export() if s["name"] == "nexus.route"][1]
    kids = [s for s in tracer.export() if s["parent_span_id"] == second_route["span_id"]]
    assert [
        (k["name"], k["attributes"]["nexus.hit"], k["attributes"]["nexus.cost_usd"]) for k in kids
    ] == [("nexus.stage.cache", True, 0.0)]
    assert (
        replay(await d1.log.read(r1.run_id)) == r1.state
        and replay(await d2.log.read(r2.run_id)) == r2.state
    )
    chain_ok(stack)
