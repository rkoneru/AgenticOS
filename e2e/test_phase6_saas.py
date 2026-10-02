"""Phase 6 exit check: a new tenant signs up via SSO, configures keys and policies, runs agents and sees accurate metered usage.

Real on the decision and money paths: the control plane (SSO callback, sessions, RBAC/ABAC on the OPA Wasm authorization pack,
SCIM, API keys, BYO key envelope encryption, the policy toolchain that validates and compiles a tenant's pack, region pinning, the
tenant -> database router) on Postgres 16 with forced RLS; the Risk Kernel process over gRPC loading the tenant's OWN activated
policy; the Postgres hash-chained audit log; the Python runtime (HttpSecretStore reading the BYO key from the control plane, TKI
with the tenant's control-plane budgets, NEXUS cache, HttpUsageEmitter on RunDeps.usage); the billing service (usage ledger with
idempotency and RLS, period close and seal, rating with the price book, invoices) on Postgres.

Fakes (and nothing else): the identity provider (a user "logs in" through the SSO flow with a fake IdP), KMS (local master key),
DNS, the model provider (scripted; it records the key it was called with and the tokens it billed), and the payment provider
(`FakePaymentProvider`, Stripe test mode semantics; the real Stripe adapter is only exercised for its live-key refusal).

Run with:  make e2e-phase6
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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from axis_runtime.controlplane import ControlPlaneBridge
from axis_runtime.events import EventType, InMemoryRunEventLog, SystemClock
from axis_runtime.gate import GrpcGateClient
from axis_runtime.manifest import RuntimeManifest
from axis_runtime.models import ModelGateway, ModelTarget
from axis_runtime.models.adapters.base import HttpCall, HttpResponse, StreamHandle
from axis_runtime.models.secrets_http import HttpSecretStore
from axis_runtime.nexus import (
    CacheStage,
    InMemoryCache,
    InMemoryTracer,
    LlmStage,
    NexusRouter,
    RulesStage,
)
from axis_runtime.process import ExitReason
from axis_runtime.run import RunContext, RunDeps
from axis_runtime.tenant_budgets import TenantBudgets
from axis_runtime.tki import (
    InMemoryLedger,
    ListSink,
    MessageRouter,
    Scheduler,
    SchedulerConfig,
    SpawnSpec,
)
from axis_runtime.tki import TkiEventType
from axis_runtime.tki.adapter import agent_workload
from axis_runtime.tki.supervisor import limits_from_manifest
from axis_runtime.tools import ToolRegistry
from axis_runtime.usage import HttpUsageEmitter

ROOT = Path(__file__).resolve().parent.parent

PLATFORM_TOKEN = "e2e-platform-" + secrets.token_hex(8)  # noqa: S105 - a fixture credential
DEV_TOKEN = "e2e-dev-" + secrets.token_hex(8)  # noqa: S105
OPS_TOKEN = "e2e-ops-" + secrets.token_hex(8)  # noqa: S105
REGION, OTHER_REGION = "us-east-1", "eu-west-1"
BYO_KEY = "sk-byo-acme-" + secrets.token_hex(12)  # the key the tenant admin configures; the provider must be called with THIS
BYO_KEY_B = "sk-byo-beta-" + secrets.token_hex(12)


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


# ---- the stack -----------------------------------------------------------------------------------------------------


@dataclass
class Stack:
    manifest: dict[str, Any]
    admin_url: str
    db_url: str
    db2_url: str
    kernel_target: str
    cp: str
    billing: str
    ops_url: str
    work: Path
    bundle_dir: Path
    kernel_tokens: Path
    kernel_tokens_doc: dict[str, Any] = field(default_factory=dict)
    procs: list[subprocess.Popen[str]] = field(default_factory=list)

    async def ops(self, name: str, **body: Any) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=60) as c:
            r = await c.post(
                f"{self.ops_url}/ops/{name}",
                json=body,
                headers={"authorization": f"Bearer {OPS_TOKEN}"},
            )
        assert r.status_code == 200, (name, r.status_code, r.text)
        return r.json()  # type: ignore[no-any-return]

    def grant_kernel_token(self, token: str, tenant: str) -> None:
        """The kernel dev process re-reads its token file when it changes (tenants are created after it started)."""
        self.kernel_tokens_doc[token] = {
            "tenantId": tenant,
            "subject": f"svc-{tenant[:8]}",
            "platformOperator": False,
        }
        tmp = self.kernel_tokens.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.kernel_tokens_doc))
        tmp.replace(self.kernel_tokens)


def _spawn(
    args: list[str], env: dict[str, str], err: Path, cwd: Path = ROOT
) -> tuple[subprocess.Popen[str], str]:
    proc = subprocess.Popen(
        args,
        cwd=cwd,
        env={**os.environ, **env},
        stdout=subprocess.PIPE,
        stderr=err.open("w"),
        text=True,
    )
    assert proc.stdout is not None
    deadline = time.time() + 90
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line.strip().startswith(("{", "listening")):
            return proc, line.strip()
        if proc.poll() is not None:
            break
    proc.kill()
    raise RuntimeError(f"{args} did not start: {err.read_text()}")


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    admin = os.environ.get("PG_ADMIN_URL")
    if not admin:
        raise RuntimeError("PG_ADMIN_URL is required: run via `make e2e-phase6`")
    work = tmp_path_factory.mktemp("e2e6")
    suffix = secrets.token_hex(4)
    dbs = (f"axis_e2e6_{suffix}", f"axis_e2e6d_{suffix}")
    for db in dbs:
        psql(admin, f"CREATE DATABASE {db}")
    base = admin.rsplit("/", 1)[0]
    db_url, db2_url = (f"{base}/{db}" for db in dbs)
    procs: list[subprocess.Popen[str]] = []
    try:
        for url in (db_url, db2_url):  # the control/shared database and the dedicated one: same migrations
            sh(["pnpm", "--filter", "@axis/db", "exec", "tsx", "src/cli.ts"], env={"DATABASE_URL": url})
        manifest = json.loads(
            sh(["node", "scripts/compile-abl.mjs", "agents/claims.abl.yaml"], cwd=ROOT / "e2e")
        )
        bundle_dir = work / "bundles"
        bundle_dir.mkdir()
        tokens = work / "kernel-tokens.json"
        tokens.write_text("{}")
        kernel, line = _spawn(
            ["node", "--import", "tsx", "services/risk-kernel/src/main.ts"],
            {
                "AXIS_POLICY_BUNDLE_DIR": str(bundle_dir),
                "AXIS_RK_TOKENS": str(tokens),
                "AXIS_AUDIT_PG_URL": db_url,
                "AXIS_AUDIT_PG_ROLE": "axis_app",
            },
            work / "kernel.err",
        )
        procs.append(kernel)
        kernel_target = f"127.0.0.1:{json.loads(line)['port']}"
        cfg = work / "saas.json"
        cfg.write_text(
            json.dumps(
                {
                    "db_url": db_url, "db2_url": db2_url, "role": "axis_app", "region": REGION,
                    "other_region": OTHER_REGION, "bundle_dir": str(bundle_dir),
                    "platform_token": PLATFORM_TOKEN, "dev_token": DEV_TOKEN, "ops_token": OPS_TOKEN,
                    "seal_key": "e2e-seal-key-" + secrets.token_hex(16),
                }
            )  # fmt: skip
        )
        saas, line = _spawn(
            ["node", "scripts/saas-stack.mjs", str(cfg)], {}, work / "saas.err", cwd=ROOT / "e2e"
        )
        procs.append(saas)
        _, cp_port, billing_port, ops_port = line.split()
        yield Stack(
            manifest, admin, db_url, db2_url, kernel_target,
            f"http://127.0.0.1:{cp_port}", f"http://127.0.0.1:{billing_port}",
            f"http://127.0.0.1:{ops_port}", work, bundle_dir, tokens, {}, procs,
        )  # fmt: skip
    finally:
        for p in procs:
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
        for db in dbs:
            psql(admin, f"DROP DATABASE IF EXISTS {db} WITH (FORCE)")


# ---- HTTP helpers --------------------------------------------------------------------------------------------------


async def call(
    base: str,
    method: str,
    path: str,
    *,
    token: str | None = None,
    json_body: Any = None,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
) -> httpx.Response:
    h = dict(headers or {})
    if token:
        h["authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(timeout=60, follow_redirects=False) as c:
        return await c.request(method, base + path, headers=h, json=json_body, params=params)


async def admin_call(
    stack: Stack, method: str, path: str, token: str, body: Any = None, **kw: Any
) -> httpx.Response:
    return await call(stack.cp, method, f"/admin/v1{path}", token=token, json_body=body, **kw)


def idp_profile(org: str, uid: str, email: str, **over: Any) -> dict[str, Any]:
    return {
        "id": uid, "email": email, "emailVerified": True, "organizationId": org,
        "connectionType": "oidc", "firstName": uid, **over,
    }  # fmt: skip


async def sso_login(stack: Stack, org: str, profile: dict[str, Any]) -> httpx.Response:
    """The whole browser dance: start (302 to the IdP), the user authenticates at the FAKE IdP, the callback (302 + session cookies)."""
    start = await call(stack.cp, "GET", "/auth/sso/start", params={"org": org})
    assert start.status_code == 302, start.text
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    login_cookie = next(c for c in start.headers.get_list("set-cookie") if c.startswith("__Host-axis_login="))
    code = (await stack.ops("idp/complete", state=state, profile=profile))["code"]
    return await call(
        stack.cp,
        "GET",
        "/auth/sso/callback",
        params={"code": code, "state": state},
        headers={"cookie": login_cookie.split(";")[0]},
    )


def access_token(resp: httpx.Response) -> str:
    assert resp.status_code == 302, (resp.status_code, resp.text)
    for c in resp.headers.get_list("set-cookie"):
        if c.startswith("__Host-axis_at="):
            return c.split("=", 1)[1].split(";")[0]
    raise AssertionError("no session cookie")


def problem_code(resp: httpx.Response) -> str:
    return str(resp.json().get("code"))


# ---- tenants -------------------------------------------------------------------------------------------------------


@dataclass
class Tenant:
    slug: str
    org: str
    id: str = ""
    owner_member: str = ""
    owner_email: str = ""
    owner: str = ""  # the owner's SSO session access token
    kernel_token: str = ""
    runtime_token: str = ""
    ingest_token: str = ""
    read_token: str = ""
    policy_version: str = ""
    members: dict[str, tuple[str, str]] = field(default_factory=dict)  # role -> (member id, session token)
    cache: InMemoryCache | None = None


def short() -> str:
    return secrets.token_hex(3)


async def signup(stack: Stack, slug: str, *, region: str = REGION) -> Tenant:
    """Platform-operated signup (NEEDS #185), the platform links the tenant's IdP organization, then the OWNER signs in through SSO."""
    t = Tenant(slug=slug, org=f"org_{slug}", owner_email=f"owner@{slug}.example")
    r = await call(
        stack.cp, "POST", "/platform/v1/tenants", token=PLATFORM_TOKEN,
        json_body={"slug": slug, "name": f"Tenant {slug}", "owner_email": t.owner_email, "region": region},
    )  # fmt: skip
    assert r.status_code == 201, r.text
    t.id, t.owner_member = r.json()["tenant_id"], r.json()["owner_member_id"]
    await stack.ops("sso-connection", tenant_id=t.id, idp_org_id=t.org, jit_enabled=False)
    t.owner = access_token(await sso_login(stack, t.org, idp_profile(t.org, f"idp-owner-{slug}", t.owner_email)))
    # credentials the platform operator hands the trusted host of this tenant (static, dev bridges)
    t.kernel_token, t.runtime_token = (f"{p}-{slug}-{secrets.token_hex(8)}" for p in ("rk", "rt"))
    t.ingest_token, t.read_token = (f"{p}-{slug}-{secrets.token_hex(8)}" for p in ("bi", "br"))
    stack.grant_kernel_token(t.kernel_token, t.id)
    await stack.ops("runtime-token", tenant_id=t.id, token=t.runtime_token)
    await stack.ops("billing-token", tenant_id=t.id, token=t.ingest_token, scopes=["ingest"], subject=f"rt-{slug}")
    await stack.ops("billing-token", tenant_id=t.id, token=t.read_token, scopes=["read"], subject=f"stmt-{slug}")
    t.cache = InMemoryCache(_Mono())  # type: ignore[arg-type]
    return t


class _Mono:
    def monotonic(self) -> float:
        return time.monotonic()


async def invite_and_login(stack: Stack, t: Tenant, role: str) -> tuple[str, str]:
    """Owner invites a member (HTTP); the member signs in through the same SSO flow (verified e-mail match)."""
    email = f"{role}-{short()}@{t.slug}.example"
    r = await admin_call(stack, "POST", "/members", t.owner, {"email": email, "role": role})
    assert r.status_code == 201, r.text
    token = access_token(await sso_login(stack, t.org, idp_profile(t.org, f"idp-{role}-{short()}", email)))
    t.members[role] = (r.json()["id"], token)
    return r.json()["id"], token


# ---- audit helpers -------------------------------------------------------------------------------------------------


def audit_dump(url: str, tenant: str) -> dict[str, Any]:
    return json.loads(sh(["node", "scripts/verify-audit.mjs", url, tenant], cwd=ROOT / "e2e"))  # type: ignore[no-any-return]


def chain_ok(url: str, tenant: str) -> None:
    verdict = audit_dump(url, tenant)["verdict"]
    assert verdict["ok"] is True, verdict


def events(url: str, tenant: str, point: str | None = None) -> list[dict[str, Any]]:
    return [
        e for e in audit_dump(url, tenant)["events"] if point is None or e["enforcement_point"] == point
    ]


# ---- a scripted model provider (the only fake on the model path) -----------------------------------------------------


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
            {"id": f"call_{i}", "type": "function", "function": {"name": n, "arguments": json.dumps(a)}}
            for i, (n, a) in enumerate(calls)
        ]  # fmt: skip
    return {
        "id": "chatcmpl-e2e",
        "model": "gpt-4o",
        "choices": [{"index": 0, "message": msg, "finish_reason": "tool_calls" if calls else "stop"}],
        "usage": {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "prompt_tokens_details": {"cached_tokens": 0},
        },
    }


def last_user(body: dict[str, Any]) -> str:
    return next(m["content"] for m in reversed(body["messages"]) if m["role"] == "user")


def tool_results(body: dict[str, Any]) -> list[dict[str, Any]]:
    return [m for m in body["messages"] if m["role"] == "tool"]


def claims_handler(body: dict[str, Any]) -> dict[str, Any]:
    ask = last_user(body)
    if ask == "review claim 42":
        if not tool_results(body):
            return openai_turn(
                None,
                [
                    ("lookup-claim", {"claim_id": "42"}),
                    ("lookup-restricted", {"claim_id": "42"}),
                    ("send-report", {"claim_id": "42", "summary": "ok"}),
                ],
                prompt=120,
                completion=30,
            )
        return openai_turn("report filed: " + " | ".join(m["content"][:30] for m in tool_results(body)), prompt=80, completion=20)
    if ask.startswith("heavy"):
        return openai_turn("done", prompt=4000, completion=1000)
    return openai_turn("the policy is: be careful", prompt=50, completion=10)


@dataclass
class Provider:
    handler: Callable[[dict[str, Any]], dict[str, Any]] = claims_handler
    calls: list[dict[str, Any]] = field(default_factory=list)  # {"auth": ..., "prompt": n, "completion": n}

    async def send(self, call: HttpCall) -> HttpResponse:
        body = json.loads(call.body)
        out = self.handler(body)
        self.calls.append(
            {
                "auth": call.headers.get("authorization") or call.headers.get("Authorization"),
                "prompt": out["usage"]["prompt_tokens"],
                "completion": out["usage"]["completion_tokens"],
            }
        )
        return HttpResponse(200, {}, json.dumps(out).encode())

    def stream(self, call: HttpCall) -> Any:  # pragma: no cover - the agent loop does not stream
        raise NotImplementedError
        yield StreamHandle


@dataclass
class Effects:
    looked_up: list[dict[str, Any]] = field(default_factory=list)
    restricted: list[dict[str, Any]] = field(default_factory=list)
    reports: list[dict[str, Any]] = field(default_factory=list)


def make_tools(fx: Effects) -> ToolRegistry:
    tools = ToolRegistry()
    tools.register("lookup-claim", lambda a: fx.looked_up.append(dict(a)) or {"claim": a.get("claim_id"), "status": "open"}, description="Read a claim")  # fmt: skip
    tools.register("lookup-restricted", lambda a: fx.restricted.append(dict(a)) or {"secret": "restricted"}, description="Read a restricted claim")  # fmt: skip
    tools.register("send-report", lambda a: fx.reports.append(dict(a)) or {"filed": True}, description="File a report")  # fmt: skip
    return tools


# ---- running the tenant's agent: control-plane key + budgets, real kernel, TKI, NEXUS, metering --------------------------


@dataclass
class Outcome:
    run_id: str
    exit_reason: ExitReason | None
    log: InMemoryRunEventLog
    provider: Provider
    effects: Effects
    emitted: list[dict[str, Any]]
    tki: ListSink


EMITTED: dict[str, list[dict[str, Any]]] = {}


class SpyEmitter(HttpUsageEmitter):
    """The real HttpUsageEmitter, recording what billing answered (the test asserts on it)."""

    def __init__(self, *a: Any, sink: list[dict[str, Any]], **k: Any) -> None:
        super().__init__(*a, **k)
        self._sink = sink

    async def emit_run(self, log: Any, run_id: str) -> dict[str, Any]:
        out = await super().emit_run(log, run_id)
        self._sink.append(out)
        return out


async def run_claims(
    stack: Stack,
    t: Tenant,
    prompt: str,
    *,
    provider: Provider | None = None,
    run_id: str | None = None,
    meter: bool = True,
    ingest_token: str | None = None,
) -> Outcome:
    manifest = RuntimeManifest.from_dict(stack.manifest)
    provider = provider or Provider()
    fx = Effects()
    log = InMemoryRunEventLog()
    run_id = run_id or f"run-{short()}-{secrets.token_hex(3)}"
    emitted: list[dict[str, Any]] = []
    bridge = ControlPlaneBridge(stack.cp, tenant_id=t.id, token=t.runtime_token)
    emitter = SpyEmitter(stack.billing, token=ingest_token or t.ingest_token, sink=emitted)
    try:
        # (3) the tenant's budgets, produced by the control plane, become the TKI ledger's tenant and run limits
        budgets = TenantBudgets.from_json(await bridge.budget_config())
        sink, clock = ListSink(), SystemClock()
        ledger = InMemoryLedger(sink)
        budgets.apply_to_ledger(ledger, t.id)

        async def no_ipc(_env: Any) -> bool:
            return False

        sched = Scheduler(
            ledger=ledger,
            router=MessageRouter(sink=sink, authorize=no_ipc, clock=clock),
            sink=sink,
            clock=clock,
            config=SchedulerConfig(max_running=4, default_tenant_limit=4),
        )
        # (2) the BYO key comes from the control plane; the model gateway never sees any other source
        deps = RunDeps(
            tenant_id=t.id,
            gate=GrpcGateClient(stack.kernel_target, timeout=5, token=t.kernel_token),
            models=ModelGateway(HttpSecretStore(bridge), transport=provider),
            tools=make_tools(fx),
            log=log,
            run_id=run_id,
            usage=emitter if meter else None,
        )
        tracer = InMemoryTracer()
        mono = _Mono()

        def nexus(ctx: RunContext) -> NexusRouter:
            p = manifest.primary
            stages = {
                "cache": CacheStage(t.cache, mono, ttl_seconds=300),  # type: ignore[arg-type]
                "rules": RulesStage([]),
                "llm": LlmStage(ctx.runner, ModelTarget(p.provider, p.model, p.endpoint, p.params)),
            }
            return NexusRouter.from_manifest(manifest, stages, tracer=tracer, sink=ctx.nexus_event_sink(), clock=mono)  # type: ignore[arg-type]

        deps.nexus_factory = nexus
        pid = sched.spawn(
            SpawnSpec(
                tenant_id=t.id,
                agent="claims@1.0.0",
                run_id=run_id,
                limits=budgets.spawn_limits(limits_from_manifest(manifest)),
            ),
            agent_workload(manifest, prompt, deps),
        )
        view = await asyncio.wait_for(sched.wait(pid), 90)
        return Outcome(run_id, view.exit_reason, log, provider, fx, emitted, sink)
    finally:
        await bridge.aclose()
        await emitter.aclose()


def provider_tokens(*providers: Provider) -> tuple[int, int]:
    """What the model provider itself billed: the independent source of truth for token metering."""
    return (
        sum(c["prompt"] for p in providers for c in p.calls),
        sum(c["completion"] for p in providers for c in p.calls),
    )


def running_ms(events_: list[Any]) -> int:
    """Independent recomputation of runtime: milliseconds each process spent RUNNING, from the run log's transitions."""
    since: dict[str, float] = {}
    total = 0.0
    for e in events_:
        if e.type != EventType.PROCESS_TRANSITION or e.pid is None:
            continue
        ts = datetime.fromisoformat(e.ts).timestamp() * 1000
        if e.pid in since:
            total += ts - since.pop(e.pid)
        if e.data.get("to") == "running":
            since[e.pid] = ts
    return int(total)


# ---- shared scenario state -----------------------------------------------------------------------------------------


@dataclass
class Scenario:
    a: Tenant | None = None
    b: Tenant | None = None
    runs: list[Outcome] = field(default_factory=list)
    providers: list[Provider] = field(default_factory=list)


S = Scenario()


def tenant_a() -> Tenant:
    assert S.a is not None, "scenario order: signup first"
    return S.a


def tenant_b() -> Tenant:
    assert S.b is not None
    return S.b


# ==== (1) SSO signup -> tenant provisioned -> owner session ===========================================================


async def test_01_a_new_tenant_signs_up_and_its_owner_logs_in_through_sso(stack: Stack) -> None:
    a = S.a = await signup(stack, f"acme-{short()}")
    assert a.id and a.owner
    me = await admin_call(stack, "GET", "/tenant", a.owner)
    assert me.status_code == 200 and me.json()["id"] == a.id
    members = (await admin_call(stack, "GET", "/members", a.owner)).json()["items"]
    assert [m["email"] for m in members] == [a.owner_email] and members[0]["role"] == "owner"
    # signup published the baseline-deny floor for the kernel, before anything else happened
    assert (stack.bundle_dir / f"{a.id}.tar.gz").exists()
    packs = (await admin_call(stack, "GET", "/policies", a.owner)).json()["items"]
    assert [(p["pack"], p["active"]) for p in packs] == [("baseline-deny", True)]
    # the tenant's own chain records the provisioning and the SSO login
    acts = [(e["action"], e["decision"]) for e in events(stack.db_url, a.id, "admin")]
    assert ("tenant.provision", "ALLOW") in acts and ("auth.sso_login", "ALLOW") in acts
    chain_ok(stack.db_url, a.id)
    S.b = await signup(stack, f"beta-{short()}")


async def test_02_sso_refuses_a_forged_replayed_or_foreign_login(stack: Stack) -> None:
    a = tenant_a()
    # an organization nobody linked
    start = await call(stack.cp, "GET", "/auth/sso/start", params={"org": "org_unknown"})
    assert start.status_code in (401, 404, 422), start.text
    # a callback with a state that does not match the login cookie (login CSRF)
    start = await call(stack.cp, "GET", "/auth/sso/start", params={"org": a.org})
    cookie = next(c for c in start.headers.get_list("set-cookie") if c.startswith("__Host-axis_login="))
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    code = (await stack.ops("idp/complete", state=state, profile=idp_profile(a.org, "idp-x", a.owner_email)))["code"]
    bad = await call(stack.cp, "GET", "/auth/sso/callback", params={"code": code, "state": "forged"}, headers={"cookie": cookie.split(";")[0]})
    assert bad.status_code == 401
    # an unverified e-mail never matches a member (account takeover by e-mail)
    r = await sso_login(stack, a.org, idp_profile(a.org, "idp-unv", a.owner_email, emailVerified=False))
    assert r.status_code == 401
    # JIT is off: an IdP user with no member gets nothing
    r = await sso_login(stack, a.org, idp_profile(a.org, "idp-stranger", "stranger@elsewhere.example"))
    assert r.status_code == 401


# ==== (1)(2)(3) the admin configures key, policy and budget over HTTP; the runtime obtains them ============================


async def test_03_admin_configures_the_byo_key_and_a_budget_and_the_runtime_reads_both(stack: Stack) -> None:
    a = tenant_a()
    put = await admin_call(stack, "PUT", "/model-keys/openai/default", a.owner, {"value": BYO_KEY})
    assert put.status_code == 200, put.text
    assert BYO_KEY not in put.text  # never echoed
    listed = await admin_call(stack, "GET", "/model-keys", a.owner)
    assert BYO_KEY not in listed.text and "openai" in listed.text
    r = await admin_call(stack, "PUT", "/budgets", a.owner, {"scope": "tenant", "metric": "tokens", "period": "day", "soft": 80_000, "hard": 100_000})
    assert r.status_code == 200, r.text
    # the runtime (a different principal: the tenant's runtime token) reads exactly what was configured
    bridge = ControlPlaneBridge(stack.cp, tenant_id=a.id, token=a.runtime_token)
    try:
        assert (await HttpSecretStore(bridge).get(a.id, "openai", "default")).reveal() == BYO_KEY
        cfg = TenantBudgets.from_json(await bridge.budget_config())
    finally:
        await bridge.aclose()
    assert any(e.metric == "tokens" and e.hard == 100_000 for e in cfg.tenant)
    # the plaintext is not in the database, in the tenant's chain or in any response
    assert psql(stack.db_url, f"SELECT count(*) FROM model_credentials WHERE ciphertext::text LIKE '%{BYO_KEY}%'").strip() == "0"  # fmt: skip
    assert BYO_KEY not in json.dumps(audit_dump(stack.db_url, a.id)["events"])


def tenant_pack() -> dict[str, Any]:
    return json.loads(  # type: ignore[no-any-return]
        sh(["node", "scripts/yaml-to-json.mjs", "policies/phase6-saas/pack.yaml"], cwd=ROOT / "e2e")
    )


def shape(rows: list[dict[str, Any]]) -> list[tuple[str, str, str]]:
    return [
        (e["enforcement_point"], e["action"], e["decision"])
        for e in rows
        if e["enforcement_point"] != "admin"
    ]


def current_period() -> str:
    return datetime.now(UTC).strftime("%Y-%m")


async def usage_entries(stack: Stack, t: Tenant, period: str) -> list[dict[str, Any]]:
    return (await stack.ops("billing/entries", tenant_id=t.id, period=period))["entries"]  # type: ignore[no-any-return]


# ==== (2) the run: baseline-deny alone, then the tenant's own activated pack =============================================


async def test_04_before_a_pack_is_activated_the_baseline_denies_the_agent_and_nothing_is_billed(
    stack: Stack,
) -> None:
    a = tenant_a()
    o = await run_claims(stack, a, "review claim 42")
    S.runs.append(o)
    assert o.exit_reason is ExitReason.POLICY_DENIED
    assert o.provider.calls == []  # the model was never called, so the BYO key was never used
    assert shape(events(stack.db_url, a.id)) == [("model_call", "openai/gpt-4o", "DENY")]
    # what billing took: the process ran (runtime time) but there is nothing else to bill for a denied action
    metered = await usage_entries(stack, a, current_period())
    assert {e["meter"] for e in metered} <= {"runtime_seconds"}
    chain_ok(stack.db_url, a.id)


async def test_05_the_tenant_publishes_validates_and_activates_a_pack_which_reaches_the_kernel(
    stack: Stack,
) -> None:
    a = tenant_a()
    # a pack that does not compile is refused by the policy toolchain and never becomes active
    broken = {
        "apiVersion": "policy.axis.dev/v1", "kind": "PolicyPack",
        "metadata": {"name": "broken", "version": "1.0.0"},
        "spec": {"defaultDecision": "ALLOW", "rules": [{"id": "x", "enforcementPoints": ["nope"], "decision": "ALLOW"}]},
    }  # fmt: skip
    bad = await admin_call(stack, "POST", "/policies", a.owner, {"policy": broken})
    assert bad.status_code == 422, bad.text
    pub = await admin_call(stack, "POST", "/policies", a.owner, {"policy": tenant_pack()})
    assert pub.status_code == 201, pub.text
    version_id = pub.json()["versionId"]
    before = (stack.bundle_dir / f"{a.id}.tar.gz").read_bytes()
    act = await admin_call(stack, "POST", f"/policies/{version_id}/activate", a.owner)
    assert act.status_code == 200, act.text
    a.policy_version = act.json()["policyVersion"]
    assert (stack.bundle_dir / f"{a.id}.tar.gz").read_bytes() != before  # the kernel's bundle for THIS tenant changed
    items = (await admin_call(stack, "GET", "/policies", a.owner)).json()["items"]
    assert {(p["pack"], p["active"]) for p in items} >= {("baseline-deny", True), ("tenant-acme", True)}
    # baseline-deny can never be switched off
    off = await admin_call(stack, "DELETE", "/policies/baseline-deny", a.owner)
    assert off.status_code == 409
    # another tenant's policy is untouched: tenant B still has only the floor
    packs_b = (await admin_call(stack, "GET", "/policies", tenant_b().owner)).json()["items"]
    assert [p["pack"] for p in packs_b] == ["baseline-deny"]


async def test_06_the_agent_runs_with_the_tenants_policy_and_byo_key_and_the_tenants_deny_is_enforced(
    stack: Stack,
) -> None:
    a = tenant_a()
    n_before = len(events(stack.db_url, a.id))
    o = await run_claims(stack, a, "review claim 42")
    S.runs.append(o)
    S.providers.append(o.provider)
    assert o.exit_reason is ExitReason.COMPLETED
    # the provider was called with the BYO key the admin configured (read from the control plane), twice (tool turn + final)
    assert [c["auth"] for c in o.provider.calls] == [f"Bearer {BYO_KEY}"] * 2
    # the tenant's DENY (priority rule of ITS pack) is enforced: the tool never ran; baseline-allowed and pack-allowed ones did
    assert o.effects.restricted == []
    assert o.effects.looked_up == [{"claim_id": "42"}]
    assert o.effects.reports == [{"claim_id": "42", "summary": "ok"}]
    rows = events(stack.db_url, a.id)[n_before:]
    assert shape(rows) == [
        ("model_call", "openai/gpt-4o", "ALLOW"),  # allowed only because the tenant's pack allows model calls
        ("tool_call", "lookup-claim", "ALLOW"),
        ("tool_call", "lookup-restricted", "DENY"),
        ("tool_call", "send-report", "ALLOW"),
        ("model_call", "openai/gpt-4o", "ALLOW"),
    ]
    # the kernel decided with the policy version the control plane reported at activation
    assert {r["policy_version"] for r in rows if r["enforcement_point"] != "admin"} == {a.policy_version}
    chain_ok(stack.db_url, a.id)
    # the same agent under tenant B (still baseline-deny only) is denied: policy is per tenant
    ob = await run_claims(stack, tenant_b(), "review claim 42")
    assert ob.exit_reason is ExitReason.POLICY_DENIED and ob.provider.calls == []


async def test_07_a_cache_hit_is_gated_but_reaches_no_provider_and_bills_zero_tokens(stack: Stack) -> None:
    a = tenant_a()
    first = await run_claims(stack, a, "summarize policy")
    second = await run_claims(stack, a, "summarize policy")
    S.runs += [first, second]
    S.providers.append(first.provider)
    assert first.exit_reason is ExitReason.COMPLETED and second.exit_reason is ExitReason.COMPLETED
    assert len(first.provider.calls) == 1 and second.provider.calls == []  # the second answer came from the NEXUS cache
    calls = [e for e in await second.log.read(second.run_id) if e.type == EventType.MODEL_CALL]
    assert [c.data["provider"] for c in calls] == ["nexus-cache"] and calls[0].data["input_tokens"] == 0
    # the cache hit is still a gated model_call: the run log has the event, with zero tokens ...
    assert [e.type for e in await second.log.read(second.run_id)].count(EventType.GATE_DECISION) == 1
    # ... and billing took no model tokens for that run (the service saw the event and billed nothing for it)
    assert second.emitted
    metered = await usage_entries(stack, a, current_period())
    by_run = {r: {e["meter"] for e in metered if e["dimensions"].get("run") == r} for r in (first.run_id, second.run_id)}
    assert {"tokens_in", "tokens_out"} <= by_run[first.run_id]
    assert not ({"tokens_in", "tokens_out", "tool_executions"} & by_run[second.run_id])


async def set_budget(stack: Stack, t: Tenant, metric: str, soft: float, hard: float) -> None:
    r = await admin_call(stack, "PUT", "/budgets", t.owner, {"scope": "tenant", "metric": metric, "period": "day", "soft": soft, "hard": hard})  # fmt: skip
    assert r.status_code == 200, r.text


async def test_08_the_tenants_token_hard_cap_from_the_control_plane_stops_the_run(stack: Stack) -> None:
    a = tenant_a()
    await set_budget(stack, a, "tokens", 2_000, 3_000)  # the admin lowers the cap over HTTP
    o = await run_claims(stack, a, "heavy-tokens")  # the provider bills 5000 tokens for the one call
    S.runs.append(o)
    S.providers.append(o.provider)
    assert o.exit_reason is ExitReason.BUDGET_EXCEEDED
    # the process' own ABL cap is 60000 and the run cap 250000: only the TENANT's 3000 (set over HTTP) can have clamped 5000 to 3000
    caps = list(o.tki.of(TkiEventType.BUDGET_HARD_CAP))
    assert [(e.data["resource"], e.data["overrun"]) for e in caps] == [("tokens", 5_000 - 3_000)], [e.data for e in caps]
    committed = sum(e.data["granted"].get("tokens", 0) for e in o.tki.of(TkiEventType.BUDGET_COMMITTED))
    assert committed <= 3_000  # the cap held: never more than the tenant's hard cap was committed
    # metering is independent of the cap: the provider DID bill 5000 tokens, and the ledger says so
    assert o.provider.calls and (o.provider.calls[0]["prompt"], o.provider.calls[0]["completion"]) == (4000, 1000)
    await set_budget(stack, a, "tokens", 80_000, 100_000)


async def test_09_the_tenants_cost_hard_cap_from_the_control_plane_stops_the_run(stack: Stack) -> None:
    a = tenant_a()
    await set_budget(stack, a, "cost_usd", 0.0005, 0.001)
    o = await run_claims(stack, a, "heavy-cost")
    S.runs.append(o)
    S.providers.append(o.provider)
    assert o.exit_reason is ExitReason.BUDGET_EXCEEDED
    caps = list(o.tki.of(TkiEventType.BUDGET_HARD_CAP))
    assert [e.data["resource"] for e in caps] == ["cost_micro_usd"] and caps[0].data["overrun"] > 0
    spent = sum(e.data["granted"].get("cost_micro_usd", 0) for e in o.tki.of(TkiEventType.BUDGET_COMMITTED))
    assert spent <= 1_000  # $0.001: the cap held
    await set_budget(stack, a, "cost_usd", 80, 100)
    # with the caps restored the same agent completes again (the caps, not the agent, stopped the runs)
    ok = await run_claims(stack, a, "heavy-after")
    S.runs.append(ok)
    S.providers.append(ok.provider)
    assert ok.exit_reason is ExitReason.COMPLETED


# ==== (4) metering: the ledger equals what an independent recomputation says =============================================


def by_meter(totals: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for t in totals:
        out[t["meter"]] = out.get(t["meter"], 0) + int(t["quantity"])
    return out


async def independent_expectation(stack: Stack, a: Tenant) -> dict[str, int]:
    """What the ledger MUST say, from sources the billing service never touched: the model provider's own token counts, the
    tenant's audit chain (ALLOWed tool calls) and the runs' event logs (time spent RUNNING)."""
    tokens_in, tokens_out = provider_tokens(*S.providers)
    tool_rows = [e for e in events(stack.db_url, a.id, "tool_call") if e["decision"] == "ALLOW"]
    runtime = 0
    for o in S.runs:
        runtime += running_ms(await o.log.read(o.run_id))
    return {
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "tool_executions": len(tool_rows),
        "runtime_seconds": runtime,
    }


async def test_10_the_ledger_equals_totals_recomputed_from_the_audit_chain_and_the_run_logs(stack: Stack) -> None:
    a = tenant_a()
    period = current_period()
    ledger = by_meter((await stack.ops("billing/totals", tenant_id=a.id, period=period))["totals"])
    want = await independent_expectation(stack, a)
    assert want["tokens_in"] == 200 + 50 + 3 * 4000 and want["tokens_out"] == 50 + 10 + 3 * 1000  # sanity of the scenario itself
    assert want["tool_executions"] == 2  # lookup-claim and send-report; the DENIED lookup-restricted is not billed
    assert {k: ledger.get(k, 0) for k in want} == want, (ledger, want)
    assert set(ledger) <= {"tokens_in", "tokens_out", "tool_executions", "runtime_seconds"}
    # per run: the denied run, the cache hit and the cap-stopped runs each carry exactly what they spent
    entries = await usage_entries(stack, a, period)
    per_run: dict[str, dict[str, int]] = {}
    for e in entries:
        per_run.setdefault(e["dimensions"]["run"], {}).setdefault(e["meter"], 0)
        per_run[e["dimensions"]["run"]][e["meter"]] += int(e["quantity"])
    denied, full, miss, hit, tok_cap, cost_cap, after = (r.run_id for r in S.runs)
    assert not {"tokens_in", "tokens_out", "tool_executions"} & set(per_run.get(denied, {}))
    assert {k: v for k, v in per_run[full].items() if k != "runtime_seconds"} == {"tokens_in": 200, "tokens_out": 50, "tool_executions": 2}  # fmt: skip
    assert not {"tokens_in", "tokens_out", "tool_executions"} & set(per_run.get(hit, {}))  # cache hit: zero tokens
    assert per_run[tok_cap]["tokens_in"] == 4000 and per_run[tok_cap]["tokens_out"] == 1000  # the provider billed it, the cap stopped the run
    # the tenant sees the same numbers through the billing read API (a statement), with ITS read credential
    st = await call(stack.billing, "GET", "/v1/usage/statement", token=a.read_token, params={"period": period})
    assert st.status_code == 200, st.text
    assert by_meter(st.json()["totals"]) == ledger
    # and nothing of tenant B's is in tenant A's ledger
    assert (await stack.ops("billing/totals", tenant_id=tenant_b().id, period=period))["totals"] == []


async def test_11_replayed_conflicting_and_forged_usage_cannot_change_the_ledger(stack: Stack) -> None:
    from axis_runtime.usage import project_event

    a, b = tenant_a(), tenant_b()
    period = current_period()
    before = (await stack.ops("billing/totals", tenant_id=a.id, period=period))["totals"]
    full = S.runs[1]
    events_ = await full.log.read(full.run_id)
    proj = [p for e in events_ if (p := project_event(e)) is not None]

    async def post(token: str | None, body: dict[str, Any]) -> httpx.Response:
        return await call(stack.billing, "POST", "/v1/usage/run-events", token=token, json_body=body)

    # replay: the same run sent again is a no-op (idempotency keys), reported as duplicates
    again = await post(a.ingest_token, {"run_id": full.run_id, "events": proj})
    assert again.status_code == 200 and again.json()["inserted"] == 0 and again.json()["duplicates"] >= 1
    # a conflicting payload under an existing key is rejected and reported, never applied
    tampered = json.loads(json.dumps(proj))
    for p in tampered:
        if p["type"] == "model_call":
            p["data"]["output_tokens"] += 1_000_000
    conflict = await post(a.ingest_token, {"run_id": full.run_id, "events": tampered})
    assert conflict.status_code == 200 and conflict.json()["inserted"] == 0 and conflict.json()["conflicts"] >= 1
    assert (await stack.ops("billing/conflicts", tenant_id=a.id))["conflicts"]
    # forged usage for another tenant: the ingest token fixes the tenant
    forged_events = json.loads(json.dumps(proj))
    for p in forged_events:
        if p["type"] == "run_started":
            p["data"]["tenant_id"] = b.id
    r = await post(a.ingest_token, {"run_id": full.run_id, "events": forged_events})
    assert r.status_code == 403  # the run says it belongs to B, the credential says A
    r = await post(a.ingest_token, {"tenant_id": b.id, "run_id": full.run_id, "events": proj})
    assert r.status_code == 403  # a tenant named in the body is never honoured
    r = await post(b.ingest_token, {"run_id": full.run_id, "events": proj})
    assert r.status_code == 403  # B's runtime cannot bill A's run (run_started names A)
    r = await call(stack.billing, "GET", "/v1/usage/statement", token=b.read_token, params={"period": period, "tenant_id": a.id})
    assert r.status_code == 403
    # credentials are scoped: read cannot ingest, ingest cannot read, anonymous gets nothing
    assert (await post(a.read_token, {"run_id": full.run_id, "events": proj})).status_code == 403
    assert (await call(stack.billing, "GET", "/v1/usage/statement", token=a.ingest_token, params={"period": period})).status_code == 403
    assert (await post(None, {"run_id": full.run_id, "events": proj})).status_code == 401
    # none of it changed anything
    assert (await stack.ops("billing/totals", tenant_id=a.id, period=period))["totals"] == before
    assert (await stack.ops("billing/totals", tenant_id=b.id, period=period))["totals"] == []


def next_month_start() -> datetime:
    n = datetime.now(UTC)
    return datetime(n.year + (n.month == 12), n.month % 12 + 1, 1, 0, 5, tzinfo=UTC)


def rnd(numerator: int, per: int) -> int:
    return (2 * numerator + per) // (2 * per)  # half up (all quantities are non-negative)


async def test_12_period_close_seal_invoice_and_stripe_fake_reconcile_clean(stack: Stack) -> None:
    a = tenant_a()
    period = current_period()
    totals_open = (await stack.ops("billing/totals", tenant_id=a.id, period=period))["totals"]
    # the month cannot be closed while it is running
    early = await call(stack.ops_url, "POST", "/ops/billing/close", token=OPS_TOKEN, json_body={"tenant_id": a.id, "period": period})
    assert early.status_code == 500 and "PERIOD_NOT_CLOSABLE" in early.text
    await stack.ops("clock", iso=next_month_start().isoformat())
    closed = await stack.ops("billing/close", tenant_id=a.id, period=period)
    assert closed["seal"]["periodId"] == period and closed["seal"]["eventCount"] > 0
    assert (await stack.ops("billing/verify-seal", tenant_id=a.id, period=period))["verdict"] == {"ok": True}
    assert (await stack.ops("billing/totals", tenant_id=a.id, period=period))["totals"] == totals_open  # sealing changes no number
    # the invoice, rated with the price book, equals the invoice recomputed independently from the audit/run/provider numbers
    want = await independent_expectation(stack, a)
    price = {
        "tokens_in": rnd(want["tokens_in"] * 3_000_000, 1_000_000),
        "tokens_out": rnd(want["tokens_out"] * 15_000_000, 1_000_000),
        "tool_executions": rnd(want["tool_executions"] * 1_000, 1),
        "runtime_seconds": rnd(want["runtime_seconds"] * 100, 1_000),
    }
    inv = closed["invoice"]
    lines = {ln["meter"]: int(ln["amountMicro"]) for ln in inv["lines"] if ln["meter"]}
    assert lines == {k: v for k, v in price.items() if want[k] > 0}, (lines, price)
    assert int(inv["totalMicro"]) == 10_000_000 + sum(price.values())  # + the $10 base fee
    assert inv["warnings"] == [] and inv["revision"] == 1
    # push to the Stripe FAKE (test mode) and reconcile: ledger vs provider usage vs our invoice vs the provider's invoice
    pushed = await stack.ops("billing/push", tenant_id=a.id, period=period)
    assert pushed["usage_events"] >= 3 and pushed["provider_invoice"]
    state = await stack.ops("billing/provider-state", tenant_id=a.id)
    assert {u["meter"]: int(u["quantity"]) for u in state["usage"] if u["meter"] != "runtime_seconds"} == {k: v for k, v in want.items() if k != "runtime_seconds"}
    assert int(state["invoices"][0]["totalMinor"]) == rnd(int(inv["totalMicro"]), 10_000)
    report = (await stack.ops("billing/reconcile", tenant_id=a.id, period=period))["report"]
    assert report == {"tenantId": a.id, "periodId": period, "clean": True, "discrepancies": []}
    # the statement shows the sealed period and the invoice
    st = (await call(stack.billing, "GET", "/v1/usage/statement", token=a.read_token, params={"period": period})).json()
    assert st["sealed"] is True and int(st["invoice"]["totalMicro"]) == int(inv["totalMicro"])


async def test_13_injected_provider_faults_are_reported_and_never_silently_fixed(stack: Stack) -> None:
    a = tenant_a()
    period = current_period()
    ledger_before = (await stack.ops("billing/totals", tenant_id=a.id, period=period))["totals"]
    await stack.ops("billing/inject", tenant_id=a.id, period=period, meter="tokens_in", kind="duplicate")
    await stack.ops("billing/inject", tenant_id=a.id, period=period, meter="tool_executions", kind="drop")
    await stack.ops("billing/inject", tenant_id=a.id, period=period, meter="tokens_out", kind="alter")
    provider_before = await stack.ops("billing/provider-state", tenant_id=a.id)
    rep = (await stack.ops("billing/reconcile", tenant_id=a.id, period=period))["report"]
    assert rep["clean"] is False
    kinds = {(d["kind"], d.get("meter")) for d in rep["discrepancies"]}
    assert ("usage_duplicated_at_provider", "tokens_in") in kinds  # the duplicate record
    assert ("usage_missing_at_provider", "tool_executions") in kinds  # the dropped event
    assert ("usage_quantity_mismatch", "tokens_out") in kinds  # an altered quantity
    # reconciliation is read-only: asking again gives the same answer, and neither side changed
    assert (await stack.ops("billing/reconcile", tenant_id=a.id, period=period))["report"] == rep
    assert await stack.ops("billing/provider-state", tenant_id=a.id) == provider_before
    assert (await stack.ops("billing/totals", tenant_id=a.id, period=period))["totals"] == ledger_before
    assert (await stack.ops("billing/verify-seal", tenant_id=a.id, period=period))["verdict"] == {"ok": True}
    st = (await call(stack.billing, "GET", "/v1/usage/statement", token=a.read_token, params={"period": period})).json()
    assert st["invoice"]["revision"] == 1  # nothing re-rated the invoice behind our back
