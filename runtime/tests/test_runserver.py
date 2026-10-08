"""The dev run service (docs/adr/0026): auth, tenant isolation, start/signal/events/SSE/replay over real HTTP."""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import AsyncIterator, Callable, Mapping
from typing import Any

import httpx
import pytest
from axis_runtime.events import InMemoryRunEventLog
from axis_runtime.manifest import RuntimeManifest
from axis_runtime.process import ExitReason
from axis_runtime.run import RunDeps
from axis_runtime.runserver import (
    HttpError,
    RunServer,
    RunServerConfig,
    RunService,
    RunSetup,
)
from axis_runtime.tki import InMemoryLedger, ListSink, MessageRouter, Scheduler, SchedulerConfig
from axis_runtime.tki.supervisor import limits_from_manifest
from conftest import (
    TENANT,
    FakeClock,
    ScriptedGate,
    ScriptedTransport,
    final_body,
    make_deps,
    manifest_dict,
)

OTHER = "22222222-2222-4222-8222-222222222222"
TOKEN_A, TOKEN_B = "tok-a-" + secrets.token_hex(8), "tok-b-" + secrets.token_hex(8)  # noqa: S105
BP = {"name": "claims-triage", "version": "1.0.0"}
READ_A, READ_B = "rd-a-" + secrets.token_hex(8), "rd-b-" + secrets.token_hex(8)  # noqa: S105


def rid() -> str:
    h = secrets.token_hex(16)
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-8{h[17:20]}-{h[20:32]}"


class Env:
    def __init__(self) -> None:
        self.gate = ScriptedGate()
        self.release: asyncio.Event | None = None
        self.factory_calls: list[tuple[str, str, Mapping[str, Any]]] = []
        self.fail_factory = False
        self.use_tki = False
        self.service = RunService(self.factory)
        self.server = RunServer(
            self.service,
            RunServerConfig(
                tokens={TOKEN_A: TENANT, TOKEN_B: OTHER},
                read_tokens={READ_A: TENANT, READ_B: OTHER},
                max_body_bytes=4096,
                sse_poll_seconds=0.01,
                max_active_runs_per_tenant=3,
            ),
        )
        self.base = ""

    async def factory(
        self, tenant: str, manifest: RuntimeManifest, principal: Mapping[str, Any]
    ) -> RunSetup:
        self.factory_calls.append((tenant, manifest.name, principal))
        if self.fail_factory:
            raise HttpError(503, "tenant budgets are unavailable")
        transport = ScriptedTransport([(200, final_body("done"))])
        if self.release is not None:
            ev = self.release

            async def wait() -> None:
                await ev.wait()

            transport.delay = wait
        deps = make_deps(gate=self.gate, transport=transport, clock=FakeClock())
        if not self.use_tki:
            return RunSetup(deps=deps)
        sink, clock = ListSink(), FakeClock()
        ledger = InMemoryLedger(sink)

        async def no_ipc(_e: Any) -> bool:
            return False

        sched = Scheduler(
            ledger=ledger,
            router=MessageRouter(sink=sink, authorize=no_ipc, clock=clock),
            sink=sink,
            clock=clock,
            config=SchedulerConfig(max_running=2, default_tenant_limit=2),
        )
        return RunSetup(deps=deps, scheduler=sched, limits=limits_from_manifest(manifest))

    async def call(
        self,
        method: str,
        path: str,
        token: str | None = TOKEN_A,
        body: Any = None,
        headers: dict[str, str] | None = None,
        raw: bytes | None = None,
    ) -> httpx.Response:
        h = dict(headers or {})
        if token:
            h["authorization"] = f"Bearer {token}"
        async with httpx.AsyncClient(timeout=10) as c:
            return await c.request(
                method, self.base + path, headers=h, json=body if raw is None else None, content=raw
            )

    def start_body(self, **over: Any) -> dict[str, Any]:
        b: dict[str, Any] = {
            "run_id": rid(),
            "trace_id": secrets.token_hex(16),
            "blueprint": BP,
            "manifest": manifest_dict(),
            "input": {"prompt": "review claim 42"},
            "principal": {"id": "member-1", "role": "owner"},
        }
        b.update(over)
        return b

    async def wait_state(self, run_id: str, state: str, token: str = TOKEN_A) -> dict[str, Any]:
        for _ in range(300):
            r = (await self.call("GET", f"/v1/runs/{run_id}", token)).json()
            if r["state"] == state:
                return r  # type: ignore[no-any-return]
            await asyncio.sleep(0.02)
        raise AssertionError(f"run never reached {state}: {r}")


@pytest.fixture
async def env() -> AsyncIterator[Env]:
    e = Env()
    port = await e.server.start()
    e.base = f"http://127.0.0.1:{port}"
    yield e
    await e.server.stop()
    for rec in e.service.runs.values():
        if rec.task and not rec.task.done():
            rec.task.cancel()


async def test_run_completes_and_state_is_the_fold_of_the_log(env: Env) -> None:
    body = env.start_body()
    r = await env.call("POST", "/v1/runs", body=body)
    assert r.status_code == 202, r.text
    assert r.json()["id"] == body["run_id"] and r.json()["trace_id"] == body["trace_id"]
    done = await env.wait_state(body["run_id"], "terminated")
    assert done["exit_reason"] == ExitReason.COMPLETED.value
    assert done["finished_at"] and done["init_pid"].startswith("axp_")
    assert done["tenant_id"] == TENANT  # the gateway cross-checks this field and strips it
    # the tenant and principal given to the factory are the token's and the credential's
    assert env.factory_calls[0][0] == TENANT and env.factory_calls[0][2]["id"] == "member-1"
    # every action went through the injected gate, with the tenant of the TOKEN and the run's trace id
    assert env.gate.requests and all(q.tenant_id == TENANT for q in env.gate.requests)
    assert all(q.trace_id == body["trace_id"] for q in env.gate.requests)
    ev = (await env.call("GET", f"/v1/runs/{body['run_id']}/events?limit=200")).json()
    types = [e["type"] for e in ev["items"]]
    assert types[0] == "run_started" and "model_call" in types and "gate_decision" in types
    assert [e["sequence"] for e in ev["items"]] == list(range(1, len(types) + 1))
    assert all(e["pid"].startswith("axp_") for e in ev["items"])  # run_started carries the init pid
    page = (await env.call("GET", f"/v1/runs/{body['run_id']}/events?limit=2")).json()
    assert len(page["items"]) == 2 and page["next_cursor"] == "2"
    rp = (await env.call("POST", f"/v1/runs/{body['run_id']}/replay")).json()
    assert rp["ok"] and rp["events"] == len(types) and rp["state"] == "terminated"
    assert rp["tokens_used"] > 0


async def test_tenants_are_isolated_on_every_path(env: Env) -> None:
    a = env.start_body()
    assert (await env.call("POST", "/v1/runs", body=a)).status_code == 202
    await env.wait_state(a["run_id"], "terminated")
    rid_ = a["run_id"]
    for method, path, body in [
        ("GET", f"/v1/runs/{rid_}", None),
        ("GET", f"/v1/runs/{rid_}/events", None),
        ("GET", f"/v1/runs/{rid_}/events/stream", None),
        ("POST", f"/v1/runs/{rid_}/signals", {"signal": "KILL"}),
        ("POST", f"/v1/runs/{rid_}/replay", None),
    ]:
        foreign = await env.call(method, path, TOKEN_B, body)
        missing = await env.call(method, path.replace(rid_, rid()), TOKEN_B, body)
        assert foreign.status_code == 404, path
        assert foreign.json() == missing.json(), path  # indistinguishable
    assert (await env.call("GET", "/v1/runs", TOKEN_B)).json()["items"] == []
    assert len((await env.call("GET", "/v1/runs", TOKEN_A)).json()["items"]) == 1
    # B reusing A's run id for its own start is refused, never aliased
    assert (
        await env.call("POST", "/v1/runs", TOKEN_B, env.start_body(run_id=rid_))
    ).status_code == 409
    # a tenant in the body is refused outright
    spoof = env.start_body(tenant_id=OTHER)
    assert (await env.call("POST", "/v1/runs", body=spoof)).status_code == 422


async def test_authentication(env: Env) -> None:
    for tok in (None, "nope", TOKEN_A + "x", TOKEN_A[:-1], ""):
        r = await env.call("GET", "/v1/runs", tok)
        assert r.status_code == 401, tok
        assert r.headers["www-authenticate"].startswith("Bearer")
    r = await env.call("GET", "/v1/runs", headers={"authorization": "Basic abc"}, token=None)
    assert r.status_code == 401
    assert (await env.call("GET", "/v1/runs", TOKEN_B)).status_code == 200
    assert env.factory_calls == []  # nothing ran for an unauthenticated caller


async def test_request_validation_and_limits(env: Env) -> None:
    bad: list[dict[str, Any]] = [
        env.start_body(run_id="nope"),
        env.start_body(trace_id="short"),
        env.start_body(blueprint={"name": "x"}),
        env.start_body(manifest="x"),
        env.start_body(input=[1]),
        env.start_body(manifest=manifest_dict(manifest_version=2)),
        env.start_body(blueprint={"name": "other", "version": "1.0.0"}),
    ]
    for b in bad:
        assert (await env.call("POST", "/v1/runs", body=b)).status_code == 422, b
    assert (await env.call("POST", "/v1/runs", raw=b"{nope")).status_code == 400
    assert (await env.call("POST", "/v1/runs", raw=b"[]")).status_code == 422
    assert (await env.call("POST", "/v1/runs", raw=b"x" * 5000)).status_code == 413
    assert (await env.call("GET", "/v1/nothing")).status_code == 404
    assert (await env.call("DELETE", f"/v1/runs/{rid()}")).status_code in (404, 405)
    assert (await env.call("GET", "/v1/runs?state=bogus")).status_code == 422
    assert (await env.call("GET", "/v1/runs?limit=0")).status_code == 422
    assert (await env.call("GET", "/v1/runs?limit=1&limit=2")).status_code == 422
    assert env.factory_calls == []
    # a chunked body is refused, not misparsed
    async with httpx.AsyncClient() as c:

        async def gen() -> AsyncIterator[bytes]:
            yield b"{}"

        r = await c.post(
            env.base + "/v1/runs", headers={"authorization": f"Bearer {TOKEN_A}"}, content=gen()
        )
    assert r.status_code == 501


async def test_signals_kill_a_running_run(env: Env) -> None:
    env.release = asyncio.Event()
    b = env.start_body()
    assert (await env.call("POST", "/v1/runs", body=b)).status_code == 202
    run = await env.wait_state(b["run_id"], "waiting")
    assert (
        await env.call("POST", f"/v1/runs/{b['run_id']}/signals", body={"signal": "HUP"})
    ).status_code == 422
    unknown = await env.call(
        "POST", f"/v1/runs/{b['run_id']}/signals", body={"signal": "KILL", "pid": "axp_" + "1" * 26}
    )
    assert unknown.status_code == 404
    r = await env.call(
        "POST", f"/v1/runs/{b['run_id']}/signals", body={"signal": "KILL", "reason": "test"}
    )
    assert r.status_code == 200, r.text
    assert r.json() == {"pid": run["init_pid"], "state": "terminated"}
    final = await env.wait_state(b["run_id"], "terminated")
    assert final["exit_reason"] == ExitReason.KILLED.value
    assert (
        await env.call("POST", f"/v1/runs/{b['run_id']}/signals", body={"signal": "RESUME"})
    ).status_code == 409
    env.release.set()


async def test_tki_scheduler_path_signals_and_completes(env: Env) -> None:
    env.use_tki = True
    ok = env.start_body()
    assert (await env.call("POST", "/v1/runs", body=ok)).status_code == 202
    assert (await env.wait_state(ok["run_id"], "terminated"))["exit_reason"] == "completed"
    env.release = asyncio.Event()
    b = env.start_body()
    await env.call("POST", "/v1/runs", body=b)
    await env.wait_state(b["run_id"], "waiting")
    r = await env.call("POST", f"/v1/runs/{b['run_id']}/signals", body={"signal": "KILL"})
    assert r.status_code == 200
    assert (await env.wait_state(b["run_id"], "terminated"))["exit_reason"] in (
        "killed",
        "completed",
        "failed",
    )
    env.release.set()


async def test_sse_streams_the_log_resumes_and_ends(env: Env) -> None:
    b = env.start_body()
    await env.call("POST", "/v1/runs", body=b)
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(
            env.base + f"/v1/runs/{b['run_id']}/events/stream",
            headers={"authorization": f"Bearer {TOKEN_A}"},
        )
        text = r.text
        resumed = await c.get(
            env.base + f"/v1/runs/{b['run_id']}/events/stream",
            headers={"authorization": f"Bearer {TOKEN_A}", "last-event-id": "3"},
        )
        none = await c.get(env.base + f"/v1/runs/{b['run_id']}/events/stream")
    assert r.headers["content-type"].startswith("text/event-stream")
    assert "id: 1\nevent: run_event" in text and text.rstrip().endswith('"reason":"completed"}')
    ids = [int(line[4:]) for line in resumed.text.splitlines() if line.startswith("id: ")]
    assert ids and min(ids) == 4
    assert none.status_code == 401


async def test_list_filters_and_cursor(env: Env) -> None:
    ids = []
    for _ in range(3):
        b = env.start_body()
        await env.call("POST", "/v1/runs", body=b)
        await env.wait_state(b["run_id"], "terminated")
        ids.append(b["run_id"])
        await asyncio.sleep(0.002)
    p1 = (await env.call("GET", "/v1/runs?limit=2")).json()
    assert len(p1["items"]) == 2 and p1["next_cursor"]
    p2 = (await env.call("GET", f"/v1/runs?limit=2&cursor={p1['next_cursor']}")).json()
    assert len(p2["items"]) == 1 and p2["next_cursor"] is None
    assert {r["id"] for r in p1["items"] + p2["items"]} == set(ids)
    assert (await env.call("GET", "/v1/runs?state=running")).json()["items"] == []
    assert (
        len(
            (await env.call("GET", "/v1/runs?state=terminated&blueprint=claims-triage")).json()[
                "items"
            ]
        )
        == 3
    )
    assert (await env.call("GET", "/v1/runs?blueprint=other")).json()["items"] == []


async def test_active_run_cap_and_factory_failure(env: Env) -> None:
    env.release = asyncio.Event()
    for _ in range(3):
        assert (await env.call("POST", "/v1/runs", body=env.start_body())).status_code == 202
    capped = await env.call("POST", "/v1/runs", body=env.start_body())
    assert capped.status_code == 429 and capped.headers["retry-after"] == "1"
    assert (
        await env.call("POST", "/v1/runs", TOKEN_B, env.start_body())
    ).status_code == 202  # per tenant
    env.release.set()
    env.fail_factory = True
    n = len(env.service.runs)
    r = await env.call("POST", "/v1/runs", TOKEN_B, env.start_body())
    assert r.status_code == 503 and len(env.service.runs) == n  # fail closed, nothing recorded


async def test_workload_crash_is_reported_not_left_running(env: Env) -> None:
    async def crash(*_a: Any) -> RunSetup:
        deps = make_deps(gate=ScriptedGate(), transport=ScriptedTransport([(200, final_body())]))
        deps.gate = None  # type: ignore[assignment]  # the first gate call raises
        return RunSetup(deps=deps)

    env.service.factory = crash
    b = env.start_body()
    assert (await env.call("POST", "/v1/runs", body=b)).status_code == 202
    final = await env.wait_state(b["run_id"], "terminated")
    assert final["exit_reason"] in ("failed", "policy_denied")


async def test_corrupt_log_is_a_server_error_and_replay_reports_it(env: Env) -> None:
    b = env.start_body()
    await env.call("POST", "/v1/runs", body=b)
    await env.wait_state(b["run_id"], "terminated")
    log = env.service.log
    assert isinstance(log, InMemoryRunEventLog)
    events = log._runs[b["run_id"]]  # noqa: SLF001 - tamper with the stored log
    import dataclasses

    events[2] = dataclasses.replace(events[2], data={**events[2].data, "tampered": True})
    rp = (await env.call("POST", f"/v1/runs/{b['run_id']}/replay")).json()
    assert rp["ok"] is False and rp["seq"] == 3
    assert (await env.call("GET", f"/v1/runs/{b['run_id']}")).status_code == 500


def test_event_dto_shapes() -> None:
    from axis_runtime.events import seal_event

    e = seal_event(
        run_id=rid(), seq=1, ts="2026-10-02T00:00:00.000Z", type="gate_decision", pid=None,
        data={"audit_event_id": "123e4567-e89b-42d3-a456-426614174000"}, prev_hash="0" * 64,
    )  # fmt: skip
    d = RunService.event_dto(e, None)
    assert (
        d["pid"] == "axp_" + "0" * 26
        and d["audit_event_id"] == "123e4567-e89b-42d3-a456-426614174000"
    )
    e2 = seal_event(
        run_id=rid(), seq=1, ts="2026-10-02T00:00:00.000Z", type="x", pid="bad",
        data={"audit_event_id": ""}, prev_hash="0" * 64,
    )  # fmt: skip
    d2 = RunService.event_dto(e2, "axp_" + "1" * 26)
    assert d2["pid"] == "axp_" + "1" * 26 and "audit_event_id" not in d2


_unused: Callable[..., Any] = lambda: RunDeps  # noqa: E731


# ---- the read-only completed-runs feed for the online eval sampler -------------------------------------------------------


async def test_completed_runs_feed_is_read_only_tenant_scoped_and_redacted(env: Env) -> None:
    secret = "sk-" + "a1B2c3D4" * 4
    done = env.start_body()
    assert (await env.call("POST", "/v1/runs", body=done)).status_code == 202
    await env.wait_state(done["run_id"], "terminated")
    other = env.start_body(blueprint={"name": "other-agent", "version": "2.0.0"})
    other["manifest"] = manifest_dict(
        blueprint={"name": "other-agent", "version": "2.0.0", "content_hash": "b" * 64}
    )
    assert (await env.call("POST", "/v1/runs", TOKEN_A, other)).status_code == 202
    await env.wait_state(other["run_id"], "terminated")

    feed = (await env.call("GET", "/v1/completed-runs", READ_A)).json()["items"]
    assert {i["run_id"] for i in feed} == {done["run_id"], other["run_id"]}
    row = next(i for i in feed if i["run_id"] == done["run_id"])
    assert row["blueprint"] == "claims-triage" and row["version"] == "1.0.0"
    assert len(row["content_hash"]) == 64 and row["completed_at"] and row["phi"] is False
    assert row["trace"]["exit_reason"] == "completed" and row["trace"]["events_hash"]
    assert row["output"] == "done" and "input" not in row and "input_text" not in row
    # filters: blueprint name, since (inclusive), limit
    only = (await env.call("GET", "/v1/completed-runs?blueprint=other-agent", READ_A)).json()
    assert [i["run_id"] for i in only["items"]] == [other["run_id"]]
    late = (await env.call("GET", "/v1/completed-runs?since=2999-01-01T00:00:00Z", READ_A)).json()
    assert late["items"] == []
    one = (await env.call("GET", "/v1/completed-runs?limit=1", READ_A)).json()["items"]
    assert len(one) == 1
    assert (await env.call("GET", "/v1/completed-runs?limit=0", READ_A)).status_code == 422
    # another tenant's read credential sees none of it
    assert (await env.call("GET", "/v1/completed-runs", READ_B)).json()["items"] == []
    assert secret not in str(feed)


async def test_completed_runs_scrubs_credentials_from_the_output() -> None:
    secret = "sk-" + "a1B2c3D4" * 4
    log = InMemoryRunEventLog()
    clock = FakeClock()

    async def factory(
        tenant: str, manifest: RuntimeManifest, principal: Mapping[str, Any]
    ) -> RunSetup:
        t = ScriptedTransport([(200, final_body(f"your key is {secret}, keep it"))])
        return RunSetup(deps=make_deps(gate=ScriptedGate(), transport=t, clock=clock))

    svc = RunService(factory, log, clock)
    server = RunServer(svc, RunServerConfig(tokens={TOKEN_A: TENANT}, read_tokens={READ_A: TENANT}))
    port = await server.start()
    base = f"http://127.0.0.1:{port}"
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            body = {
                "run_id": rid(),
                "trace_id": secrets.token_hex(16),
                "blueprint": BP,
                "manifest": manifest_dict(),
                "input": {"prompt": "hi"},
                "principal": {"id": "m", "role": "owner"},
            }
            r = await c.post(
                base + "/v1/runs", json=body, headers={"authorization": f"Bearer {TOKEN_A}"}
            )
            assert r.status_code == 202
            for _ in range(200):
                got = (
                    await c.get(
                        base + f"/v1/runs/{body['run_id']}",
                        headers={"authorization": f"Bearer {TOKEN_A}"},
                    )
                ).json()
                if got["state"] == "terminated":
                    break
                await asyncio.sleep(0.02)
            feed = (
                await c.get(
                    base + "/v1/completed-runs", headers={"authorization": f"Bearer {READ_A}"}
                )
            ).json()
        assert secret not in str(feed) and "[REDACTED" in str(feed).upper()
    finally:
        await server.stop()


async def test_a_read_token_reaches_nothing_else_and_no_other_token_reaches_the_feed(
    env: Env,
) -> None:
    body = env.start_body()
    assert (await env.call("POST", "/v1/runs", body=body)).status_code == 202
    await env.wait_state(body["run_id"], "terminated")
    # read-only credential: 403 everywhere but the feed (not 404: it is recognised and refused), including writes
    for method, path, b in [
        ("GET", "/v1/runs", None),
        ("GET", f"/v1/runs/{body['run_id']}", None),
        ("POST", "/v1/runs", env.start_body()),
        ("POST", f"/v1/runs/{body['run_id']}/signals", {"signal": "KILL"}),
        ("POST", "/v1/completed-runs", {}),
        ("GET", "/v1/nothing", None),
    ]:
        assert (await env.call(method, path, READ_A, b)).status_code == 403, path
    # the gateway's own credential cannot read the feed, and neither can an unknown or missing one
    assert (await env.call("GET", "/v1/completed-runs", TOKEN_A)).status_code == 403
    assert (await env.call("GET", "/v1/completed-runs", "nope")).status_code == 401
    assert (await env.call("GET", "/v1/completed-runs", None)).status_code == 401
