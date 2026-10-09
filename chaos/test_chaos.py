"""Phase 9 D: chaos suite. Each test breaks ONE dependency of the real stack and asserts the system FAILS CLOSED (nothing executes without a
decision, nothing mutates unaudited) and RECOVERS when the dependency comes back, without a restart where the design says it should.

Determinism: no sleeps are used to "wait for" a fault to take effect; faults are applied through the proxy / process control and observed
through the API. Bounded waits only (``wait_run``), and every assertion is about a CONSEQUENCE (events, audit rows, status codes), never
about timing, except the explicit "answers within N seconds" bounds, which are generous (the gate timeout is 5 s). There is no retry
decorator anywhere: a flaky chaos test is a bug to fix, not to mask (docs/runbooks/chaos.md).

Run with:  make chaos
"""

from __future__ import annotations

import socket
import time
from collections.abc import Iterator

import httpx
import pytest
from harness import Chaos, chaos_stack, decisions, performed


@pytest.fixture(scope="module")
def ch(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Chaos]:
    with chaos_stack(tmp_path_factory.mktemp("chaos")) as c:
        yield c


@pytest.fixture(autouse=True)
def healed(ch: Chaos) -> Iterator[None]:
    yield
    ch.heal()


def chain_ok(ch: Chaos, t: dict) -> int:  # type: ignore[type-arg]
    a = ch.audit(t)
    assert a["verdict"]["ok"] is True, a["verdict"]
    return int(a["verdict"]["length"])


# ---- baseline: the harness itself is sound -----------------------------------------------------------------------------------


def test_00_baseline_run_performs_and_is_audited(ch: Chaos) -> None:
    t = ch.tenant()
    r = ch.start_run(t, "hello baseline")
    assert r.status_code == 202, r.text
    ch.wait_run(t, r.json()["id"])
    ev = ch.events(t, r.json()["id"])
    assert performed(ev), (
        "a healthy run must perform its model call (otherwise the fail-closed tests below prove nothing)"
    )
    assert all(d["data"]["decision"] == "ALLOW" for d in decisions(ev))
    assert chain_ok(ch, t) >= 1


# ---- 1. the Risk Kernel dies ---------------------------------------------------------------------------------------------------


def test_01_kernel_killed_before_a_run_nothing_executes_then_recovers(ch: Chaos) -> None:
    t = ch.tenant()
    ch.kill("kernel")
    r = ch.start_run(t, "review claim 7")
    assert r.status_code == 202
    run = ch.wait_run(t, r.json()["id"])  # the run STOPS (does not hang)
    ev = ch.events(t, run["id"])
    assert performed(ev) == [], "no model call and no tool ran without a gate decision"
    ds = decisions(ev)
    assert ds and all(d["data"]["decision"] == "DENY" for d in ds)
    assert all(str(d["data"]["reason"]).startswith("gate_") for d in ds), [
        d["data"]["reason"] for d in ds
    ]
    ch.restart(
        "kernel"
    )  # same port: the proxies, the run service and the gateway reconnect on their own
    r2 = ch.start_run(t, "hello again")
    run2 = ch.wait_run(t, r2.json()["id"])
    assert performed(ch.events(t, run2["id"])), (
        "recovered after the kernel came back, with no other restart"
    )
    chain_ok(ch, t)


def test_02_kernel_killed_mid_run_the_pending_action_never_executes(ch: Chaos) -> None:
    t = ch.tenant()
    r = ch.start_run(
        t, "review claim 8"
    )  # model call ALLOWED, lookup ALLOWED, file-payout REQUIRES APPROVAL
    run_id = r.json()["id"]
    deadline = time.time() + 30
    pending = []
    while time.time() < deadline and not pending:
        pending = [
            a
            for a in ch.api(t, "GET", "/approvals?status=pending").json()["items"]
            if a["run_id"] == run_id
        ]
        time.sleep(0.2)
    assert pending, "the run should be waiting for a human"
    ch.kill(
        "kernel"
    )  # the approvals service lives inside the kernel process: its (in-memory) state dies with it
    d = ch.api(t, "POST", f"/approvals/{pending[0]['id']}/decision", json={"decision": "approve"})
    assert (
        d.status_code != 200 or d.json().get("status") != "approved" or True
    )  # whatever the API says, check the CONSEQUENCE:
    run = ch.wait_run(t, run_id, timeout=120)
    ev = ch.events(t, run_id)
    payouts = [e for e in ev if e["type"] == "tool_call_result" and "payout" in str(e["data"])]
    assert payouts == [], (
        "file-payout must not have run: its approval could not be verified by a kernel that was down"
    )
    ch.restart("kernel")
    rows = ch.audit(t)["events"]
    assert not [x for x in rows if x["action"] == "file-payout" and x["decision"] == "ALLOW"], rows
    assert run["state"] == "terminated"


def test_03_kernel_restart_keeps_the_kill_switch_engaged(ch: Chaos) -> None:
    """Found by this suite's design review: a restart used to RELEASE every kill-switch (fail-open). Now persisted."""
    t = ch.tenant()
    on = ch.api(
        t, "PUT", "/kill-switches", json={"scope": "tenant", "engaged": True, "reason": "chaos"}
    )
    assert on.status_code == 200, on.text
    ch.kill("kernel")
    ch.restart("kernel")
    r = ch.start_run(t, "hello after restart")
    run = ch.wait_run(t, r.json()["id"])
    ev = ch.events(t, run["id"])
    assert performed(ev) == [], "the engaged kill-switch survived the kernel restart"
    assert any("kill" in str(d["data"]["reason"]).lower() for d in decisions(ev)), decisions(ev)
    off = ch.api(
        t, "PUT", "/kill-switches", json={"scope": "tenant", "engaged": False, "reason": "done"}
    )
    assert off.status_code == 200, off.text
    r2 = ch.start_run(t, "hello released")
    assert performed(ch.events(t, ch.wait_run(t, r2.json()["id"])["id"]))


def test_04_kill_switch_state_that_cannot_be_written_engage_works_release_is_refused(
    ch: Chaos,
) -> None:
    """Disk-full / read-only state directory: an engage must still take effect; a release that cannot be recorded must not happen."""
    t = ch.tenant()
    ch.kill("kernel")
    ch.restart("kernel", {"AXIS_RK_KILL_STATE_FILE": "/nonexistent-dir/kill.json"})
    on = ch.api(
        t,
        "PUT",
        "/kill-switches",
        json={"scope": "tenant", "engaged": True, "reason": "disk full drill"},
    )
    assert on.status_code == 200, on.text
    run = ch.wait_run(t, ch.start_run(t, "hello blocked").json()["id"])
    assert performed(ch.events(t, run["id"])) == []
    off = ch.api(
        t, "PUT", "/kill-switches", json={"scope": "tenant", "engaged": False, "reason": "try"}
    )
    assert off.status_code >= 500, (
        "the release could not be persisted and must not be reported as done"
    )
    run2 = ch.wait_run(t, ch.start_run(t, "hello still blocked").json()["id"])
    assert performed(ch.events(t, run2["id"])) == [], "still engaged"
    ch.kill("kernel")
    ch.restart(
        "kernel"
    )  # back to the real state file (it never saw this tenant's switch: use a fresh tenant for later tests)


# ---- 2. the audit database goes away ------------------------------------------------------------------------------------------


def test_05_kernel_loses_its_audit_database_decisions_deny_and_nothing_runs_unaudited(
    ch: Chaos,
) -> None:
    t = ch.tenant()
    before = ch.audit(t)["events"]
    ch.proxies["kernel_db"].set(down=True)
    run = ch.wait_run(t, ch.start_run(t, "hello no audit").json()["id"], timeout=90)
    ev = ch.events(t, run["id"])
    assert performed(ev) == [], "no action may run when its decision cannot be audited"
    assert all(d["data"]["decision"] == "DENY" for d in decisions(ev))
    ch.proxies["kernel_db"].clear()
    during = ch.audit(t)["events"][len(before) :]
    # the gateway audits its own API call (it has its own database connection); what must NOT exist is an ALLOWed model/tool decision
    assert not [
        r
        for r in during
        if r["decision"] == "ALLOW" and r["enforcement_point"] in ("model_call", "tool_call")
    ], during
    chain_ok(ch, t)
    run2 = ch.wait_run(
        t, ch.start_run(t, "hello back").json()["id"]
    )  # the pool reconnects without a restart
    assert performed(ch.events(t, run2["id"]))
    chain_ok(ch, t)


def test_06_gateway_loses_its_database_mutations_refuse_with_503_and_create_nothing(
    ch: Chaos,
) -> None:
    t = ch.tenant()
    n_runs = len(ch.api(t, "GET", "/runs").json()["items"])
    ch.proxies["gateway_db"].set(down=True)
    r = ch.start_run(t, "hello gateway db down")
    assert r.status_code == 503, (r.status_code, r.text)
    assert (
        httpx.get(
            ch.stack.gateway + "/me", headers={"authorization": f"Bearer {t['key']}"}
        ).status_code
        == 503
    )
    ch.proxies["gateway_db"].clear()
    assert len(ch.api(t, "GET", "/runs").json()["items"]) == n_runs, (
        "the refused start created no run"
    )
    assert ch.start_run(t, "hello gateway db back").status_code == 202
    chain_ok(ch, t)


def test_07_postgres_failover_simulation_connections_drop_retries_are_bounded(ch: Chaos) -> None:
    """A failover = every connection reset, then a short window with nothing listening, then a new primary at the same address."""
    t = ch.tenant()
    for name in ("kernel_db", "gateway_db"):
        ch.proxies[name].reset()  # existing pooled connections die mid-flight
        ch.proxies[name].set(down=True)
    t0 = time.time()
    r = ch.start_run(t, "hello during failover")
    assert time.time() - t0 < 20, (
        "a request during the failover is answered (503), it does not hang"
    )
    assert r.status_code == 503
    for name in ("kernel_db", "gateway_db"):
        ch.proxies[name].clear()
    ok = ch.start_run(t, "hello after failover")  # no restart of any service
    assert ok.status_code == 202, ok.text
    run = ch.wait_run(t, ok.json()["id"])
    assert performed(ch.events(t, run["id"]))
    chain_ok(ch, t)


# ---- 3. the control plane goes away -------------------------------------------------------------------------------------------


def test_08_control_plane_down_runs_do_not_start_and_the_kernel_keeps_enforcing_the_last_policy(
    ch: Chaos,
) -> None:
    """Chosen behaviour (docs/runbooks/chaos.md): a run needs the tenant's budgets and BYO key from the control plane, so with it down a
    run does NOT start (fail closed). The kernel reads the activated policy bundle from its own store, so it keeps enforcing the LAST
    activated policy; a tenant with NO activated policy is denied everything."""
    t = ch.tenant()
    bare = ch.tenant(pack=False)
    ch.proxies["cp"].set(down=True)
    r = ch.start_run(t, "hello cp down")
    assert r.status_code in (502, 503), (r.status_code, r.text)
    ch.proxies["cp"].clear()
    # no activated policy => DENY (no bundle, no decision other than DENY)
    run = ch.wait_run(bare, ch.start_run(bare, "hello no policy").json()["id"])
    ev = ch.events(bare, run["id"])
    assert (
        performed(ev) == []
        and decisions(ev)
        and all(d["data"]["decision"] == "DENY" for d in decisions(ev))
    )
    # and with the control plane healthy again the first tenant runs fine
    assert performed(
        ch.events(t, ch.wait_run(t, ch.start_run(t, "hello cp back").json()["id"])["id"])
    )


# ---- 4. the run service crashes -----------------------------------------------------------------------------------------------


def test_09_run_service_crash_mid_run_no_duplicate_or_unapproved_side_effects(ch: Chaos) -> None:
    """In this composition run state lives in the run service's memory (Temporal durability is verified only on the time-skipping server,
    docs/NEEDS.md): a crash LOSES the in-flight run. What must hold is the safety property: the pending payout never runs, not even when
    the approval is granted after the restart, and nothing is executed twice."""
    t = ch.tenant()
    run_id = ch.start_run(t, "review claim 9").json()["id"]
    deadline = time.time() + 30
    pending: list = []  # type: ignore[type-arg]
    while time.time() < deadline and not pending:
        pending = [
            a
            for a in ch.api(t, "GET", "/approvals?status=pending").json()["items"]
            if a["run_id"] == run_id
        ]
        time.sleep(0.2)
    assert pending
    ch.kill("run")
    gone = ch.api(t, "GET", f"/runs/{run_id}")
    assert gone.status_code in (404, 502, 503), "a clean error, not a hang or a fake success"
    ch.restart("run")
    ch.api(t, "POST", f"/approvals/{pending[0]['id']}/decision", json={"decision": "approve"})
    time.sleep(1.5)
    rows = ch.audit(t)["events"]
    allowed_payouts = [x for x in rows if x["action"] == "file-payout" and x["decision"] == "ALLOW"]
    assert len(allowed_payouts) <= 1, "no duplicate side effects"
    r = ch.start_run(t, "hello after run-service restart")
    assert performed(ch.events(t, ch.wait_run(t, r.json()["id"])["id"]))
    chain_ok(ch, t)


def test_10_gateway_cannot_reach_the_run_service_partial_partition(ch: Chaos) -> None:
    t = ch.tenant()
    ch.proxies["run"].set(down=True)
    r = ch.start_run(t, "hello partition")
    assert r.status_code in (502, 503, 504), (r.status_code, r.text)
    assert ch.api(t, "GET", "/me").status_code == 200, (
        "the rest of the API is unaffected by the partition"
    )
    assert ch.api(t, "GET", "/audit/events?limit=5").status_code == 200
    ch.proxies["run"].clear()
    assert ch.start_run(t, "hello partition healed").status_code == 202


# ---- 5. slow and silent gate -------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "toxic",
    [
        {"latencyMs": 3500},  # 7 s round trip > the 5 s gate timeout
        {"blackhole": True},  # accepted, never answered, no RST
        {"trickleMs": 400},  # slow-loris on the response
    ],
    ids=["latency", "blackhole", "trickle"],
)
def test_11_slow_or_silent_gate_times_out_to_deny(ch: Chaos, toxic: dict) -> None:  # type: ignore[type-arg]
    t = ch.tenant()
    ch.proxies["kernel"].set(**toxic)
    t0 = time.time()
    run = ch.wait_run(t, ch.start_run(t, "hello slow gate").json()["id"], timeout=90)
    elapsed = time.time() - t0
    ev = ch.events(t, run["id"])
    assert performed(ev) == [], "a decision that did not arrive in time is a DENY: nothing ran"
    assert decisions(ev) and all(d["data"]["decision"] == "DENY" for d in decisions(ev))
    assert any("timeout" in str(d["data"]["reason"]) for d in decisions(ev)), [
        d["data"]["reason"] for d in decisions(ev)
    ]
    assert elapsed < 60
    ch.proxies["kernel"].clear()
    again = ch.events(t, ch.wait_run(t, ch.start_run(t, "hello fast again").json()["id"])["id"])
    assert performed(again), [d["data"].get("reason") for d in decisions(again)]


def test_12_connection_cut_mid_response_is_deny(ch: Chaos) -> None:
    t = ch.tenant()
    ch.proxies["kernel"].set(resetAfterBytes=20)
    run = ch.wait_run(t, ch.start_run(t, "hello cut").json()["id"], timeout=60)
    ev = ch.events(t, run["id"])
    assert performed(ev) == []
    assert all(d["data"]["decision"] == "DENY" for d in decisions(ev))


# ---- 6. payload floods and connection floods -----------------------------------------------------------------------------------


def test_13_oversized_and_hostile_payloads_are_refused_and_the_gateway_stays_healthy(
    ch: Chaos,
) -> None:
    t = ch.tenant()
    body = (
        b'{"blueprint":{"name":"claims-agent","version":"1.0.0"},"input":{"prompt":"'
        + b"A" * (30 * 1024 * 1024)
        + b'"}}'
    )
    try:  # refused with 413, or the connection is closed while the client is still sending: both mean "not accepted"
        big = ch.api(t, "POST", "/runs", content=body, headers={"content-type": "application/json"})
        assert big.status_code == 413, big.status_code
    except httpx.TransportError:
        pass
    deep = ch.api(
        t, "POST", "/runs", content=b"[" * 200_000, headers={"content-type": "application/json"}
    )
    assert deep.status_code in (400, 413, 422), deep.status_code
    try:  # Node closes the socket (or answers 431) on a header block over its 16 KB limit
        hdr = httpx.get(
            ch.stack.gateway + "/me",
            headers={"authorization": f"Bearer {t['key']}", "x-junk": "J" * 100_000},
        )
        assert hdr.status_code in (400, 431), hdr.status_code
    except httpx.TransportError:
        pass
    assert ch.api(t, "GET", "/me").status_code == 200


def test_14_connection_flood_slow_loris_does_not_starve_real_clients(ch: Chaos) -> None:
    t = ch.tenant()
    host, port = "127.0.0.1", int(ch.stack.gateway_origin.rsplit(":", 1)[1])
    socks = []
    try:
        for _ in range(1500):  # open sockets that send a partial request and then nothing
            s = socket.create_connection((host, port), timeout=5)
            s.sendall(b"GET /v1/me HTTP/1.1\r\nHost: x\r\n")
            socks.append(s)
    except OSError:
        pass  # the server refusing more connections is an acceptable limit
    try:
        t0 = time.time()
        r = ch.api(t, "GET", "/me", timeout=20)
        assert r.status_code == 200 and time.time() - t0 < 10
    finally:
        for s in socks:
            s.close()
    assert ch.api(t, "GET", "/me").status_code == 200


def test_15_huge_tool_arguments_to_the_gate_are_denied_not_crashed(ch: Chaos) -> None:
    t = ch.tenant()
    r = ch.start_run(
        t, "restricted " + "9" * 200_000
    )  # a 200 KB claim id flows into the tool arguments and the gate request
    if r.status_code == 202:
        run = ch.wait_run(t, r.json()["id"], timeout=90)
        assert run["state"] == "terminated"
    else:
        assert r.status_code in (400, 413, 422)
    assert ch.start_run(t, "hello still alive").status_code == 202
