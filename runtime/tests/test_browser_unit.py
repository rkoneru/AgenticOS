"""Browser policy, URL guard, gate view, worker and executor wiring (no browser needed)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import pytest
from axis_runtime import Decision
from axis_runtime.actions import Backends, BrowserExec
from axis_runtime.browser.args import gate_view, is_sensitive, merge_redacted, operation_of
from axis_runtime.browser.backend import (
    BlockedRequest,
    BrowserBlockedError,
    BrowserError,
    InMemoryArtifactStore,
    PageState,
    Telemetry,
)
from axis_runtime.browser.policy import (
    BlockedError,
    BrowserPolicy,
    PolicyError,
    UrlGuard,
    canonical_hash,
    safe_url,
)
from axis_runtime.browser.worker import BrowserWorker, BrowserWorkerFactory
from axis_runtime.events import EventType, InMemoryRunEventLog, RunRecorder
from axis_runtime.executor import ActionExecutor, Completed, Denied, Failed
from axis_runtime.gate import GateDecision
from conftest import TENANT, FakeClock, ScriptedGate, allow, deny
from helpers import PID, identity

PUBLIC = "93.184.216.34"


def resolver_for(table: Mapping[str, list[str]]) -> Any:
    calls: list[str] = []

    async def resolve(host: str, port: int) -> list[str]:
        calls.append(host)
        if host not in table:
            raise OSError("nxdomain")
        return table[host]

    resolve.calls = calls  # type: ignore[attr-defined]
    return resolve


async def any_public(host: str, port: int) -> list[str]:
    return [PUBLIC]


def guard(*hosts: str, table: Mapping[str, list[str]] | None = None, **kw: Any) -> UrlGuard:
    res = resolver_for(table) if table is not None else any_public
    return UrlGuard(BrowserPolicy(allowed_hosts=hosts, **kw), res)


async def reason_of(g: UrlGuard, url: str, **kw: Any) -> str:
    with pytest.raises(BlockedError) as ei:
        await g.check(url, **kw)
    return ei.value.reason


# ---- policy ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "entry",
    [
        "",
        " example.com",
        "https://example.com",
        "example.com/path",
        "user@example.com",
        "*",
        "*.com",
        "*.",
        "ex*.com",
        "a.*.com",
        "example.com:abc",
        "example.com:0",
        "example.com:70000",
        "[::1",
        "[::1]x",
    ],
)
def test_bad_allowlist_entries_are_rejected(entry: str) -> None:
    with pytest.raises(PolicyError):
        BrowserPolicy(allowed_hosts=(entry,))


@pytest.mark.parametrize(
    "bad",
    [
        {"private_hosts": ("example.com",)},  # names other than localhost are not exceptions
        {"private_hosts": ("*.localhost",)},
        {"private_hosts": ("169.254.169.254",)},
        {"max_pages": 0},
        {"max_requests": -1},
        {"op_timeout_seconds": 0},
        {"session_timeout_seconds": -1},
    ],
)
def test_bad_policies_are_rejected(bad: dict[str, Any]) -> None:
    with pytest.raises(PolicyError):
        BrowserPolicy(allowed_hosts=("example.com",), **bad)


def test_from_config() -> None:
    p = BrowserPolicy.from_config({"allowed_domains": ["example.com"], "max_pages": 2})
    assert p.allowed_hosts == ("example.com",) and p.max_pages == 2
    assert BrowserPolicy.from_config(None).allowed_hosts == ()
    with pytest.raises(PolicyError, match="unknown"):
        BrowserPolicy.from_config({"allow_everything": True})


# ---- guard: scheme / syntax -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "chrome://version",
        "about:blank",
        "data:text/html,x",
        "javascript:1",
        "ftp://example.com/",
        "blob:https://example.com/x",
        "view-source:https://example.com",
        "ws://example.com/",
        "FILE:///etc/passwd",
        "//example.com/x",
        "example.com",
    ],
)
async def test_non_http_schemes_are_blocked(url: str) -> None:
    assert await reason_of(guard("example.com"), url) in {"scheme_not_allowed", "no_host"}


async def test_websocket_schemes_only_for_websockets() -> None:
    g = guard("example.com")
    assert (await g.check("wss://example.com/s", websocket=True)).port == 443
    assert await reason_of(g, "https://example.com/", websocket=True) == "scheme_not_allowed"
    assert await reason_of(g, "wss://example.com/s") == "scheme_not_allowed"


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("https://user:pw@example.com/", "credentials_in_url"),
        ("https://@example.com/", "credentials_in_url"),
        ("https://example.com:99999/", "malformed_url"),
        ("https://[::1/", "malformed_url"),
        ("https:///x", "no_host"),
        ("https://example.com%2f/", "host_not_allowlisted"),
    ],
)
async def test_malformed_urls_are_blocked(url: str, reason: str) -> None:
    assert await reason_of(guard("example.com"), url) in {reason, "no_host", "host_not_allowlisted"}


# ---- guard: allowlist -----------------------------------------------------------------------------


async def test_allowlist_matching() -> None:
    g = guard("example.com", "*.docs.example.com")
    for ok in (
        "https://example.com/",
        "https://EXAMPLE.com./x",
        "http://example.com/",
        "https://a.docs.example.com/",
        "https://x.y.docs.example.com/",
    ):
        await g.check(ok)
    for bad in (
        "https://evilexample.com/",
        "https://example.com.evil.com/",
        "https://docs.example.com/",  # wildcard does not match its apex
        "https://sub.example.com/",
        "https://notexample.com/",
        "https://evil.com/?example.com",
    ):
        assert await reason_of(g, bad) == "host_not_allowlisted", bad


async def test_ports_default_to_80_and_443_unless_the_entry_names_one() -> None:
    g = guard("example.com", "api.example.com:8443")
    await g.check("https://example.com/")
    assert await reason_of(g, "https://example.com:8443/") == "host_not_allowlisted"
    assert await reason_of(g, "http://example.com:8080/") == "host_not_allowlisted"
    await g.check("https://api.example.com:8443/")
    assert await reason_of(g, "https://api.example.com/") == "host_not_allowlisted"


async def test_empty_allowlist_denies_everything_and_never_resolves() -> None:
    res = resolver_for({"example.com": [PUBLIC]})
    g = UrlGuard(BrowserPolicy(), res)
    assert await reason_of(g, "https://example.com/") == "host_not_allowlisted"
    assert res.calls == []  # a non-allowlisted name is not even looked up (no DNS leak)


# ---- guard: private ranges / rebinding / metadata -------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.100.100.200",
        "0.0.0.0",  # noqa: S104
        "::1",
        "fe80::1",
        "fd00:ec2::254",
        "::ffff:127.0.0.1",
        "64:ff9b::7f00:1",
        "224.0.0.1",
    ],
)
async def test_an_allowlisted_name_resolving_to_a_non_public_address_is_blocked(ip: str) -> None:
    g = guard("example.com", table={"example.com": [PUBLIC, ip]})  # ONE bad answer is enough
    assert await reason_of(g, "https://example.com/") == "private_address"


async def test_dns_rebinding_is_caught_per_request_but_not_pinned() -> None:
    """The guard re-resolves per request: a flip to a private address is caught on the NEXT request.
    The window between check and Chromium's own lookup is the documented limit (NEEDS #99)."""
    answers = [[PUBLIC], ["127.0.0.1"]]

    async def flip(host: str, port: int) -> list[str]:
        return answers.pop(0)

    g = UrlGuard(BrowserPolicy(allowed_hosts=("example.com",)), flip)
    await g.check("https://example.com/")
    assert await reason_of(g, "https://example.com/") == "private_address"


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "10.1.2.3",
        "169.254.169.254",
        "[::1]",
        "[fd00:ec2::254]",
        "2130706433",
        "0x7f.1",
        "0177.0.0.1",
        "127.1",
        "localhost",
        "foo.localhost",
        "metadata.google.internal",
    ],
)
async def test_ip_literals_and_ambiguous_hosts_are_blocked_even_when_allowlisted(host: str) -> None:
    entry = host.strip("[]")
    try:
        g = guard(entry)
    except PolicyError:
        pytest.skip("not a valid allowlist entry")
    assert await reason_of(g, f"http://{host}/") in {"private_address", "metadata_address"}


async def test_unresolvable_and_failing_resolvers_fail_closed() -> None:
    assert (
        await reason_of(guard("nx.example.com", table={}), "https://nx.example.com/")
        == "unresolvable"
    )

    async def boom(host: str, port: int) -> list[str]:
        raise ValueError("idna")

    g = UrlGuard(BrowserPolicy(allowed_hosts=("example.com",)), boom)
    assert await reason_of(g, "https://example.com/") == "unresolvable"


async def test_private_exceptions_are_exact_and_never_cover_metadata() -> None:
    g = guard("127.0.0.1:8000", private_hosts=("127.0.0.1:8000",))
    assert (await g.check("http://127.0.0.1:8000/x")).host == "127.0.0.1"
    assert await reason_of(g, "http://127.0.0.1:8001/") == "host_not_allowlisted"
    g2 = guard("127.0.0.1:8000", "127.0.0.2:8000", private_hosts=("127.0.0.1:8000",))
    assert await reason_of(g2, "http://127.0.0.2:8000/") == "private_address"
    # an exception for the host does not need the port, and still never opens metadata
    g3 = guard("localhost:80", "169.254.169.254:80", private_hosts=("localhost",))
    await g3.check("http://localhost/")
    assert await reason_of(g3, "http://169.254.169.254/latest/meta-data") == "metadata_address"


async def test_the_guard_never_raises_anything_but_blocked() -> None:
    class Weird(UrlGuard):
        async def _check(self, url: str, websocket: bool) -> Any:
            raise RuntimeError("boom")

    g = Weird(BrowserPolicy(allowed_hosts=("example.com",)), resolver_for({}))
    assert await reason_of(g, "https://example.com/") == "guard_error"


# ---- log hygiene ----------------------------------------------------------------------------------


def test_safe_url_strips_credentials_query_and_fragment() -> None:
    out = safe_url("https://u:p@Example.com:8443/a/b?token=SECRET#frag")
    assert "SECRET" not in out and "u:p" not in out and "frag" not in out
    assert out.startswith("https://example.com:8443/a/b?q_sha256=")
    assert safe_url("https://[::1]:80/x") == "https://[::1]:80/x"
    assert safe_url("mailto:x") == "mailto:"
    assert safe_url("http://h:99999/") == "invalid-url"
    assert len(safe_url("https://e.com/" + "a" * 1000)) == 300
    assert canonical_hash({"a": 1, "b": 2}) == canonical_hash({"b": 2, "a": 1})


# ---- gate view ------------------------------------------------------------------------------------


def test_gate_view_hashes_typed_text_and_hides_sensitive_text_completely() -> None:
    args = {"operation": "type", "selector": "#note", "text": "hello world"}
    doc = gate_view(args, "https://example.com/form?x=1")
    assert doc["operation"] == "type" and doc["host"] == "example.com"
    assert doc["text_len"] == 11 and len(doc["text_sha256"]) == 64
    assert "hello" not in json.dumps(doc) and "x=1" not in json.dumps(doc)
    pw = gate_view(
        {"operation": "type", "selector": "#password", "text": "hunter2"}, "https://e.com/"
    )
    assert pw["sensitive"] is True and pw["text_sha256"] is None and pw["text_len"] is None
    assert "hunter2" not in json.dumps(pw)
    # the args hash of a sensitive action must not depend on the secret (no offline oracle)
    a = gate_view({"operation": "type", "selector": "#x", "text": "aaa", "sensitive": True}, "u")
    b = gate_view({"operation": "type", "selector": "#x", "text": "bbb", "sensitive": True}, "u")
    assert a["args_hash"] == b["args_hash"]
    c = gate_view({"operation": "type", "selector": "#x", "text": "aaa"}, "u")
    d = gate_view({"operation": "type", "selector": "#x", "text": "bbb"}, "u")
    assert c["args_hash"] != d["args_hash"]


def test_gate_view_navigate_uses_the_destination_and_other_ops_the_page() -> None:
    nav = gate_view({"operation": "navigate", "url": "https://a.com/x?q=1"}, "https://other.com/")
    assert nav["host"] == "a.com"
    assert gate_view({"url": "https://a.com/"}, "")["operation"] == "navigate"  # default
    click = gate_view({"operation": "click", "selector": "#b"}, "https://page.com/p")
    assert click["host"] == "page.com" and click["url"] == "https://page.com/p"
    assert gate_view({"operation": "navigate", "url": "http://[::1/"}, "")["host"] == ""
    assert gate_view({"operation": "navigate", "url": 5}, "")["url"] == ""
    assert operation_of({}) == ""


@pytest.mark.parametrize(
    "selector", ["#password", "input[name=pwd]", "#cc-card-number", "#otp", "#api_token", "#ssn"]
)
def test_credential_selectors_are_sensitive(selector: str) -> None:
    assert is_sensitive({"selector": selector})
    assert not is_sensitive({"selector": "#note"}) and not is_sensitive({})
    assert is_sensitive({"selector": "#note", "sensitive": True})


def test_merge_redacted_only_applies_fields_the_view_carries() -> None:
    args = {"operation": "navigate", "url": "https://a.com/x?q=1", "text": "t"}
    view = gate_view(args, "")
    assert merge_redacted(args, view) == args  # an untouched view changes nothing
    assert merge_redacted(args, {**view, "url": "[REDACTED]"})["url"] == "[REDACTED]"
    typing = {"operation": "type", "selector": "#a", "text": "t"}
    assert merge_redacted(typing, {"selector": "[REDACTED]"})["selector"] == "[REDACTED]"
    assert merge_redacted(typing, {"text_sha256": "x"}) == typing


# ---- worker with a fake backend -------------------------------------------------------------------


class FakeSession:
    def __init__(self, url: str = "https://example.com/") -> None:
        self.url = url
        self.calls: list[tuple[Any, ...]] = []
        self.closed = False
        self.fail: Exception | None = None
        self.blocked = (
            BlockedRequest("https://evil.com/x", "evil.com", "host_not_allowlisted", "image"),
        )

    def _st(self) -> PageState:
        return PageState(safe_url(self.url), self.url, "Title " + "t" * 400, 200)

    async def _do(self, *call: Any) -> None:
        self.calls.append(call)
        if self.fail:
            raise self.fail

    async def navigate(self, url: str) -> PageState:
        await self._do("navigate", url)
        self.url = url
        return self._st()

    async def click(self, selector: str) -> PageState:
        await self._do("click", selector)
        return self._st()

    async def type_text(self, selector: str, text: str, *, sensitive: bool) -> PageState:
        await self._do("type", selector, text, sensitive)
        return self._st()

    async def extract(self, selector: str | None) -> tuple[str, bool]:
        await self._do("extract", selector)
        return "page text é", True

    async def screenshot(self) -> bytes:
        await self._do("screenshot")
        return b"\x89PNG-bytes"

    async def state(self) -> PageState:
        return self._st()

    def telemetry(self) -> Telemetry:
        return Telemetry(blocked=self.blocked, blocked_total=1, requests=3)

    async def close(self) -> None:
        self.closed = True


class FakeBackend:
    def __init__(self) -> None:
        self.sessions: list[FakeSession] = []
        self.guards: list[UrlGuard] = []

    async def open_session(self, policy: BrowserPolicy, g: UrlGuard) -> FakeSession:
        self.guards.append(g)
        s = FakeSession()
        self.sessions.append(s)
        return s

    async def aclose(self) -> None:
        pass


def worker(
    backend: FakeBackend | None = None, **over: Any
) -> tuple[BrowserWorker, FakeBackend, InMemoryArtifactStore]:
    backend = backend or FakeBackend()
    store = InMemoryArtifactStore()
    pol = BrowserPolicy(allowed_hosts=("example.com",), **over)
    return (
        BrowserWorker(
            backend,
            pol,
            tenant_id=TENANT,
            agent="a",
            run_id="run_1",
            artifacts=store,
            resolver=resolver_for({"example.com": [PUBLIC]}),
        ),
        backend,
        store,
    )


async def test_navigate_prechecks_the_guard_then_reports_evidence() -> None:
    w, backend, _ = worker()
    with pytest.raises(BrowserBlockedError, match="host_not_allowlisted"):
        await w.run({"operation": "navigate", "url": "https://evil.com/"})
    with pytest.raises(BrowserBlockedError, match="scheme_not_allowed"):
        await w.run({"operation": "navigate", "url": "file:///etc/passwd"})
    assert backend.sessions == []  # a blocked navigation never even opens a browser context
    out = await w.run({"operation": "navigate", "url": "https://example.com/"})
    assert out["final_url"] == "https://example.com/" and out["status"] == 200
    assert len(out["title"]) == 200
    assert out["blocked_requests"] == [
        {
            "url": "https://evil.com/x",
            "host": "evil.com",
            "reason": "host_not_allowlisted",
            "type": "image",
        }
    ]
    assert out["blocked_total"] == 1 and out["requests"] == 3
    assert w.current_url == "https://example.com/"
    await w.aclose()
    assert backend.sessions[0].closed


async def test_non_navigation_ops_require_the_declared_target_to_match_the_live_page() -> None:
    w, backend, _ = worker()
    await w.run({"operation": "navigate", "url": "https://example.com/"})
    act = w.action("web", {"operation": "extract"})
    assert act.target_url == "https://example.com/"
    out = await w.run({"operation": "extract", "target_url": act.target_url})
    assert out["text"] == "page text é" and out["text_bytes"] == len("page text é".encode())
    assert len(out["text_sha256"]) == 64 and out["text_truncated"] is True
    with pytest.raises(BrowserError, match="target_url_required"):
        await w.run({"operation": "click", "selector": "#a"})
    backend.sessions[0].url = "https://example.com/moved"  # the page navigated by itself
    with pytest.raises(BrowserError, match="target_changed"):
        await w.run({"operation": "click", "selector": "#a", "target_url": "https://example.com/"})
    assert ("click", "#a") not in backend.sessions[0].calls
    assert w.current_url == "https://example.com/moved"  # the next action is bound to the new page


async def test_type_screenshot_and_validation() -> None:
    w, backend, store = worker()
    await w.run({"operation": "navigate", "url": "https://example.com/"})
    t = "https://example.com/"
    out = await w.run({"operation": "type", "selector": "#n", "text": "hi", "target_url": t})
    assert out["typed"]["text_len"] == 2 and "hi" not in json.dumps(out)
    out = await w.run({"operation": "type", "selector": "#password", "text": "pw", "target_url": t})
    assert out["typed"] == {"masked": True} and "pw" not in json.dumps(out)
    assert ("type", "#password", "pw", True) in backend.sessions[0].calls
    out = await w.run({"operation": "screenshot", "target_url": t})
    assert out["screenshot_ref"].startswith(f"artifact://{TENANT}/run_1/")
    assert out["screenshot_bytes"] == 10 and "png" not in json.dumps(out).lower().replace(
        "pngbytes", ""
    )
    assert store.items[out["screenshot_ref"]] == (b"\x89PNG-bytes", "image/png")
    for bad in (
        {"operation": "click", "target_url": t},
        {"operation": "click", "selector": "", "target_url": t},
        {"operation": "click", "selector": "x" * 501, "target_url": t},
        {"operation": "type", "selector": "#a", "text": 5, "target_url": t},
        {"operation": "type", "selector": "#a", "text": "x" * 10_001, "target_url": t},
        {"operation": "navigate"},
        {"operation": "explode"},
        {},
    ):
        with pytest.raises(BrowserError):
            await w.run(bad)


async def test_screenshot_over_the_cap_is_an_error() -> None:
    w, _, store = worker(max_screenshot_bytes=4)
    await w.run({"operation": "navigate", "url": "https://example.com/"})
    with pytest.raises(BrowserError, match="screenshot_too_large"):
        await w.run({"operation": "screenshot", "target_url": "https://example.com/"})
    assert store.items == {}


async def test_backend_failures_are_error_outcomes_with_only_the_type() -> None:
    w, backend, _ = worker()
    await w.run({"operation": "navigate", "url": "https://example.com/"})
    backend.sessions[0].fail = RuntimeError("secret internal detail")
    with pytest.raises(BrowserError, match="browser_failure:RuntimeError") as ei:
        await w.run({"operation": "extract", "target_url": "https://example.com/"})
    assert "secret" not in str(ei.value)

    class Down:
        async def open_session(self, policy: BrowserPolicy, g: UrlGuard) -> FakeSession:
            raise ConnectionError("no browser")

        async def aclose(self) -> None:
            pass

    w2, _, _ = worker(Down())  # type: ignore[arg-type]
    with pytest.raises(BrowserError, match="browser_failure:ConnectionError"):
        await w2.run({"operation": "navigate", "url": "https://example.com/"})


async def test_operation_and_session_limits_and_closed_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    w, _, _ = worker(max_operations=2)
    await w.run({"operation": "navigate", "url": "https://example.com/"})
    await w.run({"operation": "navigate", "url": "https://example.com/"})
    with pytest.raises(BrowserBlockedError, match="operation_limit"):
        await w.run({"operation": "navigate", "url": "https://example.com/"})
    w, _, _ = worker(session_timeout_seconds=1.0)
    clock = [100.0]
    monkeypatch.setattr("axis_runtime.browser.worker.time.monotonic", lambda: clock[0])
    await w.run({"operation": "navigate", "url": "https://example.com/"})
    clock[0] += 5
    with pytest.raises(BrowserBlockedError, match="session_timeout"):
        await w.run({"operation": "navigate", "url": "https://example.com/"})
    await w.aclose()
    with pytest.raises(BrowserError, match="closed"):
        await w.run({"operation": "navigate", "url": "https://example.com/"})
    await w.aclose()  # idempotent


async def test_an_operation_timeout_is_an_error() -> None:
    import asyncio

    class Slow(FakeSession):
        async def navigate(self, url: str) -> PageState:
            await asyncio.sleep(5)
            return self._st()

    class B(FakeBackend):
        async def open_session(self, policy: BrowserPolicy, g: UrlGuard) -> FakeSession:
            return Slow()

    w, _, _ = worker(B(), op_timeout_seconds=0.01)
    import axis_runtime.browser.worker as wk

    orig = wk.asyncio.wait_for

    async def quick(coro: Any, timeout: float) -> Any:
        return await orig(coro, 0.05)

    wk.asyncio.wait_for = quick  # type: ignore[assignment]
    try:
        with pytest.raises(BrowserError, match="operation_timeout"):
            await w.run({"operation": "navigate", "url": "https://example.com/"})
    finally:
        wk.asyncio.wait_for = orig  # type: ignore[assignment]


def test_factory_without_a_policy_denies_everything() -> None:
    backend = FakeBackend()
    f = BrowserWorkerFactory(backend, lambda t, a: None)
    w = f.for_run(tenant_id=TENANT, agent="a", run_id="r")
    assert w._policy.allowed_hosts == ()

    def boom(t: str, a: str) -> BrowserPolicy:
        raise RuntimeError("policy store down")

    assert (
        BrowserWorkerFactory(backend, boom)
        .for_run(tenant_id=TENANT, agent="a", run_id="r")
        ._policy.allowed_hosts
        == ()
    )
    p = BrowserPolicy(allowed_hosts=("example.com",))
    assert (
        BrowserWorkerFactory(backend, lambda t, a: p)
        .for_run(tenant_id=TENANT, agent="a", run_id="r")
        ._policy
        is p
    )


async def test_default_resolver_is_used_when_none_is_given() -> None:
    w = BrowserWorker(
        FakeBackend(),
        BrowserPolicy(allowed_hosts=("example.com",)),
        tenant_id=TENANT,
        agent="a",
        run_id="r",
    )
    assert w._guard is not None


# ---- through the executor and the gate ------------------------------------------------------------


async def executor(
    gate: ScriptedGate, w: BrowserWorker
) -> tuple[ActionExecutor, RunRecorder, InMemoryRunEventLog]:
    log = InMemoryRunEventLog()
    clock = FakeClock()
    rec = await RunRecorder.start(log, clock, run_id="run_1", tenant_id=TENANT, meta={})
    await rec.record(EventType.PROCESS_SPAWNED, PID, {"ppid": None, "agent": "a@1"})
    for frm, to, trig in (("spawn", "ready", "init_complete"), ("ready", "running", "scheduled")):
        await rec.record(
            EventType.PROCESS_TRANSITION, PID, {"from": frm, "to": to, "trigger": trig}
        )
    ex = ActionExecutor(
        gate=gate, recorder=rec, identity=identity(), backends=Backends(browser=w), gate_timeout=0.2
    )
    return ex, rec, log


async def test_gate_context_carries_operation_url_host_and_hash_but_never_typed_text() -> None:
    w, backend, _ = worker()
    gate = ScriptedGate()
    ex, _, log = await executor(gate, w)
    out = await ex.run(
        w.action("web", {"operation": "navigate", "url": "https://example.com/a?k=SECRET"}), pid=PID
    )
    assert isinstance(out, Completed)
    out = await ex.run(
        w.action("web", {"operation": "type", "selector": "#n", "text": "TYPED-TEXT"}), pid=PID
    )
    assert isinstance(out, Completed)
    out = await ex.run(
        w.action("web", {"operation": "type", "selector": "#password", "text": "P4SSW0RD"}), pid=PID
    )
    assert isinstance(out, Completed)
    out = await ex.run(w.action("web", {"operation": "extract"}), pid=PID)
    nav, typ, pw, ext = (r.context for r in gate.requests)
    assert nav["tool"] == {"name": "web", "kind": "browser", "side_effects": "external"}
    assert gate.requests[0].enforcement_point.value == "browser_exec"
    assert nav["args"]["operation"] == "navigate" and nav["args"]["host"] == "example.com"
    assert nav["args"]["url"].startswith("https://example.com/a?q_sha256=")
    assert len(nav["args"]["args_hash"]) == 64
    assert typ["args"]["text_len"] == 10 and typ["args"]["host"] == "example.com"
    assert pw["args"]["sensitive"] is True and pw["args"]["text_sha256"] is None
    assert ext["args"]["operation"] == "extract" and ext["args"]["host"] == "example.com"
    dump = json.dumps([r.context for r in gate.requests])
    for secret in ("TYPED-TEXT", "P4SSW0RD", "SECRET"):
        assert secret not in dump
    events = json.dumps([e.data for e in await log.read("run_1")], default=str)
    for secret in ("TYPED-TEXT", "P4SSW0RD", "SECRET", "page text é"):
        assert secret not in events, secret  # the extracted text goes to the agent, not the log
    assert isinstance(out, Completed) and out.result["text"] == "page text é"
    assert '"text_sha256"' in events and '"blocked_requests"' in events


async def test_denied_browser_action_opens_no_context_and_failure_is_not_approved() -> None:
    w, backend, _ = worker()
    ex, _, _ = await executor(ScriptedGate(deny("no browsing")), w)
    out = await ex.run(
        w.action("web", {"operation": "navigate", "url": "https://example.com/"}), pid=PID
    )
    assert isinstance(out, Denied) and backend.sessions == []
    w, backend, _ = worker()
    ex, _, log = await executor(ScriptedGate(), w)
    out = await ex.run(
        w.action("web", {"operation": "navigate", "url": "https://evil.com/"}), pid=PID
    )
    assert (
        isinstance(out, Failed) and "host_not_allowlisted" in out.error and backend.sessions == []
    )
    failed = [e for e in await log.read("run_1") if str(e.type) == "tool_call_result"]
    assert failed and failed[-1].data["ok"] is False


async def test_redaction_of_the_selector_is_applied_and_unknown_paths_are_harmless() -> None:
    w, backend, _ = worker()
    gate = ScriptedGate(
        GateDecision(
            Decision.ALLOW_WITH_REDACTION, "r", "v1", redact_fields=("args.selector", "args.nope")
        )
    )
    ex, _, _ = await executor(gate, w)
    await ex.run(w.action("web", {"operation": "navigate", "url": "https://example.com/"}), pid=PID)
    out = await ex.run(w.action("web", {"operation": "click", "selector": "#buy"}), pid=PID)
    assert isinstance(out, Completed)
    assert ("click", "[REDACTED]") in backend.sessions[0].calls


async def test_agent_cannot_spoof_target_url() -> None:
    w, backend, _ = worker()
    ex, _, _ = await executor(ScriptedGate(), w)
    await ex.run(w.action("web", {"operation": "navigate", "url": "https://example.com/"}), pid=PID)
    spoof = BrowserExec(
        name="web",
        args={"operation": "click", "selector": "#a", "target_url": "https://example.com/"},
        target_url="",
    )
    out = await ex.run(spoof, pid=PID)
    assert (
        isinstance(out, Failed) and "target_url_required" in out.error
    )  # args value is overwritten


def test_browser_exec_serialises_for_temporal() -> None:
    from axis_runtime.actions import action_from_spec

    a = BrowserExec(
        name="web", args={"operation": "click", "selector": "#a"}, target_url="https://x/"
    )
    assert action_from_spec(a.to_spec()) == a


async def test_allow_decision_helpers_are_used() -> None:
    assert allow().decision is Decision.ALLOW
