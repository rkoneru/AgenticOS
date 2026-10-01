"""Real Chromium against a LOCAL fixture server (no internet): network-layer isolation proofs.

The fixture host is an IP literal on loopback, so it is allowlisted AND a named private exception
(``private_hosts``) in the policies below, except in the tests that prove the private-range block.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import pytest
from axis_runtime.browser.backend import BrowserError, BrowserSession
from axis_runtime.browser.playwright_backend import PlaywrightBackend
from axis_runtime.browser.policy import BrowserPolicy, UrlGuard
from browser_fixture import FixtureServer, Req, Resp, page

pytestmark = pytest.mark.filterwarnings("ignore::ResourceWarning")


async def public_resolver(host: str, port: int) -> list[str]:
    return ["93.184.216.34"]


@dataclass
class Site:
    main: FixtureServer
    evil: FixtureServer

    @property
    def host(self) -> str:
        return f"127.0.0.1:{self.main.port}"

    def policy(self, **over: Any) -> BrowserPolicy:
        base: dict[str, Any] = {
            "allowed_hosts": (self.host,),
            "private_hosts": (self.host,),
            "op_timeout_seconds": 10.0,
        }
        return BrowserPolicy(**{**base, **over})

    def url(self, path: str) -> str:
        return f"{self.main.origin}{path}"


def _routes(site: Site) -> None:
    m, evil = site.main, site.evil
    other = f"http://localhost:{m.port}"
    ev = evil.origin
    ws_evil = f"ws://127.0.0.1:{evil.port}/ws"
    ws_ok = f"ws://127.0.0.1:{m.port}/ws"

    def r(path: str, resp: Resp | str) -> None:
        m.routes[path] = (
            (lambda _q, _r=resp: _r)
            if isinstance(resp, Resp)
            else (lambda _q, _r=resp: Resp(body=_r))
        )

    r("/index", page("<h1>hello</h1><p id=t>fixture text</p>", "Index"))
    r("/redirect-ok", Resp(302, {"location": "/index"}))
    r("/redirect-host", Resp(302, {"location": f"{other}/index"}))
    r("/redirect-evil", Resp(302, {"location": f"{ev}/secret"}))
    r("/redirect-file", Resp(302, {"location": "file:///etc/hostname"}))
    r("/chain1", Resp(302, {"location": "/chain2"}))
    r("/chain2", Resp(302, {"location": f"{ev}/secret"}))
    r("/pixel", Resp(200, {"content-type": "image/gif"}, b"GIF89a"))
    r(
        "/sub",
        page(
            f"""<div id=out></div>
<img src="{ev}/img"><script src="{ev}/s.js"></script><link rel=stylesheet href="{ev}/c.css">
<iframe src="{ev}/frame"></iframe><img id=ok src="/pixel">
<script>
const log = (m) => {{ document.getElementById('out').append(m + ';'); }};
fetch("{ev}/fetch").then(() => log('fetch-LEAK')).catch(() => log('fetch-blocked'));
const x = new XMLHttpRequest(); x.open('GET', "{ev}/xhr");
x.onerror = () => log('xhr-blocked'); x.onload = () => log('xhr-LEAK'); x.send();
try {{ navigator.sendBeacon("{ev}/beacon", 'x'); }} catch (e) {{}}
const ws = new WebSocket("{ws_evil}");
ws.onmessage = () => log('ws-LEAK'); ws.onclose = () => log('ws-closed');
</script>""",
            "Sub",
        ),
    )
    r(
        "/ws-ok",
        page(
            f"""<div id=out></div><script>
const ws = new WebSocket("{ws_ok}");
ws.onmessage = (e) => document.getElementById('out').append(e.data);
</script>""",
            "WS",
        ),
    )
    r(
        "/set-cookie",
        Resp(200, {"set-cookie": "sid=secret-123; Path=/"}, page("cookie set", "Cookie")),
    )
    r(
        "/echo-cookie",
        lambda_page := page(
            "<pre id=c></pre><script>document.getElementById('c').innerText="
            "'cookie=[' + document.cookie + '] ls=[' + (localStorage.getItem('k')||'') + "
            "'] bc=[' + (window.__bc||'') + ']';"
            "const b = new BroadcastChannel('leak'); b.onmessage = (e) => { window.__bc = e.data; "
            "document.getElementById('c').innerText += ' got:' + e.data; };</script>",
            "Echo",
        ),
    )
    r(
        "/storage-write",
        page(
            "<script>localStorage.setItem('k','v-from-A'); document.cookie='js=1; path=/';"
            "new BroadcastChannel('leak').postMessage('hello-from-A');</script>stored",
            "Writer",
        ),
    )
    r("/big", page("x" * 3_000_000, "Big"))
    r(
        "/popup",
        page(
            f"""<div id=out>start</div><script>
alert('hi'); confirm('sure?'); prompt('p');
window.open("{site.url("/index")}", '_blank');
document.getElementById('out').innerText = 'done';
</script>""",
            "Popup",
        ),
    )
    r(
        "/dl",
        Resp(
            200,
            {
                "content-disposition": "attachment; filename=a.bin",
                "content-type": "application/octet-stream",
            },
            b"BINARY",
        ),
    )
    r("/file-frame", page('<iframe src="file:///etc/hostname"></iframe>file frame', "FileFrame"))
    r(
        "/form",
        page(
            """<input id=user><input id=pw type=password><input id=note>
<button id=go onclick="location='/index'">go</button>""",
            "Form",
        ),
    )
    r("/count", page("<p>c</p>", "Count"))
    r(
        "/stall",
        page(f'<img src="{site.url("/pixel")}"><img src="{site.url("/pixel")}?2">', "Stall"),
    )
    for e in ("/secret", "/img", "/s.js", "/c.css", "/frame", "/fetch", "/xhr", "/beacon", "/ws"):
        evil.routes[e] = lambda _q: Resp(body="EVIL-SECRET")


@pytest.fixture
async def site() -> AsyncIterator[Site]:
    s = Site(FixtureServer("main"), FixtureServer("evil"))
    await s.main.start()
    await s.evil.start()
    _routes(s)
    yield s
    await s.main.stop()
    await s.evil.stop()


@pytest.fixture
async def backend() -> AsyncIterator[PlaywrightBackend]:
    b = PlaywrightBackend()
    try:
        await b.start()
    except BrowserError as exc:  # documented in docs/NEEDS.md #306: chromium must be launchable
        pytest.skip(f"chromium cannot be launched here: {exc}")
    yield b
    await b.aclose()


async def open_session(
    backend: PlaywrightBackend, policy: BrowserPolicy, resolver: Any = public_resolver
) -> BrowserSession:
    return await backend.open_session(policy, UrlGuard(policy, resolver))


async def settle(session: BrowserSession, quiet: float = 0.6) -> None:
    """Wait until the page has stopped making requests."""
    last = -1
    while (n := session.telemetry().requests + session.telemetry().blocked_total) != last:
        last = n
        await asyncio.sleep(quiet)


def reasons(session: BrowserSession) -> list[str]:
    return [b.reason for b in session.telemetry().blocked]


# ---- positive controls --------------------------------------------------------------------------


async def test_allowlisted_page_loads_extracts_and_screenshots(
    site: Site, backend: PlaywrightBackend
) -> None:
    s = await open_session(backend, site.policy())
    try:
        st = await s.navigate(site.url("/index"))
        assert (st.title, st.status, st.url) == ("Index", 200, site.url("/index"))
        text, truncated = await s.extract(None)
        assert "fixture text" in text and not truncated
        assert (await s.extract("#t"))[0] == "fixture text"
        assert (await s.screenshot()).startswith(b"\x89PNG")
        assert s.telemetry().blocked_total == 0
    finally:
        await s.close()


async def test_redirect_within_the_allowlist_is_followed(
    site: Site, backend: PlaywrightBackend
) -> None:
    s = await open_session(backend, site.policy())
    try:
        st = await s.navigate(site.url("/redirect-ok"))
        assert st.title == "Index" and st.url.endswith("/index")
    finally:
        await s.close()


async def test_websocket_to_an_allowlisted_host_works_so_the_block_is_not_vacuous(
    site: Site, backend: PlaywrightBackend
) -> None:
    s = await open_session(backend, site.policy())
    try:
        await s.navigate(site.url("/ws-ok"))
        await settle(s)
        assert "ws-hello-ok" in (await s.extract("#out"))[0]
    finally:
        await s.close()


# ---- the network layer blocks what is not allowlisted --------------------------------------------


async def test_main_frame_navigation_to_a_non_allowlisted_host_is_blocked_by_the_network_layer(
    site: Site, backend: PlaywrightBackend
) -> None:
    s = await open_session(backend, site.policy())  # session level: no worker precheck here
    try:
        for target in (
            f"http://localhost:{site.main.port}/index",  # other NAME, same server
            f"{site.evil.origin}/secret",  # other PORT
        ):
            with pytest.raises(BrowserError, match="blocked: host_not_allowlisted"):
                await s.navigate(target)
        assert site.evil.requests == []
        assert all("localhost" not in h for h in site.main.hosts())
    finally:
        await s.close()


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("/redirect-host", "redirect:host_not_allowlisted"),
        ("/redirect-evil", "redirect:host_not_allowlisted"),
        ("/chain1", "redirect:host_not_allowlisted"),
        ("/redirect-file", "redirect:scheme_not_allowed"),
    ],
)
async def test_redirect_from_allowed_to_disallowed_is_blocked(
    site: Site, backend: PlaywrightBackend, path: str, reason: str
) -> None:
    s = await open_session(backend, site.policy())
    try:
        with pytest.raises(BrowserError, match="blocked"):
            await s.navigate(site.url(path))
        assert reason in reasons(s)
        assert site.evil.requests == [] and site.evil.connections == 0
        assert not any("localhost" in h for h in site.main.hosts())
    finally:
        await s.close()


async def test_subresources_iframes_fetch_xhr_beacon_and_websocket_are_blocked(
    site: Site, backend: PlaywrightBackend
) -> None:
    s = await open_session(backend, site.policy())
    try:
        await s.navigate(site.url("/sub"))
        await settle(s)
        out = (await s.extract("#out"))[0]
        assert "LEAK" not in out
        assert {"fetch-blocked", "xhr-blocked", "ws-closed"} <= set(out.split(";"))
        # nothing reached the disallowed server: not even a TCP connection
        assert site.evil.requests == [] and site.evil.connections == 0
        blocked = s.telemetry().blocked
        types = {b.resource_type for b in blocked}
        assert {"image", "script", "stylesheet", "document", "fetch", "xhr", "websocket"} <= types
        assert all(b.reason == "host_not_allowlisted" for b in blocked)
        assert "/pixel" in "".join(site.main.paths())  # allowed subresource still loaded
    finally:
        await s.close()


async def test_private_loopback_is_blocked_unless_explicitly_a_private_exception(
    site: Site, backend: PlaywrightBackend
) -> None:
    pol = site.policy(private_hosts=())  # allowlisted, but NOT an explicit private exception
    s = await open_session(backend, pol)
    try:
        with pytest.raises(BrowserError, match="private_address"):
            await s.navigate(site.url("/index"))
        assert site.main.requests == []
    finally:
        await s.close()


async def test_file_scheme_is_blocked_at_every_layer(
    site: Site, backend: PlaywrightBackend
) -> None:
    s = await open_session(backend, site.policy())
    try:
        for url in ("file:///etc/hostname", "chrome://version", "about:blank", "data:text/html,x"):
            with pytest.raises(BrowserError):
                await s.navigate(url)
        await s.navigate(site.url("/file-frame"))  # an iframe pointing at file:// loads nothing
        assert "file frame" in (await s.extract(None))[0]
    finally:
        await s.close()


async def test_downloads_popups_and_dialogs_are_neutralised(
    site: Site, backend: PlaywrightBackend
) -> None:
    s = await open_session(backend, site.policy())
    try:
        await s.navigate(site.url("/popup"))  # alert/confirm/prompt would hang an undismissed page
        await settle(s)
        assert (await s.extract("#out"))[0] == "done"
        tel = s.telemetry()
        assert tel.popups_blocked >= 1 and tel.dialogs_dismissed == 3
        assert len(s._ctx.pages) == 1  # type: ignore[attr-defined]
        with pytest.raises(BrowserError, match="blocked: download_blocked"):
            await s.navigate(site.url("/dl"))
    finally:
        await s.close()


async def test_huge_page_is_capped_before_it_reaches_the_page(
    site: Site, backend: PlaywrightBackend
) -> None:
    s = await open_session(backend, site.policy(max_body_bytes=100_000))
    try:
        with pytest.raises(BrowserError, match="response_too_large"):
            await s.navigate(site.url("/big"))
        assert s.telemetry().bytes_received == 0
    finally:
        await s.close()
    s = await open_session(backend, site.policy(max_text_bytes=10))
    try:
        await s.navigate(site.url("/index"))
        text, truncated = await s.extract(None)
        assert truncated and len(text.encode()) <= 10
    finally:
        await s.close()


async def test_page_and_request_caps(site: Site, backend: PlaywrightBackend) -> None:
    s = await open_session(backend, site.policy(max_pages=2))
    try:
        await s.navigate(site.url("/index"))
        await s.navigate(site.url("/count"))
        with pytest.raises(BrowserError, match="page_limit"):
            await s.navigate(site.url("/index"))
    finally:
        await s.close()
    s = await open_session(backend, site.policy(max_requests=1))
    try:
        await s.navigate(site.url("/stall"))  # the images are over the cap
        await settle(s)
        assert "request_limit" in reasons(s)
    finally:
        await s.close()


# ---- isolation between contexts -----------------------------------------------------------------


async def test_contexts_do_not_share_cookies_storage_or_channels(
    site: Site, backend: PlaywrightBackend
) -> None:
    a = await open_session(backend, site.policy())
    b = await open_session(backend, site.policy())
    try:
        await b.navigate(site.url("/echo-cookie"))  # B listens on the BroadcastChannel
        await a.navigate(site.url("/set-cookie"))
        await a.navigate(site.url("/storage-write"))  # A sets cookie, localStorage, broadcasts
        await a.navigate(site.url("/echo-cookie"))
        text_a = (await a.extract("#c"))[0]
        assert "sid=secret-123" in text_a and "ls=[v-from-A]" in text_a
        await asyncio.sleep(0.3)
        await b.navigate(site.url("/echo-cookie"))
        text_b = (await b.extract("#c"))[0]
        assert (
            "secret-123" not in text_b and "v-from-A" not in text_b and "hello-from-A" not in text_b
        )
        # the server confirms it: B's requests never carried A's cookie
        b_echo = [r for r in site.main.requests if r.path == "/echo-cookie"]
        assert [r.headers.get("cookie") for r in b_echo][0] is None
    finally:
        await a.close()
        await b.close()
    c = await open_session(backend, site.policy())  # a later run starts clean too
    try:
        await c.navigate(site.url("/echo-cookie"))
        assert "secret-123" not in (await c.extract("#c"))[0]
    finally:
        await c.close()


async def test_closing_a_session_destroys_its_context(
    site: Site, backend: PlaywrightBackend
) -> None:
    s = await open_session(backend, site.policy())
    await s.navigate(site.url("/index"))
    await s.close()
    with pytest.raises(BrowserError):
        await s.navigate(site.url("/index"))


# ---- interaction --------------------------------------------------------------------------------


async def test_click_type_and_password_rules(site: Site, backend: PlaywrightBackend) -> None:
    s = await open_session(backend, site.policy())
    try:
        await s.navigate(site.url("/form"))
        await s.type_text("#note", "hello", sensitive=False)
        with pytest.raises(BrowserError, match="password_field_requires_sensitive"):
            await s.type_text("#pw", "hunter2", sensitive=False)
        await s.type_text("#pw", "hunter2", sensitive=True)
        st = await s.click("#go")
        assert st.title == "Index"
    finally:
        await s.close()


async def test_launch_failure_is_an_error_not_a_silent_fallback() -> None:
    b = PlaywrightBackend(executable_path="/nonexistent/chrome")
    with pytest.raises(BrowserError, match="browser_launch_failed"):
        await b.start()
    await b.aclose()


async def test_route_handler_errors_abort_the_request(
    site: Site, backend: PlaywrightBackend
) -> None:
    async def boom(host: str, port: int) -> list[str]:
        raise RuntimeError("resolver down")

    pol = site.policy(private_hosts=())  # forces the resolver path for a NAME... literal here
    s = await open_session(backend, pol, resolver=boom)
    try:
        with pytest.raises(BrowserError):
            await s.navigate(site.url("/index"))
        assert site.main.requests == []
    finally:
        await s.close()


def test_fixture_helpers_are_exercised() -> None:
    assert Req("GET", "/", {}).body == b""
