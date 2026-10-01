"""Redirect handling, failure paths and caps of the Playwright backend (real Chromium)."""

from __future__ import annotations

import pytest
from axis_runtime.browser.backend import BrowserError
from axis_runtime.browser.playwright_backend import PlaywrightBackend, PlaywrightSession
from axis_runtime.browser.policy import BlockedError
from browser_fixture import Resp, page
from test_browser_backend import (  # noqa: F401  (fixtures)
    Site,
    backend,
    open_session,
    reasons,
    settle,
    site,
)


def _more(site: Site) -> None:
    m, ev = site.main.routes, site.evil.origin

    def r(path: str, resp: Resp | str) -> None:
        m[path] = lambda _q, _r=resp: _r if isinstance(resp, Resp) else Resp(body=_r)

    r("/img-redir", Resp(302, {"location": "/pixel"}))
    r("/img-redir-evil", Resp(302, {"location": f"{ev}/img"}))
    r("/loop", Resp(302, {"location": "/loop"}))
    r("/pixel", Resp(200, {"content-type": "image/gif"}, b"GIF89a"))
    r(
        "/sub-redir",
        page('<img src="/img-redir"><img src="/img-redir-evil"><img src="/loop">', "SubRedir"),
    )
    r("/click-redir", page("<button id=go onclick=\"location='/redirect-ok'\">go</button>"))
    r("/redirect-ok", Resp(302, {"location": "/index"}))
    r("/index", page("<p>index</p>", "Index"))
    r("/post-form", page('<form method=post action="/post303"><button id=s>s</button></form>'))
    r("/post-form307", page('<form method=post action="/post307"><button id=s>s</button></form>'))
    r("/post303", Resp(303, {"location": "/index"}))
    r("/post307", Resp(307, {"location": "/index"}))
    r("/dl-link", page('<a id=d href="/pixel" download="x.gif">d</a>', "DL"))
    r("/total", page("".join(f'<img src="/big-img{i}">' for i in range(3)), "Total"))
    for i in range(3):
        r(f"/big-img{i}", Resp(200, {"content-type": "image/gif"}, b"G" * 60_000))


async def test_subresource_redirects_are_followed_hop_by_hop(
    site: Site, backend: PlaywrightBackend
) -> None:
    _more(site)
    s = await open_session(backend, site.policy())
    try:
        await s.navigate(site.url("/sub-redir"))
        await settle(s)
        assert "/pixel" in site.main.paths()  # the allowed redirect was followed
        r = reasons(s)
        assert "redirect:host_not_allowlisted" in r  # the redirect into the other host
        assert "too_many_redirects" in r
        assert site.evil.requests == [] and site.evil.connections == 0
    finally:
        await s.close()


async def test_main_frame_redirect_loop_is_cut_off(site: Site, backend: PlaywrightBackend) -> None:
    _more(site)
    s = await open_session(backend, site.policy())
    try:
        with pytest.raises(BrowserError, match="too_many_redirects"):
            await s.navigate(site.url("/loop"))
    finally:
        await s.close()


async def test_a_click_that_navigates_through_a_redirect_is_followed(
    site: Site, backend: PlaywrightBackend
) -> None:
    _more(site)
    s = await open_session(backend, site.policy())
    try:
        await s.navigate(site.url("/click-redir"))
        st = await s.click("#go")
        assert st.title == "Index"
        assert s.telemetry().pages_visited == 2
    finally:
        await s.close()


async def test_post_redirects_follow_http_semantics(site: Site, backend: PlaywrightBackend) -> None:
    _more(site)
    s = await open_session(backend, site.policy())
    try:
        await s.navigate(site.url("/post-form"))
        st = await s.click("#s")  # 303 turns the POST into a GET of /index
        assert st.title == "Index"
        await s.navigate(site.url("/post-form307"))
        await s.click("#s")  # 307 would replay the POST: refused
        assert "redirect_method_unsupported" in reasons(s)
    finally:
        await s.close()


async def test_download_links_are_cancelled(site: Site, backend: PlaywrightBackend) -> None:
    _more(site)
    s = await open_session(backend, site.policy())
    try:
        await s.navigate(site.url("/dl-link"))
        await s.click("#d")
        await settle(s)
        assert s.telemetry().downloads_blocked == 1
    finally:
        await s.close()


async def test_total_bytes_cap(site: Site, backend: PlaywrightBackend) -> None:
    _more(site)
    s = await open_session(backend, site.policy(max_total_bytes=150_000))
    try:
        await s.navigate(site.url("/total"))
        await settle(s)
        assert "response_too_large" in reasons(s)
        assert s.telemetry().bytes_received <= 150_000
    finally:
        await s.close()


async def test_unexpected_guard_errors_abort_requests_and_websockets(
    site: Site, backend: PlaywrightBackend
) -> None:
    _more(site)
    s = await open_session(backend, site.policy())
    assert isinstance(s, PlaywrightSession)
    try:
        await s.navigate(site.url("/index"))
        real = s._guard.check

        async def boom(url: str, *, websocket: bool = False) -> object:
            raise RuntimeError("boom")

        s._guard.check = boom  # type: ignore[method-assign]
        await s._page.evaluate(  # type: ignore[union-attr]
            "(u) => { fetch(u).catch(() => {}); new WebSocket(u.replace('http', 'ws') + 'x'); }",
            site.url("/pixel"),
        )
        await settle(s)
        s._guard.check = real  # type: ignore[method-assign]
        assert reasons(s).count("handler_error") >= 2
        with pytest.raises(BlockedError):
            await s._guard.check("https://not-allowed.example/")
    finally:
        await s.close()


async def test_a_page_that_left_http_is_closed_and_reported(
    site: Site, backend: PlaywrightBackend
) -> None:
    s = await open_session(backend, site.policy())
    assert isinstance(s, PlaywrightSession)
    try:
        await s.navigate(site.url("/index"))
        await s._page.goto("data:text/html,x")  # type: ignore[union-attr]
        with pytest.raises(BrowserError, match="page_left_http:data"):
            await s._check_scheme()
    finally:
        await s.close()


async def test_operations_on_a_closed_page_or_session_fail(
    site: Site, backend: PlaywrightBackend
) -> None:
    s = await open_session(backend, site.policy())
    assert isinstance(s, PlaywrightSession)
    await s.navigate(site.url("/index"))
    await s._page.close()  # type: ignore[union-attr]
    with pytest.raises(BrowserError, match="page_closed"):
        await s.extract(None)
    await s.close()


async def test_context_setup_and_close_failures_are_errors(
    site: Site, backend: PlaywrightBackend, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def bad_setup(self: PlaywrightSession) -> None:
        raise RuntimeError("x")

    with monkeypatch.context() as mp:
        mp.setattr(PlaywrightSession, "setup", bad_setup)
        with pytest.raises(BrowserError, match="browser_setup_failed"):
            await open_session(backend, site.policy())

    s = await open_session(backend, site.policy())
    assert isinstance(s, PlaywrightSession)

    class Boom:
        async def close(self) -> None:
            raise RuntimeError("x")

    real, s._ctx = s._ctx, Boom()  # type: ignore[assignment]
    with pytest.raises(BrowserError, match="browser_close_failed"):
        await s.close()
    await real.close()


async def test_backend_lifecycle_and_context_creation_failure(site: Site) -> None:
    b = PlaywrightBackend()
    s = await open_session(b, site.policy())  # lazily starts the browser
    await b.start()  # idempotent
    await s.close()
    assert b._browser is not None
    await b._browser.close()
    with pytest.raises(BrowserError, match="browser_context_failed"):
        await open_session(b, site.policy())
    await b.aclose()
    await b.aclose()
