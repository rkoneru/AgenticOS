# ruff: noqa: F811
"""Phase 4 review probes against real Chromium and the local fixture (no internet)."""

from __future__ import annotations

import pytest
from axis_runtime.browser.playwright_backend import PlaywrightBackend
from browser_fixture import Resp, page
from test_browser_backend import (  # noqa: F401  (fixtures)
    Site,
    backend,
    open_session,
    settle,
    site,
)


def _two_origin_policy(site: Site):  # type: ignore[no-untyped-def]
    other = f"localhost:{site.evil.port}"  # a different HOST (cookies / auth are per host)
    return site.policy(
        allowed_hosts=(site.host, other),
        private_hosts=(site.host, other),
    )


async def test_credentials_are_not_forwarded_to_another_origin_on_a_redirect(
    site: Site, backend: PlaywrightBackend
) -> None:
    """A browser strips Authorization (and never sends host-only cookies) on a cross-origin redirect.
    The backend re-issues each hop itself, so it must do the same."""
    other = f"http://localhost:{site.evil.port}"
    site.main.routes["/redir"] = lambda _q: Resp(302, {"location": f"{other}/collect"})
    site.evil.routes["/collect"] = lambda _q: Resp(
        200, {"access-control-allow-origin": "*"}, "collected"
    )
    site.main.routes["/app"] = lambda _q: Resp(
        body=page(
            "<script>fetch('/redir', {headers: {Authorization: 'Bearer SECRET-TOKEN',"
            " 'X-Api-Key': 'k-123'}}).catch(() => {});</script>"
        )
    )
    s = await open_session(backend, _two_origin_policy(site))
    try:
        await s.navigate(site.url("/app"))
        await settle(s)
        got = [r for r in site.evil.requests if r.path == "/collect"]
        assert got, "the allowlisted redirect target was never reached (vacuous test)"
        assert "authorization" not in got[0].headers, got[0].headers
    finally:
        await s.close()


async def test_authorization_survives_a_same_origin_redirect_and_body_headers_go_on_a_303(
    site: Site, backend: PlaywrightBackend
) -> None:
    """Negative control for the fix: only a cross-origin hop loses Authorization, and only a
    method-changing redirect loses the request-body headers."""
    site.main.routes["/redir-same"] = lambda _q: Resp(302, {"location": "/landed"})
    site.main.routes["/landed"] = lambda _q: Resp(200, {}, "landed")
    site.main.routes["/post303"] = lambda _q: Resp(303, {"location": "/landed2"})
    site.main.routes["/landed2"] = lambda _q: Resp(200, {}, "landed2")
    site.main.routes["/app"] = lambda _q: Resp(
        body=page(
            "<script>fetch('/redir-same', {headers: {Authorization: 'Bearer SAME'}});"
            "fetch('/post303', {method: 'POST', body: '{}',"
            " headers: {'Content-Type': 'application/json', Authorization: 'Bearer P'}});</script>"
        )
    )
    s = await open_session(backend, site.policy())
    try:
        await s.navigate(site.url("/app"))
        await settle(s)
        landed = [r for r in site.main.requests if r.path == "/landed"]
        assert landed and landed[0].headers.get("authorization") == "Bearer SAME"
        assert landed[0].body == b"" and landed[0].headers.get("content-length") in (None, "0")
        landed2 = [r for r in site.main.requests if r.path == "/landed2"]
        assert landed2 and landed2[0].method == "GET"
        assert landed2[0].headers.get("authorization") == "Bearer P"
        assert "content-type" not in landed2[0].headers
        assert landed2[0].body == b"", "the POST payload must not travel on to the redirected GET"
    finally:
        await s.close()


async def test_a_backslash_host_confusion_url_never_reaches_the_network(
    site: Site, backend: PlaywrightBackend
) -> None:
    """``http://evil\\.allowed-suffix/`` parses (urlsplit) as a host under the wildcard, but Chromium reads
    the backslash as a path separator and would connect to ``evil``. The session-level navigate (no worker
    pre-check) must still be blocked by the network layer."""
    from axis_runtime.browser.backend import BrowserError

    policy = site.policy(allowed_hosts=(site.host, "*.example.org"))
    s = await open_session(backend, policy)
    try:
        with pytest.raises(BrowserError):
            await s.navigate(f"http://localhost:{site.main.port}\\.example.org/index")
        assert all("localhost" not in h for h in site.main.hosts())
    finally:
        await s.close()
