"""PlaywrightBackend: Chromium via Playwright, one isolated context per run.

Network-layer enforcement (every request the page makes goes through ``UrlGuard`` BEFORE it leaves):

* ``context.route`` sees main frame, iframes, subresources, fetch/XHR, beacons, EventSource.
  Each allowed request is performed by the route handler itself with ``max_redirects=0`` so EVERY
  redirect hop is checked (on the ``Location`` header and again when the browser follows it), the
  body size is capped before it reaches the page, and ``Content-Disposition: attachment`` is
  refused;
* ``context.route_web_socket`` gates WebSockets (a refused socket is closed with 1008 and never
  connected to the server);
* service workers are blocked, downloads are disabled, popups are closed, dialogs are dismissed;
  WebRTC/WebTransport are removed (they bypass request interception).

KNOWN LIMITS (docs/spec/browser.md, NEEDS #99-#101): the address the guard resolved is NOT the one
Chromium connects to (no connect-time pinning: DNS rebinding of an ALLOWLISTED name is not closed);
Chromium-internal preconnect/DNS prefetch is disabled by flags, not intercepted; response bodies are
buffered by the driver before the size cap applies. The strong fix is an egress proxy / network
namespace for the browser process.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from urllib.parse import urljoin, urlsplit

from axis_runtime.browser.backend import (
    BlockedRequest,
    BrowserError,
    BrowserSession,
    PageState,
    Telemetry,
)
from axis_runtime.browser.policy import BlockedError, BrowserPolicy, UrlGuard, safe_url
from playwright.async_api import (
    Browser,
    BrowserContext,
    Dialog,
    Download,
    Page,
    Playwright,
    Request,
    Route,
    WebSocketRoute,
    async_playwright,
)

MAX_REDIRECTS = 10
#: Fetch standard, "HTTP-redirect fetch": a redirect to another ORIGIN drops Authorization; a
#: redirect that turns the request into a GET drops the request-body headers. The backend re-issues
#: every hop itself with the original request's headers, so it must apply these rules as the
#: browser would.
_CROSS_ORIGIN_DROP = frozenset({"authorization", "proxy-authorization"})
_BODY_HEADERS = frozenset(
    {"content-encoding", "content-language", "content-location", "content-type", "content-length"}
)
_LAUNCH_ARGS = (
    "--disable-features=NetworkPrediction,Prerender2,PrefetchProxy,WebRtcHideLocalIpsWithMdns",
    "--dns-prefetch-disable",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--disable-background-networking",
    "--disable-component-update",
    "--no-pings",
    "--disable-sync",
)
# Browser features that open sockets outside request interception.
_INIT_SCRIPT = """
for (const n of ['RTCPeerConnection','webkitRTCPeerConnection','RTCDataChannel','WebTransport']) {
  try { Object.defineProperty(window, n, {value: undefined, configurable: false}); } catch (e) {}
}
"""


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        port = None
    return (parts.scheme.lower(), (parts.hostname or "").lower(), port)


class PlaywrightBackend:
    """Launches one Chromium and hands out isolated contexts. Call ``start`` before use."""

    def __init__(
        self,
        *,
        executable_path: str | None = None,
        headless: bool = True,
        extra_args: Sequence[str] = (),
    ) -> None:
        self._executable_path = executable_path
        self._headless = headless
        self._extra_args = tuple(extra_args)
        self._pw: Playwright | None = None
        self._browser: Browser | None = None

    async def start(self) -> None:
        if self._browser is not None:
            return
        self._pw = await async_playwright().start()
        try:
            self._browser = await self._pw.chromium.launch(
                executable_path=self._executable_path,
                headless=self._headless,
                args=[*_LAUNCH_ARGS, *self._extra_args],
            )
        except Exception as exc:
            await self._pw.stop()
            self._pw = None
            raise BrowserError(f"browser_launch_failed:{type(exc).__name__}") from exc

    async def open_session(self, policy: BrowserPolicy, guard: UrlGuard) -> BrowserSession:
        if self._browser is None:
            await self.start()
        assert self._browser is not None  # noqa: S101
        try:
            context = await self._browser.new_context(
                accept_downloads=False,
                service_workers="block",
                permissions=[],
                ignore_https_errors=False,
                bypass_csp=False,
                viewport={"width": 1280, "height": 800},
            )
        except Exception as exc:
            raise BrowserError(f"browser_context_failed:{type(exc).__name__}") from exc
        session = PlaywrightSession(context, policy, guard)
        try:
            await session.setup()
        except Exception as exc:
            await context.close()
            raise BrowserError(f"browser_setup_failed:{type(exc).__name__}") from exc
        return session

    async def aclose(self) -> None:
        browser, self._browser = self._browser, None
        pw, self._pw = self._pw, None
        if browser is not None:
            await browser.close()
        if pw is not None:
            await pw.stop()


class PlaywrightSession:
    def __init__(self, context: BrowserContext, policy: BrowserPolicy, guard: UrlGuard) -> None:
        self._ctx = context
        self._policy = policy
        self._guard = guard
        self._page: Page | None = None
        self._blocked: list[BlockedRequest] = []
        self._blocked_total = 0
        self._requests = 0
        self._bytes = 0
        self._pages_visited = 0
        self._popups = 0
        self._dialogs = 0
        self._downloads = 0
        self._status: int | None = None
        self._nav_redirect: str | None = None
        self._closed = False

    # ---- setup -----------------------------------------------------------------------------------
    async def setup(self) -> None:
        self._ctx.set_default_timeout(self._policy.op_timeout_seconds * 1000)
        await self._ctx.add_init_script(_INIT_SCRIPT)
        await self._ctx.route("**/*", self._on_route)
        await self._ctx.route_web_socket("**/*", self._on_websocket)
        self._ctx.on("page", self._on_page)
        self._page = await self._ctx.new_page()

    def _on_page(self, page: Page) -> None:
        if self._page is None:
            self._page = page
            page.on("dialog", self._on_dialog)
            page.on("download", self._on_download)
            return
        if page is self._page:
            return
        self._popups += 1  # popups / new tabs: closed at once, never navigated
        self._record("popup", "", "popup_blocked", "popup")
        asyncio.ensure_future(self._close_quietly(page))

    @staticmethod
    async def _close_quietly(page: Page) -> None:
        try:
            await page.close()
        except Exception:  # noqa: BLE001, S110 - the page may already be gone
            pass

    def _on_dialog(self, dialog: Dialog) -> None:
        self._dialogs += 1
        asyncio.ensure_future(self._dismiss(dialog))

    @staticmethod
    async def _dismiss(dialog: Dialog) -> None:
        try:
            await dialog.dismiss()
        except Exception:  # noqa: BLE001, S110
            pass

    def _on_download(self, download: Download) -> None:
        self._downloads += 1
        self._record(download.url, "", "download_blocked", "download")
        asyncio.ensure_future(self._cancel_download(download))

    @staticmethod
    async def _cancel_download(download: Download) -> None:
        try:
            await download.cancel()
        except Exception:  # noqa: BLE001, S110
            pass

    # ---- network layer ---------------------------------------------------------------------------
    def _record(self, url: str, host: str, reason: str, rtype: str) -> None:
        self._blocked_total += 1
        if len(self._blocked) < self._policy.max_blocked_logged:
            self._blocked.append(BlockedRequest(safe_url(url) if url else "", host, reason, rtype))

    @staticmethod
    async def _abort(route: Route) -> None:
        try:
            await route.abort("blockedbyclient")
        except Exception:  # noqa: BLE001, S110 - already handled / page closed
            pass

    async def _on_route(self, route: Route) -> None:
        request = route.request
        try:
            await self._handle(route, request)
        except Exception:  # noqa: BLE001 - fail closed: anything unexpected aborts the request
            self._record(request.url, "", "handler_error", request.resource_type)
            await self._abort(route)

    async def _handle(self, route: Route, request: Request) -> None:
        """Perform the request ourselves, following redirects HOP BY HOP.

        Chromium does NOT call the route handler for redirect hops (verified: a fulfilled or
        continued 3xx is followed natively and unseen), so letting it follow a redirect would bypass
        the allowlist after the first hop. Hence: sub-resources and iframes are resolved to their
        final response here (every hop guarded) and the page only ever receives a non-redirect
        response; for a main-frame navigation the request is aborted and ``navigate`` re-issues it
        to the verified target, so that the next hop is a fresh, routed request.
        """
        rtype = request.resource_type
        if self._closed:
            await self._abort(route)
            return
        current, method = request.url, request.method
        post = request.post_data_buffer
        headers: dict[str, str] | None = None  # None = the request's own headers (first hop)
        main_nav = request.is_navigation_request() and request.frame.parent_frame is None
        hops = 0
        while True:
            self._requests += 1
            if self._requests > self._policy.max_requests:
                self._record(current, "", "request_limit", rtype)
                await self._abort(route)
                return
            try:
                await self._guard.check(current)
            except BlockedError as exc:
                reason = f"redirect:{exc.reason}" if hops else exc.reason
                self._record(current, exc.host, reason, rtype)
                await self._abort(route)
                return
            response = await route.fetch(
                url=current,
                method=method,
                headers=headers,
                post_data=post,
                max_redirects=0,
                timeout=self._policy.op_timeout_seconds * 1000,
            )
            location = response.headers.get("location")
            if not (300 <= response.status < 400 and location):
                break
            hops += 1
            if hops > MAX_REDIRECTS:
                self._record(current, "", "too_many_redirects", rtype)
                await self._abort(route)
                return
            previous, current = current, urljoin(current, location)
            drop: set[str] = set()
            if _origin(previous) != _origin(current):
                drop |= _CROSS_ORIGIN_DROP
            if response.status in (301, 302, 303) and method not in ("GET", "HEAD"):
                # None would mean "the original body" to ``route.fetch``: an explicit empty body is
                # how a redirect-converted GET really drops the POST payload.
                method, post = "GET", b""
                drop |= _BODY_HEADERS
            if drop:
                headers = {
                    k: v
                    for k, v in (headers if headers is not None else request.headers).items()
                    if k.lower() not in drop
                }
            elif main_nav and method not in ("GET", "HEAD"):
                self._record(current, "", "redirect_method_unsupported", rtype)
                await self._abort(route)
                return
            if main_nav:
                try:  # verify now so the blocked reason names the redirect; navigate() re-routes
                    await self._guard.check(current)
                except BlockedError as exc:
                    self._record(current, exc.host, f"redirect:{exc.reason}", rtype)
                    await self._abort(route)
                    return
                self._nav_redirect = current
                await self._abort(route)
                return
        if "attachment" in response.headers.get("content-disposition", "").lower():
            self._record(current, "", "download_blocked", rtype)
            await self._abort(route)
            return
        body = await response.body()
        if (
            len(body) > self._policy.max_body_bytes
            or self._bytes + len(body) > self._policy.max_total_bytes
        ):
            self._record(current, "", "response_too_large", rtype)
            await self._abort(route)
            return
        self._bytes += len(body)
        await route.fulfill(response=response, body=body)

    async def _on_websocket(self, ws: WebSocketRoute) -> None:
        try:
            await self._guard.check(ws.url, websocket=True)
        except BlockedError as exc:
            self._record(ws.url, exc.host, exc.reason, "websocket")
            await ws.close(code=1008, reason="blocked")
            return
        except Exception:  # noqa: BLE001
            self._record(ws.url, "", "handler_error", "websocket")
            await ws.close(code=1008, reason="blocked")
            return
        ws.connect_to_server()

    # ---- operations ------------------------------------------------------------------------------
    @property
    def _live(self) -> Page:
        if self._closed or self._page is None or self._page.is_closed():
            raise BrowserError("page_closed")
        return self._page

    async def _check_scheme(self) -> PageState:
        page = self._live
        scheme = urlsplit(page.url).scheme
        if scheme not in {"http", "https", "about"}:
            await page.goto("about:blank")
            raise BrowserError(f"page_left_http:{scheme[:20]}")
        return await self.state()

    async def state(self) -> PageState:
        page = self._live
        try:
            title = await page.title()
        except Exception:  # noqa: BLE001 - mid-navigation / closed frame
            title = ""
        return PageState(safe_url(page.url), page.url, title, self._status)

    async def _goto(self, url: str) -> int | None:
        """goto + manual main-frame redirect following (each hop is a fresh, guarded request)."""
        page = self._live
        target = url
        retried = 0
        for _ in range(MAX_REDIRECTS + 1):
            self._nav_redirect = None
            blocked_before = self._blocked_total
            try:
                response = await page.goto(
                    target, wait_until="load", timeout=self._policy.op_timeout_seconds * 1000
                )
            except Exception as exc:
                if self._nav_redirect is not None:
                    target = self._nav_redirect
                    await page.wait_for_timeout(
                        100
                    )  # let the aborted navigation's error page settle
                    continue
                if "interrupted by another navigation" in str(exc) and retried < 3:
                    retried += 1  # the previous aborted hop's error page committed late
                    await page.wait_for_timeout(100)
                    continue
                if self._blocked_total > blocked_before:
                    last = self._blocked[-1].reason if self._blocked else "blocked"
                    raise BrowserError(f"navigation blocked: {last}") from None
                raise BrowserError(f"navigation_failed:{type(exc).__name__}") from exc
            return response.status if response is not None else None
        raise BrowserError("navigation blocked: too_many_redirects")

    async def navigate(self, url: str) -> PageState:
        _ = self._live
        if urlsplit(url).scheme.lower() not in ("http", "https"):
            raise BrowserError("navigation blocked: scheme_not_allowed")
        if self._pages_visited >= self._policy.max_pages:
            raise BrowserError("page_limit")
        self._pages_visited += 1
        self._status = await self._goto(url)
        return await self._check_scheme()

    async def click(self, selector: str) -> PageState:
        page = self._live
        self._nav_redirect = None
        await page.click(selector, timeout=self._policy.op_timeout_seconds * 1000)
        if self._nav_redirect is not None:  # the click navigated through a redirect
            self._pages_visited += 1
            self._status = await self._goto(self._nav_redirect)
        await page.wait_for_load_state("domcontentloaded")
        return await self._check_scheme()

    async def type_text(self, selector: str, text: str, *, sensitive: bool) -> PageState:
        page = self._live
        locator = page.locator(selector).first
        kind = await locator.evaluate("e => (e.type || '').toLowerCase()")
        if kind == "password" and not sensitive:
            raise BrowserError("password_field_requires_sensitive")
        await locator.fill(text, timeout=self._policy.op_timeout_seconds * 1000)
        return await self.state()

    async def extract(self, selector: str | None) -> tuple[str, bool]:
        page = self._live
        text = await page.locator(selector or "body").first.inner_text(
            timeout=self._policy.op_timeout_seconds * 1000
        )
        data = text.encode()
        cap = self._policy.max_text_bytes
        if len(data) <= cap:
            return text, False
        return data[:cap].decode(errors="ignore"), True

    async def screenshot(self) -> bytes:
        return await self._live.screenshot(
            type="png", timeout=self._policy.op_timeout_seconds * 1000
        )

    def telemetry(self) -> Telemetry:
        return Telemetry(
            blocked=tuple(self._blocked),
            blocked_total=self._blocked_total,
            requests=self._requests,
            bytes_received=self._bytes,
            pages_visited=self._pages_visited,
            popups_blocked=self._popups,
            dialogs_dismissed=self._dialogs,
            downloads_blocked=self._downloads,
        )

    async def close(self) -> None:
        self._closed = True
        try:
            await self._ctx.close()  # drops cookies, storage, cache and every page
        except Exception as exc:
            raise BrowserError(f"browser_close_failed:{type(exc).__name__}") from exc


__all__: list[str] = ["PlaywrightBackend", "PlaywrightSession"]
