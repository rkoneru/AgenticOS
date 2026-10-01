"""BrowserWorker: the ``BrowserRunner`` the executor hands to ``BrowserExec``.

One worker = one run = one isolated browser context (opened lazily, closed by ``aclose``). It
re-checks the policy before touching the browser and builds the evidence the audit log keeps; the
network-layer enforcement itself lives in the backend (``PlaywrightBackend``), which asks the same
``UrlGuard`` for every request the page makes.

Fail closed: anything unexpected is a ``BrowserError`` (an error outcome), never a partial result.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Mapping
from typing import Any

from axis_runtime.actions import BrowserExec
from axis_runtime.browser.args import OPERATIONS, is_sensitive, operation_of
from axis_runtime.browser.backend import (
    ArtifactStore,
    BrowserBackend,
    BrowserBlockedError,
    BrowserError,
    BrowserSession,
    InMemoryArtifactStore,
    PageState,
)
from axis_runtime.browser.policy import (
    BlockedError,
    BrowserPolicy,
    UrlGuard,
    sha256_hex,
)
from axis_runtime.models.adapters.base import default_resolver
from axis_runtime.models.endpoints import Resolver

PolicyProvider = Callable[[str, str], BrowserPolicy | None]
_MAX_SELECTOR = 500
_MAX_TYPED = 10_000


def _norm(url: str) -> str:
    return url.rstrip("/")


class BrowserWorker:
    def __init__(
        self,
        backend: BrowserBackend,
        policy: BrowserPolicy,
        *,
        tenant_id: str,
        agent: str,
        run_id: str,
        artifacts: ArtifactStore | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        self._backend = backend
        self._policy = policy
        self._tenant_id = tenant_id
        self._agent = agent
        self._run_id = run_id
        self._artifacts: ArtifactStore = artifacts or InMemoryArtifactStore()
        self._guard = UrlGuard(policy, resolver or default_resolver())
        self._session: BrowserSession | None = None
        self._state: PageState | None = None
        self._ops = 0
        self._started: float | None = None
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def current_url(self) -> str:
        """Raw URL of the page the next operation will act on ('' before the first navigation)."""
        return self._state.raw_url if self._state else ""

    def action(
        self, name: str, args: Mapping[str, Any], *, side_effects: str = "external"
    ) -> BrowserExec:
        """Build the gated action for ``args``, bound to the page it will act on."""
        return BrowserExec(
            name=name, args=dict(args), side_effects=side_effects, target_url=self.current_url
        )

    async def run(self, args: Mapping[str, Any]) -> dict[str, Any]:
        async with self._lock:  # one operation at a time: the page is a single shared state
            return await self._run(args)

    async def _run(self, args: Mapping[str, Any]) -> dict[str, Any]:
        if self._closed:
            raise BrowserError("worker is closed")
        op = operation_of(args)
        if op not in OPERATIONS:
            raise BrowserError(f"unsupported operation {op!r}")
        pol = self._policy
        self._ops += 1
        if self._ops > pol.max_operations:
            raise BrowserBlockedError("operation_limit")
        now = time.monotonic()
        if self._started is None:
            self._started = now
        elif now - self._started > pol.session_timeout_seconds:
            raise BrowserBlockedError("session_timeout")
        try:
            return await asyncio.wait_for(self._dispatch(op, args), pol.op_timeout_seconds + 5)
        except BrowserError:
            raise
        except TimeoutError:
            raise BrowserError("operation_timeout") from None
        except Exception as exc:
            # Backend/browser failure: an error outcome carrying only the exception type.
            raise BrowserError(f"browser_failure:{type(exc).__name__}") from exc

    async def _open(self) -> BrowserSession:
        if self._session is None:
            self._session = await self._backend.open_session(self._policy, self._guard)
        return self._session

    def _selector(self, args: Mapping[str, Any], *, required: bool) -> str | None:
        sel = args.get("selector")
        if sel is None and not required:
            return None
        if not isinstance(sel, str) or not sel or len(sel) > _MAX_SELECTOR:
            raise BrowserError("invalid selector")
        return sel

    async def _dispatch(self, op: str, args: Mapping[str, Any]) -> dict[str, Any]:
        extra: dict[str, Any] = {}
        if op == "navigate":
            url = args.get("url")
            if not isinstance(url, str) or not url:
                raise BrowserError("navigate needs a url")
            try:
                await self._guard.check(url)
            except BlockedError as exc:
                raise BrowserBlockedError(f"navigation blocked: {exc.reason}") from None
            session = await self._open()
            self._state = await session.navigate(url)
        else:
            session = await self._open()
            declared = args.get("target_url")
            if not isinstance(declared, str) or not declared:
                raise BrowserError("target_url_required")
            actual = await session.state()
            if _norm(declared) != _norm(actual.raw_url):
                self._state = actual
                raise BrowserError("target_changed")
            if op == "click":
                sel = self._selector(args, required=True)
                assert sel is not None  # noqa: S101 - narrowed by required=True
                self._state = await session.click(sel)
            elif op == "type":
                sel = self._selector(args, required=True)
                assert sel is not None  # noqa: S101
                text = args.get("text")
                if not isinstance(text, str) or len(text) > _MAX_TYPED:
                    raise BrowserError("invalid text")
                sensitive = is_sensitive(args)
                self._state = await session.type_text(sel, text, sensitive=sensitive)
                extra["typed"] = (
                    {"masked": True}
                    if sensitive
                    else {"text_sha256": sha256_hex(text), "text_len": len(text)}
                )
            elif op == "extract":
                sel = self._selector(args, required=False)
                text_out, truncated = await session.extract(sel)
                data = text_out.encode()
                extra.update(
                    text=text_out,
                    text_sha256=sha256_hex(data),
                    text_bytes=len(data),
                    text_truncated=truncated,
                )
                self._state = await session.state()
            else:  # screenshot
                png = await session.screenshot()
                if len(png) > self._policy.max_screenshot_bytes:
                    raise BrowserError("screenshot_too_large")
                ref = await self._artifacts.put(
                    tenant_id=self._tenant_id,
                    run_id=self._run_id,
                    data=png,
                    media_type="image/png",
                )
                extra.update(
                    screenshot_ref=ref, screenshot_sha256=sha256_hex(png), screenshot_bytes=len(png)
                )
                self._state = await session.state()
        assert self._state is not None  # noqa: S101
        tel = session.telemetry()
        return {
            "operation": op,
            "final_url": self._state.url,
            "title": self._state.title[:200],
            "status": self._state.status,
            **extra,
            "blocked_requests": [
                {"url": b.url, "host": b.host, "reason": b.reason, "type": b.resource_type}
                for b in tel.blocked
            ],
            "blocked_total": tel.blocked_total,
            "requests": tel.requests,
            "bytes_received": tel.bytes_received,
            "pages_visited": tel.pages_visited,
            "popups_blocked": tel.popups_blocked,
            "dialogs_dismissed": tel.dialogs_dismissed,
            "downloads_blocked": tel.downloads_blocked,
        }

    async def aclose(self) -> None:
        """Destroy the run's browser context (cookies, storage and cache go with it)."""
        self._closed = True
        session, self._session = self._session, None
        if session is not None:
            await session.close()


class BrowserWorkerFactory:
    """One worker per run. Policy comes from ``policies(tenant_id, agent)``; no policy: deny all."""

    def __init__(
        self,
        backend: BrowserBackend,
        policies: PolicyProvider,
        *,
        artifacts: ArtifactStore | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        self._backend = backend
        self._policies = policies
        self._artifacts = artifacts
        self._resolver = resolver

    def for_run(self, *, tenant_id: str, agent: str, run_id: str) -> BrowserWorker:
        try:
            policy = self._policies(tenant_id, agent)
        except Exception:  # noqa: BLE001 - a failing policy lookup is "no policy"
            policy = None
        return BrowserWorker(
            self._backend,
            policy or BrowserPolicy(),  # empty allowlist: every request is blocked
            tenant_id=tenant_id,
            agent=agent,
            run_id=run_id,
            artifacts=self._artifacts,
            resolver=self._resolver,
        )
