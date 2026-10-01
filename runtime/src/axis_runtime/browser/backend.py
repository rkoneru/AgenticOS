"""Backend contracts for browser workers (no IO here)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from axis_runtime.browser.policy import BrowserPolicy, UrlGuard


class BrowserError(RuntimeError):
    """The browser operation failed. The executor turns this into a ``Failed`` outcome."""


class BrowserBlockedError(BrowserError):
    """The operation was refused by the egress policy (nothing was fetched)."""


@dataclass(frozen=True)
class BlockedRequest:
    url: str  # sanitised (no userinfo, query hashed)
    host: str
    reason: str
    resource_type: str = ""


@dataclass(frozen=True)
class PageState:
    url: str  # sanitised final URL
    raw_url: str  # as the browser reports it; used ONLY for the target check, never logged
    title: str
    status: int | None


@dataclass(frozen=True)
class Telemetry:
    blocked: tuple[BlockedRequest, ...] = ()
    blocked_total: int = 0
    requests: int = 0
    bytes_received: int = 0
    pages_visited: int = 0
    popups_blocked: int = 0
    dialogs_dismissed: int = 0
    downloads_blocked: int = 0


class BrowserSession(Protocol):
    """One isolated browsing context. Created per run, closed at the end of the run."""

    async def navigate(self, url: str) -> PageState: ...
    async def click(self, selector: str) -> PageState: ...
    async def type_text(self, selector: str, text: str, *, sensitive: bool) -> PageState: ...
    async def extract(self, selector: str | None) -> tuple[str, bool]:
        """Text of the page (or element), truncated to the policy cap: ``(text, truncated)``."""
        ...

    async def screenshot(self) -> bytes: ...
    async def state(self) -> PageState: ...
    def telemetry(self) -> Telemetry: ...
    async def close(self) -> None: ...


class BrowserBackend(Protocol):
    async def open_session(self, policy: BrowserPolicy, guard: UrlGuard) -> BrowserSession:
        """A FRESH context: no cookies, storage, cache or permissions shared with any other."""
        ...

    async def aclose(self) -> None: ...


class ArtifactStore(Protocol):
    async def put(self, *, tenant_id: str, run_id: str, data: bytes, media_type: str) -> str:
        """Store bytes, return an opaque reference (never the bytes) for the audit record."""
        ...


@dataclass
class InMemoryArtifactStore:
    """Dev/test store. Real object storage is NEEDS #98."""

    items: dict[str, tuple[bytes, str]] = field(default_factory=dict)

    async def put(self, *, tenant_id: str, run_id: str, data: bytes, media_type: str) -> str:
        import hashlib

        ref = f"artifact://{tenant_id}/{run_id}/{hashlib.sha256(data).hexdigest()[:32]}"
        self.items[ref] = (data, media_type)
        return ref
