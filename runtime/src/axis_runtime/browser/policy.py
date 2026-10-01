"""Browser egress policy and the URL guard (pure logic; DNS goes through an injected resolver).

The guard is what the NETWORK layer of the browser backend asks about EVERY request (main frame,
subresource, iframe, fetch/XHR, redirect hop, WebSocket).  It reuses the model-endpoint SSRF
primitives (``models.endpoints``) for address classification, so the two stay in step.

Order of checks (the first failure wins and is the recorded reason):

1. scheme is ``http``/``https`` (``ws``/``wss`` for WebSockets): ``file:``, ``chrome:``, ``data:``,
   ``javascript:``, ``ftp:`` ... are refused;
2. no userinfo, a usable host, an acceptable port (80/443 unless the allowlist entry names one);
3. the host is on the per-tenant/agent ALLOWLIST (exact name or ``*.suffix``); empty denies all;
4. unless the host is an explicit private exception (``private_hosts``, tests / self-hosted only):
   literal IPs and names must be public and the name must RESOLVE to public addresses only;
5. cloud metadata addresses are refused even for private exceptions.

Any unexpected exception becomes a block: the guard fails closed.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from axis_runtime.models.endpoints import (
    EndpointError,
    Resolver,
    check_host_literal,
    check_resolved,
    is_public_ip,
)

HTTP_SCHEMES = frozenset({"http", "https"})
WS_SCHEMES = frozenset({"ws", "wss"})
DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}

#: Hosts that must never be reachable, even through ``private_hosts``.
METADATA_ADDRESSES = frozenset(
    ipaddress.ip_address(a)
    for a in ("169.254.169.254", "169.254.170.2", "100.100.100.200", "192.0.0.192", "fd00:ec2::254")
)
_HOST_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$")


class PolicyError(ValueError):
    """The browser policy itself is invalid (configuration error)."""


class BlockedError(Exception):
    """A request was refused by the guard; ``reason`` is a short stable code."""

    def __init__(self, reason: str, host: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.host = host


def _split_entry(entry: str) -> tuple[str, int | None]:
    if not isinstance(entry, str) or not entry or entry != entry.strip():
        raise PolicyError("allowlist entry must be a non-empty string without padding")
    if "://" in entry or "/" in entry or "@" in entry or "?" in entry or "#" in entry:
        raise PolicyError(f"allowlist entry must be host[:port], got {entry!r}")
    host, port = entry, None
    if entry.startswith("["):  # [v6]:port
        close = entry.find("]")
        if close < 0:
            raise PolicyError("malformed IPv6 allowlist entry")
        host, rest = entry[1:close], entry[close + 1 :]
        if rest:
            if not rest.startswith(":") or not rest[1:].isdigit():
                raise PolicyError("malformed allowlist port")
            port = int(rest[1:])
    elif entry.count(":") == 1:
        host, p = entry.split(":")
        if not p.isdigit():
            raise PolicyError("malformed allowlist port")
        port = int(p)
    host = host.lower().rstrip(".")
    if port is not None and not 0 < port < 65536:
        raise PolicyError("allowlist port out of range")
    if host.startswith("*."):
        suffix = host[2:]
        labels = suffix.split(".")
        if len(labels) < 2 or not all(_HOST_LABEL.match(x) for x in labels):
            raise PolicyError("wildcard entries need at least two labels after '*.'")
    elif "*" in host:
        raise PolicyError("'*' is only allowed as a leading '*.' label")
    elif not host:
        raise PolicyError("empty host in allowlist entry")
    return host, port


def _host_matches(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com": the bare apex does NOT match
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


@dataclass(frozen=True)
class BrowserPolicy:
    """Per tenant + agent browser policy (from policy packs / the ABL tool config)."""

    allowed_hosts: tuple[str, ...] = ()
    #: Exact ``host[:port]`` entries exempt from the private-range block (tests, self-hosted).
    #: Must also be in ``allowed_hosts``. Cloud metadata addresses stay blocked.
    private_hosts: tuple[str, ...] = ()
    max_pages: int = 5  # navigations per run
    max_operations: int = 50
    max_requests: int = 300  # network requests per run
    max_body_bytes: int = 2_000_000  # one response
    max_total_bytes: int = 10_000_000  # all responses of the run
    max_text_bytes: int = 100_000  # extracted text returned to the agent
    max_screenshot_bytes: int = 5_000_000
    op_timeout_seconds: float = 15.0
    session_timeout_seconds: float = 120.0
    max_blocked_logged: int = 50

    def __post_init__(self) -> None:
        for e in (*self.allowed_hosts, *self.private_hosts):
            _split_entry(e)
        for e in self.private_hosts:
            host, port = _split_entry(e)
            if host.startswith("*."):
                raise PolicyError("private exceptions must name an exact host")
            if host != "localhost" and _ip(host) is None:
                raise PolicyError("private exceptions are limited to IP literals and localhost")
            if (_ip(host) or None) in METADATA_ADDRESSES:
                raise PolicyError("metadata addresses can never be allowlisted")
        limits = (
            self.max_pages,
            self.max_operations,
            self.max_requests,
            self.max_body_bytes,
            self.max_total_bytes,
            self.max_text_bytes,
            self.max_screenshot_bytes,
            self.max_blocked_logged,
        )
        if any(v < 1 for v in limits):
            raise PolicyError("size and count limits must be positive")
        if self.op_timeout_seconds <= 0 or self.session_timeout_seconds <= 0:
            raise PolicyError("timeouts must be positive")

    @classmethod
    def from_config(cls, config: Mapping[str, Any] | None) -> BrowserPolicy:
        """Build from a tool-config mapping. ``None``/empty means no allowlist: deny everything."""
        cfg = dict(config or {})
        known = {
            "allowed_domains": "allowed_hosts",
            "private_hosts": "private_hosts",
            "max_pages": "max_pages",
            "max_operations": "max_operations",
            "max_requests": "max_requests",
            "max_body_bytes": "max_body_bytes",
            "max_total_bytes": "max_total_bytes",
            "max_text_bytes": "max_text_bytes",
            "max_screenshot_bytes": "max_screenshot_bytes",
            "op_timeout_seconds": "op_timeout_seconds",
            "session_timeout_seconds": "session_timeout_seconds",
        }
        unknown = set(cfg) - set(known)
        if unknown:
            raise PolicyError(f"unknown browser config keys: {sorted(unknown)}")
        kwargs: dict[str, Any] = {}
        for src, dst in known.items():
            if src in cfg:
                v = cfg[src]
                kwargs[dst] = tuple(v) if dst in {"allowed_hosts", "private_hosts"} else v
        return cls(**kwargs)

    def is_private_exception(self, host: str, port: int) -> bool:
        for e in self.private_hosts:
            ph, pp = _split_entry(e)
            if ph == host and pp in (None, port):
                return True
        return False

    def allows(self, host: str, port: int, scheme: str) -> bool:
        for e in self.allowed_hosts:
            ph, pp = _split_entry(e)
            if not _host_matches(ph, host):
                continue
            if pp is not None:
                if pp == port:
                    return True
            elif port == DEFAULT_PORTS[scheme]:
                return True
        return False


def _ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int


class UrlGuard:
    """Decides whether one URL may be requested under a policy."""

    def __init__(self, policy: BrowserPolicy, resolver: Resolver) -> None:
        self.policy = policy
        self._resolver = resolver

    async def check(self, url: str, *, websocket: bool = False) -> Target:
        """Return the target or raise ``BlockedError``. Never raises anything else."""
        try:
            return await self._check(url, websocket)
        except BlockedError:
            raise
        except Exception:  # noqa: BLE001 - the guard fails closed on ANY unexpected error
            raise BlockedError("guard_error") from None

    async def _check(self, url: str, websocket: bool) -> Target:
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            raise BlockedError("malformed_url") from None
        scheme = parts.scheme.lower()
        allowed = WS_SCHEMES if websocket else HTTP_SCHEMES
        if scheme not in allowed:
            raise BlockedError("scheme_not_allowed")
        if parts.username is not None or parts.password is not None:
            raise BlockedError("credentials_in_url")
        host = (parts.hostname or "").rstrip(".").lower()
        if not host or "%" in host:
            raise BlockedError("no_host")
        port = port if port is not None else DEFAULT_PORTS[scheme]
        if not self.policy.allows(host, port, scheme):
            raise BlockedError("host_not_allowlisted", host)
        literal = _ip(host)
        if literal is not None and literal in METADATA_ADDRESSES:
            raise BlockedError("metadata_address", host)
        if self.policy.is_private_exception(host, port):
            return Target(scheme, host, port)
        try:
            check_host_literal(host)
        except EndpointError:
            raise BlockedError("private_address", host) from None
        if literal is None:
            try:
                await check_resolved(host, port, self._resolver)
            except EndpointError as exc:
                reason = "private_address" if "non-public" in str(exc) else "unresolvable"
                raise BlockedError(reason, host) from None
        elif not is_public_ip(literal):  # defence in depth: check_host_literal already refused
            raise BlockedError("private_address", host)
        return Target(scheme, host, port)


def sha256_hex(data: bytes | str) -> str:
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def safe_url(url: str, limit: int = 300) -> str:
    """URL for logs: no userinfo, no fragment, query replaced by its hash."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        port = f":{parts.port}" if parts.port else ""
        query = f"?q_sha256={sha256_hex(parts.query)[:16]}" if parts.query else ""
        out = f"{parts.scheme}://{host}{port}{parts.path}{query}" if host else parts.scheme + ":"
    except ValueError:
        out = "invalid-url"
    return out[:limit]


def canonical_hash(doc: Mapping[str, Any]) -> str:
    return sha256_hex(json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str))
