"""Endpoint validation for ABL ``target.endpoint`` overrides (SSRF defence).

Pure logic, no IO: name resolution goes through an injected ``Resolver`` (the default, which needs
``socket``, lives in ``adapters/base.py`` with the rest of the model layer's network code).

What is checked (unless the tenant policy sets ``allow_private_endpoints``, for self-hosted setups):

* scheme ``https`` (``http`` only when the gateway was built with ``allow_http_endpoints``);
* no userinfo (``https://user:pw@host``), no IPv6 zone ids, a parseable host;
* port 443 (80 for allowed http) unless the gateway lists the port in ``extra_ports``;
* IP-literal hosts must be public (IPv4 + IPv6, incl. IPv4-mapped / 6to4 / NAT64 / Teredo forms);
  numeric-looking hosts that ``ipaddress`` would not parse strictly (``2130706433``, ``0x7f.1``,
  ``0177.0.0.1``, ``127.1``) are rejected outright because resolvers and HTTP stacks may still
  interpret them as IPv4;
* malformed DNS names (empty label, label > 63, name > 253) are rejected before any lookup, and ANY
  resolver exception (``UnicodeError`` from IDNA, ``OSError``, ...) becomes an ``EndpointError``;
* special-purpose space is denied even where ``ipaddress.is_global`` disagrees: ``fec0::/10``,
  ``2001:db8::/32``, ``3fff::/20``, ``100::/64``, ``64:ff9b:1::/48``, ``192.0.0.0/24``,
  ``192.88.99.0/24``, ``198.18.0.0/15``, ``240.0.0.0/4`` and a few more (``_EXTRA_DENIED``);
* ``localhost``, ``*.localhost``, ``*.internal``, ``*.local``, ``*.localdomain`` are rejected;
* the hostname is resolved and ALL returned addresses must be public.

KNOWN LIMIT: the address that was checked is not the one the HTTP client connects to (no
connect-time pinning), so DNS rebinding between check and connect is not closed.
See docs/spec/runtime.md.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Awaitable, Callable, Iterable
from urllib.parse import urlsplit

# host, port -> resolved address strings
Resolver = Callable[[str, int], Awaitable[Iterable[str]]]

_BLOCKED_SUFFIXES = (".localhost", ".internal", ".local", ".localdomain")
_BLOCKED_NAMES = frozenset({"localhost", "localdomain", "metadata.google.internal"})
# Blocks that Python's ``is_global`` (version dependent) may still call global, or that are special
# purpose / deprecated / documentation space with no business being an model endpoint.
_EXTRA_DENIED = tuple(
    ipaddress.ip_network(n)
    for n in (
        "192.0.0.0/24",  # IETF protocol assignments (incl. 192.0.0.9/10 which is_global allows)
        "192.88.99.0/24",  # deprecated 6to4 relay anycast
        "198.18.0.0/15",  # benchmarking
        "240.0.0.0/4",  # reserved
        "fec0::/10",  # deprecated site-local
        "2001:db8::/32",  # documentation
        "3fff::/20",  # documentation (RFC 9637)
        "100::/64",  # discard-only
        "64:ff9b:1::/48",  # local-use NAT64
        "2001:2::/48",  # benchmarking
        "2001:20::/28",  # ORCHIDv2
    )
)
_MAX_LABEL = 63
_MAX_HOST = 253
_NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$", re.IGNORECASE)


class EndpointError(ValueError):
    """The endpoint is not acceptable; the message is safe to show (it never echoes userinfo)."""


def is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        embedded: list[ipaddress.IPv4Address] = []
        if ip.ipv4_mapped is not None:
            embedded.append(ip.ipv4_mapped)
        if ip.sixtofour is not None:
            embedded.append(ip.sixtofour)
        if ip.teredo is not None:
            embedded.extend(ip.teredo)
        if ip in ipaddress.ip_network("64:ff9b::/96"):
            embedded.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        if any(not is_public_ip(v4) for v4 in embedded):
            return False
    if any(ip.version == n.version and ip in n for n in _EXTRA_DENIED):
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
        or not ip.is_global
    )


def _literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def check_static(endpoint: str, *, allow_http: bool, extra_ports: frozenset[int]) -> str:
    """Scheme/userinfo/port checks that hold even for private deployments. Returns the host."""
    try:
        parts = urlsplit(endpoint)
        port = parts.port
    except ValueError:
        raise EndpointError("endpoint is not a valid URL") from None
    if parts.scheme != "https" and not (parts.scheme == "http" and allow_http):
        raise EndpointError("endpoint must be https")
    if parts.username is not None or parts.password is not None:
        raise EndpointError("endpoint must not contain credentials")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host or "%" in host:
        raise EndpointError("endpoint has no usable host")
    default = 443 if parts.scheme == "https" else 80
    if port is not None and port != default and port not in extra_ports:
        raise EndpointError("endpoint port is not allowed")
    return host


def port_of(endpoint: str) -> int:
    parts = urlsplit(endpoint)
    return parts.port or (443 if parts.scheme == "https" else 80)


def check_host_literal(host: str) -> None:
    """Reject non-public IP literals, blocked names and ambiguous numeric hosts (no DNS)."""
    ip = _literal(host)
    if ip is not None:
        if not is_public_ip(ip):
            raise EndpointError("endpoint address is not public")
        return
    labels = host.split(".")
    if len(host) > _MAX_HOST or any(not label or len(label) > _MAX_LABEL for label in labels):
        raise EndpointError("endpoint host is not a valid DNS name")
    if all(_NUMERIC_LABEL.match(label) for label in labels):
        raise EndpointError("endpoint host is an ambiguous numeric address")
    if host in _BLOCKED_NAMES or host.endswith(_BLOCKED_SUFFIXES):
        raise EndpointError("endpoint host is not public")


async def check_resolved(host: str, port: int, resolver: Resolver) -> None:
    """Resolve ``host`` and require EVERY address to be public (skipped for IP literals)."""
    if _literal(host) is not None:
        return
    try:
        addresses = [str(a).split("%", 1)[0] for a in await resolver(host, port)]
    except Exception:  # noqa: BLE001 - ANY resolver/IDNA failure (UnicodeError, ValueError, ...) must
        # become a configuration error, never escape as a foreign exception type.
        raise EndpointError("endpoint host could not be resolved") from None
    if not addresses:
        raise EndpointError("endpoint host could not be resolved")
    for address in addresses:
        ip = _literal(address)
        if ip is None or not is_public_ip(ip):
            raise EndpointError("endpoint host resolves to a non-public address")


async def validate_endpoint(
    endpoint: str,
    *,
    allow_http: bool,
    allow_private: bool,
    extra_ports: frozenset[int],
    resolver: Resolver,
) -> None:
    host = check_static(endpoint, allow_http=allow_http, extra_ports=extra_ports)
    if allow_private:
        return
    check_host_literal(host)
    await check_resolved(host, port_of(endpoint), resolver)
