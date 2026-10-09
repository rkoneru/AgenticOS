"""One TLS context for every outbound ``httpx`` client of the runtime.

A default ``httpx.AsyncClient`` builds its own SSL context and loads the whole CA bundle into it
(about 1.7 MB resident, never returned to the OS). The run service creates several clients per
run, so a per-client context cost ~5 MB of resident memory per run, forever. The clients now
share one context (immutable once built, safe to share across tasks). Trust behaviour is
exactly httpx's default (certifi, or ``SSL_CERT_FILE`` / ``SSL_CERT_DIR``); nothing is relaxed.
Opens no connection.
"""

from __future__ import annotations

import functools
import ssl

import httpx


@functools.lru_cache(maxsize=1)
def shared_ssl_context() -> ssl.SSLContext:
    return httpx.create_ssl_context()
