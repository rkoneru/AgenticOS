"""Perf regression (Phase 9 D, found by `make loadtest`): the run service built three httpx clients PER RUN (control-plane bridge, usage
emitter, approval resolver) and each default ``httpx.AsyncClient`` loads the whole CA bundle into its own SSL context, about 1.7 MB each and
not returned to the OS when closed. Every run therefore cost ~5 MB of resident memory forever (2.3 GB after ~2000 runs).
The clients now share ONE SSL context (``axis_runtime._tls``)."""

from __future__ import annotations

import gc
from pathlib import Path

import pytest
from axis_runtime._tls import shared_ssl_context
from axis_runtime.approvals import HttpApprovalResolver
from axis_runtime.controlplane import ControlPlaneBridge
from axis_runtime.models.adapters.base import HttpxTransport
from axis_runtime.usage import HttpUsageEmitter


def rss_mib() -> float:
    pages = int(Path("/proc/self/statm").read_text().split()[1])
    return pages * 4096 / 2**20


def test_the_ssl_context_is_built_once() -> None:
    assert shared_ssl_context() is shared_ssl_context()


def test_per_run_clients_do_not_each_load_a_ca_bundle() -> None:
    ctx = shared_ssl_context()
    bridge = ControlPlaneBridge("http://127.0.0.1:1", tenant_id="t", token="x")
    emitter = HttpUsageEmitter("http://127.0.0.1:1", token="x")
    resolver = HttpApprovalResolver("http://127.0.0.1:1", token="x")
    transport = HttpxTransport()
    for c in (bridge._client, emitter._client, resolver._client, transport._client):
        assert c._transport._pool._ssl_context is ctx  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_resident_memory_per_run_is_bounded() -> None:
    gc.collect()
    before = rss_mib()
    keep = []
    for _ in range(150):  # 150 runs' worth of clients, kept alive like RunRecord keeps them
        keep.append(
            (
                ControlPlaneBridge("http://127.0.0.1:1", tenant_id="t", token="x"),
                HttpUsageEmitter("http://127.0.0.1:1", token="x"),
                HttpApprovalResolver("http://127.0.0.1:1", token="x"),
            )
        )
    grown = rss_mib() - before
    for trio in keep:
        await trio[0].aclose()
        await trio[1].aclose()
        await trio[2].close()
    # before the fix: 150 * 3 * 1.7 MiB = ~770 MiB. A client without its own CA bundle is a few hundred KiB.
    assert grown < 120, f"150 per-run client trios grew resident memory by {grown:.0f} MiB"
