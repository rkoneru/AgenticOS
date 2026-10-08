"""The runner's network sources: the hub's manifest route and the run service's completed-runs feed."""

from __future__ import annotations

import httpx
import pytest
from axis_runtime.evals.hubclient import HubError, RunnerIdentity
from axis_runtime.evals.sources_http import HttpManifestSource, HttpRunLogReader
from axis_runtime.evals.types import BlueprintRef
from conftest import manifest_dict

IDENT = RunnerIdentity("runner-1", "tok-runner")
H = "a" * 64


def client(handler):  # type: ignore[no-untyped-def]
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_manifest_source_asks_with_the_runner_credential_and_parses_the_manifest() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json={"manifest": manifest_dict()})

    src = HttpManifestSource("http://hub.test/", IDENT, client=client(handler))
    m = await src.manifest(BlueprintRef("claims-triage", "1.0.0", H, namespace="pub"))
    assert m.name == "claims-triage"
    r = seen[0]
    assert r.url.path == "/v1/evals/runner/manifest"
    assert dict(r.url.params) == {"name": "claims-triage", "version": "1.0.0", "namespace": "pub"}
    assert r.headers["authorization"] == "Bearer tok-runner"
    assert r.headers["x-axis-runner-id"] == "runner-1"
    await src.manifest(BlueprintRef("claims-triage", "1.0.0", H))
    assert "namespace" not in dict(seen[1].url.params)
    await src.aclose()


@pytest.mark.parametrize(
    ("status", "body", "kind"),
    [
        (403, {"error": {}}, "http_403"),
        (404, {}, "http_404"),
        (200, {"manifest": {"nonsense": True}}, "malformed_manifest"),
        (200, {"nothing": 1}, "malformed_manifest"),
    ],
)
async def test_manifest_source_fails_closed(status: int, body: object, kind: str) -> None:
    src = HttpManifestSource(
        "http://hub.test", IDENT, client=client(lambda r: httpx.Response(status, json=body))
    )
    with pytest.raises(HubError) as e:
        await src.manifest(BlueprintRef("a", "1", H))
    assert e.value.kind == kind


async def test_manifest_source_transport_error_is_a_hub_error() -> None:
    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no")

    src = HttpManifestSource("http://hub.test", IDENT, client=client(boom))
    with pytest.raises(HubError) as e:
        await src.manifest(BlueprintRef("a", "1", H))
    assert e.value.kind == "transport:ConnectError"


FEED_ITEM = {
    "run_id": "11111111-1111-4111-8111-111111111111",
    "blueprint": "claims-agent",
    "version": "1.0.0",
    "content_hash": H,
    "completed_at": "2026-10-08T12:00:00Z",
    "phi": True,
    "output": "done",
    "trace": {
        "run_id": "11111111-1111-4111-8111-111111111111",
        "trace_id": "t" * 32,
        "exit_reason": "completed",
        "events_hash": "e" * 64,
        "event_count": 7,
        "latency_ms": 12,
        "tool_calls": [{"name": "lookup", "ok": True, "result_sha256": "c" * 64, "error": None}],
        "gate_decisions": [
            {
                "action": "lookup",
                "enforcement_point": "tool_call",
                "decision": "ALLOW",
                "reason": "ok",
            }
        ],
        "model_calls": [
            {
                "provider": "openai",
                "model": "gpt-4o",
                "input_tokens": 3,
                "output_tokens": 4,
                "cost_micro_usd": 5,
                "latency_ms": 6,
            }
        ],
    },
}


async def test_run_log_reader_parses_the_feed_with_a_read_credential() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json={"items": [FEED_ITEM]})

    rd = HttpRunLogReader("http://runs.test/", "rd-tok", client=client(handler))
    runs = await rd.completed_runs(
        tenant_id="T", blueprint="claims-agent", since="2026-10-08T11:00:00Z", limit=5
    )
    assert len(runs) == 1
    r = runs[0]
    assert (r.tenant_id, r.run_id, r.blueprint, r.version, r.phi) == (
        "T",
        FEED_ITEM["run_id"],
        "claims-agent",
        "1.0.0",
        True,
    )
    assert r.input_text is None and r.trace.output == "done"
    assert r.trace.tool_calls[0].name == "lookup" and r.trace.gate_decisions[0].decision == "ALLOW"
    assert r.trace.model_calls[0].cost_micro_usd == 5 and r.trace.events_hash == "e" * 64
    q = seen[0]
    assert q.headers["authorization"] == "Bearer rd-tok"
    assert dict(q.url.params) == {
        "blueprint": "claims-agent",
        "since": "2026-10-08T11:00:00Z",
        "limit": "5",
    }
    await rd.aclose()


@pytest.mark.parametrize(
    ("status", "body", "kind"),
    [
        (403, {}, "http_403"),
        (200, {"items": [{"run_id": "x"}]}, "malformed_run_feed"),
        (200, {}, "malformed_run_feed"),
    ],
)
async def test_run_log_reader_fails_closed(status: int, body: object, kind: str) -> None:
    rd = HttpRunLogReader(
        "http://runs.test", "t", client=client(lambda r: httpx.Response(status, json=body))
    )
    with pytest.raises(HubError) as e:
        await rd.completed_runs(tenant_id="T", blueprint="b", since="", limit=1)
    assert e.value.kind == kind


async def test_run_log_reader_transport_error() -> None:
    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    rd = HttpRunLogReader("http://runs.test", "t", client=client(boom))
    with pytest.raises(HubError) as e:
        await rd.completed_runs(tenant_id="T", blueprint="b", since="", limit=1)
    assert e.value.kind == "transport:ReadTimeout"
