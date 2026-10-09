"""The runner's two read-only network sources: compiled manifests and the production run feed.

* ``HttpManifestSource`` asks the Eval Hub (with the runner's own credential) for the compiled
  ``RuntimeManifest`` of the blueprint version it is executing. The hub serves it only while this
  runner holds a running run of exactly that version, and the executor still refuses a manifest
  whose content hash differs from the queued one.
* ``HttpRunLogReader`` reads the run service's REDACTED, read-only feed of finished runs for the
  online sampler (a separate read-only credential; the feed can neither start nor change a run).

Neither can reach an agent action; both fail closed (an error is an exception the caller counts).
"""

from __future__ import annotations

from typing import Any

import httpx

from axis_runtime._tls import shared_ssl_context
from axis_runtime.evals.hubclient import HubError, RunnerIdentity
from axis_runtime.evals.sampler import CompletedRun
from axis_runtime.evals.types import (
    RUNNER_VERSION,
    BlueprintRef,
    CaseTrace,
    GateDecisionTrace,
    ModelCallTrace,
    ToolCallTrace,
)
from axis_runtime.manifest import ManifestError, RuntimeManifest


class HttpManifestSource:
    def __init__(
        self,
        hub_url: str,
        identity: RunnerIdentity,
        *,
        client: httpx.AsyncClient | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._base = hub_url.rstrip("/")
        self._identity = identity
        self._client = client or httpx.AsyncClient(
            timeout=timeout, follow_redirects=False, verify=shared_ssl_context()
        )

    async def manifest(self, blueprint: BlueprintRef) -> RuntimeManifest:
        params = {"name": blueprint.name, "version": blueprint.version}
        if blueprint.namespace:
            params["namespace"] = blueprint.namespace
        try:
            resp = await self._client.get(
                f"{self._base}/v1/evals/runner/manifest",
                params=params,
                headers={
                    "authorization": f"Bearer {self._identity.token}",
                    "x-axis-runner-id": self._identity.runner_id,
                    "x-axis-runner-version": RUNNER_VERSION,
                },
            )
        except httpx.HTTPError as exc:
            raise HubError(f"transport:{type(exc).__name__}") from None
        if resp.status_code != 200:
            raise HubError(f"http_{resp.status_code}")
        try:
            raw: Any = resp.json()["manifest"]
            return RuntimeManifest.from_dict(raw)
        except (ValueError, KeyError, TypeError, ManifestError):
            raise HubError("malformed_manifest") from None

    async def aclose(self) -> None:
        await self._client.aclose()


def _trace(raw: dict[str, Any], output: str | None) -> CaseTrace:
    return CaseTrace(
        run_id=str(raw["run_id"]),
        trace_id=str(raw.get("trace_id", "")),
        exit_reason=str(raw["exit_reason"]),
        output=output,
        tool_calls=tuple(
            ToolCallTrace(
                name=str(c["name"]),
                ok=bool(c["ok"]),
                result_sha256=str(c["result_sha256"]),
                error=c.get("error"),
            )
            for c in raw.get("tool_calls", [])
        ),
        gate_decisions=tuple(
            GateDecisionTrace(
                str(d["action"]),
                str(d["enforcement_point"]),
                str(d["decision"]),
                str(d["reason"]),
            )
            for d in raw.get("gate_decisions", [])
        ),
        model_calls=tuple(
            ModelCallTrace(
                str(m["provider"]),
                str(m["model"]),
                int(m["input_tokens"]),
                int(m["output_tokens"]),
                int(m["cost_micro_usd"]),
                int(m["latency_ms"]),
            )
            for m in raw.get("model_calls", [])
        ),
        latency_ms=int(raw.get("latency_ms", 0)),
        events_hash=str(raw.get("events_hash", "")),
        event_count=int(raw.get("event_count", 0)),
    )


class HttpRunLogReader:
    """``RunLogReader`` over the run service's ``GET /v1/completed-runs`` (read-only credential)."""

    def __init__(
        self,
        base_url: str,
        read_token: str,
        *,
        client: httpx.AsyncClient | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._token = read_token
        self._client = client or httpx.AsyncClient(
            timeout=timeout, follow_redirects=False, verify=shared_ssl_context()
        )

    async def completed_runs(
        self, *, tenant_id: str, blueprint: str, since: str, limit: int
    ) -> list[CompletedRun]:
        try:
            resp = await self._client.get(
                f"{self._base}/v1/completed-runs",
                params={"blueprint": blueprint, "since": since, "limit": str(limit)},
                headers={"authorization": f"Bearer {self._token}"},
            )
        except httpx.HTTPError as exc:
            raise HubError(f"transport:{type(exc).__name__}") from None
        if resp.status_code != 200:
            raise HubError(f"http_{resp.status_code}")
        try:
            items = resp.json()["items"]
            return [
                CompletedRun(
                    tenant_id=tenant_id,  # the feed is tenant-scoped by its credential
                    run_id=str(i["run_id"]),
                    blueprint=str(i["blueprint"]),
                    version=str(i["version"]),
                    content_hash=str(i["content_hash"]),
                    completed_at=str(i["completed_at"]),
                    trace=_trace(i["trace"], i.get("output")),
                    phi=bool(i.get("phi", False)),
                    input_text=None,
                )
                for i in items
            ]
        except (ValueError, KeyError, TypeError):
            raise HubError("malformed_run_feed") from None

    async def aclose(self) -> None:
        await self._client.aclose()
