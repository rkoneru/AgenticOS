"""Usage metering emitter: forwards the billing-relevant projection of a run's event log to the
billing service's loopback dev surface (``services/billing/src/dev-server.ts``).

The service, not this module, decides what is billable: it joins ``gate_decision`` with
``model_call`` / ``tool_call_result`` by ``action_id`` and bills only ALLOWed actions, so a denied
action is never billed even if a result event were present. Cache hits carry no ``model_call`` and
therefore bill zero tokens. The events are a WHITELISTED projection (counts, ids, durations): no
tool arguments or results, no text, no audio ever leave the runtime for billing.

Sending is idempotent: the service keys every record by ``run:<run_id>:<seq>:<meter>``, so
re-sending the whole log, or a prefix, only reports duplicates. A failed send raises
``UsageUnavailable``; metering is NOT on the decision path (a failure never denies or stops an
action), so callers retry later from the durable run log. The tenant is bound by the bearer token; a
client built for tenant A cannot bill tenant B (the service rejects a run of another tenant).
This is a dev bridge, not a production surface (docs/NEEDS.md)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol

import httpx

from axis_runtime.events import RunEvent, RunEventLog

#: event type -> the data keys that leave the runtime. Everything else is dropped.
BILLING_FIELDS: Mapping[str, tuple[str, ...]] = {
    "run_started": ("tenant_id",),
    "process_spawned": ("agent",),
    "process_transition": ("from", "to", "trigger"),
    "gate_decision": ("action_id", "decision", "enforcement_point"),
    "tool_call_result": ("action_id", "enforcement_point", "ok"),
    "model_call": (
        "action_id",
        "provider",
        "model",
        "input_tokens",
        "output_tokens",
        "cached_tokens",
    ),
    "voice_call": ("call_id", "phase", "duration_ms"),
}


class UsageUnavailable(RuntimeError):  # noqa: N818 - a condition, not a failure class hierarchy
    """The billing service could not take the usage. Retry later; never a reason to deny."""


def project_event(event: RunEvent) -> dict[str, Any] | None:
    """The billing projection of one event, or ``None`` for events that are never billed."""
    keys = BILLING_FIELDS.get(event.type)
    if keys is None:
        return None
    return {
        "run_id": event.run_id,
        "seq": event.seq,
        "ts": event.ts,
        "type": event.type,
        "pid": event.pid,
        "data": {k: event.data[k] for k in keys if k in event.data},
    }


class UsageEmitter(Protocol):
    """What ``RunDeps.usage`` needs: forward one finished run's log. Raises ``UsageUnavailable`` (or
    anything) on failure;
    the run never depends on it."""

    async def emit_run(self, log: RunEventLog, run_id: str) -> dict[str, Any]: ...


class HttpUsageEmitter:
    def __init__(
        self,
        base_url: str,
        *,
        token: str,
        client: httpx.AsyncClient | None = None,
        timeout: float = 15.0,
    ) -> None:
        self._url = base_url.rstrip("/") + "/v1/usage/run-events"
        self._headers = {"authorization": f"Bearer {token}"}
        self._client = client or httpx.AsyncClient(timeout=timeout)

    async def emit_events(self, run_id: str, events: Sequence[RunEvent]) -> dict[str, Any]:
        """Send the billing projection of ``events`` (one run, in order). Returns the service's
        summary (``records``/``inserted``/``duplicates``/``conflicts``/``skipped``)."""
        projected = [p for e in events if (p := project_event(e)) is not None]
        if not projected:
            return {"records": 0, "inserted": 0, "duplicates": 0, "conflicts": 0, "skipped": []}
        try:
            resp = await self._client.post(
                self._url, headers=self._headers, json={"run_id": run_id, "events": projected}
            )
        except httpx.HTTPError as exc:
            raise UsageUnavailable(f"transport:{type(exc).__name__}") from None
        if resp.status_code != 200:
            raise UsageUnavailable(f"http_{resp.status_code}")
        try:
            out = resp.json()
        except ValueError:
            raise UsageUnavailable("invalid_json") from None
        if not isinstance(out, dict) or "records" not in out:
            raise UsageUnavailable("invalid_response")
        return out

    async def emit_run(self, log: RunEventLog, run_id: str) -> dict[str, Any]:
        """Read the durable run log and send all of it (idempotent, safe to repeat)."""
        return await self.emit_events(run_id, await log.read(run_id))

    async def aclose(self) -> None:
        await self._client.aclose()
