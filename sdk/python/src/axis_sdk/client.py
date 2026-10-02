"""Ergonomic clients: ``Axis`` (sync) and ``AsyncAxis``.

The tenant is always derived from the credential by the server. There is deliberately no tenant argument.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any, cast

import httpx

from ._generated.client import AsyncGeneratedApi, GeneratedApi
from ._generated.models import (
    Approval,
    ApprovalStatus,
    BlueprintVersion,
    EvalRun,
    GateDecision,
    KillSwitch,
    ProcessState,
    Run,
    RunEvent,
    Signal,
    StartRunRequest,
)
from ._generated.operations import DEFAULT_BASE_URL, OPERATIONS
from .errors import (
    AxisApiError,
    AxisConnectionError,
    AxisError,
    AxisWaitTimeoutError,
    ResponseMeta,
)
from .pagination import apaginate, paginate
from .redact import Secret
from .sse import SseParser
from .transport import AsyncHttpTransport, HttpTransport, TransportConfig
from .transport_types import RequestOptions

BlueprintRef = str | dict[str, str]
_TERMINAL: frozenset[str] = frozenset({"terminated"})
_TENANT_KEYS = frozenset({"tenant", "tenant_id", "tenantid"})


def parse_blueprint_ref(ref: BlueprintRef) -> Any:
    """``"name@version"`` or ``{"name":..., "version":...}`` to the wire shape."""
    if not isinstance(ref, str):
        return {"name": ref["name"], "version": ref["version"]}
    name, sep, version = ref.rpartition("@")
    if not sep or not name or not version:
        raise ValueError(f'blueprint must be "name@version", got "{ref}"')
    return {"name": name, "version": version}


def _drop_none(**kw: Any) -> dict[str, Any]:
    return {k: v for k, v in kw.items() if v is not None}


def _config(
    api_key: str | None,
    token: str | None,
    base_url: str | None,
    kw: dict[str, Any],
) -> TransportConfig:
    for k in kw:
        if k.lower() in _TENANT_KEYS:
            raise TypeError("the tenant is derived from the credential; it cannot be passed to the client")
    key = api_key if api_key is not None else (None if token else os.environ.get("AXIS_API_KEY"))
    if not key and not token:
        raise TypeError("an API key is required (api_key argument or AXIS_API_KEY)")
    return TransportConfig(
        base_url=base_url or os.environ.get("AXIS_BASE_URL") or DEFAULT_BASE_URL,
        api_key=Secret(key) if key else None,
        token=Secret(token) if token else None,
        **kw,
    )


def _event_from_sse(data: str) -> RunEvent:
    import json

    try:
        parsed = json.loads(data)
    except ValueError as e:
        raise AxisApiError("event stream carried malformed JSON") from e
    if not isinstance(parsed, dict):
        raise AxisApiError("event stream carried a non-object event")
    return cast("RunEvent", parsed)


# --------------------------------------------------------------------------------------------- sync


class Runs:
    def __init__(self, ax: Axis) -> None:
        self._ax = ax

    def start(
        self,
        blueprint: BlueprintRef,
        input: dict[str, Any] | None = None,  # noqa: A002 - mirrors the wire field
        *,
        idempotency_key: str | None = None,
        options: RequestOptions | None = None,
    ) -> Run:
        """Start a run. Retried safely: an Idempotency-Key is generated once and reused across retries."""
        body: StartRunRequest = {"blueprint": parse_blueprint_ref(blueprint)}
        if input is not None:
            body["input"] = input
        return self._ax.api.start_run(body=body, idempotency_key=idempotency_key, options=options)

    def get(self, run_id: str, *, options: RequestOptions | None = None) -> Run:
        return self._ax.api.get_run(run_id=run_id, options=options)

    def list(
        self,
        *,
        limit: int | None = None,
        cursor: str | None = None,
        state: ProcessState | None = None,
        blueprint: str | None = None,
        options: RequestOptions | None = None,
    ) -> Any:
        return self._ax.api.list_runs(limit=limit, cursor=cursor, state=state, blueprint=blueprint, options=options)

    def iterate(
        self,
        *,
        limit: int | None = None,
        state: ProcessState | None = None,
        blueprint: str | None = None,
        max_items: int | None = None,
        options: RequestOptions | None = None,
    ) -> Iterator[Run]:
        return paginate(
            lambda c: dict(self.list(limit=limit, cursor=c, state=state, blueprint=blueprint, options=options)),
            max_items,
        )

    def signal(
        self,
        run_id: str,
        signal: Signal,
        *,
        pid: str | None = None,
        reason: str | None = None,
        idempotency_key: str | None = None,
        options: RequestOptions | None = None,
    ) -> Any:
        body: Any = {"signal": signal, **_drop_none(pid=pid, reason=reason)}
        return self._ax.api.signal_run(
            run_id=run_id, body=body, idempotency_key=idempotency_key, options=options
        )

    def cancel(
        self,
        run_id: str,
        *,
        reason: str | None = None,
        force: bool = False,
        pid: str | None = None,
        options: RequestOptions | None = None,
    ) -> Any:
        """TERM by default (graceful); ``force`` sends KILL."""
        return self.signal(run_id, "KILL" if force else "TERM", pid=pid, reason=reason, options=options)

    def events(
        self,
        run_id: str,
        *,
        after_sequence: int | None = None,
        limit: int | None = None,
        options: RequestOptions | None = None,
    ) -> Any:
        return self._ax.api.list_run_events(
            run_id=run_id, after_sequence=after_sequence, limit=limit, options=options
        )

    def all_events(self, run_id: str, *, options: RequestOptions | None = None) -> Iterator[RunEvent]:
        after = 0
        while True:
            page = self.events(run_id, after_sequence=after, options=options)
            for e in page["items"]:
                after = max(after, e["sequence"])
                yield e
            if not page["items"] or not page.get("next_cursor"):
                return

    def wait(
        self,
        run_id: str,
        *,
        timeout: float = 300.0,
        poll_interval: float = 1.0,
        options: RequestOptions | None = None,
    ) -> Run:
        """Poll until the run terminates; raises AxisWaitTimeoutError when ``timeout`` seconds elapse first."""
        started = self._ax._clock()
        while True:
            run = self.get(run_id, options=options)
            if run["state"] in _TERMINAL:
                return run
            remaining = timeout - (self._ax._clock() - started)
            if remaining <= 0:
                raise AxisWaitTimeoutError(f"run {run_id} still {run['state']} after {timeout} s")
            self._ax._sleep(min(poll_interval, remaining))

    def stream(
        self,
        run_id: str,
        *,
        after_sequence: int = 0,
        max_reconnects: int = 5,
        reconnect_delay: float = 1.0,
        options: RequestOptions | None = None,
    ) -> Iterator[RunEvent]:
        """Live typed events over SSE; reconnects with Last-Event-ID, skips duplicates, honours ``retry:``."""
        parser = SseParser()
        last = after_sequence
        failures = 0
        while True:
            progressed = False
            try:
                chunks = self._ax._transport.open_stream(
                    OPERATIONS["listRunEvents"],
                    path={"runId": run_id},
                    query={"after_sequence": last},
                    headers={"last-event-id": str(last), **dict((options.headers or {}) if options else {})},
                    timeout=(options.timeout if options and options.timeout else 24 * 3600.0),
                )
                for chunk in chunks:
                    for ev in parser.push(chunk):
                        if ev.event not in ("message", "run_event"):
                            continue
                        parsed = _event_from_sse(ev.data)
                        seq = parsed.get("sequence")
                        if not isinstance(seq, int) or seq <= last:
                            continue
                        last = seq
                        progressed = True
                        yield parsed
                parser.end()
                failures = 0 if progressed else failures + 1
                if self.get(run_id, options=options)["state"] in _TERMINAL:
                    return
            except AxisApiError as err:
                if err.status is not None and not (err.status in (408, 429) or err.status >= 500):
                    raise
                failures = 1 if progressed else failures + 1
            except AxisConnectionError:
                failures = 1 if progressed else failures + 1
            if failures > max_reconnects:
                raise AxisError(f"event stream for run {run_id} failed {failures} times in a row")
            delay = (
                parser.retry / 1000 if parser.retry is not None
                else min(reconnect_delay * 2 ** max(0, failures - 1), 10.0)
            )
            self._ax._sleep(delay)


class Blueprints:
    def __init__(self, ax: Axis) -> None:
        self._ax = ax

    def list(self, *, limit: int | None = None, cursor: str | None = None, options: RequestOptions | None = None) -> Any:
        return self._ax.api.list_blueprints(limit=limit, cursor=cursor, options=options)

    def iterate(self, *, limit: int | None = None, max_items: int | None = None, options: RequestOptions | None = None) -> Iterator[BlueprintVersion]:
        return paginate(lambda c: dict(self.list(limit=limit, cursor=c, options=options)), max_items)

    def get(self, name: str, version: str, *, options: RequestOptions | None = None) -> BlueprintVersion:
        return self._ax.api.get_blueprint_version(name=name, version=version, options=options)

    def publish(self, abl: dict[str, Any], *, idempotency_key: str | None = None, options: RequestOptions | None = None) -> BlueprintVersion:
        return self._ax.api.publish_blueprint_version(body={"abl": abl}, idempotency_key=idempotency_key, options=options)


class Approvals:
    def __init__(self, ax: Axis) -> None:
        self._ax = ax

    def list(self, *, status: ApprovalStatus | None = None, limit: int | None = None, cursor: str | None = None, options: RequestOptions | None = None) -> Any:
        return self._ax.api.list_approvals(status=status, limit=limit, cursor=cursor, options=options)

    def iterate(self, *, status: ApprovalStatus | None = None, limit: int | None = None, max_items: int | None = None, options: RequestOptions | None = None) -> Iterator[Approval]:
        return paginate(lambda c: dict(self.list(status=status, limit=limit, cursor=c, options=options)), max_items)

    def decide(self, approval_id: str, decision: str, *, comment: str | None = None, idempotency_key: str | None = None, options: RequestOptions | None = None) -> Approval:
        if decision not in ("approve", "reject"):
            raise ValueError('decision must be "approve" or "reject"')
        body: Any = {"decision": decision, **_drop_none(comment=comment)}
        return self._ax.api.decide_approval(approval_id=approval_id, body=body, idempotency_key=idempotency_key, options=options)

    def approve(self, approval_id: str, comment: str | None = None, *, options: RequestOptions | None = None) -> Approval:
        return self.decide(approval_id, "approve", comment=comment, options=options)

    def reject(self, approval_id: str, comment: str | None = None, *, options: RequestOptions | None = None) -> Approval:
        return self.decide(approval_id, "reject", comment=comment, options=options)


class Policies:
    def __init__(self, ax: Axis) -> None:
        self._ax = ax

    def list(self, *, limit: int | None = None, cursor: str | None = None, options: RequestOptions | None = None) -> Any:
        return self._ax.api.list_policy_packs(limit=limit, cursor=cursor, options=options)

    def iterate(self, *, limit: int | None = None, max_items: int | None = None, options: RequestOptions | None = None) -> Iterator[Any]:
        return paginate(lambda c: dict(self.list(limit=limit, cursor=c, options=options)), max_items)

    def publish(self, policy: dict[str, Any], *, options: RequestOptions | None = None) -> Any:
        return self._ax.api.publish_policy_pack(body={"policy": policy}, options=options)

    def test(self, policy: dict[str, Any], request: dict[str, Any], *, options: RequestOptions | None = None) -> GateDecision:
        """Evaluate a hypothetical request against a policy without executing anything."""
        return self._ax.api.test_policy(body={"policy": policy, "request": request}, options=options)  # type: ignore[typeddict-item]


class Audit:
    def __init__(self, ax: Axis) -> None:
        self._ax = ax

    def events(self, *, limit: int | None = None, cursor: str | None = None, trace_id: str | None = None, decision: str | None = None, from_seq: int | None = None, options: RequestOptions | None = None) -> Any:
        return self._ax.api.list_audit_events(limit=limit, cursor=cursor, trace_id=trace_id, decision=decision, from_seq=from_seq, options=options)  # type: ignore[arg-type]

    def iterate(self, *, limit: int | None = None, trace_id: str | None = None, decision: str | None = None, from_seq: int | None = None, max_items: int | None = None, options: RequestOptions | None = None) -> Iterator[Any]:
        return paginate(lambda c: dict(self.events(limit=limit, cursor=c, trace_id=trace_id, decision=decision, from_seq=from_seq, options=options)), max_items)

    def verify(self, *, from_seq: int | None = None, to_seq: int | None = None, options: RequestOptions | None = None) -> Any:
        body: Any = _drop_none(from_seq=from_seq, to_seq=to_seq) or None
        return self._ax.api.verify_audit_chain(body=body, options=options)


class KillSwitches:
    def __init__(self, ax: Axis) -> None:
        self._ax = ax

    def list(self, *, options: RequestOptions | None = None) -> Any:
        return self._ax.api.list_kill_switches(options=options)

    def set(self, scope: str, engaged: bool, *, target: str | None = None, reason: str | None = None, options: RequestOptions | None = None) -> KillSwitch:
        if scope not in ("tenant", "agent", "tool"):
            raise ValueError('scope must be "tenant", "agent" or "tool"')
        if scope != "tenant" and not target:
            raise ValueError(f'kill-switch scope "{scope}" needs a target')
        body: Any = {"scope": scope, "engaged": engaged, **_drop_none(target=target, reason=reason)}
        return self._ax.api.set_kill_switch(body=body, options=options)

    def engage(self, scope: str, target: str | None = None, reason: str | None = None, *, options: RequestOptions | None = None) -> KillSwitch:
        return self.set(scope, True, target=target, reason=reason, options=options)

    def release(self, scope: str, target: str | None = None, reason: str | None = None, *, options: RequestOptions | None = None) -> KillSwitch:
        return self.set(scope, False, target=target, reason=reason, options=options)


class Usage:
    def __init__(self, ax: Axis) -> None:
        self._ax = ax

    def get(self, from_: str, to: str, *, group_by: str | None = None, options: RequestOptions | None = None) -> Any:
        return self._ax.api.get_usage(from_=from_, to=to, group_by=group_by, options=options)  # type: ignore[arg-type]


class Evals:
    def __init__(self, ax: Axis) -> None:
        self._ax = ax

    def start(self, suite: str, blueprint: BlueprintRef, *, idempotency_key: str | None = None, options: RequestOptions | None = None) -> EvalRun:
        return self._ax.api.start_eval_run(body={"suite": suite, "blueprint": parse_blueprint_ref(blueprint)}, idempotency_key=idempotency_key, options=options)


class Axis:
    """Synchronous AXIS client."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        token: str | None = None,
        base_url: str | None = None,
        http_client: httpx.Client | None = None,
        timeout: float = 30.0,
        max_retries: int = 2,
        allow_insecure: bool = False,
        on_response: Callable[[ResponseMeta], None] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        **extra: Any,
    ) -> None:
        cfg = _config(
            api_key, token, base_url,
            {"timeout": timeout, "max_retries": max_retries, "allow_insecure": allow_insecure, "on_response": on_response, **extra},
        )
        self._sleep = sleep
        self._clock = clock
        self._transport = HttpTransport(cfg, http_client, sleep)
        self.api = GeneratedApi(self._transport)
        self.runs = Runs(self)
        self.blueprints = Blueprints(self)
        self.approvals = Approvals(self)
        self.policies = Policies(self)
        self.audit = Audit(self)
        self.kill_switches = KillSwitches(self)
        self.usage = Usage(self)
        self.evals = Evals(self)

    @property
    def base_url(self) -> str:
        return self._transport.base_url

    def close(self) -> None:
        self._transport.close()

    def __enter__(self) -> Axis:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"Axis(base_url={self.base_url!r}, credential=[REDACTED])"


# -------------------------------------------------------------------------------------------- async


class AsyncRuns:
    def __init__(self, ax: AsyncAxis) -> None:
        self._ax = ax

    async def start(
        self,
        blueprint: BlueprintRef,
        input: dict[str, Any] | None = None,  # noqa: A002 - mirrors the wire field
        *,
        idempotency_key: str | None = None,
        options: RequestOptions | None = None,
    ) -> Run:
        body: StartRunRequest = {"blueprint": parse_blueprint_ref(blueprint)}
        if input is not None:
            body["input"] = input
        return await self._ax.api.start_run(body=body, idempotency_key=idempotency_key, options=options)

    async def get(self, run_id: str, *, options: RequestOptions | None = None) -> Run:
        return await self._ax.api.get_run(run_id=run_id, options=options)

    async def list(
        self,
        *,
        limit: int | None = None,
        cursor: str | None = None,
        state: ProcessState | None = None,
        blueprint: str | None = None,
        options: RequestOptions | None = None,
    ) -> Any:
        return await self._ax.api.list_runs(limit=limit, cursor=cursor, state=state, blueprint=blueprint, options=options)

    def iterate(
        self,
        *,
        limit: int | None = None,
        state: ProcessState | None = None,
        blueprint: str | None = None,
        max_items: int | None = None,
        options: RequestOptions | None = None,
    ) -> AsyncIterator[Run]:
        async def page(c: str | None) -> dict[str, Any]:
            return dict(await self.list(limit=limit, cursor=c, state=state, blueprint=blueprint, options=options))

        return apaginate(page, max_items)

    async def signal(
        self,
        run_id: str,
        signal: Signal,
        *,
        pid: str | None = None,
        reason: str | None = None,
        idempotency_key: str | None = None,
        options: RequestOptions | None = None,
    ) -> Any:
        body: Any = {"signal": signal, **_drop_none(pid=pid, reason=reason)}
        return await self._ax.api.signal_run(run_id=run_id, body=body, idempotency_key=idempotency_key, options=options)

    async def cancel(
        self,
        run_id: str,
        *,
        reason: str | None = None,
        force: bool = False,
        pid: str | None = None,
        options: RequestOptions | None = None,
    ) -> Any:
        return await self.signal(run_id, "KILL" if force else "TERM", pid=pid, reason=reason, options=options)

    async def events(
        self,
        run_id: str,
        *,
        after_sequence: int | None = None,
        limit: int | None = None,
        options: RequestOptions | None = None,
    ) -> Any:
        return await self._ax.api.list_run_events(run_id=run_id, after_sequence=after_sequence, limit=limit, options=options)

    async def all_events(self, run_id: str, *, options: RequestOptions | None = None) -> AsyncIterator[RunEvent]:
        after = 0
        while True:
            page = await self.events(run_id, after_sequence=after, options=options)
            for e in page["items"]:
                after = max(after, e["sequence"])
                yield e
            if not page["items"] or not page.get("next_cursor"):
                return

    async def wait(
        self,
        run_id: str,
        *,
        timeout: float = 300.0,
        poll_interval: float = 1.0,
        options: RequestOptions | None = None,
    ) -> Run:
        started = self._ax._clock()
        while True:
            run = await self.get(run_id, options=options)
            if run["state"] in _TERMINAL:
                return run
            remaining = timeout - (self._ax._clock() - started)
            if remaining <= 0:
                raise AxisWaitTimeoutError(f"run {run_id} still {run['state']} after {timeout} s")
            await self._ax._sleep(min(poll_interval, remaining))

    async def stream(
        self,
        run_id: str,
        *,
        after_sequence: int = 0,
        max_reconnects: int = 5,
        reconnect_delay: float = 1.0,
        options: RequestOptions | None = None,
    ) -> AsyncIterator[RunEvent]:
        parser = SseParser()
        last = after_sequence
        failures = 0
        while True:
            progressed = False
            try:
                chunks = await self._ax._transport.open_stream(
                    OPERATIONS["listRunEvents"],
                    path={"runId": run_id},
                    query={"after_sequence": last},
                    headers={"last-event-id": str(last), **dict((options.headers or {}) if options else {})},
                    timeout=(options.timeout if options and options.timeout else 24 * 3600.0),
                )
                async for chunk in chunks:
                    for ev in parser.push(chunk):
                        if ev.event not in ("message", "run_event"):
                            continue
                        parsed = _event_from_sse(ev.data)
                        seq = parsed.get("sequence")
                        if not isinstance(seq, int) or seq <= last:
                            continue
                        last = seq
                        progressed = True
                        yield parsed
                parser.end()
                failures = 0 if progressed else failures + 1
                if (await self.get(run_id, options=options))["state"] in _TERMINAL:
                    return
            except AxisApiError as err:
                if err.status is not None and not (err.status in (408, 429) or err.status >= 500):
                    raise
                failures = 1 if progressed else failures + 1
            except AxisConnectionError:
                failures = 1 if progressed else failures + 1
            if failures > max_reconnects:
                raise AxisError(f"event stream for run {run_id} failed {failures} times in a row")
            delay = (
                parser.retry / 1000 if parser.retry is not None
                else min(reconnect_delay * 2 ** max(0, failures - 1), 10.0)
            )
            await self._ax._sleep(delay)


class AsyncBlueprints:
    def __init__(self, ax: AsyncAxis) -> None:
        self._ax = ax

    async def list(self, *, limit: int | None = None, cursor: str | None = None, options: RequestOptions | None = None) -> Any:
        return await self._ax.api.list_blueprints(limit=limit, cursor=cursor, options=options)

    def iterate(self, *, limit: int | None = None, max_items: int | None = None, options: RequestOptions | None = None) -> AsyncIterator[BlueprintVersion]:
        async def page(c: str | None) -> dict[str, Any]:
            return dict(await self.list(limit=limit, cursor=c, options=options))

        return apaginate(page, max_items)

    async def get(self, name: str, version: str, *, options: RequestOptions | None = None) -> BlueprintVersion:
        return await self._ax.api.get_blueprint_version(name=name, version=version, options=options)

    async def publish(self, abl: dict[str, Any], *, idempotency_key: str | None = None, options: RequestOptions | None = None) -> BlueprintVersion:
        return await self._ax.api.publish_blueprint_version(body={"abl": abl}, idempotency_key=idempotency_key, options=options)


class AsyncApprovals:
    def __init__(self, ax: AsyncAxis) -> None:
        self._ax = ax

    async def list(self, *, status: ApprovalStatus | None = None, limit: int | None = None, cursor: str | None = None, options: RequestOptions | None = None) -> Any:
        return await self._ax.api.list_approvals(status=status, limit=limit, cursor=cursor, options=options)

    def iterate(self, *, status: ApprovalStatus | None = None, limit: int | None = None, max_items: int | None = None, options: RequestOptions | None = None) -> AsyncIterator[Approval]:
        async def page(c: str | None) -> dict[str, Any]:
            return dict(await self.list(status=status, limit=limit, cursor=c, options=options))

        return apaginate(page, max_items)

    async def decide(self, approval_id: str, decision: str, *, comment: str | None = None, idempotency_key: str | None = None, options: RequestOptions | None = None) -> Approval:
        if decision not in ("approve", "reject"):
            raise ValueError('decision must be "approve" or "reject"')
        body: Any = {"decision": decision, **_drop_none(comment=comment)}
        return await self._ax.api.decide_approval(approval_id=approval_id, body=body, idempotency_key=idempotency_key, options=options)

    async def approve(self, approval_id: str, comment: str | None = None, *, options: RequestOptions | None = None) -> Approval:
        return await self.decide(approval_id, "approve", comment=comment, options=options)

    async def reject(self, approval_id: str, comment: str | None = None, *, options: RequestOptions | None = None) -> Approval:
        return await self.decide(approval_id, "reject", comment=comment, options=options)


class AsyncPolicies:
    def __init__(self, ax: AsyncAxis) -> None:
        self._ax = ax

    async def list(self, *, limit: int | None = None, cursor: str | None = None, options: RequestOptions | None = None) -> Any:
        return await self._ax.api.list_policy_packs(limit=limit, cursor=cursor, options=options)

    def iterate(self, *, limit: int | None = None, max_items: int | None = None, options: RequestOptions | None = None) -> AsyncIterator[Any]:
        async def page(c: str | None) -> dict[str, Any]:
            return dict(await self.list(limit=limit, cursor=c, options=options))

        return apaginate(page, max_items)

    async def publish(self, policy: dict[str, Any], *, options: RequestOptions | None = None) -> Any:
        return await self._ax.api.publish_policy_pack(body={"policy": policy}, options=options)

    async def test(self, policy: dict[str, Any], request: dict[str, Any], *, options: RequestOptions | None = None) -> GateDecision:
        return await self._ax.api.test_policy(body={"policy": policy, "request": request}, options=options)  # type: ignore[typeddict-item]


class AsyncAudit:
    def __init__(self, ax: AsyncAxis) -> None:
        self._ax = ax

    async def events(self, *, limit: int | None = None, cursor: str | None = None, trace_id: str | None = None, decision: str | None = None, from_seq: int | None = None, options: RequestOptions | None = None) -> Any:
        return await self._ax.api.list_audit_events(limit=limit, cursor=cursor, trace_id=trace_id, decision=decision, from_seq=from_seq, options=options)  # type: ignore[arg-type]

    def iterate(self, *, limit: int | None = None, trace_id: str | None = None, decision: str | None = None, from_seq: int | None = None, max_items: int | None = None, options: RequestOptions | None = None) -> AsyncIterator[Any]:
        async def page(c: str | None) -> dict[str, Any]:
            return dict(await self.events(limit=limit, cursor=c, trace_id=trace_id, decision=decision, from_seq=from_seq, options=options))

        return apaginate(page, max_items)

    async def verify(self, *, from_seq: int | None = None, to_seq: int | None = None, options: RequestOptions | None = None) -> Any:
        body: Any = _drop_none(from_seq=from_seq, to_seq=to_seq) or None
        return await self._ax.api.verify_audit_chain(body=body, options=options)


class AsyncKillSwitches:
    def __init__(self, ax: AsyncAxis) -> None:
        self._ax = ax

    async def list(self, *, options: RequestOptions | None = None) -> Any:
        return await self._ax.api.list_kill_switches(options=options)

    async def set(self, scope: str, engaged: bool, *, target: str | None = None, reason: str | None = None, options: RequestOptions | None = None) -> KillSwitch:
        if scope not in ("tenant", "agent", "tool"):
            raise ValueError('scope must be "tenant", "agent" or "tool"')
        if scope != "tenant" and not target:
            raise ValueError(f'kill-switch scope "{scope}" needs a target')
        body: Any = {"scope": scope, "engaged": engaged, **_drop_none(target=target, reason=reason)}
        return await self._ax.api.set_kill_switch(body=body, options=options)

    async def engage(self, scope: str, target: str | None = None, reason: str | None = None, *, options: RequestOptions | None = None) -> KillSwitch:
        return await self.set(scope, True, target=target, reason=reason, options=options)

    async def release(self, scope: str, target: str | None = None, reason: str | None = None, *, options: RequestOptions | None = None) -> KillSwitch:
        return await self.set(scope, False, target=target, reason=reason, options=options)


class AsyncUsage:
    def __init__(self, ax: AsyncAxis) -> None:
        self._ax = ax

    async def get(self, from_: str, to: str, *, group_by: str | None = None, options: RequestOptions | None = None) -> Any:
        return await self._ax.api.get_usage(from_=from_, to=to, group_by=group_by, options=options)  # type: ignore[arg-type]


class AsyncEvals:
    def __init__(self, ax: AsyncAxis) -> None:
        self._ax = ax

    async def start(self, suite: str, blueprint: BlueprintRef, *, idempotency_key: str | None = None, options: RequestOptions | None = None) -> EvalRun:
        return await self._ax.api.start_eval_run(body={"suite": suite, "blueprint": parse_blueprint_ref(blueprint)}, idempotency_key=idempotency_key, options=options)


class AsyncAxis:
    """Asynchronous AXIS client (same surface as :class:`Axis`, every call is awaitable)."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        token: str | None = None,
        base_url: str | None = None,
        http_client: httpx.AsyncClient | None = None,
        timeout: float = 30.0,
        max_retries: int = 2,
        allow_insecure: bool = False,
        on_response: Callable[[ResponseMeta], None] | None = None,
        sleep: Callable[[float], Any] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
        **extra: Any,
    ) -> None:
        cfg = _config(
            api_key, token, base_url,
            {"timeout": timeout, "max_retries": max_retries, "allow_insecure": allow_insecure, "on_response": on_response, **extra},
        )
        self._sleep = sleep
        self._clock = clock
        self._transport = AsyncHttpTransport(cfg, http_client, sleep)
        self.api = AsyncGeneratedApi(self._transport)
        self.runs = AsyncRuns(self)
        self.blueprints = AsyncBlueprints(self)
        self.approvals = AsyncApprovals(self)
        self.policies = AsyncPolicies(self)
        self.audit = AsyncAudit(self)
        self.kill_switches = AsyncKillSwitches(self)
        self.usage = AsyncUsage(self)
        self.evals = AsyncEvals(self)

    @property
    def base_url(self) -> str:
        return self._transport.base_url

    async def aclose(self) -> None:
        await self._transport.aclose()

    async def __aenter__(self) -> AsyncAxis:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    def __repr__(self) -> str:
        return f"AsyncAxis(base_url={self.base_url!r}, credential=[REDACTED])"
