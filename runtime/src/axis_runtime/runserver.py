"""DEV, NON-PRODUCTION run service (docs/adr/0026): the network surface the API gateway uses to
start, signal and read runs.

Properties (all pinned by ``runtime/tests/test_runserver.py``):

* Bearer authentication from a ``token -> tenant`` table (constant-time). The tenant is the
TOKEN's, never the request's; a run that
  belongs to another tenant is a 404 exactly like an unknown id.
* ``POST /v1/runs`` receives the RuntimeManifest the gateway compiled from the blueprint (the
runtime never parses ABL). The agent
  runs through ``start_agent`` or, when the deps factory supplies a TKI scheduler, as a TKI
  process with the tenant's budgets. Every
  action of the run still passes the kernel gate through ``RunDeps.gate``; this module has no
  code path that performs an action.
* Run state is the FOLD of the run's event log (``events.reduce``), exposed as the OpenAPI
``Run``; the log is an
  ``InMemoryRunEventLog`` behind the ``RunEventLog`` port (lost on restart; NEEDS #1010). ``GET
  .../events`` and an SSE feed serve it,
  ``POST .../replay`` re-folds it and verifies the hash chain.
* Stdlib asyncio HTTP/1.1, one request per connection, Content-Length bodies only, size and time
limits.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hmac
import json
import logging
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote_plus

from axis_runtime.events import (
    CorruptLogError,
    InMemoryRunEventLog,
    RunEvent,
    RunEventLog,
    RunState,
    SystemClock,
    format_ts,
    replay,
)
from axis_runtime.manifest import ManifestError, RuntimeManifest
from axis_runtime.process import Signal, is_terminal
from axis_runtime.run import RunDeps, RunHandle, start_agent
from axis_runtime.tki import Scheduler, SpawnSpec
from axis_runtime.tki.adapter import agent_workload
from axis_runtime.tki.supervisor import limits_from_manifest

log = logging.getLogger("axis_runtime.runserver")

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
TRACE_RE = re.compile(r"^[0-9a-f]{32}$")
PID_RE = re.compile(r"^axp_[0-9A-HJKMNP-TV-Z]{26}$")
PLACEHOLDER_PID = "axp_" + "0" * 26
STATES = ("spawn", "ready", "running", "waiting", "suspended", "terminated")
MAX_HEADER_BYTES = 16 * 1024


@dataclass
class RunSetup:
    """What a deps factory returns for one run."""

    deps: RunDeps
    # : When set, the root agent runs as a TKI process under this scheduler (budgets, suspension,
    # supervision).
    scheduler: Scheduler | None = None
    limits: Mapping[Any, Any] = field(default_factory=dict)
    close: Callable[[], Awaitable[None]] | None = None


# : ``(tenant_id, manifest, principal) -> RunSetup``. The service overrides ``log``, ``run_id``,
# ``trace_id`` and ``principal``.
DepsFactory = Callable[[str, RuntimeManifest, Mapping[str, Any]], Awaitable[RunSetup]]


@dataclass
class RunServerConfig:
    #: bearer token -> tenant id
    tokens: Mapping[str, str]
    max_body_bytes: int = 1 << 20
    request_timeout: float = 10.0
    max_active_runs_per_tenant: int = 50
    sse_poll_seconds: float = 0.05
    sse_heartbeat_seconds: float = 10.0
    sse_max_seconds: float = 900.0


@dataclass
class RunRecord:
    tenant_id: str
    run_id: str
    trace_id: str
    blueprint: dict[str, str]
    created_at: str
    task: asyncio.Task[Any] | None = None
    signal: Callable[[Signal, str | None, str | None], Awaitable[None]] | None = None
    error: str | None = None
    close: Callable[[], Awaitable[None]] | None = None


class HttpError(Exception):
    def __init__(self, status: int, detail: str, headers: Mapping[str, str] | None = None) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.headers = dict(headers or {})


def _init_pid(state: RunState) -> str | None:
    for pid, info in state.processes.items():
        if info.ppid is None:
            return pid
    return None


def _terminal_ts(events: list[RunEvent], pid: str | None) -> str | None:
    for e in reversed(events):
        if e.type == "process_transition" and e.pid == pid and e.data.get("to") == "terminated":
            return e.ts
    return None


class RunService:
    """Transport-independent run store and controller."""

    def __init__(
        self, factory: DepsFactory, log_: RunEventLog | None = None, clock: Any = None
    ) -> None:
        self.factory = factory
        self.log: RunEventLog = log_ or InMemoryRunEventLog()
        self.clock = clock or SystemClock()
        self.runs: dict[str, RunRecord] = {}
        self.max_active = 50
        self._poll = 0.05

    # ---- helpers -------------------------------------------------------------------------------
    # ---------------------
    def _own(self, tenant: str, run_id: str) -> RunRecord:
        rec = self.runs.get(run_id)
        if (
            rec is None or rec.tenant_id != tenant
        ):  # a foreign run is indistinguishable from a missing one
            raise HttpError(404, "run not found")
        return rec

    async def _fold(self, rec: RunRecord) -> tuple[RunState | None, list[RunEvent]]:
        events = await self.log.read(rec.run_id)
        if not events:
            return None, events
        try:
            return replay(events), events
        except CorruptLogError as exc:
            raise HttpError(500, f"run log is corrupt: {exc.reason}") from None

    async def run_dto(self, rec: RunRecord) -> dict[str, Any]:
        state, events = await self._fold(rec)
        dto: dict[str, Any] = {
            "id": rec.run_id,
            "tenant_id": rec.tenant_id,  # the gateway cross-checks it and strips it
            "blueprint": dict(rec.blueprint),
            "state": "spawn",
            "exit_reason": None,
            "trace_id": rec.trace_id,
            "created_at": rec.created_at,
            "finished_at": None,
        }
        pid = _init_pid(state) if state else None
        if state is not None and pid is not None:
            info = state.processes[pid]
            dto["init_pid"] = pid
            dto["state"] = info.state.value
            if info.exit_reason is not None:
                dto["exit_reason"] = info.exit_reason.value
                dto["finished_at"] = _terminal_ts(events, pid)
        if rec.task is not None and rec.task.done() and dto["state"] != "terminated":
            exc = None if rec.task.cancelled() else rec.task.exception()
            if exc is not None or rec.task.cancelled():
                # The workload died without a terminal event: report it, never leave a run
                # "running" forever.
                dto["state"], dto["exit_reason"] = "terminated", "failed"
                dto["finished_at"] = format_ts(self.clock.now())
        return dto

    @staticmethod
    def event_dto(e: RunEvent, init_pid: str | None) -> dict[str, Any]:
        out: dict[str, Any] = {
            "sequence": e.seq,
            "type": e.type,
            "pid": e.pid if e.pid and PID_RE.match(e.pid) else (init_pid or PLACEHOLDER_PID),
            "at": e.ts,
            "data": dict(e.data),
        }
        aid = e.data.get("audit_event_id")
        if isinstance(aid, str) and UUID_RE.match(aid):
            out["audit_event_id"] = aid
        return out

    # ---- operations ----------------------------------------------------------------------------
    # -----------------------
    async def start(self, tenant: str, body: Mapping[str, Any]) -> dict[str, Any]:
        run_id, trace_id = body.get("run_id"), body.get("trace_id")
        bp, manifest_raw, inp = body.get("blueprint"), body.get("manifest"), body.get("input", {})
        principal = body.get("principal") or {}
        if not (isinstance(run_id, str) and UUID_RE.match(run_id)):
            raise HttpError(422, "run_id must be a UUID")
        if not (isinstance(trace_id, str) and TRACE_RE.match(trace_id)):
            raise HttpError(422, "trace_id must be 32 lowercase hex characters")
        if not (
            isinstance(bp, dict)
            and isinstance(bp.get("name"), str)
            and isinstance(bp.get("version"), str)
        ):
            raise HttpError(422, "blueprint {name, version} required")
        if (
            not isinstance(manifest_raw, dict)
            or not isinstance(inp, dict)
            or not isinstance(principal, dict)
        ):
            raise HttpError(422, "manifest, input and principal must be objects")
        if "tenant_id" in body:
            raise HttpError(422, "tenant_id is not accepted: the tenant is the token's")
        if run_id in self.runs:
            raise HttpError(409, "run id already exists")
        active = sum(
            1
            for r in self.runs.values()
            if r.tenant_id == tenant and (r.task is None or not r.task.done())
        )
        if active >= self.max_active:
            raise HttpError(429, "too many active runs for this tenant", {"retry-after": "1"})
        try:
            manifest = RuntimeManifest.from_dict(manifest_raw)
            manifest.validate_supported()
        except (ManifestError, TypeError, ValueError) as exc:
            raise HttpError(422, f"manifest rejected: {exc}") from None
        if manifest.name != bp["name"] or manifest.version != bp["version"]:
            raise HttpError(422, "manifest does not match the blueprint reference")
        prompt = next(
            (inp[k] for k in ("prompt", "message", "text") if isinstance(inp.get(k), str)), None
        )
        text = (
            prompt if prompt is not None else json.dumps(inp, sort_keys=True, separators=(",", ":"))
        )
        setup = await self.factory(tenant, manifest, principal)
        deps = dataclasses.replace(
            setup.deps,
            tenant_id=tenant,
            log=self.log,
            run_id=run_id,
            trace_id=trace_id,
            clock=self.clock,
            principal=f"member:{principal.get('id', 'unknown')}",
        )
        rec = RunRecord(
            tenant,
            run_id,
            trace_id,
            {"name": bp["name"], "version": bp["version"]},
            format_ts(self.clock.now()),
            close=setup.close,
        )
        self.runs[run_id] = rec
        try:
            if setup.scheduler is not None:
                sched = setup.scheduler
                tki_pid = sched.spawn(
                    SpawnSpec(
                        tenant_id=tenant,
                        agent=f"{manifest.name}@{manifest.version}",
                        run_id=run_id,
                        limits=setup.limits or limits_from_manifest(manifest),
                        trace_id=trace_id,
                    ),
                    agent_workload(manifest, text, deps),
                )

                async def tki_signal(sig: Signal, msg: str | None, _pid: str | None) -> None:
                    sched.signal(tki_pid, sig, msg)

                rec.signal = tki_signal
                rec.task = asyncio.create_task(sched.wait(tki_pid))
            else:
                handle: RunHandle = await start_agent(manifest, text, deps)

                async def direct_signal(sig: Signal, msg: str | None, pid: str | None) -> None:
                    await handle.signal(sig, msg, pid=pid)

                rec.signal = direct_signal
                rec.task = asyncio.create_task(handle.result())
        except Exception:
            del self.runs[run_id]
            if setup.close:
                await setup.close()
            log.warning("run %s failed to start", run_id, exc_info=True)
            raise HttpError(503, "the run could not be started") from None
        rec.task.add_done_callback(lambda t: self._done(rec, t))
        await asyncio.sleep(0)
        return await self.run_dto(rec)

    def _done(self, rec: RunRecord, task: asyncio.Task[Any]) -> None:
        if not task.cancelled() and task.exception() is not None:
            rec.error = type(task.exception()).__name__
            log.warning("run %s ended with %s", rec.run_id, rec.error)
        if rec.close is not None:
            asyncio.ensure_future(rec.close())

    async def get(self, tenant: str, run_id: str) -> dict[str, Any]:
        return await self.run_dto(self._own(tenant, run_id))

    async def list(self, tenant: str, q: Mapping[str, str]) -> dict[str, Any]:
        limit = _int(q.get("limit", "50"), 1, 200)
        state, bp, after = q.get("state"), q.get("blueprint"), q.get("cursor")
        if state is not None and state not in STATES:
            raise HttpError(422, "unknown state")
        mine = sorted(
            (r for r in self.runs.values() if r.tenant_id == tenant),
            key=lambda r: (r.created_at, r.run_id),
        )
        out: list[dict[str, Any]] = []
        more = False
        for rec in mine:
            key = f"{rec.created_at}|{rec.run_id}"
            if after is not None and key <= after:
                continue
            dto = await self.run_dto(rec)
            if (state and dto["state"] != state) or (bp and rec.blueprint["name"] != bp):
                continue
            if len(out) == limit:
                more = True
                break
            out.append(dto)
        last = out[-1] if out else None
        return {
            "items": out,
            "next_cursor": f"{last['created_at']}|{last['id']}" if more and last else None,
        }

    async def signal(self, tenant: str, run_id: str, body: Mapping[str, Any]) -> dict[str, Any]:
        rec = self._own(tenant, run_id)
        try:
            sig = Signal(str(body.get("signal")))
        except ValueError:
            raise HttpError(422, "unknown signal") from None
        state, _ = await self._fold(rec)
        init = _init_pid(state) if state else None
        pid = body.get("pid")
        if pid is not None and (
            not isinstance(pid, str) or state is None or pid not in state.processes
        ):
            raise HttpError(404, "process not found in this run")
        if (
            state is not None
            and init is not None
            and is_terminal(state.processes[pid or init].state)
        ):
            raise HttpError(409, "the process has terminated")
        if rec.task is not None and rec.task.done():
            raise HttpError(409, "the run has finished")
        if rec.signal is None:
            raise HttpError(409, "the run is not ready for signals")
        reason = body.get("reason")
        await rec.signal(
            sig, reason if isinstance(reason, str) else None, pid if pid != init else None
        )
        await asyncio.sleep(0.02)
        dto = await self.run_dto(rec)
        return {"pid": pid or dto.get("init_pid") or PLACEHOLDER_PID, "state": dto["state"]}

    async def events(self, tenant: str, run_id: str, q: Mapping[str, str]) -> dict[str, Any]:
        rec = self._own(tenant, run_id)
        after = _int(q.get("after_sequence", "0"), 0, 10**12)
        limit = _int(q.get("limit", "50"), 1, 200)
        state, _ = await self._fold(rec)
        init = _init_pid(state) if state else None
        items = [self.event_dto(e, init) for e in await self.log.read_after(run_id, after)][:limit]
        return {
            "items": items,
            "next_cursor": str(items[-1]["sequence"]) if len(items) == limit else None,
        }

    async def replay(self, tenant: str, run_id: str) -> dict[str, Any]:
        rec = self._own(tenant, run_id)
        events = await self.log.read(run_id)
        if not events:
            return {"run_id": rec.run_id, "events": 0, "ok": True, "state": "spawn"}
        try:
            state = replay(events)  # validates gaps, hash chain and every transition
        except CorruptLogError as exc:
            return {
                "run_id": rec.run_id,
                "events": len(events),
                "ok": False,
                "reason": exc.reason,
                "seq": exc.seq,
            }
        init = _init_pid(state)
        return {
            "run_id": rec.run_id,
            "events": len(events),
            "ok": True,
            "head_hash": state.last_hash,
            "state": state.processes[init].state.value if init else "spawn",
            "tokens_used": state.tokens_used,
            "tool_calls": state.tool_calls_used,
            "blocked_actions": state.blocked_actions,
        }

    async def feed(self, tenant: str, run_id: str, after: int) -> Any:
        """Async generator of API events after ``after`` until the run is terminal and drained."""
        rec = self._own(tenant, run_id)
        seen = after
        while True:
            fresh = await self.log.read_after(run_id, seen)
            state, _ = await self._fold(rec) if fresh else (None, [])
            init = _init_pid(state) if state else None
            for e in fresh:
                seen = e.seq
                yield self.event_dto(e, init)
            if not fresh:
                dto = await self.run_dto(rec)
                if dto["state"] == "terminated" and not await self.log.read_after(run_id, seen):
                    return
                await asyncio.sleep(self._poll)


def _int(raw: str, lo: int, hi: int) -> int:
    try:
        v = int(raw)
    except ValueError:
        raise HttpError(422, "expected an integer") from None
    if not lo <= v <= hi:
        raise HttpError(422, "integer out of range")
    return v


# ---- HTTP --------------------------------------------------------------------------------------
# -----------------------------


class RunServer:
    def __init__(self, service: RunService, config: RunServerConfig) -> None:
        self.service = service
        self.config = config
        service.max_active = config.max_active_runs_per_tenant
        service._poll = config.sse_poll_seconds
        self._server: asyncio.Server | None = None

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> int:
        self._server = await asyncio.start_server(self._conn, host, port, limit=MAX_HEADER_BYTES)
        return int(self._server.sockets[0].getsockname()[1])

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    def _tenant(self, authorization: str | None) -> str:
        m = re.fullmatch(r"Bearer (\S{1,512})", authorization or "")
        found: str | None = None
        presented = (m.group(1) if m else "").encode()
        for (
            token,
            tenant,
        ) in self.config.tokens.items():  # no early exit: constant work per table entry
            if hmac.compare_digest(token.encode(), presented) and m:
                found = tenant
        if found is None:
            raise HttpError(
                401, "unauthenticated", {"www-authenticate": 'Bearer realm="runserver"'}
            )
        return found

    async def _conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await asyncio.wait_for(self._serve(reader, writer), None)
        except (
            ConnectionError,
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
            TimeoutError,
        ):
            pass
        except Exception:  # noqa: BLE001
            log.warning("connection failed", exc_info=True)
        finally:
            writer.close()

    async def _read_request(
        self, reader: asyncio.StreamReader
    ) -> tuple[str, str, dict[str, str], bytes]:
        async with asyncio.timeout(self.config.request_timeout):
            line = await reader.readline()
            parts = line.decode("latin-1").split()
            if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
                raise HttpError(400, "malformed request line")
            headers: dict[str, str] = {}
            total = len(line)
            while True:
                h = await reader.readline()
                total += len(h)
                if total > MAX_HEADER_BYTES or len(headers) > 100:
                    raise HttpError(431, "headers too large")
                if h in (b"\r\n", b"\n", b""):
                    break
                name, _, value = h.decode("latin-1").partition(":")
                headers[name.strip().lower()] = value.strip()
            if "transfer-encoding" in headers:
                raise HttpError(501, "chunked bodies are not supported")
            n = headers.get("content-length", "0")
            if not n.isdigit():
                raise HttpError(400, "bad content-length")
            if int(n) > self.config.max_body_bytes:
                raise HttpError(413, "body too large")
            body = await reader.readexactly(int(n)) if int(n) else b""
        return parts[0].upper(), parts[1], headers, body

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            method, target, headers, raw = await self._read_request(reader)
            tenant = self._tenant(headers.get("authorization"))
            path, _, qs = target.partition("?")
            query: dict[str, str] = {}
            for pair in filter(None, qs.split("&")):
                k, _, v = pair.partition("=")
                key = unquote_plus(k)
                if key in query:
                    raise HttpError(422, "repeated query parameter")
                query[key] = unquote_plus(v)
            body: Any = {}
            if method == "POST" and raw:
                try:
                    body = json.loads(raw)
                except ValueError:
                    raise HttpError(400, "body is not valid JSON") from None
                if not isinstance(body, dict):
                    raise HttpError(422, "body must be an object")
            await self._route(writer, method, path, query, body, tenant, headers)
        except HttpError as e:
            await self._send(writer, e.status, {"status": e.status, "detail": e.detail}, e.headers)

    async def _route(
        self,
        w: asyncio.StreamWriter,
        method: str,
        path: str,
        q: dict[str, str],
        body: Any,
        tenant: str,
        headers: dict[str, str],
    ) -> None:
        s = self.service
        if path == "/v1/runs" and method == "POST":
            return await self._send(w, 202, await s.start(tenant, body))
        if path == "/v1/runs" and method == "GET":
            return await self._send(w, 200, await s.list(tenant, q))
        m = re.fullmatch(
            r"/v1/runs/([0-9a-fA-F-]{36})(/signals|/events|/events/stream|/replay)?", path
        )
        if m is None:
            raise HttpError(404, "no such route")
        run_id, sub = m.group(1).lower(), m.group(2)
        if sub is None and method == "GET":
            return await self._send(w, 200, await s.get(tenant, run_id))
        if sub == "/signals" and method == "POST":
            return await self._send(w, 200, await s.signal(tenant, run_id, body))
        if sub == "/events" and method == "GET":
            return await self._send(w, 200, await s.events(tenant, run_id, q))
        if sub == "/replay" and method == "POST":
            return await self._send(w, 200, await s.replay(tenant, run_id))
        if sub == "/events/stream" and method == "GET":
            after = _int(q.get("after_sequence", "0"), 0, 10**12)
            last = headers.get("last-event-id")
            if last and last.isdigit():
                after = max(after, int(last))
            s._own(tenant, run_id)
            return await self._serve_sse(w, tenant, run_id, after)
        raise HttpError(405, "method not allowed")

    async def _send(
        self,
        w: asyncio.StreamWriter,
        status: int,
        body: Any,
        extra: Mapping[str, str] | None = None,
    ) -> None:
        payload = json.dumps(body, separators=(",", ":")).encode()
        head = [
            f"HTTP/1.1 {status} {'OK' if status < 400 else 'ERR'}",
            "content-type: application/json",
            f"content-length: {len(payload)}",
            "connection: close",
            "cache-control: no-store",
        ]
        head += [f"{k}: {v}" for k, v in (extra or {}).items()]
        w.write(("\r\n".join(head) + "\r\n\r\n").encode() + payload)
        await w.drain()

    async def _serve_sse(
        self, w: asyncio.StreamWriter, tenant: str, run_id: str, after: int
    ) -> None:
        w.write(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n"
            b"cache-control: no-store\r\nconnection: close\r\n\r\n"
        )
        await w.drain()
        gen = self.service.feed(tenant, run_id, after)
        reason = "completed"
        try:
            async with asyncio.timeout(self.config.sse_max_seconds):
                async for ev in gen:
                    data = json.dumps(ev, separators=(",", ":"))
                    w.write(f"id: {ev['sequence']}\nevent: run_event\ndata: {data}\n\n".encode())
                    await w.drain()
        except TimeoutError:
            reason = "max_duration"
        finally:
            w.write(f"event: end\ndata: {json.dumps({'reason': reason})}\n\n".encode())
            await w.drain()


__all__ = [
    "DepsFactory",
    "HttpError",
    "RunServer",
    "RunServerConfig",
    "RunService",
    "RunSetup",
]
