"""HTTP transports (sync + async) over httpx.

Safety properties (each has a mutation-checked test):
  * retries only for idempotent verbs or POSTs carrying an Idempotency-Key (one key per call);
  * credentials go only to the configured base origin; a redirect to another origin is refused;
  * the tenant is never a client input;
  * credentials never appear in repr(), exceptions or logs.
"""

from __future__ import annotations

import asyncio
import json
import random as _random
import re
import time
import uuid
from collections.abc import AsyncIterator, Callable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

import httpx

from ._generated.operations import OperationSpec
from .errors import (
    AxisApiError,
    AxisConnectionError,
    AxisError,
    AxisTimeoutError,
    ResponseMeta,
    error_from_problem,
    parse_retry_after,
)
from .redact import Secret, redact_text
from .transport_types import RequestOptions

SDK_VERSION = "0.1.0"
RETRY_STATUS = frozenset({408, 429, 500, 502, 503, 504})
_REDIRECT = frozenset({301, 302, 303, 307, 308})
_MAX_REDIRECTS = 5
_FORBIDDEN_HEADERS = re.compile(
    r"^(authorization|x-axis-api-key|x-axis-tenant[a-z-]*|x-tenant[a-z-]*|host|cookie|proxy-authorization)$",
    re.IGNORECASE,
)
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})
_TRACEPARENT = re.compile(r"^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$")


def normalize_base_url(raw: str, allow_insecure: bool = False) -> str:
    """Vet a base URL: https only (loopback may use http); no credentials, query or fragment."""
    try:
        u = urlsplit(raw)
        host = u.hostname
    except ValueError as e:
        raise ValueError(f"invalid base URL: {redact_text(raw)}") from e
    if not u.scheme or not host:
        raise ValueError(f"invalid base URL: {redact_text(raw)}")
    if u.username or u.password:
        raise ValueError("base URL must not embed credentials")
    if u.query or u.fragment:
        raise ValueError("base URL must not carry a query or fragment")
    if u.scheme != "https" and not (u.scheme == "http" and (allow_insecure or host in _LOOPBACK)):
        raise ValueError(
            f"base URL must be https (got {u.scheme}://{u.netloc}); loopback hosts may use http"
        )
    return raw.rstrip("/") + "/"


def origin(url: str) -> tuple[str, str, int | None]:
    u = urlsplit(url)
    default = 443 if u.scheme == "https" else 80 if u.scheme == "http" else None
    return (u.scheme, (u.hostname or "").lower(), u.port or default)


def is_retriable(op: OperationSpec, idempotency_key: str | None) -> bool:
    """Safe to repeat? Idempotent verbs and keyed POSTs only; anything else is sent exactly once."""
    return op.idempotent == "always" or (
        op.idempotent == "with-key" and idempotency_key is not None
    )


@dataclass(slots=True)
class TransportConfig:
    base_url: str
    api_key: Secret | None = None
    token: Secret | None = None
    timeout: float = 30.0
    max_retries: int = 2
    retry_base: float = 0.5
    retry_max: float = 8.0
    allow_insecure: bool = False
    user_agent: str = f"axis-sdk-python/{SDK_VERSION}"
    on_response: Callable[[ResponseMeta], None] | None = None
    random: Callable[[], float] = field(default=_random.random)  # noqa: S311 - jitter, not security

    def __repr__(self) -> str:
        return f"TransportConfig(base_url={self.base_url!r}, credentials=[REDACTED])"

    def secrets(self) -> list[str]:
        return [s.reveal() for s in (self.api_key, self.token) if s is not None]


@dataclass(slots=True)
class _Plan:
    op: OperationSpec
    method: str
    url: str
    headers: dict[str, str]
    content: bytes | None
    retriable: bool
    max_retries: int
    timeout: float
    options: RequestOptions
    sse: bool


class _Core:
    """Sans-IO request building and response interpretation shared by sync and async transports."""

    def __init__(self, config: TransportConfig) -> None:
        self.config = config
        self.base = normalize_base_url(config.base_url, config.allow_insecure)

    def scrub(self, text: str) -> str:
        return redact_text(text, self.config.secrets())

    def plan(
        self,
        op: OperationSpec,
        path: Mapping[str, Any],
        query: Mapping[str, Any],
        body: Any,
        idempotency_key: str | None,
        options: RequestOptions | None,
        *,
        sse: bool = False,
    ) -> _Plan:
        opts = options or RequestOptions()
        rel = op.path
        for name in op.path_params:
            v = path.get(name)
            if not isinstance(v, str) or v == "":
                raise TypeError(f'{op.id}: missing path parameter "{name}"')
            rel = rel.replace("{" + name + "}", quote(v, safe=""))
        url = urljoin(
            self.base, "." + rel
        )  # "./policies:test": a bare "policies:test" parses as a scheme
        pairs = [(k, _qs(v)) for k, v in query.items() if v is not None and k in op.query_params]
        if pairs:
            url += "?" + "&".join(f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in pairs)
        has_body = op.has_body and body is not None
        if op.body_required and not has_body:
            raise TypeError(f"{op.id}: request body is required")
        key = None
        if op.idempotency_key:
            key = idempotency_key if idempotency_key is not None else str(uuid.uuid4())
        headers = {
            "accept": "text/event-stream" if sse else "application/json",
            "user-agent": self.config.user_agent,
        }
        if has_body:
            headers["content-type"] = "application/json"
        cfg = self.config
        if cfg.api_key is not None:
            headers["x-axis-api-key"] = cfg.api_key.reveal()
        elif cfg.token is not None:
            headers["authorization"] = f"Bearer {cfg.token.reveal()}"
        if key is not None:
            headers["idempotency-key"] = key
        for k, v in (opts.headers or {}).items():
            if _FORBIDDEN_HEADERS.match(k):
                raise TypeError(f'header "{k}" may not be set per request')
            headers[k.lower()] = v
        retriable = is_retriable(op, key)
        max_retries = (
            0
            if sse or not retriable
            else (opts.max_retries if opts.max_retries is not None else cfg.max_retries)
        )
        return _Plan(
            op=op,
            method=op.method,
            url=url,
            headers=headers,
            content=json.dumps(body, separators=(",", ":")).encode() if has_body else None,
            retriable=retriable,
            max_retries=max_retries,
            timeout=opts.timeout if opts.timeout is not None else cfg.timeout,
            options=opts,
            sse=sse,
        )

    def build_request(
        self, client: httpx.Client | httpx.AsyncClient, plan: _Plan, url: str
    ) -> httpx.Request:
        return client.build_request(
            plan.method,
            url,
            headers=plan.headers,
            content=plan.content,
            timeout=plan.timeout,
        )

    def redirect_target(
        self, current: str, status: int, location: str | None, hop: int
    ) -> str | None:
        """Next URL for a redirect response, or None to treat the response as final."""
        if status not in _REDIRECT or not location:
            return None
        nxt = urljoin(current, location)
        if origin(nxt) != origin(self.base):
            raise AxisConnectionError(
                f"refusing to follow a redirect to another origin ({urlsplit(nxt).netloc}); "
                f"credentials are only sent to {urlsplit(self.base).netloc}"
            )
        if hop >= _MAX_REDIRECTS:
            raise AxisConnectionError("too many redirects")
        return nxt

    def backoff(self, attempt: int, retry_after: float | None) -> float:
        cfg = self.config
        if retry_after is not None:
            return min(retry_after, max(cfg.retry_max, 30.0))
        ceiling = min(cfg.retry_max, cfg.retry_base * (2**attempt))
        return float(cfg.random() * ceiling)  # full jitter

    def connection_error(self, op: OperationSpec, exc: BaseException) -> AxisError:
        if isinstance(exc, httpx.TimeoutException):
            return AxisTimeoutError(f"{op.id}: request timed out")
        return AxisConnectionError(self.scrub(f"{op.id}: {type(exc).__name__}: {exc}"))

    def meta(
        self, plan: _Plan, status: int, headers: Mapping[str, str], attempt: int, started: float
    ) -> ResponseMeta:
        trace = headers.get("x-trace-id")
        if trace is None:
            m = _TRACEPARENT.match(headers.get("traceparent") or "")
            trace = m.group(1) if m else None
        return ResponseMeta(
            operation_id=plan.op.id,
            status=status,
            request_id=headers.get("x-request-id"),
            trace_id=trace,
            attempts=attempt + 1,
            duration_s=time.monotonic() - started,
        )

    def report(self, plan: _Plan, meta: ResponseMeta) -> None:
        cb = plan.options.on_response or self.config.on_response
        if cb is not None:
            cb(meta)

    def problem(
        self, status: int, headers: Mapping[str, str], body: bytes, meta: ResponseMeta
    ) -> AxisApiError:
        parsed: dict[str, Any] | None = None
        try:
            v = json.loads(body)
            parsed = v if isinstance(v, dict) else None
        except ValueError:
            parsed = None
        return error_from_problem(
            status,
            parsed,
            request_id=meta.request_id,
            trace_id=meta.trace_id or (parsed or {}).get("trace_id"),
            retry_after=parse_retry_after(headers.get("retry-after")),
        )

    def parse_success(self, op: OperationSpec, status: int, body: bytes) -> Any:
        if status == 204 or not body:
            return None
        try:
            return json.loads(body)
        except ValueError as e:
            raise AxisApiError(f"{op.id}: response was not valid JSON", status=status) from e


def _qs(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _next_method(method: str, status: int) -> tuple[str, bool]:
    """(method, keep_body) for a followed redirect."""
    if status == 303 or (status in (301, 302) and method not in ("GET", "HEAD")):
        return "GET", False
    return method, True


class HttpTransport:
    """Synchronous transport."""

    def __init__(
        self,
        config: TransportConfig,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._core = _Core(config)
        self._client = client or httpx.Client(follow_redirects=False)
        self._owns_client = client is None
        self._sleep = sleep

    def __repr__(self) -> str:
        return f"HttpTransport({self._core.base!r})"

    @property
    def base_url(self) -> str:
        return self._core.base.rstrip("/")

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def _send(self, plan: _Plan, *, stream: bool = False) -> httpx.Response:
        url, method, content = plan.url, plan.method, plan.content
        headers = dict(plan.headers)
        for hop in range(_MAX_REDIRECTS + 2):
            req = self._client.build_request(
                method, url, headers=headers, content=content, timeout=plan.timeout
            )
            res = self._client.send(req, stream=stream, follow_redirects=False)
            try:
                nxt = self._core.redirect_target(
                    url, res.status_code, res.headers.get("location"), hop
                )
            except AxisError:
                res.close()
                raise
            if nxt is None:
                return res
            res.close()
            method, keep = _next_method(method, res.status_code)
            if not keep:
                content = None
                headers.pop("content-type", None)
            url = nxt
        raise AxisConnectionError("too many redirects")  # pragma: no cover

    def call(
        self,
        op: OperationSpec,
        *,
        path: Mapping[str, Any],
        query: Mapping[str, Any],
        body: Any,
        idempotency_key: str | None,
        options: RequestOptions | None,
    ) -> Any:
        plan = self._core.plan(op, path, query, body, idempotency_key, options)
        started = time.monotonic()
        attempt = 0
        while True:
            try:
                res = self._send(plan)
            except httpx.HTTPError as exc:
                err = self._core.connection_error(op, exc)
                if plan.retriable and attempt < plan.max_retries:
                    self._sleep(self._core.backoff(attempt, None))
                    attempt += 1
                    continue
                self._core.report(plan, self._core.meta(plan, 0, {}, attempt, started))
                raise err from None
            meta = self._core.meta(plan, res.status_code, res.headers, attempt, started)
            if res.is_success:
                self._core.report(plan, meta)
                return self._core.parse_success(op, res.status_code, res.content)
            retry_after = parse_retry_after(res.headers.get("retry-after"))
            if plan.retriable and attempt < plan.max_retries and res.status_code in RETRY_STATUS:
                self._sleep(self._core.backoff(attempt, retry_after))
                attempt += 1
                continue
            self._core.report(plan, meta)
            raise self._core.problem(res.status_code, res.headers, res.content, meta)

    def open_stream(
        self,
        op: OperationSpec,
        *,
        path: Mapping[str, Any],
        query: Mapping[str, Any],
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,  # noqa: ASYNC109 - passed through to httpx
    ) -> Iterator[str]:
        """Open a text/event-stream response and yield decoded text chunks (single attempt)."""
        plan = self._core.plan(
            op, path, query, None, None, RequestOptions(headers=headers, timeout=timeout), sse=True
        )
        started = time.monotonic()
        try:
            res = self._send(plan, stream=True)
        except httpx.HTTPError as exc:
            raise self._core.connection_error(op, exc) from None
        meta = self._core.meta(plan, res.status_code, res.headers, 0, started)
        if not res.is_success:
            try:
                res.read()
            finally:
                res.close()
            self._core.report(plan, meta)
            raise self._core.problem(res.status_code, res.headers, res.content, meta)
        self._core.report(plan, meta)
        return self._iter_text(op, res)

    def _iter_text(self, op: OperationSpec, res: httpx.Response) -> Iterator[str]:
        try:
            yield from res.iter_text()
        except httpx.HTTPError as exc:
            raise AxisConnectionError(
                self._core.scrub(f"{op.id}: event stream interrupted: {exc}")
            ) from None
        finally:
            res.close()


class AsyncHttpTransport:
    """Asynchronous transport (same behaviour as :class:`HttpTransport`)."""

    def __init__(
        self,
        config: TransportConfig,
        client: httpx.AsyncClient | None = None,
        sleep: Callable[[float], Any] = asyncio.sleep,
    ) -> None:
        self._core = _Core(config)
        self._client = client or httpx.AsyncClient(follow_redirects=False)
        self._owns_client = client is None
        self._sleep = sleep

    def __repr__(self) -> str:
        return f"AsyncHttpTransport({self._core.base!r})"

    @property
    def base_url(self) -> str:
        return self._core.base.rstrip("/")

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def _send(self, plan: _Plan, *, stream: bool = False) -> httpx.Response:
        url, method, content = plan.url, plan.method, plan.content
        headers = dict(plan.headers)
        for hop in range(_MAX_REDIRECTS + 2):
            req = self._client.build_request(
                method, url, headers=headers, content=content, timeout=plan.timeout
            )
            res = await self._client.send(req, stream=stream, follow_redirects=False)
            try:
                nxt = self._core.redirect_target(
                    url, res.status_code, res.headers.get("location"), hop
                )
            except AxisError:
                await res.aclose()
                raise
            if nxt is None:
                return res
            await res.aclose()
            method, keep = _next_method(method, res.status_code)
            if not keep:
                content = None
                headers.pop("content-type", None)
            url = nxt
        raise AxisConnectionError("too many redirects")  # pragma: no cover

    async def call(
        self,
        op: OperationSpec,
        *,
        path: Mapping[str, Any],
        query: Mapping[str, Any],
        body: Any,
        idempotency_key: str | None,
        options: RequestOptions | None,
    ) -> Any:
        plan = self._core.plan(op, path, query, body, idempotency_key, options)
        started = time.monotonic()
        attempt = 0
        while True:
            try:
                res = await self._send(plan)
            except httpx.HTTPError as exc:
                err = self._core.connection_error(op, exc)
                if plan.retriable and attempt < plan.max_retries:
                    await self._sleep(self._core.backoff(attempt, None))
                    attempt += 1
                    continue
                self._core.report(plan, self._core.meta(plan, 0, {}, attempt, started))
                raise err from None
            meta = self._core.meta(plan, res.status_code, res.headers, attempt, started)
            if res.is_success:
                self._core.report(plan, meta)
                return self._core.parse_success(op, res.status_code, res.content)
            retry_after = parse_retry_after(res.headers.get("retry-after"))
            if plan.retriable and attempt < plan.max_retries and res.status_code in RETRY_STATUS:
                await self._sleep(self._core.backoff(attempt, retry_after))
                attempt += 1
                continue
            self._core.report(plan, meta)
            raise self._core.problem(res.status_code, res.headers, res.content, meta)

    async def open_stream(
        self,
        op: OperationSpec,
        *,
        path: Mapping[str, Any],
        query: Mapping[str, Any],
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,  # noqa: ASYNC109 - passed through to httpx
    ) -> AsyncIterator[str]:
        plan = self._core.plan(
            op, path, query, None, None, RequestOptions(headers=headers, timeout=timeout), sse=True
        )
        started = time.monotonic()
        try:
            res = await self._send(plan, stream=True)
        except httpx.HTTPError as exc:
            raise self._core.connection_error(op, exc) from None
        meta = self._core.meta(plan, res.status_code, res.headers, 0, started)
        if not res.is_success:
            try:
                await res.aread()
            finally:
                await res.aclose()
            self._core.report(plan, meta)
            raise self._core.problem(res.status_code, res.headers, res.content, meta)
        self._core.report(plan, meta)
        return self._iter_text(op, res)

    async def _iter_text(self, op: OperationSpec, res: httpx.Response) -> AsyncIterator[str]:
        try:
            async for chunk in res.aiter_text():
                yield chunk
        except httpx.HTTPError as exc:
            raise AxisConnectionError(
                self._core.scrub(f"{op.id}: event stream interrupted: {exc}")
            ) from None
        finally:
            await res.aclose()
