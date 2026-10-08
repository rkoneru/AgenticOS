"""ModelGateway: provider-neutral completion/streaming with BYO keys, retries, circuit breakers,
fallbacks and cost accounting.

The gateway is itself guarded: ``complete``/``stream`` only work while the ActionExecutor is
performing a ``ModelCall`` (so data-egress policy always applies).  Unit tests use the explicit,
clearly named seam ``unguarded_for_tests()``; the bypass test forbids using it from ``src``.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from decimal import Decimal

from axis_runtime.guard import DirectExecutionError, in_executor
from axis_runtime.models.adapters import Adapter, Transport, default_adapters, default_transport
from axis_runtime.models.adapters.base import HttpCall, ParsedResponse, default_resolver
from axis_runtime.models.costs import CostTable
from axis_runtime.models.endpoints import EndpointError, Resolver, validate_endpoint
from axis_runtime.models.resilience import (
    BreakerState,
    CircuitBreaker,
    ModelClock,
    RetryPolicy,
    Rng,
    SystemModelClock,
    default_rng,
)
from axis_runtime.models.secrets import (
    PLATFORM_TENANT,
    Secret,
    SecretNotFoundError,
    SecretStore,
    scrub,
)
from axis_runtime.models.speech import (
    SttAdapter,
    SttRequest,
    SttSession,
    TtsAdapter,
    TtsRequest,
    TtsSession,
    WsTransport,
    open_error,
)
from axis_runtime.models.types import (
    Attempt,
    ErrorKind,
    ModelError,
    ModelRequest,
    ModelResponse,
    ModelTarget,
    StreamEvent,
)
from axis_runtime.voice.clock import VoiceClock
from axis_runtime.voice.interfaces import SttStream, TtsStream

log = logging.getLogger("axis_runtime.models")


@dataclass(frozen=True)
class TenantModelPolicy:
    """Per-tenant model settings. Platform keys are OFF unless the tenant explicitly allows them."""

    allow_platform_keys: bool = False
    # Self-hosted deployments only: permit private/loopback/internal endpoint hosts (no DNS check).
    allow_private_endpoints: bool = False
    # Data residency: None = unrestricted; a set = the ONLY regions prompts may be sent to.
    # Fail-closed: when set, a target with no declared region is refused, and so is an empty set.
    allowed_regions: frozenset[str] | None = None


class ModelGateway:
    def __init__(
        self,
        secrets: SecretStore,
        *,
        platform_secrets: SecretStore | None = None,
        tenant_policy: Callable[[str], TenantModelPolicy] | None = None,
        transport: Transport | None = None,
        adapters: dict[str, Adapter] | None = None,
        retry: RetryPolicy | None = None,
        clock: ModelClock | None = None,
        rng: Rng | None = None,
        cost_table: CostTable | None = None,
        breaker_threshold: int = 5,
        breaker_reset_seconds: float = 30.0,
        max_breakers: int = 1024,
        allow_http_endpoints: bool = False,
        request_timeout: float = 120.0,
        resolver: Resolver | None = None,
        extra_endpoint_ports: frozenset[int] = frozenset(),
        stt_adapters: dict[str, SttAdapter] | None = None,
        tts_adapters: dict[str, TtsAdapter] | None = None,
        ws_transport: WsTransport | None = None,
        voice_clock: VoiceClock | None = None,
    ) -> None:
        self._secrets = secrets
        self._platform = platform_secrets
        self._policy = tenant_policy or (lambda _tenant: TenantModelPolicy())
        self._transport = transport or default_transport()
        self._adapters = adapters or default_adapters()
        self._retry = retry or RetryPolicy()
        self._clock = clock or SystemModelClock()
        self._rng = rng or default_rng()
        self.cost_table = cost_table or CostTable()
        if max_breakers < 1:
            raise ValueError("max_breakers must be at least 1")
        self._max_breakers = max_breakers
        # LRU order (dicts keep insertion order; a hit re-inserts): least recently used first.
        # Bounded because the key includes a tenant-controlled endpoint string.
        self._breakers: dict[tuple[str, str, str], CircuitBreaker] = {}
        self._breaker_args = (breaker_threshold, breaker_reset_seconds)
        self._allow_http = allow_http_endpoints
        self._timeout = request_timeout
        # Only built on first use (never at import/construction time): the default does real DNS.
        self._resolver = resolver
        self._extra_ports = extra_endpoint_ports
        # speech plane (docs/spec/voice.md): vendors by name; none unless the deployment lists them
        self._stt_adapters = dict(stt_adapters or {})
        self._tts_adapters = dict(tts_adapters or {})
        self._ws = ws_transport
        self._voice_clock = voice_clock

    # ---- public API (guarded) -----------------------------------------------------------
    async def complete(self, request: ModelRequest) -> ModelResponse:
        _require_executor()
        return await self._complete(request)

    def stream(self, request: ModelRequest) -> AsyncIterator[StreamEvent]:
        _require_executor()
        return self._stream(request)

    # ---- speech plane (guarded the same way) -----------------------------------------------
    async def open_stt(self, request: SttRequest) -> SttStream:
        """Open a streaming recognition session.  One gated ``SttOpen`` covers the stream."""
        _require_executor()
        adapter = self._stt_adapters.get(request.provider)
        if adapter is None:
            raise ModelError(ErrorKind.INVALID_REQUEST, request.provider, "unknown stt provider")
        base = request.endpoint or adapter.default_endpoint
        await self._check_endpoint_for(
            request.tenant_id, request.provider, request.endpoint, websocket=True
        )
        secret = await self._resolve_secret(
            request.tenant_id,
            adapter.provider,
            request.key_label,
            custom_endpoint=bool(request.endpoint),
            auth_optional=adapter.auth_optional,
        )
        if self._ws is None:
            raise ModelError(ErrorKind.CONFIGURATION, request.provider, "no websocket transport")
        breaker = self.breaker(request.tenant_id, request.provider, request.endpoint)
        if not breaker.allow():
            raise ModelError(ErrorKind.CIRCUIT_OPEN, request.provider, "circuit breaker open")
        try:
            spec = adapter.connect_spec(request, secret, base)
            conn = await self._ws.connect(spec)
            for first in spec.init_messages:
                await conn.send(first)
        except Exception as exc:
            err = open_error(request.provider, exc)
            if err.retryable:
                breaker.record_failure()
            raise ModelError(err.kind, request.provider, scrub(err.detail, secret)) from None
        breaker.record_success()
        return SttSession(conn, adapter, clock=self._voice_clock, secret=secret)

    async def synthesize(self, request: TtsRequest) -> TtsStream:
        """Start synthesising ``request.text``; the audio streams back until cancelled."""
        _require_executor()
        adapter = self._tts_adapters.get(request.provider)
        if adapter is None:
            raise ModelError(ErrorKind.INVALID_REQUEST, request.provider, "unknown tts provider")
        base = request.endpoint or adapter.default_endpoint
        await self._check_endpoint_for(request.tenant_id, request.provider, request.endpoint)
        secret = await self._resolve_secret(
            request.tenant_id,
            adapter.provider,
            request.key_label,
            custom_endpoint=bool(request.endpoint),
            auth_optional=adapter.auth_optional,
        )
        encoding, rate = adapter.output_format(request)
        breaker = self.breaker(request.tenant_id, request.provider, request.endpoint)
        if not breaker.allow():
            raise ModelError(ErrorKind.CIRCUIT_OPEN, request.provider, "circuit breaker open")
        call = adapter.build(request, secret, base)
        cm = self._transport.stream(
            HttpCall(call.method, call.url, call.headers, call.body, self._timeout)
        )
        try:
            handle = await cm.__aenter__()
            if handle.status >= 400:
                body = await handle.read()
                await cm.__aexit__(None, None, None)
                raise adapter.classify(handle.status, handle.headers, body, secret)
        except ModelError as err:
            if err.retryable:
                breaker.record_failure()
            else:
                breaker.record_success()
            raise
        except Exception as exc:
            breaker.record_failure()
            raise ModelError(ErrorKind.NETWORK, request.provider, type(exc).__name__) from None
        breaker.record_success()
        return TtsSession(
            cm, handle, encoding=encoding, sample_rate=rate, provider=request.provider
        )

    def unguarded_for_tests(self) -> UnguardedModelGateway:
        """TEST-ONLY seam. Production code must go through ActionExecutor (see bypass test)."""
        return UnguardedModelGateway(self)

    def breaker(self, tenant_id: str, provider: str, endpoint: str | None = None) -> CircuitBreaker:
        """One breaker per (tenant, provider, endpoint): a tenant's failing endpoint must never
        open the circuit for another tenant (or for the same tenant's other endpoints).

        The map is a bounded LRU (``max_breakers``). When full, the least recently used CLOSED
        breaker is evicted (a closed breaker only forgets a few sub-threshold failures). OPEN and
        HALF_OPEN breakers are never evicted, so eviction cannot reset a tripped circuit; if every
        breaker is tripped, a new key is refused with a non-retryable CONFIGURATION error."""
        key = (tenant_id, provider, (endpoint or "").rstrip("/"))
        existing = self._breakers.get(key)
        if existing is not None:
            self._breakers[key] = self._breakers.pop(key)
            return existing
        if len(self._breakers) >= self._max_breakers:
            victim = next(
                (k for k, b in self._breakers.items() if b.state is BreakerState.CLOSED), None
            )
            if victim is None:
                raise ModelError(
                    ErrorKind.CONFIGURATION,
                    provider,
                    "too many tripped circuit breakers; endpoint refused",
                )
            del self._breakers[victim]
        created = self._breakers[key] = CircuitBreaker(self._clock, *self._breaker_args)
        return created

    def _recording_breaker(self, request: ModelRequest, target: ModelTarget) -> CircuitBreaker:
        """Breaker for recording an outcome: never raises (a refused key gets a throwaway one)."""
        try:
            return self._breaker_for(request, target)
        except ModelError:
            return CircuitBreaker(self._clock, *self._breaker_args)

    def _breaker_for(self, request: ModelRequest, target: ModelTarget) -> CircuitBreaker:
        return self.breaker(request.tenant_id, target.provider, target.endpoint)

    # ---- helpers ------------------------------------------------------------------------
    def _adapter(self, target: ModelTarget) -> Adapter:
        adapter = self._adapters.get(target.provider)
        if adapter is None:
            raise ModelError(ErrorKind.INVALID_REQUEST, target.provider, "unknown provider")
        if adapter.endpoint_required and not target.endpoint:
            raise ModelError(ErrorKind.INVALID_REQUEST, target.provider, "endpoint is required")
        return adapter

    async def _check_endpoint(self, request: ModelRequest, target: ModelTarget) -> None:
        self._check_region(request.tenant_id, target)
        await self._check_endpoint_for(request.tenant_id, target.provider, target.endpoint)

    def _check_region(self, tenant_id: str, target: ModelTarget) -> None:
        allowed = self._policy(tenant_id).allowed_regions
        if allowed is None:
            return
        region = (target.region or "").strip().lower()
        if region == "" or region not in {r.strip().lower() for r in allowed}:
            raise ModelError(
                ErrorKind.CONFIGURATION,
                target.provider,
                "provider region is not permitted for this tenant",
            )

    async def _check_endpoint_for(
        self, tenant_id: str, provider: str, endpoint: str | None, *, websocket: bool = False
    ) -> None:
        if not endpoint:
            return
        resolver = self._resolver or default_resolver()
        checked = endpoint
        if websocket:  # the SSRF rules are about the host, not the scheme: validate as http(s)
            if endpoint.startswith("wss://"):
                checked = "https://" + endpoint[len("wss://") :]
            elif endpoint.startswith("ws://"):
                checked = "http://" + endpoint[len("ws://") :]
        try:
            await validate_endpoint(
                checked,
                allow_http=self._allow_http,
                allow_private=self._policy(tenant_id).allow_private_endpoints,
                extra_ports=self._extra_ports,
                resolver=resolver,
            )
        except EndpointError as exc:
            raise ModelError(ErrorKind.INVALID_REQUEST, provider, str(exc)) from None

    async def _secret(
        self, request: ModelRequest, adapter: Adapter, target: ModelTarget
    ) -> Secret | None:
        return await self._resolve_secret(
            request.tenant_id,
            adapter.provider,
            request.key_label,
            custom_endpoint=bool(target.endpoint),
            auth_optional=adapter.auth_optional,
        )

    async def _resolve_secret(
        self,
        tenant_id: str,
        provider: str,
        key_label: str,
        *,
        custom_endpoint: bool,
        auth_optional: bool,
    ) -> Secret | None:
        try:
            return await self._secrets.get(tenant_id, provider, key_label)
        except SecretNotFoundError:
            pass
        if self._platform is not None and self._policy(tenant_id).allow_platform_keys:
            try:
                platform_secret = await self._platform.get(PLATFORM_TENANT, provider, "default")
            except SecretNotFoundError:
                pass
            else:
                if custom_endpoint:
                    # An ABL-supplied endpoint plus the platform's key would exfiltrate that key.
                    raise ModelError(
                        ErrorKind.CONFIGURATION,
                        provider,
                        "custom endpoints require the tenant's own key; "
                        "platform keys never go to a custom endpoint",
                    )
                return platform_secret
        if auth_optional:
            return None
        raise ModelError(
            ErrorKind.NO_CREDENTIALS,
            provider,
            "no tenant key and platform keys are not permitted for this tenant",
        )

    def _call(
        self,
        adapter: Adapter,
        request: ModelRequest,
        target: ModelTarget,
        secret: Secret | None,
        *,
        stream: bool,
    ) -> HttpCall:
        built = adapter.build(request, target, secret, stream=stream, now=self._clock.now())
        return HttpCall(built.method, built.url, built.headers, built.body, self._timeout)

    def _finish(
        self, parsed: ParsedResponse, target: ModelTarget, started: float, attempts: list[Attempt]
    ) -> ModelResponse:
        cost: Decimal | None = self.cost_table.cost(
            target.provider,
            parsed.model or target.model,
            parsed.usage,
            pricing_model=_pricing_model(target),
        )
        return ModelResponse(
            text=parsed.text,
            tool_calls=parsed.tool_calls,
            usage=parsed.usage,
            finish_reason=parsed.finish_reason,
            provider=target.provider,
            model=parsed.model or target.model,
            latency_ms=int((self._clock.monotonic() - started) * 1000),
            cost_usd=cost,
            attempts=tuple(attempts),
        )

    def _on_error(
        self, err: ModelError, request: ModelRequest, target: ModelTarget, attempts: list[Attempt]
    ) -> None:
        attempts.append(Attempt(target.provider, target.model, err.kind.value))
        breaker = self._recording_breaker(request, target)
        if err.retryable:
            breaker.record_failure()
        else:
            breaker.record_success()  # the provider answered; it is healthy, the request is not
        log.warning(
            "model call failed provider=%s model=%s kind=%s status=%s",
            target.provider,
            target.model,
            err.kind.value,
            err.status,
        )

    @staticmethod
    def _fatal(err: ModelError) -> bool:
        """Errors that a different provider would not fix."""
        return err.kind in (ErrorKind.INVALID_REQUEST, ErrorKind.CONTENT_FILTER)

    @staticmethod
    def _rewrap(err: ModelError, provider: str) -> ModelError:
        return err if err.provider else ModelError(err.kind, provider, err.detail)

    # ---- complete -----------------------------------------------------------------------
    async def _complete(self, request: ModelRequest) -> ModelResponse:
        attempts: list[Attempt] = []
        last: ModelError | None = None
        for target in (request.target, *request.fallbacks):
            try:
                return await self._complete_target(request, target, attempts)
            except ModelError as err:
                last = err
                if self._fatal(err):
                    break
        last = last or ModelError(ErrorKind.UNKNOWN, request.target.provider, "no targets")
        last.attempts = tuple(attempts)
        raise last

    async def _complete_target(
        self, request: ModelRequest, target: ModelTarget, attempts: list[Attempt]
    ) -> ModelResponse:
        adapter = self._adapter(target)
        await self._check_endpoint(request, target)
        secret = await self._secret(request, adapter, target)
        started = self._clock.monotonic()
        for attempt in range(1, self._retry.max_attempts + 1):
            if not self._breaker_for(request, target).allow():
                attempts.append(
                    Attempt(target.provider, target.model, ErrorKind.CIRCUIT_OPEN.value)
                )
                raise ModelError(ErrorKind.CIRCUIT_OPEN, target.provider, "circuit breaker open")
            try:
                parsed = await self._send(adapter, request, target, secret)
            except ModelError as err:
                err = self._rewrap(err, target.provider)
                self._on_error(err, request, target, attempts)
                if not err.retryable or attempt == self._retry.max_attempts:
                    raise err from None
                await self._clock.sleep(self._retry.delay(attempt, self._rng, err.retry_after))
                continue
            self._recording_breaker(request, target).record_success()
            attempts.append(Attempt(target.provider, target.model, "ok"))
            return self._finish(parsed, target, started, attempts)
        raise AssertionError("unreachable")  # pragma: no cover

    async def _send(
        self, adapter: Adapter, request: ModelRequest, target: ModelTarget, secret: Secret | None
    ) -> ParsedResponse:
        call = self._call(adapter, request, target, secret, stream=False)
        resp = await self._transport.send(call)
        if resp.status >= 400:
            raise adapter.classify(resp.status, resp.headers, resp.body, secret)
        try:
            data = json.loads(resp.body)
            if not isinstance(data, dict):
                raise ValueError
        except ValueError:
            raise ModelError(ErrorKind.SERVER, adapter.provider, "invalid JSON response") from None
        try:
            return adapter.parse(data)
        except (KeyError, TypeError, AttributeError, ValueError) as exc:
            raise ModelError(
                ErrorKind.SERVER,
                adapter.provider,
                f"unexpected response shape ({type(exc).__name__})",
            ) from None

    # ---- stream -------------------------------------------------------------------------
    async def _stream(self, request: ModelRequest) -> AsyncIterator[StreamEvent]:
        attempts: list[Attempt] = []
        last: ModelError | None = None
        for target in (request.target, *request.fallbacks):
            committed = False
            try:
                async for event in self._stream_target(request, target, attempts):
                    committed = True
                    yield event
                return
            except ModelError as err:
                if committed:  # cannot retry or fall back after bytes reached the consumer
                    err.attempts = tuple(attempts)
                    raise
                last = err
                if self._fatal(err):
                    break
        last = last or ModelError(ErrorKind.UNKNOWN, request.target.provider, "no targets")
        last.attempts = tuple(attempts)
        raise last

    async def _stream_target(
        self, request: ModelRequest, target: ModelTarget, attempts: list[Attempt]
    ) -> AsyncIterator[StreamEvent]:
        adapter = self._adapter(target)
        await self._check_endpoint(request, target)
        secret = await self._secret(request, adapter, target)
        started = self._clock.monotonic()
        for attempt in range(1, self._retry.max_attempts + 1):
            if not self._breaker_for(request, target).allow():
                attempts.append(
                    Attempt(target.provider, target.model, ErrorKind.CIRCUIT_OPEN.value)
                )
                raise ModelError(ErrorKind.CIRCUIT_OPEN, target.provider, "circuit breaker open")
            parser = adapter.stream_parser()
            started_yielding = False
            try:
                call = self._call(adapter, request, target, secret, stream=True)
                async with self._transport.stream(call) as handle:
                    if handle.status >= 400:
                        raise adapter.classify(
                            handle.status, handle.headers, await handle.read(), secret
                        )
                    async for chunk in handle.aiter_bytes():
                        for event in parser.feed(chunk):
                            started_yielding = True
                            yield event
            except ModelError as err:
                err = self._rewrap(err, target.provider)
                self._on_error(err, request, target, attempts)
                if started_yielding or not err.retryable or attempt == self._retry.max_attempts:
                    raise err from None
                await self._clock.sleep(self._retry.delay(attempt, self._rng, err.retry_after))
                continue
            self._recording_breaker(request, target).record_success()
            attempts.append(Attempt(target.provider, target.model, "ok"))
            yield StreamEvent(
                "done", response=self._finish(parser.result(), target, started, attempts)
            )
            return
        raise AssertionError("unreachable")  # pragma: no cover


class UnguardedModelGateway:
    """Test-only facade over a ModelGateway (skips the executor guard)."""

    def __init__(self, gateway: ModelGateway) -> None:
        self._gw = gateway

    async def complete(self, request: ModelRequest) -> ModelResponse:
        return await self._gw._complete(request)  # noqa: SLF001

    def stream(self, request: ModelRequest) -> AsyncIterator[StreamEvent]:
        return self._gw._stream(request)  # noqa: SLF001


def _require_executor() -> None:
    if not in_executor():
        raise DirectExecutionError(
            "ModelGateway may only be used through ActionExecutor (ModelCall)"
        )


def _pricing_model(target: ModelTarget) -> str | None:
    value = target.params.get("pricing_model")
    return str(value) if value else None


__all__ = ["ModelGateway", "TenantModelPolicy", "UnguardedModelGateway", "scrub"]
