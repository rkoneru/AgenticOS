"""Outbound calls: toll-fraud limits BEFORE the gate, the gated action, and the dialer backend.

Placing a call spends money and reaches a person, so it is a gated ``message_send`` of kind
``voice`` (``actions.VoiceCall``).  Two layers, both fail closed:

1. ``OutboundLimiter`` runs first and is NOT policy (it needs no kernel): per-tenant allowed country
   prefixes (an empty allow list denies everything), a deny list of premium-rate / satellite ranges,
   concurrent and rolling-window call caps, a per-destination cool-down and a max duration.  A
   refusal places no call, makes no gate request and is recorded as ``action_blocked``.
2. The gate decides on a derived view that includes the same facts (prefix, caps, usage), so a
   policy can be stricter than the limiter but a missing or erroring policy is still a DENY.

The dialer (``GatewayDialer``) is the ONLY code that asks the telephony gateway to originate.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from axis_runtime.actions import VoiceCall
from axis_runtime.events import EventType, RunRecorder
from axis_runtime.executor import ActionRunner, Completed, Denied, Failed, PendingApproval
from axis_runtime.voice.clock import VoiceClock
from axis_runtime.voice.gateway import CallGateway, OriginateRequest

_E164 = re.compile(r"^\+[1-9]\d{6,14}$")

#: Ranges where toll fraud concentrates (premium rate, international revenue share, satellite and
#: global networks).  A starting point, not a complete list: tenants extend it.
DEFAULT_DENIED_PREFIXES: tuple[str, ...] = (
    "+1900",
    "+1976",
    "+449",
    "+870",
    "+881",
    "+882",
    "+883",
    "+979",
    "+247",
    "+290",
)


class CallRefusedError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class OutboundCallPolicy:
    allowed_prefixes: tuple[str, ...] = ()  # EMPTY = no destination is allowed (fail closed)
    denied_prefixes: tuple[str, ...] = DEFAULT_DENIED_PREFIXES
    max_concurrent: int = 2
    max_per_window: int = 20
    window_ms: int = 3_600_000
    max_per_destination: int = 2  # per window
    max_duration_ms: int = 600_000


@dataclass
class _Usage:
    starts: list[int] = field(default_factory=list)
    by_dest: dict[str, list[int]] = field(default_factory=dict)
    active: int = 0


@dataclass(frozen=True)
class Reservation:
    tenant_id: str
    to: str
    context: Mapping[str, Any]


def country_prefix(to: str, candidates: Sequence[str]) -> str:
    """The longest of ``candidates`` that ``to`` starts with ("" if none)."""
    best = ""
    for c in candidates:
        if to.startswith(c) and len(c) > len(best):
            best = c
    return best


class OutboundLimiter:
    def __init__(self, policy_for: Mapping[str, OutboundCallPolicy], clock: VoiceClock) -> None:
        self._policies = dict(policy_for)
        self._clock = clock
        self._usage: dict[str, _Usage] = {}

    def check_and_reserve(self, tenant_id: str, to: str) -> Reservation:
        policy = self._policies.get(tenant_id)
        if policy is None:
            raise CallRefusedError("no_outbound_policy")
        if not _E164.match(to):
            raise CallRefusedError("invalid_number")
        denied = country_prefix(to, policy.denied_prefixes)
        if denied:
            raise CallRefusedError("destination_denied")
        allowed = country_prefix(to, policy.allowed_prefixes)
        if not allowed:
            raise CallRefusedError("country_not_allowed")
        now = self._clock.now_ms()
        usage = self._usage.setdefault(tenant_id, _Usage())
        horizon = now - policy.window_ms
        usage.starts = [t for t in usage.starts if t > horizon]
        usage.by_dest = {d: [t for t in ts if t > horizon] for d, ts in usage.by_dest.items()}
        if usage.active >= policy.max_concurrent:
            raise CallRefusedError("concurrent_cap")
        if len(usage.starts) >= policy.max_per_window:
            raise CallRefusedError("rate_cap")
        if len(usage.by_dest.get(to, [])) >= policy.max_per_destination:
            raise CallRefusedError("destination_cooldown")
        usage.active += 1
        usage.starts.append(now)
        usage.by_dest.setdefault(to, []).append(now)
        return Reservation(
            tenant_id,
            to,
            {
                "country_prefix": allowed,
                "calls_in_window": len(usage.starts),
                "max_per_window": policy.max_per_window,
                "concurrent_calls": usage.active,
                "max_concurrent": policy.max_concurrent,
                "max_duration_ms": policy.max_duration_ms,
            },
        )

    def release(self, tenant_id: str) -> None:
        """A reserved or placed call is over (or never placed): free its concurrency slot."""
        usage = self._usage.get(tenant_id)
        if usage is not None and usage.active > 0:
            usage.active -= 1


@dataclass(frozen=True)
class CallPlacement:
    call_id: str
    status: str


class OutboundCaller:
    """Places calls for one call-run: limiter -> gate -> dialer."""

    def __init__(
        self,
        runner: ActionRunner,
        recorder: RunRecorder,
        pid: str,
        limiter: OutboundLimiter,
        tenant_id: str,
    ) -> None:
        self._runner = runner
        self._rec = recorder
        self._pid = pid
        self._limiter = limiter
        self._tenant = tenant_id

    async def place(self, to: str, *, purpose: str = "", from_number: str = "") -> CallPlacement:
        try:
            reservation = self._limiter.check_and_reserve(self._tenant, to)
        except CallRefusedError as exc:
            await self._rec.record(
                EventType.ACTION_BLOCKED,
                self._pid,
                {
                    "action_id": "voice_pre_gate",
                    "enforcement_point": "message_send",
                    "action": "place_call",
                    "reason": f"voice_policy:{exc.reason}",
                },
            )
            raise
        args = {"to": to, "purpose": purpose, "from": from_number, "tenant_id": self._tenant}
        action = VoiceCall(name="place_call", args=args, context=reservation.context)
        try:
            outcome = await self._runner.run(action, pid=self._pid)
        except BaseException:
            self._limiter.release(self._tenant)
            raise
        if isinstance(outcome, Completed) and isinstance(outcome.result, Mapping):
            return CallPlacement(str(outcome.result.get("call_id", "")), "ringing")
        self._limiter.release(self._tenant)
        if isinstance(outcome, Denied):
            raise CallRefusedError(f"gate_denied:{outcome.reason}")
        if isinstance(outcome, PendingApproval):
            raise CallRefusedError("approval_pending")
        if isinstance(outcome, Failed):
            raise CallRefusedError("dial_failed")
        raise CallRefusedError("unexpected_outcome")

    def call_ended(self) -> None:
        self._limiter.release(self._tenant)


class GatewayDialer:
    """``Backends.voice``: originates through the telephony gateway.  Reachable only via the
    gated ``VoiceCall`` action."""

    def __init__(self, gateway: CallGateway) -> None:
        self._gw = gateway

    async def place(self, args: Mapping[str, Any]) -> Any:
        call = await self._gw.originate(
            OriginateRequest(
                tenant_id=str(args.get("tenant_id", "")),
                to_number=str(args["to"]),
                from_number=str(args.get("from", "")),
            )
        )
        return {"call_id": call.call_id, "status": call.status}
