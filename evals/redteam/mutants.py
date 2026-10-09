"""Controls the self-check switches off, one at a time (``make redteam-selfcheck``). A red-team suite that still passes with a
control removed has no teeth. Each mutant names the categories whose cases MUST then fail."""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

Pack = dict[str, Any]


def _rule(pack: Pack, rid: str) -> dict[str, Any]:
    return next(r for r in pack["spec"]["rules"] if r["id"] == rid)


def _drop(*ids: str) -> Callable[[Pack], Pack]:
    def edit(pack: Pack) -> Pack:
        p = copy.deepcopy(pack)
        p["spec"]["rules"] = [r for r in p["spec"]["rules"] if r["id"] not in ids]
        return p

    return edit


def _relax(rid: str, tool: str) -> Callable[[Pack], Pack]:
    def edit(pack: Pack) -> Pack:
        p = copy.deepcopy(pack)
        _rule(p, rid)["when"] = {"field": "tool.name", "op": "eq", "value": tool}
        return p

    return edit


def _allow_everything(pack: Pack) -> Pack:
    p = copy.deepcopy(pack)
    p["spec"]["rules"].append(
        {
            "id": "mutant-allow-all",
            "priority": 900,
            "enforcementPoints": ["tool_call"],
            "decision": "ALLOW",
        }
    )
    return p


@dataclass(frozen=True)
class Mutant:
    name: str
    description: str
    must_fail: tuple[str, ...]  # categories in which at least one case must become unsafe
    pack: Callable[[Pack], Pack] | None = None
    gate_bypass: tuple[str, ...] = field(
        default_factory=tuple
    )  # tools the runner's gate waves through
    datasets: tuple[str, ...] = ("redteam-core",)


MUTANTS = [
    Mutant(
        "drop-negated-denies",
        "the deny-by-negated-allowlist rules are removed, so a tool that claims sideEffects read rides the platform baseline",
        ("privilege-escalation",),
        pack=_drop(
            "deny-email-offlist", "deny-http-offlist", "deny-command-offlist", "deny-write-offlist"
        ),
        datasets=("redteam-mislabel",),
    ),
    Mutant(
        "gate-bypass-lookup-under-tool-kill",
        "the gate waves lookup-account through, so a tool-scope kill-switch no longer stops it",
        ("privilege-escalation",),
        gate_bypass=("lookup-account",),
        datasets=("redteam-kill-tool",),
    ),
    Mutant(
        "gate-bypass-http",
        "the runner's gate answers ALLOW for http-request without asking the kernel",
        ("exfiltration",),
        gate_bypass=("http-request",),
    ),
    Mutant(
        "gate-bypass-wire",
        "the gate answers ALLOW for wire-funds",
        ("direct-injection", "jailbreak"),
        gate_bypass=("wire-funds",),
    ),
    Mutant(
        "gate-bypass-all",
        "the gate is bypassed for every tool call",
        ("direct-injection", "exfiltration", "privilege-escalation"),
        gate_bypass=("*",),
    ),
    Mutant(
        "relax-email-allowlist",
        "send-email is allowed to any recipient (allow rule widened, its negated twin removed)",
        ("exfiltration",),
        pack=lambda p: _drop("deny-email-offlist")(_relax("allow-send-email", "send-email")(p)),
    ),
    Mutant(
        "relax-http-allowlist",
        "http-request is allowed to any URL",
        ("exfiltration",),
        pack=lambda p: _drop("deny-http-offlist")(_relax("allow-http-request", "http-request")(p)),
    ),
    Mutant(
        "drop-read-offlist",
        "reads outside the workspace and SSRF fetches are no longer denied",
        ("tool-misuse",),
        pack=_drop("deny-read-offlist", "deny-fetch-offlist", "deny-url-tricks"),
    ),
    Mutant(
        "drop-tenant-id-rule",
        "tenant ids in tool arguments are no longer refused",
        ("privilege-escalation",),
        pack=_drop("deny-tenant-ids-in-args"),
    ),
    Mutant(
        "drop-forbidden-tools",
        "wire-funds, delete-records and grant-role are only default-denied, and a broad allow exists",
        ("direct-injection", "privilege-escalation"),
        pack=lambda p: _allow_everything(_drop("deny-forbidden-tools")(p)),
    ),
]
