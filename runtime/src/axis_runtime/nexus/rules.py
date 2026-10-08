"""Rules stage: a declarative, tenant-scoped rule list (exact / regex / intent) answered verbatim.

Regexes come from tenant configuration, so they are untrusted: patterns are length-capped and
rejected when they contain constructs that make the stdlib ``re`` engine exponential (nested
quantifiers, backreferences, lookarounds), and the input is truncated before matching.  This is a
mitigation, not a proof; the real fix is a linear-time engine (RE2), tracked in docs/NEEDS.md.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from axis_runtime.nexus.types import Hit, Miss, RouteRequest, RouteState, StageOutcome
from axis_runtime.regex_guard import MAX_INPUT_LEN, UnsafePatternError, compile_safe

__all__ = ["Kind", "Rule", "RulesStage", "UnsafePatternError", "compile_safe"]

Kind = Literal["exact", "regex", "intent"]


@dataclass(frozen=True)
class Rule:
    id: str
    kind: Kind
    match: str
    answer: str
    tenant_id: str | None = None  # None = platform-wide rule; otherwise only that tenant
    confidence: float = 1.0


class RulesStage:
    name = "rules"

    def __init__(self, rules: Sequence[Rule]) -> None:
        ids = [r.id for r in rules]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate rule id")
        self._rules: list[tuple[Rule, re.Pattern[str] | None]] = []
        for r in rules:
            if r.kind not in ("exact", "regex", "intent"):
                raise ValueError(f"unknown rule kind {r.kind!r}")
            self._rules.append((r, compile_safe(r.match) if r.kind == "regex" else None))

    async def run(self, request: RouteRequest, state: RouteState) -> StageOutcome:
        prompt = " ".join(request.prompt.split())
        for rule, rx in self._rules:  # declaration order = priority
            if rule.tenant_id is not None and rule.tenant_id != request.tenant_id:
                continue
            if self._matches(rule, rx, prompt, request):
                return Hit(
                    rule.answer,
                    confidence=rule.confidence,
                    cacheable=False,
                    meta={"rule_id": rule.id},
                )
        return Miss("no_rule")

    @staticmethod
    def _matches(
        rule: Rule, rx: re.Pattern[str] | None, prompt: str, request: RouteRequest
    ) -> bool:
        if rule.kind == "exact":
            return prompt.casefold() == " ".join(rule.match.split()).casefold()
        if rule.kind == "intent":
            return request.intent is not None and request.intent == rule.match
        return rx is not None and rx.search(prompt[:MAX_INPUT_LEN]) is not None
