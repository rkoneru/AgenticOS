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

MAX_PATTERN_LEN = 256
MAX_INPUT_LEN = 1024
MAX_QUANTIFIERS = 8  # every ``?`` ``*`` ``+`` ``{m,n}``: ``a?a?a?..a?aaa..`` is 2^n
MAX_UNBOUNDED = 2  # ``*`` ``+`` ``{m,}`` and wide ``{m,n}``: k adjacent ones cost O(len^k)
_BOUNDED_MAX = 10  # a ``{m,n}`` with n above this counts as unbounded
_BRACE_QUANT = re.compile(r"\{(\d*)(?:(,)(\d*))?\}")
_NESTED_QUANT = re.compile(r"[+*}]\)?[+*{]|\([^)]*[+*}]\)[+*{]")
_UNSAFE_CONSTRUCT = re.compile(r"\\[1-9]|\(\?[=!<P]|\(\?\(")

Kind = Literal["exact", "regex", "intent"]


class UnsafePatternError(ValueError):
    pass


def _check_repetition(pattern: str) -> None:
    """Reject the shapes a denylist of ``(a+)+`` misses: a quantified group (``(a|aa)+`` is
    exponential with no inner quantifier), too many repeats (``a?a?..a?aa..``) and adjacent
    unbounded repeats (``a*a*a*b``).  ``(?:...)?`` stays allowed. Classes, escapes skipped."""
    total = unbounded = 0
    i, n = 0, len(pattern)
    prev = "start"  # start | atom | open | close | alt | quant
    while i < n:
        c = pattern[i]
        if c == "\\":
            i, prev = i + 2, "atom"
            continue
        if c == "[":
            i += 1
            if i < n and pattern[i] == "^":
                i += 1
            if i < n and pattern[i] == "]":
                i += 1  # a leading ] is a literal
            while i < n and pattern[i] != "]":
                i += 2 if pattern[i] == "\\" else 1
            i, prev = i + 1, "atom"
            continue
        if c == "(":
            i += 2 if pattern[i + 1 : i + 2] == "?" else 1
            prev = "open"
            continue
        if c == ")":
            i, prev = i + 1, "close"
            continue
        if c == "|":
            i, prev = i + 1, "alt"
            continue
        wide = False
        step = 1
        if c in "*+?":
            wide = c != "?"
        elif c == "{" and (m := _BRACE_QUANT.match(pattern, i)) and (m.group(1) or m.group(3)):
            step = m.end() - i
            wide = m.group(2) is not None and (not m.group(3) or int(m.group(3)) > _BOUNDED_MAX)
        else:
            i, prev = i + 1, "atom"
            continue
        if prev == "quant":  # lazy / possessive suffix of the previous quantifier
            i, prev = i + step, "quant"
            continue
        if prev == "close" and c != "?":
            raise UnsafePatternError("a quantified group is not allowed")
        total += 1
        unbounded += wide
        if total > MAX_QUANTIFIERS or unbounded > MAX_UNBOUNDED:
            raise UnsafePatternError("too many repetitions in pattern")
        i, prev = i + step, "quant"


def compile_safe(pattern: str) -> re.Pattern[str]:
    if len(pattern) > MAX_PATTERN_LEN:
        raise UnsafePatternError("pattern too long")
    if _UNSAFE_CONSTRUCT.search(pattern):
        raise UnsafePatternError("backreferences and lookarounds are not allowed")
    if _NESTED_QUANT.search(pattern):
        raise UnsafePatternError("nested quantifiers are not allowed")
    _check_repetition(pattern)
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise UnsafePatternError(f"invalid pattern: {exc}") from exc


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
