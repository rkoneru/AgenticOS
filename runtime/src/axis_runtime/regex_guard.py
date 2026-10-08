"""Regex guard shared by the NEXUS rules stage and the eval graders.

Patterns can come from tenant configuration (rules, eval suites), so they are untrusted: length-
capped and rejected when they contain constructs that make the stdlib ``re`` engine exponential
(nested quantifiers, backreferences, lookarounds, quantified groups, too many repeats). This is a
mitigation, not a proof; the real fix is a linear-time engine (RE2), tracked in docs/NEEDS.md.
It lives in its own module so that importing it does not pull in the NEXUS pipeline (and with it
the run path): the online eval sampler must stay free of decision code.
"""

from __future__ import annotations

import re

MAX_PATTERN_LEN = 256
MAX_INPUT_LEN = 1024
MAX_QUANTIFIERS = 8  # every ``?`` ``*`` ``+`` ``{m,n}``: ``a?a?a?..a?aaa..`` is 2^n
MAX_UNBOUNDED = 2  # ``*`` ``+`` ``{m,}`` and wide ``{m,n}``: k adjacent ones cost O(len^k)
_BOUNDED_MAX = 10  # a ``{m,n}`` with n above this counts as unbounded
_BRACE_QUANT = re.compile(r"\{(\d*)(?:(,)(\d*))?\}")
_NESTED_QUANT = re.compile(r"[+*}]\)?[+*{]|\([^)]*[+*}]\)[+*{]")
_UNSAFE_CONSTRUCT = re.compile(r"\\[1-9]|\(\?[=!<P]|\(\?\(")


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
