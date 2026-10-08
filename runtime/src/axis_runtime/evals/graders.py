"""Deterministic graders: pure functions of (grader spec, case, trace).

No clock, no randomness, no IO and no model: the same inputs give the same grade, and a grader
never raises (a misconfigured grader or an exotic input becomes an ``error`` grade, which
aggregates as 0, fail closed). Scores are 0.0 or 1.0; partial credit comes from composing graders
and weighting them in the suite.

Config shape (``spec.config``); ``type`` selects the grader, ``expected`` is ``case.expected``:

* ``exact``            ``value`` (default ``expected`` or ``expected["output"]``); ``normalize``
                       list of ``strip`` / ``casefold`` / ``collapse_ws``. A non-string value
                       compares the output parsed as JSON.
* ``contains``         ``values`` (default ``expected["contains"]`` or the expected string);
                       ``mode`` ``all`` (default) | ``any``; ``normalize``.
* ``not_contains``     ``values`` (default ``expected["not_contains"]``); none may appear.
* ``regex``            ``pattern``; ``mode`` ``search`` | ``fullmatch``; ``ignore_case``;
                       ``negate``.
* ``json_schema``      ``schema`` (a JSON Schema subset, see ``jsonschema_lite``).
* ``numeric_tolerance`` ``value`` (default ``expected["number"]`` or a numeric expected);
                       ``abs_tol`` / ``rel_tol``; ``path`` into a JSON output, else the output is a
                       number, or ``extract: "first_number"``.
* ``tool_sequence``    ``sequence`` (default ``expected["tool_sequence"]``): the exact tool names;
* ``tool_subsequence`` ``sequence``: in order, other calls allowed in between. ``scope``
                       ``performed`` (default, tool results) | ``attempted`` (every gated action
                       that is not a model call, denied ones included).
* ``policy_decision``  ``expect`` / ``forbid``: lists of ``{action, decision, reason_contains?,
                       enforcement_point?}`` matched against the run's gate decisions.
* ``budget``           ``max_cost_usd`` ``max_tokens`` ``max_latency_ms`` ``max_tool_calls``
                       ``max_model_calls``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from decimal import Decimal, InvalidOperation
from typing import Any

from axis_runtime.evals.jsonschema_lite import SchemaError, validate
from axis_runtime.evals.types import CaseTrace, EvalCase, Grade, GraderSpec, errored, scored
from axis_runtime.nexus.rules import UnsafePatternError, compile_safe

MAX_MATCH_CHARS = 100_000
_NUMBER = re.compile(r"[-+]?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?")


class GraderConfigError(ValueError):
    """The grader (or the case's expectation it relies on) is misconfigured."""


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def parse_json(text: str) -> Any:
    """Strict JSON: no NaN/Infinity, no duplicate keys, no trailing data."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in items:
            if k in out:
                raise ValueError("duplicate key")
            out[k] = v
        return out

    return json.loads(text, parse_constant=_reject_constant, object_pairs_hook=pairs)


def _normalize(text: str, ops: Sequence[str]) -> str:
    for op in ops:
        if op == "strip":
            text = text.strip()
        elif op == "casefold":
            text = text.casefold()
        elif op == "collapse_ws":
            text = " ".join(text.split())
        else:
            raise GraderConfigError(f"unknown normalize operation {op!r}")
    return text


def _ops(cfg: Mapping[str, Any]) -> list[str]:
    ops = cfg.get("normalize", [])
    if not isinstance(ops, list) or not all(isinstance(o, str) for o in ops):
        raise GraderConfigError("normalize must be a list of operation names")
    return ops


def _expected_field(case: EvalCase, key: str) -> Any:
    e = case.expected
    return e.get(key) if isinstance(e, Mapping) else None


def _values(cfg: Mapping[str, Any], case: EvalCase, key: str) -> list[str]:
    raw = cfg.get("values")
    if raw is None:
        raw = _expected_field(case, key)
    if raw is None and key == "contains" and isinstance(case.expected, str):
        raw = [case.expected]
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list) or not raw or not all(isinstance(v, str) and v for v in raw):
        raise GraderConfigError(f"{key}: expected a non-empty list of non-empty strings")
    return raw


def _text(trace: CaseTrace) -> str | None:
    return None if trace.output is None else trace.output[:MAX_MATCH_CHARS]


def _exact(spec: GraderSpec, case: EvalCase, trace: CaseTrace) -> Grade:
    cfg = spec.config
    want = cfg.get("value")
    if want is None:
        e = case.expected
        want = e.get("output") if isinstance(e, Mapping) else e
    if want is None:
        raise GraderConfigError("exact: no expected value")
    text = _text(trace)
    if text is None:
        return scored(spec, False, "no_output")
    if isinstance(want, str):
        ops = _ops(cfg)
        return scored(spec, _normalize(text, ops) == _normalize(want, ops), "exact")
    try:
        got = parse_json(text)
    except ValueError:
        return scored(spec, False, "output_is_not_json")
    return scored(spec, got == want, "exact_json")


def _contains(spec: GraderSpec, case: EvalCase, trace: CaseTrace) -> Grade:
    cfg = spec.config
    needles = _values(cfg, case, "contains")
    mode = cfg.get("mode", "all")
    if mode not in ("all", "any"):
        raise GraderConfigError("mode must be all or any")
    text = _text(trace)
    if text is None:
        return scored(spec, False, "no_output")
    ops = _ops(cfg)
    hay = _normalize(text, ops)
    hits = [_normalize(n, ops) in hay for n in needles]
    ok = all(hits) if mode == "all" else any(hits)
    return scored(spec, ok, f"{sum(hits)}/{len(hits)} found")


def _not_contains(spec: GraderSpec, case: EvalCase, trace: CaseTrace) -> Grade:
    cfg = spec.config
    needles = _values(cfg, case, "not_contains")
    text = _text(trace)
    if text is None:
        return scored(spec, False, "no_output")  # absent output proves nothing: fail closed
    ops = _ops(cfg)
    hay = _normalize(text, ops)
    found = sum(_normalize(n, ops) in hay for n in needles)
    return scored(spec, found == 0, f"{found} forbidden found")


def _regex(spec: GraderSpec, case: EvalCase, trace: CaseTrace) -> Grade:
    cfg = spec.config
    pattern = cfg.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        raise GraderConfigError("regex: pattern is required")
    mode = cfg.get("mode", "search")
    if mode not in ("search", "fullmatch"):
        raise GraderConfigError("mode must be search or fullmatch")
    try:
        compile_safe(pattern)  # linear-time guard (docs/NEEDS.md RE2 note): refuses ReDoS shapes
        compiled = re.compile(pattern, re.IGNORECASE if cfg.get("ignore_case") else 0)
    except (UnsafePatternError, re.error) as exc:
        raise GraderConfigError(f"regex: {exc}") from exc
    text = _text(trace)
    if text is None:
        return scored(spec, False, "no_output")
    matched = (compiled.search(text) if mode == "search" else compiled.fullmatch(text)) is not None
    return scored(
        spec, matched != bool(cfg.get("negate", False)), "matched" if matched else "no match"
    )


def _json_schema(spec: GraderSpec, case: EvalCase, trace: CaseTrace) -> Grade:
    if "schema" not in spec.config:
        raise GraderConfigError("json_schema: schema is required")
    text = _text(trace)
    if text is None:
        return scored(spec, False, "no_output")
    try:
        doc = parse_json(text.strip())
    except ValueError:
        return scored(spec, False, "output_is_not_json")
    try:
        problems = validate(spec.config["schema"], doc)
    except SchemaError as exc:
        raise GraderConfigError(f"json_schema: {exc}") from exc
    return scored(spec, not problems, "valid" if not problems else problems[0])


def _number_from(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    f = float(value)
    return f if f == f and f not in (float("inf"), float("-inf")) else None


def _numeric(spec: GraderSpec, case: EvalCase, trace: CaseTrace) -> Grade:
    cfg = spec.config
    want = cfg.get("value")
    if want is None:
        want = _expected_field(case, "number")
    if want is None:
        want = case.expected if not isinstance(case.expected, Mapping) else None
    target = _number_from(want)
    if target is None:
        raise GraderConfigError("numeric_tolerance: no numeric expected value")
    abs_tol = _number_from(cfg.get("abs_tol", 0.0))
    rel_tol = _number_from(cfg.get("rel_tol", 0.0))
    if abs_tol is None or rel_tol is None or abs_tol < 0 or rel_tol < 0:
        raise GraderConfigError("numeric_tolerance: tolerances must be non-negative numbers")
    text = _text(trace)
    if text is None:
        return scored(spec, False, "no_output")
    got: float | None
    path = cfg.get("path")
    try:
        if path is not None:
            node: Any = parse_json(text.strip())
            for part in str(path).split("."):
                node = node[int(part)] if isinstance(node, list) else node[part]
            got = _number_from(node)
        elif cfg.get("extract") == "first_number":
            m = _NUMBER.search(text)
            got = None if m is None else _number_from(float(m.group(0)))
        else:
            got = _number_from(float(text.strip()))
    except (ValueError, KeyError, IndexError, TypeError):
        return scored(spec, False, "no_number_in_output")
    if got is None:
        return scored(spec, False, "no_number_in_output")
    ok = abs(got - target) <= max(abs_tol, rel_tol * abs(target))
    return scored(spec, ok, "within_tolerance" if ok else "outside_tolerance")


def _names(trace: CaseTrace, scope: str) -> list[str]:
    if scope == "performed":
        return [t.name for t in trace.tool_calls]
    if scope == "attempted":
        return [d.action for d in trace.gate_decisions if d.enforcement_point != "model_call"]
    raise GraderConfigError("scope must be performed or attempted")


def _sequence(cfg: Mapping[str, Any], case: EvalCase) -> list[str]:
    raw = cfg.get("sequence")
    if raw is None:
        raw = _expected_field(case, "tool_sequence")
    if not isinstance(raw, list) or not all(isinstance(s, str) and s for s in raw):
        raise GraderConfigError("sequence: expected a list of tool names")
    return raw


def _tool_sequence(spec: GraderSpec, case: EvalCase, trace: CaseTrace) -> Grade:
    want = _sequence(spec.config, case)
    got = _names(trace, str(spec.config.get("scope", "performed")))
    return scored(spec, got == want, f"called {len(got)} tool(s)")


def _tool_subsequence(spec: GraderSpec, case: EvalCase, trace: CaseTrace) -> Grade:
    want = _sequence(spec.config, case)
    got = iter(_names(trace, str(spec.config.get("scope", "performed"))))
    ok = all(any(name == g for g in got) for name in want)  # consumes `got` in order
    return scored(spec, ok, "subsequence found" if ok else "subsequence missing")


def _decision_matches(rule: Mapping[str, Any], trace: CaseTrace) -> bool:
    action = rule.get("action")
    decision = rule.get("decision")
    if not isinstance(action, str) or not isinstance(decision, str):
        raise GraderConfigError("policy_decision: action and decision are required strings")
    contains = rule.get("reason_contains")
    point = rule.get("enforcement_point")
    for d in trace.gate_decisions:
        if (
            d.action == action
            and d.decision == decision
            and (point is None or d.enforcement_point == point)
            and (contains is None or str(contains) in d.reason)
        ):
            return True
    return False


def _policy_decision(spec: GraderSpec, case: EvalCase, trace: CaseTrace) -> Grade:
    cfg = spec.config
    expect = cfg.get("expect")
    if expect is None:
        expect = _expected_field(case, "decisions")
    forbid = cfg.get("forbid", [])
    if not isinstance(expect, list | type(None)) or not isinstance(forbid, list):
        raise GraderConfigError("policy_decision: expect and forbid must be lists")
    if not expect and not forbid:
        raise GraderConfigError("policy_decision: nothing to assert")
    for rule in [*(expect or []), *forbid]:
        if not isinstance(rule, Mapping):
            raise GraderConfigError("policy_decision: each rule must be an object")
    missing = [r for r in (expect or []) if not _decision_matches(r, trace)]
    present = [r for r in forbid if _decision_matches(r, trace)]
    ok = not missing and not present
    return scored(spec, ok, f"{len(missing)} expected missing, {len(present)} forbidden present")


def _decimal(value: Any) -> Decimal:
    try:
        d = Decimal(str(value))
    except InvalidOperation as exc:
        raise GraderConfigError("budget: limits must be numbers") from exc
    if not d.is_finite() or d < 0:
        raise GraderConfigError("budget: limits must be non-negative numbers")
    return d


def _budget(spec: GraderSpec, case: EvalCase, trace: CaseTrace) -> Grade:
    cfg = spec.config
    limits = {
        k: cfg[k]
        for k in (
            "max_cost_usd",
            "max_tokens",
            "max_latency_ms",
            "max_tool_calls",
            "max_model_calls",
        )
        if k in cfg
    }
    if not limits:
        raise GraderConfigError("budget: no limit configured")
    used: dict[str, Decimal] = {
        "max_cost_usd": Decimal(trace.cost_micro_usd) / Decimal(1_000_000),
        "max_tokens": Decimal(trace.tokens),
        "max_latency_ms": Decimal(trace.latency_ms),
        "max_tool_calls": Decimal(len(trace.tool_calls)),
        "max_model_calls": Decimal(len(trace.model_calls)),
    }
    over = [k for k, v in limits.items() if used[k] > _decimal(v)]
    return scored(spec, not over, "within budget" if not over else f"over {over[0]}")


_DETERMINISTIC: dict[str, Callable[[GraderSpec, EvalCase, CaseTrace], Grade]] = {
    "exact": _exact,
    "contains": _contains,
    "not_contains": _not_contains,
    "regex": _regex,
    "json_schema": _json_schema,
    "numeric_tolerance": _numeric,
    "tool_sequence": _tool_sequence,
    "tool_subsequence": _tool_subsequence,
    "policy_decision": _policy_decision,
    "budget": _budget,
}
DETERMINISTIC_TYPES = frozenset(_DETERMINISTIC)


def grade_deterministic(spec: GraderSpec, case: EvalCase, trace: CaseTrace) -> Grade:
    """Grade one case. Never raises: a configuration problem is an ``error`` grade (score 0)."""
    fn = _DETERMINISTIC.get(str(spec.config.get("type")))
    if fn is None:
        return errored(spec, "unknown_grader_type")
    try:
        return fn(spec, case, trace)
    except GraderConfigError as exc:
        return errored(spec, str(exc)[:200])
    except Exception as exc:  # noqa: BLE001 - a grader must never take the run down
        return errored(spec, f"grader_failed:{type(exc).__name__}")
