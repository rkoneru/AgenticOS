"""Deterministic graders: each type, its configuration errors, totality (never raises) and a few
randomised properties."""

from __future__ import annotations

import json
import random
import string
from typing import Any

import pytest
from axis_runtime.evals.graders import grade_deterministic, parse_json
from axis_runtime.evals.jsonschema_lite import SchemaError, validate
from axis_runtime.evals.types import (
    CaseTrace,
    EvalCase,
    GateDecisionTrace,
    GraderSpec,
    ModelCallTrace,
    ToolCallTrace,
)
from evals_helpers import det


def trace(
    output: str | None = "hello world",
    tools: tuple[str, ...] = (),
    decisions: tuple[tuple[str, str, str, str], ...] = (),
    model_calls: tuple[ModelCallTrace, ...] = (),
    latency_ms: int = 10,
) -> CaseTrace:
    return CaseTrace(
        run_id="run_x",
        trace_id="t" * 32,
        exit_reason="completed",
        output=output,
        tool_calls=tuple(ToolCallTrace(t, True, "0" * 64) for t in tools),
        gate_decisions=tuple(GateDecisionTrace(*d) for d in decisions),
        model_calls=model_calls,
        latency_ms=latency_ms,
    )


def case(expected: Any = None) -> EvalCase:
    return EvalCase("c1", "q", expected)


def score(spec: GraderSpec, c: EvalCase | None = None, t: CaseTrace | None = None) -> tuple[str, float]:
    g = grade_deterministic(spec, c or case(), t or trace())
    return g.status, g.score


PASS = ("scored", 1.0)
FAIL = ("scored", 0.0)
ERR = ("error", 0.0)


def test_exact() -> None:
    assert score(det("g", "exact", value="hello world")) == PASS
    assert score(det("g", "exact", value="hello")) == FAIL
    assert score(det("g", "exact"), case("hello world")) == PASS
    assert score(det("g", "exact"), case({"output": "hello world"})) == PASS
    assert score(det("g", "exact", value="  HELLO   world ", normalize=["strip", "casefold", "collapse_ws"])) == PASS
    assert score(det("g", "exact", value="x"), t=trace(None)) == FAIL
    assert score(det("g", "exact")) == ERR  # no expected value at all
    assert score(det("g", "exact", value="x", normalize=["rot13"])) == ERR
    assert score(det("g", "exact", value="x", normalize="strip")) == ERR


def test_exact_json_value() -> None:
    t = trace('{"a": 1, "b": [true]}')
    assert score(det("g", "exact", value={"b": [True], "a": 1}), t=t) == PASS
    assert score(det("g", "exact", value={"a": 2}), t=t) == FAIL
    assert score(det("g", "exact", value={"a": 2}), t=trace("not json")) == FAIL
    assert score(det("g", "exact", value={"a": 1}), t=trace('{"a": 1, "a": 1}')) == FAIL  # duplicate key


def test_contains_and_not_contains() -> None:
    assert score(det("g", "contains", values=["hello", "world"])) == PASS
    assert score(det("g", "contains", values=["hello", "mars"])) == FAIL
    assert score(det("g", "contains", values=["hello", "mars"], mode="any")) == PASS
    assert score(det("g", "contains", values=["HELLO"], normalize=["casefold"])) == PASS
    assert score(det("g", "contains"), case({"contains": ["world"]})) == PASS
    assert score(det("g", "contains"), case("world")) == PASS
    assert score(det("g", "contains", values=["x"], mode="most")) == ERR
    assert score(det("g", "contains", values=[])) == ERR
    assert score(det("g", "contains", values=["x"]), t=trace(None)) == FAIL
    assert score(det("g", "not_contains", values=["mars"])) == PASS
    assert score(det("g", "not_contains", values=["mars", "world"])) == FAIL
    assert score(det("g", "not_contains"), case({"not_contains": ["mars"]})) == PASS
    assert score(det("g", "not_contains", values=["mars"]), t=trace(None)) == FAIL  # no output proves nothing


def test_regex() -> None:
    assert score(det("g", "regex", pattern=r"^hello\s\w+$", mode="fullmatch")) == PASS
    assert score(det("g", "regex", pattern=r"wor")) == PASS
    assert score(det("g", "regex", pattern=r"wor", mode="fullmatch")) == FAIL
    assert score(det("g", "regex", pattern=r"HELLO")) == FAIL
    assert score(det("g", "regex", pattern=r"HELLO", ignore_case=True)) == PASS
    assert score(det("g", "regex", pattern=r"mars", negate=True)) == PASS
    assert score(det("g", "regex", pattern=r"x"), t=trace(None)) == FAIL
    assert score(det("g", "regex")) == ERR
    assert score(det("g", "regex", pattern="(")) == ERR
    assert score(det("g", "regex", pattern="x", mode="start")) == ERR


@pytest.mark.parametrize("pattern", [r"(a+)+$", r"(a|aa)+$", r"a?a?a?a?a?a?a?a?a?aaaaaaaaa", r"(a*)*b", r"(?=a)a", r"(a)\1"])
def test_regex_refuses_redos_shapes(pattern: str) -> None:
    g = grade_deterministic(det("g", "regex", pattern=pattern), case(), trace("a" * 5000))
    assert g.status == "error" and g.score == 0.0


def test_json_schema() -> None:
    schema = {
        "type": "object",
        "required": ["id", "tags"],
        "properties": {
            "id": {"type": "integer", "minimum": 1},
            "tags": {"type": "array", "items": {"type": "string", "maxLength": 5}, "maxItems": 2},
        },
        "additionalProperties": False,
    }
    good = trace('{"id": 3, "tags": ["a", "bb"]}')
    assert score(det("g", "json_schema", schema=schema), t=good) == PASS
    for bad in ('{"id": 0, "tags": []}', '{"id": 1}', '{"id": 1, "tags": ["toolong!"]}', '{"id": 1, "tags": [], "x": 1}', "nope", '{"id": 1, "tags": ["a","b","c"]}'):
        assert score(det("g", "json_schema", schema=schema), t=trace(bad)) == FAIL
    assert score(det("g", "json_schema", schema=schema), t=trace(None)) == FAIL
    assert score(det("g", "json_schema")) == ERR
    assert score(det("g", "json_schema", schema={"$ref": "#/x"}), t=good) == ERR
    assert score(det("g", "json_schema", schema=True), t=good) == PASS
    assert score(det("g", "json_schema", schema=False), t=good) == FAIL
    assert score(det("g", "json_schema", schema={"type": "object", "properties": 3}), t=good) == ERR


def test_jsonschema_keywords() -> None:
    assert validate({"enum": [1, 2]}, 2) == [] and validate({"enum": [1, 2]}, 3)
    assert validate({"const": "a"}, "a") == [] and validate({"const": "a"}, "b")
    assert validate({"type": ["string", "null"]}, None) == []
    assert validate({"type": "number", "exclusiveMinimum": 0, "exclusiveMaximum": 1}, 0.5) == []
    assert validate({"type": "number", "exclusiveMinimum": 0}, 0)
    assert validate({"maximum": 1}, 2) and validate({"minLength": 3}, "ab")
    assert validate({"pattern": "^a+$"}, "aaa") == [] and validate({"pattern": "^a+$"}, "b")
    assert validate({"anyOf": [{"type": "string"}, {"type": "integer"}]}, 3) == []
    assert validate({"anyOf": [{"type": "string"}]}, 3)
    assert validate({"oneOf": [{"type": "integer"}, {"minimum": 0}]}, 3)  # matches both
    assert validate({"oneOf": [{"type": "integer"}, {"type": "string"}]}, 3) == []
    assert validate({"allOf": [{"type": "integer"}, {"minimum": 5}]}, 3)
    assert validate({"type": "array", "minItems": 2}, [1])
    assert validate({"type": "integer"}, True)  # bool is not an integer
    assert validate({"type": "integer"}, 3.0) == []
    assert validate({"properties": {"a": {"type": "string"}}, "additionalProperties": {"type": "integer"}}, {"a": "x", "b": "y"})
    with pytest.raises(SchemaError):
        validate({"type": "wat"}, 1)
    with pytest.raises(SchemaError):
        validate({"pattern": "(a+)+$"}, "a")
    with pytest.raises(SchemaError):
        validate({"pattern": 3}, "a")
    with pytest.raises(SchemaError):
        validate({"minimum": "1"}, 1)
    with pytest.raises(SchemaError):
        validate({"enum": 1}, 1)
    with pytest.raises(SchemaError):
        validate({"required": "a"}, {})
    with pytest.raises(SchemaError):
        validate({"allOf": []}, 1)
    with pytest.raises(SchemaError):
        validate("string", 1)
    deep: Any = {"type": "array"}
    for _ in range(40):
        deep = {"type": "array", "items": deep}
    nested: Any = []
    for _ in range(40):
        nested = [nested]
    with pytest.raises(SchemaError):
        validate(deep, nested)


def test_numeric_tolerance() -> None:
    t = trace("42.5")
    assert score(det("g", "numeric_tolerance", value=42, abs_tol=0.5), t=t) == PASS
    assert score(det("g", "numeric_tolerance", value=42, abs_tol=0.4), t=t) == FAIL
    assert score(det("g", "numeric_tolerance", value=40, rel_tol=0.07), t=t) == PASS
    assert score(det("g", "numeric_tolerance", value=40, rel_tol=0.05), t=t) == FAIL
    assert score(det("g", "numeric_tolerance"), case({"number": 42.5}), t) == PASS
    assert score(det("g", "numeric_tolerance"), case(42.5), t) == PASS
    assert score(det("g", "numeric_tolerance", value=3, extract="first_number"), t=trace("about 3 apples")) == PASS
    assert score(det("g", "numeric_tolerance", value=3), t=trace("about 3 apples")) == FAIL
    assert score(det("g", "numeric_tolerance", value=3, path="a.1"), t=trace('{"a": [0, 3]}')) == PASS
    assert score(det("g", "numeric_tolerance", value=3, path="a.9"), t=trace('{"a": [0, 3]}')) == FAIL
    assert score(det("g", "numeric_tolerance", value=3, path="a"), t=trace('{"a": "3"}')) == FAIL
    assert score(det("g", "numeric_tolerance", value=3), t=trace("nan")) == FAIL
    assert score(det("g", "numeric_tolerance", value=3), t=trace("inf")) == FAIL
    assert score(det("g", "numeric_tolerance", value=3), t=trace(None)) == FAIL
    assert score(det("g", "numeric_tolerance")) == ERR
    assert score(det("g", "numeric_tolerance", value=1, abs_tol=-1)) == ERR
    assert score(det("g", "numeric_tolerance", value=True)) == ERR


def test_tool_sequences() -> None:
    t = trace(tools=("search", "fetch", "answer"))
    assert score(det("g", "tool_sequence", sequence=["search", "fetch", "answer"]), t=t) == PASS
    assert score(det("g", "tool_sequence", sequence=["search", "answer"]), t=t) == FAIL
    assert score(det("g", "tool_sequence"), case({"tool_sequence": ["search", "fetch", "answer"]}), t) == PASS
    assert score(det("g", "tool_subsequence", sequence=["search", "answer"]), t=t) == PASS
    assert score(det("g", "tool_subsequence", sequence=["answer", "search"]), t=t) == FAIL
    assert score(det("g", "tool_subsequence", sequence=["search", "search"]), t=t) == FAIL
    assert score(det("g", "tool_subsequence", sequence=[]), t=t) == PASS
    assert score(det("g", "tool_sequence", sequence=[]), t=trace()) == PASS
    assert score(det("g", "tool_sequence")) == ERR
    assert score(det("g", "tool_sequence", sequence=[1])) == ERR
    assert score(det("g", "tool_sequence", sequence=["a"], scope="everything")) == ERR
    attempted = trace(
        tools=("search",),
        decisions=(
            ("openai/gpt-4o", "model_call", "ALLOW", ""),
            ("search", "tool_call", "ALLOW", ""),
            ("send_email", "tool_call", "DENY", "policy"),
        ),
    )
    assert score(det("g", "tool_sequence", sequence=["search", "send_email"], scope="attempted"), t=attempted) == PASS
    assert score(det("g", "tool_sequence", sequence=["search", "send_email"]), t=attempted) == FAIL


def test_policy_decision() -> None:
    t = trace(
        decisions=(
            ("openai/gpt-4o", "model_call", "ALLOW", ""),
            ("send_email", "tool_call", "DENY", "no outbound mail for tenant"),
        )
    )
    deny_email = {"action": "send_email", "decision": "DENY"}
    assert score(det("g", "policy_decision", expect=[deny_email]), t=t) == PASS
    assert score(det("g", "policy_decision", expect=[{**deny_email, "reason_contains": "outbound"}]), t=t) == PASS
    assert score(det("g", "policy_decision", expect=[{**deny_email, "reason_contains": "xyz"}]), t=t) == FAIL
    assert score(det("g", "policy_decision", expect=[{**deny_email, "enforcement_point": "mcp_call"}]), t=t) == FAIL
    assert score(det("g", "policy_decision", expect=[{"action": "send_email", "decision": "ALLOW"}]), t=t) == FAIL
    assert score(det("g", "policy_decision", forbid=[{"action": "send_email", "decision": "ALLOW"}]), t=t) == PASS
    assert score(det("g", "policy_decision", forbid=[deny_email]), t=t) == FAIL
    assert score(det("g", "policy_decision"), case({"decisions": [deny_email]}), t) == PASS
    assert score(det("g", "policy_decision"), case(None), t) == ERR  # nothing to assert
    assert score(det("g", "policy_decision", expect=["x"]), t=t) == ERR
    assert score(det("g", "policy_decision", expect=[{"action": 1, "decision": "DENY"}]), t=t) == ERR
    assert score(det("g", "policy_decision", expect="x"), t=t) == ERR


def test_budget() -> None:
    calls = (ModelCallTrace("openai", "gpt-4o", 100, 50, 2500, 40), ModelCallTrace("openai", "gpt-4o", 10, 5, 500, 20))
    t = trace(tools=("a",), model_calls=calls, latency_ms=900)
    assert score(det("g", "budget", max_cost_usd=0.003, max_tokens=165, max_latency_ms=900, max_tool_calls=1, max_model_calls=2), t=t) == PASS
    for over in ({"max_cost_usd": 0.0029}, {"max_tokens": 164}, {"max_latency_ms": 899}, {"max_tool_calls": 0}, {"max_model_calls": 1}):
        assert score(det("g", "budget", **over), t=t) == FAIL
    assert score(det("g", "budget")) == ERR
    assert score(det("g", "budget", max_tokens="many"), t=t) == ERR
    assert score(det("g", "budget", max_tokens=-1), t=t) == ERR
    assert score(det("g", "budget", max_cost_usd="NaN"), t=t) == ERR


def test_unknown_type_and_totality() -> None:
    assert score(GraderSpec("g", "deterministic", 1.0, {})) == ERR
    assert score(GraderSpec("g", "deterministic", 1.0, {"type": "vibes"})) == ERR
    rng = random.Random(7)
    types = ["exact", "contains", "not_contains", "regex", "json_schema", "numeric_tolerance", "tool_sequence", "tool_subsequence", "policy_decision", "budget"]
    junk: list[Any] = [None, 1, -1, 2.5, "x", "", [], [1], ["a"], {}, {"a": 1}, True, float("nan"), "(", "[a-"]
    for _ in range(600):
        cfg = {k: rng.choice(junk) for k in ("value", "values", "pattern", "schema", "sequence", "expect", "forbid", "mode", "scope", "normalize", "path", "max_tokens", "abs_tol", "extract")}
        out = rng.choice([None, "", "42", "{}", "[1,2", "".join(rng.choices(string.printable, k=rng.randint(0, 80)))])
        g = grade_deterministic(det("g", rng.choice(types), **cfg), case(rng.choice(junk)), trace(out))
        assert g.status in ("scored", "error") and g.score in (0.0, 1.0)


def test_random_equivalences() -> None:
    rng = random.Random(11)
    for _ in range(200):
        text = "".join(rng.choices("abc ", k=rng.randint(0, 12)))
        t = trace(text)
        needle = "".join(rng.choices("abc", k=rng.randint(1, 3)))
        c = score(det("g", "contains", values=[needle]), t=t)
        n = score(det("g", "not_contains", values=[needle]), t=t)
        assert c[1] + n[1] == 1.0  # contains and not_contains are complements
        assert score(det("g", "exact", value=text), t=t) == PASS
        assert score(det("g", "regex", pattern=f"^{needle}", mode="search"), t=t)[1] == (1.0 if text.startswith(needle) else 0.0)


def test_parse_json_is_strict() -> None:
    assert parse_json('{"a": [1, 2]}') == {"a": [1, 2]}
    for bad in ('{"a": NaN}', '{"a": Infinity}', '{"a":1} {"b":2}', '{"a":1,"a":2}', "", "{"):
        with pytest.raises(ValueError):
            parse_json(bad)
    json.loads("{}")
