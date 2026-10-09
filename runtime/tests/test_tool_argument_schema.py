"""Red-team finding (Phase 9): arguments a model smuggles into a function tool are checked against the schema the tool declares.

Before the fix a registered ``input_schema`` was only shown to the model; a call with an extra property (``bcc``, a nested
``tenant_id`` ...) reached the Risk Kernel and the handler unchanged, so a policy written for the declared arguments said nothing
about the smuggled one. Now a call that does not fit a declared schema is a tool error with no gate request and no handler call.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from axis_runtime.gate import EnforcementPoint
from axis_runtime.tools import ToolRegistry, validate_arguments
from conftest import ScriptedGate, ScriptedTransport, make_deps, make_manifest, openai_body
from test_run_tools import turn

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"to": {"type": "string"}, "n": {"type": "integer"}, "opts": {"type": "object"}},
    "required": ["to"],
    "additionalProperties": False,
}


@pytest.mark.parametrize(
    ("args", "ok"),
    [
        ({"to": "a"}, True),
        ({"to": "a", "n": 3, "opts": {"x": 1}}, True),
        ({"to": "a", "bcc": "x"}, False),  # smuggled property
        ({}, False),  # required missing
        ({"to": ["a", "b"]}, False),  # type confusion
        ({"to": "a", "n": True}, False),  # bool is not an integer
        ({"to": "a", "n": 1.5}, False),
    ],
)
def test_validate_arguments(args: dict[str, Any], ok: bool) -> None:
    assert (validate_arguments(SCHEMA, args) is None) is ok


def test_an_open_schema_accepts_anything() -> None:
    assert validate_arguments({"type": "object"}, {"anything": [1, {"x": None}]}) is None


async def test_a_smuggled_argument_reaches_neither_the_gate_nor_the_handler() -> None:
    from axis_runtime.run import run_agent

    calls: list[dict[str, Any]] = []
    reg = ToolRegistry()
    reg.register("lookup_claim", lambda a: calls.append(dict(a)) or "ok", input_schema=SCHEMA)
    gate = ScriptedGate()
    transport = ScriptedTransport(
        [(200, turn(("lookup_claim", {"to": "a", "bcc": "evil"}))), (200, openai_body("done"))]
    )
    await run_agent(make_manifest(), "go", make_deps(gate=gate, transport=transport, tools=reg))
    assert calls == []
    assert [r.enforcement_point for r in gate.requests] == [EnforcementPoint.MODEL_CALL] * 2
    reply = [m for m in json.loads(transport.calls[1].body)["messages"] if m["role"] == "tool"][0]
    assert reply["content"].startswith("invalid arguments for tool")


async def test_a_conforming_call_still_runs_through_the_gate() -> None:
    from axis_runtime.run import run_agent

    calls: list[dict[str, Any]] = []
    reg = ToolRegistry()
    reg.register("lookup_claim", lambda a: calls.append(dict(a)) or "ok", input_schema=SCHEMA)
    gate = ScriptedGate()
    transport = ScriptedTransport(
        [(200, turn(("lookup_claim", {"to": "a"}))), (200, openai_body("done"))]
    )
    await run_agent(make_manifest(), "go", make_deps(gate=gate, transport=transport, tools=reg))
    assert calls == [{"to": "a"}]
    assert EnforcementPoint.TOOL_CALL in [r.enforcement_point for r in gate.requests]
