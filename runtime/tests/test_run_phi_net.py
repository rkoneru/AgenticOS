"""Free-text PHI net on the run-log persistence path (Phase 9 / NEEDS #363, #413).

In a PHI run (``meta.phi``) every free-text value the recorder persists (tool results and errors, process output, any string
payload) passes the PHI net BEFORE the event is sealed, so neither the log nor a replay holds the raw value. Structural values
(ids, hashes, timestamps) are left alone, a non-PHI run is untouched, and a resumed PHI run keeps the net.
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

import pytest
from axis_runtime.events import EventType, InMemoryRunEventLog, RunRecorder, replay
from axis_runtime.process import Lifecycle, ProcessState, next_state
from conftest import TENANT, FakeClock

PID = "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV"
CANARIES = [
    ("patient ssn 123-45-6789 on file", "123456789"),
    ("ssn 234 56 7890 given verbally", "234567890"),
    ("ssn １３５-７９-２４６８ typed", "135792468"),
    ("ssn 246-80-13​57 pasted", "246801357"),
    ("ssn 357.91.2468 scanned", "357912468"),
    ("social security number 468013579", "468013579"),
    ("chart MRN: 99887766 reviewed", "99887766"),
    ("contact zelda.canary@clinic-example.org today", "zelda.canary@clinic-example.org"),
    ("mail zelda+rx@clinic-example.org", "zelda+rx@clinic-example.org"),
    ("call (415) 555-0134 after noon", "4155550134"),
    ("call +1 415 555 0177", "4155550177"),
]


def leaks(text: str, core: str) -> bool:
    t = "".join(
        c for c in unicodedata.normalize("NFKC", text) if unicodedata.category(c) != "Cf"
    ).lower()
    return core in t if not core.isdigit() else re.search(r"[\s.\-()]*".join(core), t) is not None


async def _started(phi: bool) -> tuple[RunRecorder, InMemoryRunEventLog]:
    log = InMemoryRunEventLog()
    rec = await RunRecorder.start(
        log, FakeClock(), run_id="run_1", tenant_id=TENANT, meta={"phi": phi, "blueprint": "b"}
    )
    return rec, log


async def _spawn(rec: RunRecorder) -> None:
    await rec.record(EventType.PROCESS_SPAWNED, PID, {"ppid": None, "agent": "b@1"})
    state = ProcessState.SPAWN
    for trigger in (Lifecycle.INIT_COMPLETE, Lifecycle.SCHEDULED):
        nxt = next_state(state, trigger)
        await rec.record(
            EventType.PROCESS_TRANSITION,
            PID,
            {"from": state.value, "to": nxt.value, "trigger": str(trigger)},
        )
        state = nxt


def _dump(events: Any) -> str:
    return json.dumps([e.to_dict() for e in events])


@pytest.mark.parametrize(("text", "core"), CANARIES)
async def test_phi_run_persists_no_raw_canary_in_results_errors_and_output(
    text: str, core: str
) -> None:
    rec, log = await _started(True)
    await _spawn(rec)
    await rec.record(
        "tool_call_result",
        PID,
        {
            "action_id": "act_000001",
            "enforcement_point": "tool_call",
            "name": "lookup",
            "ok": True,
            "result": {"echo": [text]},
            "error": None,
        },
    )
    await rec.record(
        "tool_call_result",
        PID,
        {
            "action_id": "act_000002",
            "enforcement_point": "tool_call",
            "name": "lookup",
            "ok": False,
            "result": None,
            "error": f"ValueError: {text}",
        },
    )
    events = await log.read("run_1")
    assert not leaks(_dump(events), core)
    assert not leaks(_dump(await log.read("run_1")), core)
    replay(events)  # the sealed chain still verifies and folds


async def test_a_non_phi_run_is_untouched() -> None:
    rec, log = await _started(False)
    await _spawn(rec)
    await rec.record(
        "tool_call_result",
        PID,
        {
            "action_id": "act_000001",
            "enforcement_point": "tool_call",
            "name": "t",
            "ok": True,
            "result": "ssn 123-45-6789",
            "error": None,
        },
    )
    assert "123-45-6789" in _dump(await log.read("run_1"))


async def test_structural_values_survive_the_net() -> None:
    rec, log = await _started(True)
    await _spawn(rec)
    audit_id = "12345678-1234-4234-8234-123456789012"  # an all-digit UUID: must not be mangled
    await rec.record(
        EventType.GATE_DECISION,
        PID,
        {
            "action_id": "act_000001",
            "enforcement_point": "tool_call",
            "action": "lookup",
            "decision": "ALLOW",
            "reason": "ok",
            "policy_version": "1.0.0",
            "redact_fields": [],
            "approval_id": "",
            "audit_event_id": audit_id,
        },
    )
    ev = (await log.read("run_1"))[-1]
    assert ev.data["audit_event_id"] == audit_id and ev.data["policy_version"] == "1.0.0"


async def test_a_resumed_phi_run_keeps_the_net() -> None:
    rec, log = await _started(True)
    await _spawn(rec)
    again = await RunRecorder.resume(log, FakeClock(), "run_1")
    await again.record(
        "tool_call_result",
        PID,
        {
            "action_id": "act_000001",
            "enforcement_point": "tool_call",
            "name": "t",
            "ok": True,
            "result": "ssn 123-45-6789",
            "error": None,
        },
    )
    assert "123-45-6789" not in _dump(await log.read("run_1"))
