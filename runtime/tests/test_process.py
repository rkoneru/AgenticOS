"""Process model: every transition in process-model.json is enforced, everything else raises."""

import itertools
import json
import re
from pathlib import Path

import pytest
from axis_runtime import process
from axis_runtime.process import (
    MODEL,
    ExitReason,
    IllegalTransitionError,
    Lifecycle,
    ProcessModelMismatchError,
    ProcessState,
    Signal,
    is_terminal,
    is_valid_pid,
    legal_triggers,
    load_process_model,
    new_pid,
    next_state,
    verify_enums,
)

MODEL_JSON = Path(process.__file__).resolve().parents[3] / "packages/contracts/process-model.json"
RAW = json.loads(MODEL_JSON.read_text())
ALL_TRIGGERS = sorted({t["on"] for t in RAW["transitions"]} | set(RAW["signals"]))


@pytest.mark.parametrize("t", RAW["transitions"], ids=lambda t: f"{t['from']}-{t['on']}")
def test_every_json_transition_is_enforced(t: dict[str, str]) -> None:
    assert next_state(ProcessState(t["from"]), t["on"]) == ProcessState(t["to"])


def test_every_non_listed_pair_is_illegal() -> None:
    legal = {(t["from"], t["on"]) for t in RAW["transitions"]}
    checked = 0
    for state, trigger in itertools.product(RAW["states"], ALL_TRIGGERS):
        if (state, trigger) in legal:
            continue
        with pytest.raises(IllegalTransitionError):
            next_state(ProcessState(state), trigger)
        checked += 1
    assert checked == len(RAW["states"]) * len(ALL_TRIGGERS) - len(legal)


def test_unknown_trigger_is_illegal() -> None:
    with pytest.raises(IllegalTransitionError):
        next_state(ProcessState.RUNNING, "teleport")


def test_terminated_is_absorbing() -> None:
    assert is_terminal(ProcessState.TERMINATED)
    assert legal_triggers(ProcessState.TERMINATED) == frozenset()
    assert not any(is_terminal(s) for s in ProcessState if s is not ProcessState.TERMINATED)


def test_kill_legal_from_every_non_terminal_state() -> None:
    for s in ProcessState:
        if not is_terminal(s):
            assert next_state(s, Signal.KILL) is ProcessState.TERMINATED


def test_interrupt_is_not_a_transition() -> None:
    for s in ProcessState:
        assert Signal.INTERRUPT not in legal_triggers(s)


def test_enums_match_json() -> None:
    verify_enums(MODEL)
    assert {s.value for s in ProcessState} == set(RAW["states"])
    assert {s.value for s in ExitReason} == set(RAW["exitReasons"])
    assert {s.value for s in Signal} == set(RAW["signals"])
    assert {s.value for s in Lifecycle} | {s.value for s in Signal if s.value != "INTERRUPT"} == {
        t["on"] for t in RAW["transitions"]
    }


def test_enum_drift_is_detected(tmp_path: Path) -> None:
    drifted = json.loads(MODEL_JSON.read_text())
    drifted["states"].append("zombie")
    p = tmp_path / "pm.json"
    p.write_text(json.dumps(drifted))
    with pytest.raises(ProcessModelMismatchError, match="states differ"):
        verify_enums(load_process_model(p))


def test_initial_terminal_drift_is_detected(tmp_path: Path) -> None:
    drifted = json.loads(MODEL_JSON.read_text())
    drifted["initial"] = "ready"
    p = tmp_path / "pm.json"
    p.write_text(json.dumps(drifted))
    with pytest.raises(ProcessModelMismatchError, match="initial/terminal"):
        verify_enums(load_process_model(p))


def test_duplicate_transition_in_json_is_rejected(tmp_path: Path) -> None:
    drifted = json.loads(MODEL_JSON.read_text())
    drifted["transitions"].append(drifted["transitions"][0])
    p = tmp_path / "pm.json"
    p.write_text(json.dumps(drifted))
    with pytest.raises(ProcessModelMismatchError, match="duplicate"):
        load_process_model(p)


def test_model_path_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    p = tmp_path / "pm.json"
    p.write_text(MODEL_JSON.read_text())
    monkeypatch.setenv("AXIS_PROCESS_MODEL_PATH", str(p))
    assert process._default_path() == p  # noqa: SLF001


# ---- PIDs ---------------------------------------------------------------------------------


def test_pid_matches_contract_regex_and_is_time_sortable() -> None:
    regex = re.compile(RAW["pid"]["regex"])
    pids = [new_pid(now_ms=1_700_000_000_000 + i) for i in range(50)]
    assert all(regex.match(p) for p in pids)
    assert pids == sorted(pids)
    assert len(set(pids)) == 50


def test_pid_default_clock_and_rng() -> None:
    assert is_valid_pid(new_pid())
    assert new_pid() != new_pid()


def test_pid_is_deterministic_with_injected_inputs() -> None:
    a = new_pid(now_ms=1, randbytes=lambda n: b"\x00" * n)
    b = new_pid(now_ms=1, randbytes=lambda n: b"\x00" * n)
    assert a == b == "axp_0000000001" + "0" * 16


def test_pid_extremes_still_match_regex() -> None:
    assert is_valid_pid(new_pid(now_ms=(1 << 48) - 1, randbytes=lambda n: b"\xff" * n))


@pytest.mark.parametrize("ms", [-1, 1 << 48])
def test_pid_rejects_out_of_range_timestamp(ms: int) -> None:
    with pytest.raises(ValueError, match="range"):
        new_pid(now_ms=ms)


@pytest.mark.parametrize(
    "bad", [None, 5, "", "axp_", "axp_" + "0" * 25, "axp_" + "U" * 26, "xyz_" + "0" * 26, "axp_" + "0" * 27]
)
def test_invalid_pids(bad: object) -> None:
    assert not is_valid_pid(bad)
