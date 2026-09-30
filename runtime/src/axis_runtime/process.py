"""Agent process model, loaded from ``packages/contracts/process-model.json`` (source of truth).

The transition table, terminal set, PID regex and signal list are read from the JSON at import
time and never duplicated here.  The enums below exist only so the type checker can see member
names; ``_verify_enums`` fails the import if they drift from the JSON.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from pathlib import Path

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


class ProcessState(StrEnum):
    SPAWN = "spawn"
    READY = "ready"
    RUNNING = "running"
    WAITING = "waiting"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"


class Signal(StrEnum):
    PAUSE = "PAUSE"
    RESUME = "RESUME"
    TERM = "TERM"
    KILL = "KILL"
    INTERRUPT = "INTERRUPT"


class Lifecycle(StrEnum):
    """Internal (non-signal) transition triggers."""

    INIT_COMPLETE = "init_complete"
    INIT_FAILED = "init_failed"
    SCHEDULED = "scheduled"
    AWAIT = "await"
    WAKE = "wake"
    YIELD = "yield"
    EXIT = "exit"


class ExitReason(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    KILLED = "killed"
    BUDGET_EXCEEDED = "budget_exceeded"
    POLICY_DENIED = "policy_denied"
    TIMEOUT = "timeout"
    PARENT_TERMINATED = "parent_terminated"


class IllegalTransitionError(Exception):
    """A (state, trigger) pair that the process model does not permit."""

    def __init__(self, state: str, trigger: str) -> None:
        super().__init__(f"illegal transition: {trigger!r} from state {state!r}")
        self.state = state
        self.trigger = trigger


class ProcessModelMismatchError(Exception):
    """The Python enums disagree with process-model.json."""


@dataclass(frozen=True)
class ProcessModel:
    version: int
    states: tuple[str, ...]
    initial: str
    terminal: frozenset[str]
    exit_reasons: tuple[str, ...]
    signals: tuple[str, ...]
    transitions: dict[tuple[str, str], str]
    pid_regex: re.Pattern[str]


def _default_path() -> Path:
    override = os.environ.get("AXIS_PROCESS_MODEL_PATH")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[3] / "packages" / "contracts" / "process-model.json"


@lru_cache(maxsize=4)
def load_process_model(path: Path | None = None) -> ProcessModel:
    raw = json.loads((path or _default_path()).read_text(encoding="utf-8"))
    transitions: dict[tuple[str, str], str] = {}
    for t in raw["transitions"]:
        key = (t["from"], t["on"])
        if key in transitions:
            raise ProcessModelMismatchError(f"duplicate transition {key}")
        transitions[key] = t["to"]
    return ProcessModel(
        version=raw["version"],
        states=tuple(raw["states"]),
        initial=raw["initial"],
        terminal=frozenset(raw["terminal"]),
        exit_reasons=tuple(raw["exitReasons"]),
        signals=tuple(raw["signals"].keys()),
        transitions=transitions,
        pid_regex=re.compile(raw["pid"]["regex"]),
    )


def verify_enums(model: ProcessModel) -> None:
    """Raise if the Python enums disagree with ``model`` (run at import and in tests)."""
    triggers = {on for (_, on) in model.transitions}
    internal = triggers - set(model.signals)
    checks = {
        "states": (set(model.states), {s.value for s in ProcessState}),
        "signals": (set(model.signals), {s.value for s in Signal}),
        "exitReasons": (set(model.exit_reasons), {s.value for s in ExitReason}),
        "lifecycle triggers": (internal, {s.value for s in Lifecycle}),
    }
    for name, (from_json, from_py) in checks.items():
        if from_json != from_py:
            raise ProcessModelMismatchError(
                f"{name} differ: json-only={sorted(from_json - from_py)} "
                f"python-only={sorted(from_py - from_json)}"
            )
    if model.initial != ProcessState.SPAWN or model.terminal != {ProcessState.TERMINATED}:
        raise ProcessModelMismatchError("initial/terminal states differ from the enums")


MODEL = load_process_model()
verify_enums(MODEL)
INITIAL_STATE = ProcessState(MODEL.initial)


def is_terminal(state: ProcessState) -> bool:
    return state.value in MODEL.terminal


def next_state(state: ProcessState, trigger: str) -> ProcessState:
    """Return the state reached from ``state`` on ``trigger`` or raise IllegalTransitionError."""
    target = MODEL.transitions.get((str(state), str(trigger)))
    if target is None:
        raise IllegalTransitionError(str(state), str(trigger))
    return ProcessState(target)


def legal_triggers(state: ProcessState) -> frozenset[str]:
    return frozenset(on for (frm, on) in MODEL.transitions if frm == state.value)


def _b32(value: int, length: int) -> str:
    chars = []
    for _ in range(length):
        chars.append(_CROCKFORD[value & 31])
        value >>= 5
    return "".join(reversed(chars))


def new_pid(
    *,
    now_ms: int | None = None,
    randbytes: Callable[[int], bytes] = secrets.token_bytes,
) -> str:
    """``axp_`` + ULID (48-bit ms timestamp, 80 random bits, Crockford base32)."""
    ms = int(time.time() * 1000) if now_ms is None else now_ms
    if not 0 <= ms < 1 << 48:
        raise ValueError("timestamp out of ULID range")
    rand = int.from_bytes(randbytes(10), "big")
    pid = "axp_" + _b32(ms, 10) + _b32(rand, 16)
    if not MODEL.pid_regex.match(pid):  # pragma: no cover - guards the contract regex
        raise ProcessModelMismatchError("generated PID does not match contract regex")
    return pid


def is_valid_pid(value: object) -> bool:
    return isinstance(value, str) and MODEL.pid_regex.match(value) is not None
