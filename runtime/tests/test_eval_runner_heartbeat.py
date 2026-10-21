"""NEEDS #508: runtime/scripts/eval_runner.py's heartbeat liveness surface, and the exact exec
liveness-probe command infra/helm/charts/runtime wires to it. Loaded via importlib (the script
lives outside the axis_runtime package on purpose, see its own module docstring) so this is a real
test of the actual deployed file, not a reimplementation of its logic.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import time
from pathlib import Path
from typing import Any

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "eval_runner.py"

# The exact command infra/helm/charts/runtime's eval-runner Deployment wires as its exec liveness
# probe (NEEDS #508): "the heartbeat file's mtime is recent". `find -mmin -2` with no matching
# output test -z's to failure; with a match, test -n's to success. Kept here as a single source of
# truth the chart's own comment points back to, and executed for real below (not just asserted).
PROBE_CMD = 'test -n "$(find {path} -mmin -2 2>/dev/null)"'


def _load_eval_runner() -> Any:
    spec = importlib.util.spec_from_file_location("eval_runner_under_test", _SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_heartbeat_returns_none_when_unconfigured() -> None:
    mod = _load_eval_runner()
    assert mod._heartbeat(None) is None
    assert mod._heartbeat("") is None


def test_heartbeat_touch_writes_the_current_time(tmp_path: Path) -> None:
    mod = _load_eval_runner()
    path = tmp_path / "heartbeat"
    touch = mod._heartbeat(str(path))
    assert touch is not None
    before = time.time()
    touch()
    assert path.exists()
    assert abs(float(path.read_text()) - before) < 5
    # A second call overwrites (not appends): every iteration's heartbeat replaces the last.
    touch()
    assert len(path.read_text().splitlines()) == 1


def test_heartbeat_write_failure_does_not_raise(tmp_path: Path) -> None:
    mod = _load_eval_runner()
    # A directory where a file write is expected: OSError (IsADirectoryError), caught and logged,
    # never propagated — a broken heartbeat mechanism must never crash the poll loop itself.
    touch = mod._heartbeat(str(tmp_path))
    assert touch is not None
    touch()  # must not raise


def test_probe_command_passes_on_a_fresh_heartbeat_and_fails_on_a_stale_one(
    tmp_path: Path,
) -> None:
    """Exercises the real probe COMMAND (the exact string the chart runs as `exec`), not the
    Python side: proves a fresh file passes and an old one actually fails the shell check."""
    path = tmp_path / "heartbeat"
    path.write_text("1")
    fresh = subprocess.run(  # noqa: S603
        ["/bin/sh", "-c", PROBE_CMD.format(path=path)],
        check=False,  # noqa: S607
    )
    assert fresh.returncode == 0, "a just-written heartbeat file must pass the liveness probe"

    old = time.time() - 180  # 3 minutes ago: older than the probe's 2-minute window
    os.utime(path, (old, old))
    stale = subprocess.run(  # noqa: S603
        ["/bin/sh", "-c", PROBE_CMD.format(path=path)],
        check=False,  # noqa: S607
    )
    assert stale.returncode != 0, "a stale heartbeat file must fail the liveness probe"


def test_probe_command_fails_when_the_file_is_missing(tmp_path: Path) -> None:
    missing = tmp_path / "never-written"
    result = subprocess.run(  # noqa: S603
        ["/bin/sh", "-c", PROBE_CMD.format(path=missing)],
        check=False,  # noqa: S607
    )
    assert result.returncode != 0
