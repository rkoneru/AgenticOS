"""Sandbox types, artifact capture, workdir, fail-closed behaviour and CodeRunAction wiring."""

# ruff: noqa: ASYNC240, ASYNC251, ASYNC230, S103, S108
from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from axis_runtime import Decision
from axis_runtime.actions import Backends, CodeRunAction, action_from_spec, to_jsonable
from axis_runtime.executor import Completed, Denied, Failed
from axis_runtime.gate import GateDecision
from axis_runtime.guard import executing
from axis_runtime.sandbox import (
    Artifact,
    SandboxLimits,
    SandboxPolicyError,
    SandboxResult,
    SandboxSpec,
    SandboxUnavailableError,
    sha256_hex,
)
from axis_runtime.sandbox.artifacts import MAX_DEPTH, capture_artifacts, disk_usage
from axis_runtime.sandbox.backends.local import LocalProcessBackend
from axis_runtime.sandbox.workdir import Workdir
from conftest import ScriptedGate
from helpers import PID, Effects, make_executor, recording_backends

# ---- types ---------------------------------------------------------------------------------------


def test_limits_validation_and_ceiling() -> None:
    assert SandboxLimits().wall_seconds > 0
    for bad in (
        {"cpu_seconds": 0},
        {"memory_bytes": -1},
        {"max_open_files": 1.5},
        {"wall_seconds": True},
    ):
        with pytest.raises(ValueError):
            SandboxLimits(**bad)
    with pytest.raises(ValueError, match="unknown"):
        SandboxLimits.from_mapping({"nope": 1})
    assert SandboxLimits.from_mapping(None) == SandboxLimits()
    assert SandboxLimits(cpu_seconds=9).exceeds(SandboxLimits(cpu_seconds=5)) == ["cpu_seconds"]
    assert SandboxLimits().exceeds(SandboxLimits()) == []


def test_spec_validation_and_describe_hides_code() -> None:
    with pytest.raises(SandboxPolicyError, match="language"):
        SandboxSpec("ruby", "x")
    with pytest.raises(SandboxPolicyError, match="large"):
        SandboxSpec("python", "x" * (300 * 1024))
    spec = SandboxSpec("python", "print('PHI-123')")
    d = spec.describe()
    assert "PHI-123" not in json.dumps(d) and "PHI-123" not in repr(spec)
    assert d["code_sha256"] == sha256_hex(b"print('PHI-123')") and d["code_bytes"] == 16
    assert d["network"] is False


def _result(**kw: Any) -> SandboxResult:
    base: dict[str, Any] = dict(
        exit_code=0, stdout="out", stderr="", stdout_truncated=False, stderr_truncated=False,
        stdout_bytes=3, stderr_bytes=0, duration_seconds=0.1,
    )  # fmt: skip
    return SandboxResult(**{**base, **kw})


def test_result_views() -> None:
    r = _result(artifacts=(Artifact("a", 1, sha256_hex(b"x"), b"x"),))
    assert r.ok and not r.truncated
    assert r.to_dict()["artifacts"][0]["content_b64"] == "eA=="
    s = r.audit_summary()
    assert "out" not in {v for k, v in s.items() if isinstance(v, str)}
    assert s["stdout_sha256"] == sha256_hex(b"out") and "stdout" not in s
    assert not _result(killed_reason="wall_timeout").ok and not _result(exit_code=1).ok
    assert _result(stderr_truncated=True).truncated


# ---- artifacts / workdir -------------------------------------------------------------------------


def test_capture_missing_dir_and_depth_and_unreadable(tmp_path: Path) -> None:
    assert capture_artifacts(str(tmp_path / "nope"), SandboxLimits()).artifacts == ()
    d = tmp_path / "o"
    d.mkdir()
    deep = d
    for i in range(MAX_DEPTH + 2):
        deep = deep / f"d{i}"
        deep.mkdir()
    (deep / "x").write_text("x")
    (d / "top").write_text("t")
    cap = capture_artifacts(str(d), SandboxLimits())
    assert [a.path for a in cap.artifacts] == ["top"]
    assert any(s.reason == "too_deep" for s in cap.skipped)


def test_capture_root_symlink_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / "f").write_text("x")
    link = tmp_path / "out"
    link.symlink_to(real)
    assert capture_artifacts(str(link), SandboxLimits()).artifacts == ()  # O_NOFOLLOW on the root


def test_capture_unsafe_names_and_nlink(tmp_path: Path) -> None:
    d = tmp_path / "o"
    d.mkdir()
    (d / "a").write_text("1")
    os.link(d / "a", d / "b")
    (d / "c").write_text("3")
    cap = capture_artifacts(str(d), SandboxLimits())
    assert [a.path for a in cap.artifacts] == ["c"]
    assert {s.reason for s in cap.skipped} == {"hard_link"}


def test_capture_bad_utf8_name(tmp_path: Path) -> None:
    d = tmp_path / "o"
    d.mkdir()
    open(os.path.join(os.fsencode(d), b"bad\xff"), "w").write("x")
    cap = capture_artifacts(str(d), SandboxLimits())
    assert cap.artifacts == () and cap.skipped[0].reason == "bad_name"


def test_disk_usage_counts_files_not_symlink_targets(tmp_path: Path) -> None:
    (tmp_path / "a").write_bytes(b"x" * 100)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b").write_bytes(b"x" * 50)
    big = tmp_path.parent / f"{tmp_path.name}-big"
    big.write_bytes(b"x" * 10_000)
    (tmp_path / "link").symlink_to(big)
    assert disk_usage(str(tmp_path)) == 150
    big.unlink()


def test_workdir_lifecycle_and_wipe_guard(tmp_path: Path) -> None:
    wd = Workdir.create(str(tmp_path), None)
    assert os.path.isdir(wd.out) and stat.S_IMODE(os.stat(wd.root).st_mode) == 0o700
    p = wd.write_code("main.py", b"print(1)", None)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o400
    hostile = Path(wd.root) / "h"
    hostile.mkdir()
    (hostile / "f").write_text("x")
    hostile.chmod(0)
    wd.wipe()
    assert not os.path.exists(wd.root)
    for bad in (Workdir(str(tmp_path), str(tmp_path), str(tmp_path)),
                Workdir("/etc", "/etc/out", "/")):  # fmt: skip
        with pytest.raises(RuntimeError, match="refusing"):
            bad.wipe()
    assert tmp_path.exists()


# ---- fail closed ---------------------------------------------------------------------------------


def _helpers(tmp: Path, *, unshare: str | None) -> str:
    """A helper dir with the real prlimit/setpriv/sh and a FAKE ``unshare``."""
    for name in ("prlimit", "setpriv", "sh"):
        src = next(p for d in ("/usr/bin", "/bin") if os.access(p := f"{d}/{name}", os.X_OK))
        (tmp / name).symlink_to(src)
    if unshare is not None:
        (tmp / "unshare").write_text(unshare)
        (tmp / "unshare").chmod(0o755)
    return str(tmp)


@pytest.fixture
def tmp_path() -> Iterator[Path]:
    """Shadows pytest's 0700 tmp_path: the unprivileged sandbox uid must be able to traverse it."""
    d = Path(tempfile.mkdtemp(prefix="axis-sbx-test-"))
    d.chmod(0o755)
    yield d
    shutil.rmtree(d, ignore_errors=True)


async def test_fails_closed_when_unshare_missing(tmp_path: Path) -> None:
    b = LocalProcessBackend(helper_dirs=[_helpers(tmp_path, unshare=None)])
    with executing(), pytest.raises(SandboxUnavailableError, match="unshare"):
        await b.run(SandboxSpec("python", "print('RAN')"))


async def test_fails_closed_when_namespace_creation_fails(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    b = LocalProcessBackend(
        helper_dirs=[
            _helpers(
                tmp_path, unshare="#!/bin/sh\necho 'unshare: Operation not permitted' >&2\nexit 1\n"
            )
        ]
    )
    code = f"open({str(marker)!r}, 'w').write('x')"
    with (
        executing(),
        pytest.raises(SandboxUnavailableError, match="refusing to run code unisolated"),
    ):
        await b.run(SandboxSpec("python", code))
    assert not marker.exists()
    with pytest.raises(SandboxUnavailableError):
        b.check_isolation()


async def test_fails_closed_when_unshare_silently_does_not_isolate(tmp_path: Path) -> None:
    """A wrapper that strips every flag and just execs the command: no netns, pid != 1."""
    fake = '#!/bin/sh\nwhile [ "$1" != "--" ]; do shift; done\nshift\nexec "$@"\n'
    marker = tmp_path / "ran"
    b = LocalProcessBackend(helper_dirs=[_helpers(tmp_path, unshare=fake)])
    with executing(), pytest.raises(SandboxUnavailableError, match="self-test"):
        await b.run(SandboxSpec("python", f"open({str(marker)!r}, 'w')"))
    assert not marker.exists()


async def test_failed_probe_is_not_cached(tmp_path: Path) -> None:
    helpers = _helpers(tmp_path, unshare="#!/bin/sh\nexit 1\n")
    b = LocalProcessBackend(helper_dirs=[helpers])
    for _ in range(2):
        with pytest.raises(SandboxUnavailableError):
            b.check_isolation()
    real = "/usr/bin/unshare"
    os.unlink(tmp_path / "unshare")
    os.symlink(real, tmp_path / "unshare")
    b.check_isolation()  # now isolation is real: the earlier failure did not stick


def test_run_as_requires_root_or_is_ignored() -> None:
    if os.geteuid() == 0:
        assert LocalProcessBackend(run_as=None)._run_as is None
        assert LocalProcessBackend(run_as=(1234, 1234))._run_as == (1234, 1234)
    else:
        with pytest.raises(SandboxPolicyError):
            LocalProcessBackend(run_as=(1234, 1234))


# ---- CodeRunAction -------------------------------------------------------------------------------

CODE = "print('patient SSN 111-22-3333')"


def _action(**kw: Any) -> CodeRunAction:
    return CodeRunAction(name="py", args={"language": "python", "code": CODE}, **kw)


def test_gate_args_carry_hash_size_limits_network_but_never_the_code() -> None:
    a = _action(timeout_seconds=7, limits={"cpu_seconds": 2})
    g = a.gate_args()
    assert g["language"] == "python" and g["network"] is False
    assert g["code_sha256"] == sha256_hex(CODE.encode()) and g["code_bytes"] == len(CODE)
    assert g["limits"]["wall_seconds"] == 7 and g["limits"]["cpu_seconds"] == 2
    assert "111-22-3333" not in json.dumps(to_jsonable(g))
    assert a.tool_descriptor()["kind"] == "code"
    assert _action(network=True).gate_args()["network"] is True


def test_network_cannot_be_enabled_by_agent_args() -> None:
    a = CodeRunAction(name="py", args={"language": "python", "code": "1", "network": True})
    assert a.gate_args()["network"] is False and a._spec().network is False


def test_invalid_limits_fail_at_construction() -> None:
    with pytest.raises(ValueError):
        _action(limits={"bogus": 1})
    with pytest.raises(SandboxPolicyError):
        CodeRunAction(name="x", args={"language": "cobol", "code": "x"})


def test_spec_roundtrip_and_with_args() -> None:
    a = _action(network=False, limits={"max_artifacts": 3})
    assert action_from_spec(json.loads(json.dumps(a.to_spec()))) == a
    redacted = a.with_args({"language": "python", "code_sha256": "[REDACTED]"})
    assert isinstance(redacted, CodeRunAction) and redacted.args["code"] == CODE
    with pytest.raises(ValueError, match="invalid"):
        redacted.with_args({"language": "[REDACTED]"})


class _Backend:
    def __init__(self, result: Any = None, exc: Exception | None = None) -> None:
        self.specs: list[SandboxSpec] = []
        self.result, self.exc = result, exc

    async def run(self, spec: SandboxSpec) -> Any:
        self.specs.append(spec)
        if self.exc:
            raise self.exc
        return self.result or _result(stdout="SSN 111-22-3333 here", stdout_bytes=20)


async def _exec(gate: Any, backend: Any) -> tuple[Any, Any, Any]:
    ex, rec, effects, g = await make_executor(gate)
    ex._backends = Backends(sandbox=backend)
    return ex, rec, g


async def test_executor_gates_audits_hash_only_and_returns_output() -> None:
    be = _Backend()
    ex, rec, gate = await _exec(ScriptedGate(), be)
    out = await ex.run(_action(), pid=PID)
    assert isinstance(out, Completed) and out.result["stdout"] == "SSN 111-22-3333 here"
    ctx = gate.requests[0].context
    assert ctx["tool"]["kind"] == "code" and ctx["enforcement_point"] == "code_exec"
    assert ctx["args"]["code_sha256"] == sha256_hex(CODE.encode())
    audit = json.dumps(to_jsonable(rec.state.tool_calls)) + json.dumps(ctx)
    assert CODE not in audit and "111-22-3333" not in audit and "patient" not in audit
    assert sha256_hex(b"SSN 111-22-3333 here") in audit
    assert be.specs[0].code == CODE and be.specs[0].network is False


async def test_executor_deny_runs_nothing() -> None:
    be = _Backend()
    ex, rec, _ = await _exec(ScriptedGate(GateDecision(Decision.DENY, "no code")), be)
    assert isinstance(await ex.run(_action(), pid=PID), Denied) and be.specs == []


async def test_network_flag_reaches_the_gate_so_policy_can_deny_it() -> None:
    be = _Backend()
    gate = ScriptedGate(
        lambda r: (
            GateDecision(Decision.DENY, "network_denied")
            if r.context["args"]["network"]
            else GateDecision(Decision.ALLOW, "ok")
        )
    )
    ex, _, _ = await _exec(gate, be)
    assert isinstance(await ex.run(_action(network=True), pid=PID), Denied) and be.specs == []
    assert isinstance(await ex.run(_action(), pid=PID), Completed) and len(be.specs) == 1


async def test_backend_unavailable_is_a_failed_action_not_a_run() -> None:
    be = _Backend(exc=SandboxUnavailableError("no namespaces"))
    ex, rec, _ = await _exec(ScriptedGate(), be)
    out = await ex.run(_action(), pid=PID)
    assert isinstance(out, Failed) and "no namespaces" in out.error
    assert CODE not in json.dumps(to_jsonable(rec.state.tool_calls))


async def test_dict_results_are_summarised_without_text() -> None:
    be = _Backend(
        result={
            "exit_code": 0,
            "stdout": "secret out",
            "artifacts": [{"path": "a", "size": 1, "sha256": "h", "content_b64": "eA=="}],
        }
    )
    ex, rec, _ = await _exec(ScriptedGate(), be)
    await ex.run(_action(), pid=PID)
    audit = json.dumps(to_jsonable(rec.state.tool_calls))
    assert "secret out" not in audit and "content_b64" not in audit and '"path": "a"' in audit


async def test_redaction_decision_does_not_alter_the_code_that_runs() -> None:
    be = _Backend()
    gate = ScriptedGate(
        GateDecision(Decision.ALLOW_WITH_REDACTION, "r", redact_fields=("args.language",))
    )
    ex, _, _ = await _exec(gate, be)
    out = await ex.run(_action(), pid=PID)
    assert isinstance(out, Denied) and out.reason == "redaction_failed"  # nothing ran
    assert be.specs == []
    _ = Effects, recording_backends, tempfile


def test_wipe_error_hook_repairs_unreadable_trees(tmp_path: Path) -> None:
    from axis_runtime.sandbox.workdir import _force

    d = tmp_path / "locked"
    (d / "inner").mkdir(parents=True)
    (d / "inner" / "f").write_text("x")
    d.chmod(0)
    _force(None, str(d), None)
    assert not d.exists()
    f = tmp_path / "file"
    f.write_text("x")
    _force(None, str(f), None)
    assert not f.exists()
    _force(None, str(tmp_path / "missing"), None)  # never raises


def test_safe_relative_rejects_traversal_forms() -> None:
    from axis_runtime.sandbox.artifacts import _safe_relative

    for bad in ("", "/etc/passwd", "..", "a/../b", "./a", "a//b", "a/./b", "a/"):
        assert not _safe_relative(bad), bad
    for good in ("a", "a/b.txt", "dir/.hidden", "a..b"):
        assert _safe_relative(good), good
