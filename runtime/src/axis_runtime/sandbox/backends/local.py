"""LocalProcessBackend: process-level isolation with primitives available WITHOUT a container
daemon.  It is NOT a hard security boundary (docs/spec/sandbox.md): the kernel is shared and there
is no seccomp filter.  What it does provide, per run:

* a fresh session / process group, an EMPTY environment (no host variables), a private working
  directory that is wiped afterwards, stdin closed;
* the kernel runs the code as an unprivileged uid (``nobody``) when the runtime is root, so writes
  outside the working directory fail on ordinary file permissions;
* ``prlimit`` rlimits: CPU, address space, open files, processes, file size, core=0;
* user + pid + mount (+ NETWORK unless explicitly allowed) namespaces via ``unshare``, all
  capabilities dropped and ``no_new_privs`` set via ``setpriv``;
* a wall-clock timeout, an output-size kill, a working-directory size poll, process-group kill and
  ``--kill-child`` so nothing outlives the run.

FAIL CLOSED: no namespace support, a missing helper binary or a failed self-test means the code is
NOT run (``SandboxUnavailableError``); the backend never falls back to an unisolated run.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import selectors
import signal
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from axis_runtime.guard import DirectExecutionError, in_executor
from axis_runtime.sandbox.artifacts import capture_artifacts, disk_usage
from axis_runtime.sandbox.types import (
    ResourceUsage,
    SandboxError,
    SandboxLimits,
    SandboxPolicyError,
    SandboxResult,
    SandboxSpec,
    SandboxUnavailableError,
)
from axis_runtime.sandbox.workdir import Workdir

NOBODY = 65534
#: Runs under ``run_as="auto"`` (root runtime) each get their OWN uid from this range, so two
#: simultaneous runs (two tenants) cannot read or tamper with each other's working directory: with
#: one shared uid the workdir's 0700 protected nothing between them.
_UID_MIN, _UID_MAX = 1 << 17, (1 << 31) - 1
_uids_in_use: set[int] = set()
_uid_lock = threading.Lock()
_BIN_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")
_OUTPUT_KILL_FACTOR = 32  #: kill when a stream exceeds this many times ``max_output_bytes``
_POLL = 0.05

_PROBE_CODE = (
    "import json, os\n"
    "ifaces = [ln.split(':')[0].strip() for ln in open('/proc/net/dev').read().splitlines()[2:]]\n"
    "cap = [ln for ln in open('/proc/self/status') if ln.startswith('CapEff')][0].split()[1]\n"
    "print(json.dumps({'pid': os.getpid(), 'ifaces': ifaces, 'cap_eff': cap}))\n"
)


@dataclass(frozen=True)
class _Tools:
    prlimit: str
    unshare: str
    setpriv: str
    python: str
    sh: str


def _find(name: str) -> str | None:
    for d in _BIN_DIRS:
        p = os.path.join(d, name)
        if os.access(p, os.X_OK):
            return p
    return None


def _status_signal(status: int) -> tuple[int | None, str | None]:
    if os.WIFSIGNALED(status):
        sig = os.WTERMSIG(status)
        return None, signal.Signals(sig).name
    return os.WEXITSTATUS(status), None


def _killed_reason(sig_name: str | None) -> str | None:
    if sig_name is None:
        return None
    return {"SIGXCPU": "cpu_limit", "SIGXFSZ": "file_size_limit", "SIGKILL": "killed"}.get(
        sig_name, f"signal:{sig_name}"
    )


class LocalProcessBackend:
    """See module docstring.  ``run`` only works inside an ActionExecutor-performed action."""

    def __init__(
        self,
        *,
        allow_network: bool = False,
        python: str = "/usr/bin/python3",
        workdir_base: str | None = None,
        run_as: tuple[int, int] | None | str = "auto",
        max_limits: SandboxLimits | None = None,
        helper_dirs: Sequence[str] | None = None,
    ) -> None:
        self._allow_network = allow_network
        self._python = python
        self._base = workdir_base
        self._per_run_uid = run_as == "auto" and os.geteuid() == 0
        if run_as == "auto":
            self._run_as: tuple[int, int] | None = (NOBODY, NOBODY) if os.geteuid() == 0 else None
        elif isinstance(run_as, tuple):
            if os.geteuid() != 0:
                raise SandboxPolicyError("run_as needs a root runtime (cannot setuid otherwise)")
            self._run_as = run_as
        else:
            self._run_as = None
        self._max = max_limits or SandboxLimits(
            wall_seconds=60,
            cpu_seconds=60,
            memory_bytes=2 * 1024**3,
            max_open_files=256,
            max_processes=128,
            max_file_bytes=64 * 1024**2,
            max_disk_bytes=256 * 1024**2,
            max_output_bytes=1024**2,
            max_artifacts=64,
            max_artifact_bytes=8 * 1024**2,
            max_artifacts_total_bytes=32 * 1024**2,
        )
        self._helper_dirs = tuple(helper_dirs) if helper_dirs is not None else None
        self._probed = False
        self._probe_lock = threading.Lock()

    # ---- public --------------------------------------------------------------------------------
    async def run(self, spec: SandboxSpec) -> SandboxResult:
        if not in_executor():
            raise DirectExecutionError(
                "the sandbox can only run code through ActionExecutor (CodeRunAction)"
            )
        over = spec.limits.exceeds(self._max)
        if over:
            raise SandboxPolicyError(f"limits exceed this backend's ceiling: {sorted(over)}")
        if spec.network and not self._allow_network:
            raise SandboxPolicyError("network access is not enabled on this sandbox backend")
        cancel = threading.Event()
        loop = asyncio.get_running_loop()
        fut = loop.run_in_executor(None, self._run_blocking, spec, cancel)
        try:
            return await asyncio.shield(fut)
        except asyncio.CancelledError:
            cancel.set()
            try:
                await fut
            except Exception:  # noqa: S110 - the run is being cancelled; its result is moot
                pass
            raise

    def check_isolation(self) -> None:
        """Run the self-test now.  Raises ``SandboxUnavailableError`` if isolation is not real."""
        self._ensure_probed()

    # ---- internals -----------------------------------------------------------------------------
    def _tools(self) -> _Tools:
        def locate(name: str) -> str:
            found = (
                next(
                    (
                        os.path.join(d, name)
                        for d in self._helper_dirs
                        if os.access(os.path.join(d, name), os.X_OK)
                    ),
                    None,
                )
                if self._helper_dirs is not None
                else _find(name)
            )
            if found is None:
                raise SandboxUnavailableError(
                    f"required helper {name!r} not found; refusing to run code unisolated"
                )
            return found

        for p in (self._python,):
            if not os.access(p, os.X_OK):
                raise SandboxUnavailableError(f"interpreter {p!r} is not executable")
        return _Tools(
            locate("prlimit"), locate("unshare"), locate("setpriv"), self._python, locate("sh")
        )

    def _command(self, tools: _Tools, spec: SandboxSpec, entry: str) -> list[str]:
        lim = spec.limits
        interp = (
            [tools.python, "-I", "-B", entry] if spec.language == "python" else [tools.sh, entry]
        )
        return [
            tools.prlimit,
            f"--cpu={lim.cpu_seconds}:{lim.cpu_seconds + 1}",
            f"--as={lim.memory_bytes}",
            f"--nofile={lim.max_open_files}",
            f"--nproc={lim.max_processes}",
            f"--fsize={lim.max_file_bytes}",
            "--core=0",
            "--",
            tools.unshare,
            "--user",
            "--map-root-user",
            *([] if spec.network else ["--net"]),
            "--pid",
            "--mount",
            "--fork",
            "--kill-child",
            "--mount-proc",
            "--",
            tools.setpriv,
            "--no-new-privs",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--",
            *interp,
        ]

    def _ensure_probed(self) -> None:
        with self._probe_lock:
            if self._probed:
                return
            probe = SandboxSpec(
                "python",
                _PROBE_CODE,
                SandboxLimits(wall_seconds=10, cpu_seconds=5),
                network=False,
            )
            try:
                res = self._run_once(probe, threading.Event())
            except SandboxUnavailableError:
                raise
            except SandboxError as exc:
                raise SandboxUnavailableError(f"isolation self-test could not run: {exc}") from exc
            try:
                info = json.loads(res.stdout)
                ok = (
                    res.exit_code == 0
                    and info["pid"] == 1
                    and info["ifaces"] == ["lo"]
                    and int(info["cap_eff"], 16) == 0
                )
            except (ValueError, KeyError, TypeError):
                ok = False
            if not ok:
                raise SandboxUnavailableError(
                    "cannot create user+net+pid+mount namespaces here (isolation self-test "
                    f"failed: exit={res.exit_code} stderr={res.stderr[:200]!r}); "
                    "refusing to run code unisolated"
                )
            self._probed = True

    def _run_blocking(self, spec: SandboxSpec, cancel: threading.Event) -> SandboxResult:
        self._ensure_probed()
        return self._run_once(spec, cancel)

    @staticmethod
    def _lease_uid() -> int:
        with _uid_lock:
            while True:
                uid = _UID_MIN + secrets.randbelow(_UID_MAX - _UID_MIN)
                if uid not in _uids_in_use:
                    _uids_in_use.add(uid)
                    return uid

    def _run_once(self, spec: SandboxSpec, cancel: threading.Event) -> SandboxResult:
        leased = self._lease_uid() if self._per_run_uid else None
        try:
            return self._run_as_uid(spec, cancel, (leased, leased) if leased else self._run_as)
        finally:
            if leased is not None:
                with _uid_lock:
                    _uids_in_use.discard(leased)

    def _run_as_uid(
        self, spec: SandboxSpec, cancel: threading.Event, run_as: tuple[int, int] | None
    ) -> SandboxResult:
        tools = self._tools()
        wd = Workdir.create(self._base, run_as)
        try:
            entry = wd.write_code(
                "main.py" if spec.language == "python" else "main.sh",
                spec.code.encode(),
                run_as,
            )
            cmd = self._command(tools, spec, entry)
            env: dict[str, str] = {
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "HOME": wd.root,
                "TMPDIR": wd.root,
                "LANG": "C.UTF-8",
                "AXIS_OUTPUT_DIR": wd.out,
                **spec.env,
            }
            kwargs: dict[str, Any] = {}
            if run_as is not None:
                kwargs = {"user": run_as[0], "group": run_as[1], "extra_groups": []}
            try:
                proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell, cleared env
                    cmd,
                    cwd=wd.root,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                    close_fds=True,
                    umask=0o077,
                    **kwargs,
                )
            except OSError as exc:
                raise SandboxUnavailableError(f"cannot start sandbox process: {exc}") from exc
            return self._supervise(proc, spec, wd, cancel, run_as)
        finally:
            wd.wipe()

    def _supervise(
        self,
        proc: subprocess.Popen[bytes],
        spec: SandboxSpec,
        wd: Workdir,
        cancel: threading.Event,
        run_as: tuple[int, int] | None,
    ) -> SandboxResult:
        lim = spec.limits
        started = time.monotonic()
        deadline = started + lim.wall_seconds
        pgid = proc.pid  # start_new_session made the child its own group leader
        assert proc.stdout is not None and proc.stderr is not None  # noqa: S101
        streams = {"out": proc.stdout.fileno(), "err": proc.stderr.fileno()}
        bufs = {"out": bytearray(), "err": bytearray()}
        totals = {"out": 0, "err": 0}
        sel = selectors.DefaultSelector()
        for name, fd in streams.items():
            os.set_blocking(fd, False)
            sel.register(fd, selectors.EVENT_READ, name)

        def pump(fd: int, name: str) -> bool:
            """Read what is available; False at EOF."""
            try:
                data = os.read(fd, 65536)
            except BlockingIOError:
                return True
            except OSError:
                return False
            if not data:
                return False
            totals[name] += len(data)
            room = lim.max_output_bytes - len(bufs[name])
            if room > 0:
                bufs[name] += data[:room]
            return True

        reason: str | None = None
        status: int | None = None
        rusage: Any = None
        next_disk = started + 0.1
        try:
            while status is None:
                for key, _ in sel.select(_POLL):
                    if not pump(key.fd, key.data):
                        sel.unregister(key.fd)
                done = os.wait4(proc.pid, os.WNOHANG)
                if done[0] == proc.pid:
                    status, rusage = done[1], done[2]
                    break
                now = time.monotonic()
                if cancel.is_set():
                    reason = "cancelled"
                elif now > deadline:
                    reason = "wall_timeout"
                elif max(totals.values()) > lim.max_output_bytes * _OUTPUT_KILL_FACTOR:
                    reason = "output_limit"
                elif now >= next_disk:
                    next_disk = now + 0.2
                    if disk_usage(wd.root) > lim.max_disk_bytes:
                        reason = "disk_limit"
                if reason is not None:
                    self._kill_group(pgid)
                    _, status, rusage = os.wait4(proc.pid, 0)
                    break
        finally:
            self._kill_group(pgid)  # stragglers (daemonised grandchildren) never outlive the run
            if status is None:  # an exception escaped the loop: reap, never leave a zombie
                try:
                    _, status, rusage = os.wait4(proc.pid, 0)
                except ChildProcessError:
                    status = 0
            proc.returncode = 0
        for key_fd, name in ((streams["out"], "out"), (streams["err"], "err")):
            for _ in range(64):  # drain what is already in the pipe (bounded)
                if not pump(key_fd, name):
                    break
        sel.close()
        proc.stdout.close()
        proc.stderr.close()
        duration = time.monotonic() - started
        exit_code, sig_name = _status_signal(status)
        cpu_total = rusage.ru_utime + rusage.ru_stime
        if reason is None:
            reason = _killed_reason(sig_name)
        if reason is None and exit_code != 0 and cpu_total >= lim.cpu_seconds:
            # Over RLIMIT_CPU the kernel kills the interpreter with SIGXCPU, but ``unshare`` then
            # fails to re-raise it and exits 1: classify by CPU time consumed instead.
            reason = "cpu_limit"
        captured = capture_artifacts(wd.out, lim)
        iso: Mapping[str, Any] = {
            "backend": "local-process",
            "user_namespace": True,
            "pid_namespace": True,
            "mount_namespace": True,
            "network_namespace": not spec.network,
            "network": spec.network,
            "capabilities_dropped": True,
            "no_new_privs": True,
            "unprivileged_uid": run_as[0] if run_as else None,
            "uid_per_run": self._per_run_uid,
            "rlimits": True,
            "filesystem_read_isolated": False,
            "hard_security_boundary": False,
        }
        return SandboxResult(
            exit_code=exit_code,
            stdout=bytes(bufs["out"]).decode("utf-8", "replace"),
            stderr=bytes(bufs["err"]).decode("utf-8", "replace"),
            stdout_truncated=totals["out"] > lim.max_output_bytes,
            stderr_truncated=totals["err"] > lim.max_output_bytes,
            stdout_bytes=totals["out"],
            stderr_bytes=totals["err"],
            duration_seconds=duration,
            usage=ResourceUsage(
                cpu_user_seconds=round(rusage.ru_utime, 4),
                cpu_system_seconds=round(rusage.ru_stime, 4),
                max_rss_kib=int(rusage.ru_maxrss),
            ),
            artifacts=captured.artifacts,
            skipped_artifacts=captured.skipped,
            killed_reason=reason,
            signal=sig_name,
            isolation=iso,
        )

    @staticmethod
    def _kill_group(pgid: int) -> None:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
