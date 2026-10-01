"""LocalProcessBackend against REAL adversarial payloads (no mocks).  These need unprivileged user
namespaces; where they are unavailable the backend must refuse, which test_sandbox_unit covers."""

# ruff: noqa: ASYNC240, ASYNC251, ASYNC230, S103, S108
from __future__ import annotations

import asyncio
import os
import socket
import tempfile
import textwrap
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from axis_runtime.guard import DirectExecutionError, executing
from axis_runtime.sandbox import (
    SandboxLimits,
    SandboxPolicyError,
    SandboxResult,
    SandboxSpec,
    SandboxUnavailableError,
)
from axis_runtime.sandbox.backends.local import LocalProcessBackend

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def backend() -> AsyncIterator[LocalProcessBackend]:
    b = LocalProcessBackend()
    b.check_isolation()  # fails (not skips) if this host cannot isolate
    yield b


def _host_comms() -> list[str]:
    comms = []
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            comms.append(Path(f"/proc/{pid}/comm").read_text().strip())
        except OSError:
            pass
    return comms


async def run(
    b: LocalProcessBackend, code: str, *, language: str = "python", **limits: Any
) -> SandboxResult:
    lim = SandboxLimits(**{"wall_seconds": 10.0, **limits})
    with executing():
        return await b.run(SandboxSpec(language, textwrap.dedent(code), lim))


async def test_hello_world_and_usage(backend: LocalProcessBackend) -> None:
    r = await run(backend, "print('hi')")
    assert r.ok and r.stdout == "hi\n" and r.exit_code == 0 and r.killed_reason is None
    assert r.duration_seconds > 0 and r.usage.max_rss_kib > 0
    assert r.isolation["network_namespace"] is True
    assert r.isolation["hard_security_boundary"] is False


async def test_shell_language(backend: LocalProcessBackend) -> None:
    r = await run(backend, "echo $((6*7)); echo err >&2", language="shell")
    assert r.stdout == "42\n" and r.stderr == "err\n"


async def test_nonzero_exit_reported(backend: LocalProcessBackend) -> None:
    r = await run(backend, "import sys; sys.exit(3)")
    assert r.exit_code == 3 and not r.ok


async def test_direct_use_without_executor_is_refused(backend: LocalProcessBackend) -> None:
    with pytest.raises(DirectExecutionError):
        await backend.run(SandboxSpec("python", "print(1)"))


async def test_environment_is_empty_of_host_secrets(
    backend: LocalProcessBackend, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AXIS_TEST_SECRET", "hunter2-secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret-value")
    r = await run(
        backend,
        """
        import os
        print(sorted(os.environ))
        print(open('/proc/self/environ').read())
        print(open('/proc/1/environ').read())
        """,
    )
    assert "hunter2" not in r.stdout and "aws-secret-value" not in r.stdout
    assert "AXIS_TEST_SECRET" not in r.stdout and "AWS_" not in r.stdout
    first = r.stdout.splitlines()[0]
    assert first == str(sorted(["PATH", "HOME", "TMPDIR", "LANG", "AXIS_OUTPUT_DIR"])), first


async def test_explicit_env_is_passed_but_dangerous_names_refused(
    backend: LocalProcessBackend,
) -> None:
    with executing():
        r = await backend.run(
            SandboxSpec("python", "import os;print(os.environ['FOO'])", env={"FOO": "bar"})
        )
    assert r.stdout == "bar\n"
    for bad in ("LD_PRELOAD", "PYTHONPATH", "PATH", "HOME", "A-B"):
        with pytest.raises(SandboxPolicyError):
            SandboxSpec("python", "1", env={bad: "x"})


async def test_outbound_connect_fails_without_network(backend: LocalProcessBackend) -> None:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        r = await run(
            backend,
            f"""
            import socket
            for host in ("127.0.0.1", "1.1.1.1", "10.0.0.1"):
                s = socket.socket(); s.settimeout(2)
                try:
                    s.connect((host, {port if True else 0}))
                    print("CONNECTED", host)
                except OSError as e:
                    print("blocked", host, e.errno)
            """,
        )
    finally:
        srv.close()
    assert "CONNECTED" not in r.stdout and r.stdout.count("blocked") == 3
    assert srv  # the host listener on loopback is unreachable from the sandbox's own netns


async def test_only_loopback_interface_exists(backend: LocalProcessBackend) -> None:
    r = await run(backend, "print(open('/proc/net/dev').read().count(':'))")
    assert r.stdout.strip() == "1"  # just ``lo`` (one colon per interface line)


async def test_pid_namespace_and_capabilities(backend: LocalProcessBackend) -> None:
    r = await run(
        backend,
        """
        import os
        print(os.getpid())
        print([ln for ln in open('/proc/self/status') if ln.startswith('CapEff')][0].split()[1])
        print(len([p for p in os.listdir('/proc') if p.isdigit()]))
        try:
            os.kill(os.getppid() or 1, 0); print('ppid-visible')
        except OSError: print('no-parent')
        """,
    )
    pid, caps, nprocs, _ = r.stdout.split()
    assert pid == "1" and int(caps, 16) == 0 and int(nprocs) <= 2


async def test_writes_outside_the_workdir_fail(backend: LocalProcessBackend) -> None:
    targets = ["/etc/axis_pwn", "/usr/axis_pwn", "/root/axis_pwn", "/home/axis_pwn"]
    r = await run(
        backend,
        f"""
        import os
        for p in {targets!r}:
            try:
                open(p, 'w').write('x'); print('WROTE', p)
            except OSError as e:
                print('denied', e.errno)
        open('inside.txt', 'w').write('ok'); print('inside ok')
        """,
    )
    assert "WROTE" not in r.stdout and r.stdout.count("denied") == 4 and "inside ok" in r.stdout
    assert not any(os.path.exists(t) for t in targets)
    uid = r.isolation["unprivileged_uid"]  # a root runtime gives every run its own unprivileged uid
    assert (uid is None) == (os.geteuid() != 0) and (uid is None or uid >= 65534)


async def test_cannot_read_root_only_host_files(backend: LocalProcessBackend) -> None:
    r = await run(
        backend,
        """
        for p in ('/root', '/etc/shadow'):
            try:
                import os; os.listdir(p) if p == '/root' else open(p).read(); print('READ', p)
            except OSError as e: print('denied', e.errno)
        """,
    )
    assert "READ" not in r.stdout


async def test_workdir_is_wiped_afterwards(backend: LocalProcessBackend) -> None:
    tmp_path = Path(tempfile.mkdtemp(prefix="axis-test-base-"))
    tmp_path.chmod(0o755)  # the unprivileged sandbox uid must be able to traverse it
    b = LocalProcessBackend(workdir_base=str(tmp_path))
    r = await run(
        b,
        """
        import os
        os.makedirs('d/e'); open('d/e/f', 'w').write('x'); os.chmod('d', 0)
        print(os.getcwd())
        """,
    )
    assert r.ok
    assert os.listdir(tmp_path) == []
    tmp_path.rmdir()


async def test_infinite_loop_is_killed_by_wall_timeout(backend: LocalProcessBackend) -> None:
    t0 = time.monotonic()
    r = await run(backend, "while True: pass", wall_seconds=0.5, cpu_seconds=30)
    assert r.killed_reason == "wall_timeout" and not r.ok
    assert time.monotonic() - t0 < 5


async def test_cpu_limit_kills_busy_loop(backend: LocalProcessBackend) -> None:
    r = await run(backend, "while True: pass", wall_seconds=30, cpu_seconds=1)
    assert r.killed_reason == "cpu_limit" and r.duration_seconds < 10


async def test_memory_hog_is_stopped(backend: LocalProcessBackend) -> None:
    r = await run(
        backend,
        "x = bytearray(900 * 1024 * 1024); print('ALLOCATED')",
        memory_bytes=256 * 1024 * 1024,
    )
    assert "ALLOCATED" not in r.stdout and not r.ok
    assert "MemoryError" in r.stderr


async def test_fork_bomb_is_bounded_and_leaves_nothing_behind(
    backend: LocalProcessBackend,
) -> None:
    r = await run(
        backend,
        """
        import os, time
        n = 0
        try:
            while n < 5000:
                if os.fork() == 0:
                    open('/proc/self/comm', 'w').write('axis-forkbomb'); time.sleep(60); os._exit(0)
                n += 1
        except OSError as e:
            print('forkfail', n, e.errno)
        """,
        max_processes=16,
        wall_seconds=5,
    )
    assert r.stdout.startswith("forkfail"), r.stdout
    assert int(r.stdout.split()[1]) <= 16
    time.sleep(0.3)
    assert "axis-forkbomb" not in _host_comms()  # nothing leaked into the host


async def test_daemonised_grandchild_does_not_outlive_the_run(
    backend: LocalProcessBackend,
) -> None:
    r = await run(
        backend,
        """
        import os, time
        if os.fork() == 0:
            os.setsid(); open('/proc/self/comm','w').write('axis-daemon'); time.sleep(100)
        print('parent done')
        """,
    )
    assert r.ok
    time.sleep(0.3)
    assert "axis-daemon" not in _host_comms()


async def test_huge_stdout_is_capped_and_killed(backend: LocalProcessBackend) -> None:
    r = await run(
        backend,
        "import sys\nwhile True: sys.stdout.write('x' * 100000)",
        max_output_bytes=1024,
        wall_seconds=20,
    )
    assert r.stdout_truncated and len(r.stdout) == 1024
    assert r.killed_reason == "output_limit" and r.stdout_bytes > 1024


async def test_stdout_truncation_flag_without_kill(backend: LocalProcessBackend) -> None:
    r = await run(
        backend,
        "print('a' * 5000)\nimport sys; print('e' * 3000, file=sys.stderr)",
        max_output_bytes=2000,
    )
    assert r.stdout_truncated and r.stderr_truncated and r.truncated
    assert len(r.stdout) == 2000 and len(r.stderr) == 2000 and r.stdout_bytes == 5001
    assert r.killed_reason is None and r.exit_code == 0


async def test_file_size_limit(backend: LocalProcessBackend) -> None:
    r = await run(
        backend,
        """
        try:
            open('big', 'wb').write(b'x' * 5_000_000); print('WROTE')
        except OSError as e: print('efbig', e.errno)
        """,
        max_file_bytes=100_000,
    )
    assert "WROTE" not in r.stdout and "efbig" in r.stdout


async def test_disk_limit_kills_many_small_files(backend: LocalProcessBackend) -> None:
    r = await run(
        backend,
        """
        import time
        i = 0
        while True:
            open(f'f{i}', 'wb').write(b'x' * 60000); i += 1; time.sleep(0.002)
        """,
        max_file_bytes=100_000,
        max_disk_bytes=300_000,
        wall_seconds=20,
    )
    assert r.killed_reason == "disk_limit"


async def test_open_files_limit(backend: LocalProcessBackend) -> None:
    r = await run(
        backend,
        """
        fs = []
        try:
            while True: fs.append(open('/dev/null'))
        except OSError as e: print('emfile', len(fs), e.errno)
        """,
        max_open_files=32,
    )
    assert r.stdout.startswith("emfile") and int(r.stdout.split()[1]) < 32


async def test_core_dumps_disabled(backend: LocalProcessBackend) -> None:
    r = await run(backend, "import resource; print(resource.getrlimit(resource.RLIMIT_CORE))")
    assert r.stdout.strip() == "(0, 0)"


async def test_limits_are_applied_inside_the_sandbox(backend: LocalProcessBackend) -> None:
    r = await run(
        backend,
        """
        import resource as r
        for n in ('CPU', 'AS', 'NOFILE', 'NPROC', 'FSIZE'):
            print(n, r.getrlimit(getattr(r, 'RLIMIT_' + n)))
        """,
        cpu_seconds=3,
        memory_bytes=300 * 1024 * 1024,
        max_open_files=40,
        max_processes=20,
        max_file_bytes=12345,
    )
    got = {ln.split()[0]: ln.split(" ", 1)[1] for ln in r.stdout.splitlines()}
    assert got["CPU"] == "(3, 4)"
    assert got["AS"] == f"({300 * 1024 * 1024}, {300 * 1024 * 1024})"
    assert got["NOFILE"] == "(40, 40)" and got["NPROC"] == "(20, 20)"
    assert got["FSIZE"] == "(12345, 12345)"


# ---- artifacts -------------------------------------------------------------------------------------


async def test_artifacts_captured_with_hashes(backend: LocalProcessBackend) -> None:
    r = await run(
        backend,
        """
        import os
        out = os.environ['AXIS_OUTPUT_DIR']
        os.makedirs(out + '/sub'); open(out + '/a.txt', 'w').write('alpha')
        open(out + '/sub/b.bin', 'wb').write(b'\\x00\\x01')
        open('not_an_artifact.txt', 'w').write('x')
        """,
    )
    import hashlib

    got = {a.path: a for a in r.artifacts}
    assert set(got) == {"a.txt", "sub/b.bin"}
    assert got["a.txt"].content == b"alpha"
    assert got["a.txt"].sha256 == hashlib.sha256(b"alpha").hexdigest()
    d = r.to_dict()
    assert d["artifacts"][0]["content_b64"]
    assert "content" not in str(r.audit_summary()["artifacts"])


async def test_symlink_escape_in_artifacts_is_not_followed(
    backend: LocalProcessBackend, tmp_path: Any
) -> None:
    secret = tmp_path / "host_secret.txt"
    secret.write_text("TOP-SECRET-HOST-DATA")
    secret.chmod(0o644)
    os.chmod(tmp_path, 0o755)
    r = await run(
        backend,
        f"""
        import os
        out = os.environ['AXIS_OUTPUT_DIR']
        os.symlink({str(secret)!r}, out + '/link.txt')
        os.symlink('/etc', out + '/etc_dir')
        os.symlink('..', out + '/up')
        open(out + '/ok.txt', 'w').write('fine')
        """,
    )
    assert [a.path for a in r.artifacts] == ["ok.txt"]
    reasons = {s.path: s.reason for s in r.skipped_artifacts}
    assert reasons == {"link.txt": "symlink", "etc_dir": "symlink", "up": "symlink"}
    assert "TOP-SECRET" not in str(r.to_dict())


async def test_fifo_and_hardlink_artifacts_are_skipped(backend: LocalProcessBackend) -> None:
    r = await run(
        backend,
        """
        import os
        out = os.environ['AXIS_OUTPUT_DIR']
        os.mkfifo(out + '/pipe')
        open(out + '/real', 'w').write('x'); os.link(out + '/real', out + '/real2')
        """,
    )
    assert r.artifacts == ()
    assert {s.reason for s in r.skipped_artifacts} == {"not_regular_file", "hard_link"}


async def test_artifact_path_traversal_names_never_escape(
    backend: LocalProcessBackend, tmp_path: Any
) -> None:
    r = await run(
        backend,
        """
        import os
        out = os.environ['AXIS_OUTPUT_DIR']
        for name in ('..%2f..%2fescape', '..', 'a\\\\..\\\\b'):
            try: open(out + '/' + name, 'w').write('x')
            except OSError: pass
        try: open(out + '/../escape.txt', 'w').write('x')
        except OSError: pass
        os.makedirs(out + '/d')
        open(out + '/d/../in_out.txt', 'w').write('x')
        """,
    )
    for a in r.artifacts:
        assert ".." not in a.path.split("/") and not a.path.startswith("/")
    assert not os.path.exists("/tmp/escape.txt")


async def test_artifact_caps_count_size_total(backend: LocalProcessBackend) -> None:
    r = await run(
        backend,
        """
        import os
        out = os.environ['AXIS_OUTPUT_DIR']
        for i in range(6):
            open(f'{out}/f{i}', 'wb').write(b'x' * 400)
        open(out + '/huge', 'wb').write(b'x' * 5000)
        """,
        max_artifacts=4,
        max_artifact_bytes=1000,
        max_artifacts_total_bytes=1500,
    )
    assert len(r.artifacts) == 3 and sum(a.size for a in r.artifacts) == 1200
    reasons = {s.path: s.reason for s in r.skipped_artifacts}
    assert reasons["huge"] == "too_large"
    assert "total_size_exceeded" in reasons.values()


async def test_zip_bomb_like_artifact_never_read_into_memory(backend: LocalProcessBackend) -> None:
    r = await run(
        backend,
        """
        import os
        out = os.environ['AXIS_OUTPUT_DIR']
        with open(out + '/sparse.bin', 'wb') as f:
            f.seek(7_000_000); f.write(b'x')        # 7 MB logical size, almost no blocks
        """,
        max_artifact_bytes=100_000,
    )
    assert r.artifacts == () and r.skipped_artifacts[0].reason == "too_large"


async def test_artifact_flood_is_bounded(backend: LocalProcessBackend) -> None:
    r = await run(
        backend,
        """
        import os
        out = os.environ['AXIS_OUTPUT_DIR']
        for i in range(2600):
            open(f'{out}/{i}', 'w').close()
        """,
        max_artifacts=10,
        max_open_files=64,
    )
    assert len(r.artifacts) == 10
    assert any(s.reason == "entry_limit" for s in r.skipped_artifacts)


# ---- policy / network ------------------------------------------------------------------------------


async def test_network_requires_backend_opt_in(backend: LocalProcessBackend) -> None:
    with executing(), pytest.raises(SandboxPolicyError, match="network"):
        await backend.run(SandboxSpec("python", "print(1)", network=True))


async def test_network_allowed_only_when_backend_and_spec_agree() -> None:
    b = LocalProcessBackend(allow_network=True)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        code = f"import socket; socket.create_connection(('127.0.0.1', {port}), timeout=2); print('ok')"
        with executing():
            r = await b.run(SandboxSpec("python", code, network=True))
            denied = await b.run(SandboxSpec("python", code, network=False))
    finally:
        srv.close()
    assert r.stdout == "ok\n" and r.isolation["network_namespace"] is False
    assert denied.stdout == "" and denied.exit_code == 1  # same code, default spec: blocked


async def test_limits_over_backend_ceiling_rejected(backend: LocalProcessBackend) -> None:
    with executing(), pytest.raises(SandboxPolicyError, match="ceiling"):
        await backend.run(SandboxSpec("python", "1", SandboxLimits(wall_seconds=3600)))


async def test_cancellation_kills_the_run(backend: LocalProcessBackend) -> None:
    import asyncio

    async def go() -> None:
        with executing():
            await backend.run(
                SandboxSpec("python", "import time; time.sleep(60)", SandboxLimits(wall_seconds=30))
            )

    task = asyncio.create_task(go())
    await asyncio.sleep(0.5)
    t0 = time.monotonic()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert time.monotonic() - t0 < 5


async def test_unusable_interpreter_fails_closed() -> None:
    b = LocalProcessBackend(python="/nonexistent/python")
    with executing(), pytest.raises(SandboxUnavailableError):
        await b.run(SandboxSpec("python", "print(1)"))


# ---- Phase 4 review: simultaneous runs must not see or tamper with each other's working directories --------


async def test_a_concurrent_run_cannot_read_or_tamper_with_another_runs_workdir(
    backend: LocalProcessBackend,
) -> None:
    """Every run used the same uid (nobody), so the workdir's 0700 protected nothing between two
    simultaneous runs (two tenants): B could list /tmp, read A's code file and output, and plant files
    in A's output directory (forged artifacts). Each run now gets its own uid."""
    victim = """
        import os, time
        out = os.environ['AXIS_OUTPUT_DIR']
        open(out + '/secret.txt', 'w').write('tenant-a-secret')
        time.sleep(3)
        print(sorted(os.listdir(out)))
    """
    attacker = """
        import glob, os, time
        time.sleep(1)
        seen = []
        for d in glob.glob('/tmp/axis-sbx-*'):
            if d == os.environ['AXIS_OUTPUT_DIR'].rsplit('/', 1)[0]:
                continue
            try:
                seen.append(open(d + '/out/secret.txt').read())
                open(d + '/out/forged.txt', 'w').write('forged')
            except OSError as e:
                seen.append('blocked:' + type(e).__name__)
        print(seen)
    """
    a, b = await asyncio.gather(
        run(backend, victim, wall_seconds=10.0), run(backend, attacker, wall_seconds=10.0)
    )
    assert "tenant-a-secret" not in b.stdout, b.stdout
    assert "forged.txt" not in a.stdout, a.stdout
    assert [x.path for x in a.artifacts] == ["secret.txt"]
