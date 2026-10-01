# Code sandbox (Phase 4, component C)

Status: **Prototype** (process-level isolation, tested on one Linux kernel). Not a hard security boundary.

> **Honest label: process-level isolation, not a hard security boundary.** `LocalProcessBackend`
> shares the host kernel, has no seccomp filter and does not hide the host filesystem from reads.
> It narrows what accidental or lazy untrusted code can do; it is not evidence that a determined
> attacker cannot escape. A container/gVisor/Firecracker backend is recorded as NEEDS #89-#91
> (ADR-0005 stays the target). Do not run hostile multi-tenant code on it in production.

## Interfaces (`runtime/src/axis_runtime/sandbox/`)

- `SandboxBackend.run(SandboxSpec) -> SandboxResult` (protocol; any backend must fail closed).
- `SandboxSpec`: `language` (`python`, `shell`), `code` (never logged), `limits`, `network` (default
  `False`), `env` (extra variables; `LD_*`, `PYTHON*`, `PATH`, `HOME`, `TMPDIR` refused).
- `SandboxLimits`: wall seconds, CPU seconds, address space, open files, processes, max file size, max
  working-dir bytes, per-stream output cap, artifact count / per-artifact bytes / total bytes.
- `SandboxResult`: exit code (None if signalled), stdout/stderr (capped, `*_truncated`, total byte
  counts), duration, `usage` (CPU user/system, max RSS from `wait4`), `artifacts` (path, size,
  sha256, bytes), `skipped_artifacts` (path, reason), `killed_reason`, `signal`, and an `isolation`
  map stating what protections this run actually had.
- `CodeRunAction` (`actions.py`, enforcement point `code_exec`, `tool.kind="code"`): the only way
  agent code reaches a backend. It replaced the Phase 2 `CodeExec` placeholder.

## Run-loop wiring (Phase 4 / E)

A manifest tool `{kind: code}` becomes `CodeRunAction` with a fixed model-facing schema (`language: python|shell`, `code`); the
host supplies the backend in `Backends.sandbox`. `network` stays wiring. The e2e runs real Python in `LocalProcessBackend`
(`make e2e-phase4` calls `check_isolation()` first and FAILS on a host that cannot isolate: it never skips and never runs code
unisolated), shows an outbound connect to a local site failing inside the sandbox while the site sees no request from it, and policy
denies shell, `network=true` (driven straight at the executor because no agent can set it) and PHI agents. The event log keeps the
`isolation` map, usage and duration (they were being dropped on the dict path until the e2e noticed, ADR 0014).

## Gate and audit contract

The gate request's `args` document is `{language, code_sha256, code_bytes, limits, network}`. The code
text is **not** in the gate request, the `tool_call_result` event or any failure message; the result
event carries exit code, stdout/stderr SHA-256 and byte counts, artifact `{path,size,sha256}`,
usage, killed reason and the isolation map. The agent itself receives the full stdout/stderr and
artifact bytes (base64) as the action result. (Temporal activity payloads from `to_spec()` still
carry the code; Temporal history is therefore as sensitive as the tool arguments of any other action.)

`network` is wiring, not an agent argument: an agent's `args` cannot set it. A policy can DENY on
`args.network`; independently the backend refuses `network=True` unless constructed with
`allow_network=True`. Two locks, neither on by default.

Redaction decisions only touch the gate document (metadata); they can never change the code that
runs. If a redaction makes the action invalid it is blocked (`redaction_failed`).

`LocalProcessBackend.run` raises `DirectExecutionError` outside `ActionExecutor` (same tripwire as
the ModelGateway).

## What `LocalProcessBackend` does

Per run, in a fresh `main.py`/`main.sh` inside a private `0700` temp directory that is wiped after:

| Control       | Mechanism                                                                                                                                                                                                                                                                                                                                                                     |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| process group | `start_new_session`; whole group SIGKILLed at the end, on timeout and on cancel                                                                                                                                                                                                                                                                                               |
| environment   | cleared: only `PATH`, `HOME`, `TMPDIR`, `LANG`, `AXIS_OUTPUT_DIR` + validated `spec.env`                                                                                                                                                                                                                                                                                      |
| uid           | when the runtime is root, each run gets its OWN unprivileged uid (leased from 2^17..2^31, no supplementary groups; `isolation.uid_per_run`), so writes outside the workdir fail on file permissions and simultaneous runs (two tenants) cannot read or tamper with each other's 0700 workdir; non-root runtimes cannot drop (reported in `isolation.unprivileged_uid = null`) |
| rlimits       | `prlimit`: CPU (soft N, hard N+1), AS, NOFILE, NPROC, FSIZE, `CORE=0`                                                                                                                                                                                                                                                                                                         |
| namespaces    | `unshare --user --map-root-user --net --pid --mount --fork --kill-child --mount-proc`                                                                                                                                                                                                                                                                                         |
| privileges    | `setpriv --no-new-privs --bounding-set=-all --inh-caps=-all` (zero effective capabilities inside the namespaces)                                                                                                                                                                                                                                                              |
| wall timeout  | supervisor deadline, `killed_reason="wall_timeout"`                                                                                                                                                                                                                                                                                                                           |
| output        | each stream kept up to `max_output_bytes`; the process is killed at 32x that (`output_limit`)                                                                                                                                                                                                                                                                                 |
| disk          | working directory size polled every 200 ms, killed at `max_disk_bytes` (`disk_limit`)                                                                                                                                                                                                                                                                                         |
| stdin         | `/dev/null`                                                                                                                                                                                                                                                                                                                                                                   |
| artifacts     | only `$AXIS_OUTPUT_DIR`; see below                                                                                                                                                                                                                                                                                                                                            |

CPU-limit kills are classified from CPU time consumed because `unshare` exits 1 instead of
re-raising SIGXCPU (`killed_reason="cpu_limit"`).

### Fail closed

Before the first run the backend executes a self-test inside the exact namespace chain and requires
`pid == 1`, only the `lo` interface and zero effective capabilities. If the helper binaries
(`prlimit`, `unshare`, `setpriv`, `sh`) are missing, namespaces cannot be created (unprivileged user
namespaces disabled, seccomp'd container, ...), or the chain does not actually isolate, it raises
`SandboxUnavailableError("... refusing to run code unisolated")` and **runs nothing**. A failed probe
is not cached. There is no unisolated fallback and no "network-denied but ran anyway" mode. This
applies to every run, including `network=True` ones (user/pid/mount/rlimit isolation is still
required).

### Artifact capture

Artifacts come from `$AXIS_OUTPUT_DIR` only, captured by file descriptor with `O_NOFOLLOW` (never
by joining path strings): symlinks (to files or directories), FIFOs/devices, hard-linked files,
unsafe/non-UTF-8 names and over-deep trees are skipped with a reason; caps on count, per-file and
total bytes are checked from `fstat` before reading; at most 2048 entries are inspected. Over-cap
files are never read into memory. `FSIZE` bounds what the code can write per file.

## Threat model

| Threat                                | Control                                                                                                                                                                      | Residual risk                                                                                                                                                                                                          |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Outbound network / exfiltration       | empty netns (only `lo`, down); verified by self-test                                                                                                                         | `network=True` is a full host network; a kernel netns escape defeats it                                                                                                                                                |
| Reading host files and secrets        | env cleared; uid `nobody`; `/proc` is the pid namespace's own                                                                                                                | **The host filesystem is readable wherever world-readable** (`/etc`, `/usr`, `/tmp`, other users' world-readable files). If the runtime is not root there is no uid drop, so the code reads/writes as the runtime user |
| Writing outside the workdir           | uid drop (root runtimes)                                                                                                                                                     | world-writable dirs (`/tmp`, `/var/tmp`, `/dev/shm`) stay writable; non-root runtimes can write anywhere their user can. No read-only remount/pivot_root yet (NEEDS #90)                                               |
| CPU / memory / fork / disk exhaustion | rlimits, wall timeout, disk poll, process-group + pid-ns kill                                                                                                                | RLIMIT_AS is per process; many processes x AS can still use RAM (NPROC bounds it); no cgroup memory cap; disk poll has 200 ms granularity                                                                              |
| Output flood                          | per-stream cap + kill                                                                                                                                                        | none material                                                                                                                                                                                                          |
| Artifact symlink/hardlink/traversal   | fd-relative, `O_NOFOLLOW`, regular files, nlink 1                                                                                                                            | none known                                                                                                                                                                                                             |
| Escaping via kernel bugs              | caps dropped, `no_new_privs`                                                                                                                                                 | **No seccomp**: full syscall surface; user namespaces themselves enlarge kernel attack surface. This is why this is not a boundary                                                                                     |
| Daemonised leftovers                  | pid namespace + `--kill-child` + group kill                                                                                                                                  | none known                                                                                                                                                                                                             |
| Direct use bypassing the gate         | `in_executor()` tripwire; bypass scanner: only `sandbox/backends/local.py` may import `subprocess` / call `Popen` / `os.killpg`, enforced by detail-level scanner exemptions | the tripwire is a regression net, not a barrier against a malicious in-process caller                                                                                                                                  |
| Code in logs                          | hash+size only                                                                                                                                                               | the agent and the Temporal payload still see the code                                                                                                                                                                  |

## Verification

`runtime/tests/test_sandbox_local.py` runs real adversarial payloads (fork bomb, memory hog, infinite
loop, huge stdout, disk fill, writes outside the workdir, secrets in env and `/proc`, outbound
connects, daemonising grandchild, symlink/FIFO/hardlink/traversal/sparse-file artifacts, zip-bomb-like
sizes, cancellation). `test_sandbox_unit.py` covers fail-closed behaviour with fake helper binaries,
the action's gate/audit contract and artifact/workdir internals. The tests need working unprivileged
user namespaces and **fail** (not skip) without them. Safety logic was mutation-checked by hand
(see CHANGELOG / phase notes).

## Not built

gVisor/container/Firecracker backends, seccomp, read-only root / pivot_root, cgroup limits, per-tenant
quotas, image/package provisioning for code, languages beyond Python and shell: NEEDS #89-#95.
