# STRIDE: Code sandbox

Status: Prototype. Honest label: process-level isolation on the host kernel, not a hard security boundary (`docs/spec/sandbox.md`, NEEDS #89 to #95). Do not run hostile multi-tenant code on it in production.

## Assets

- The host and other tenants' data and processes; the network.
- The integrity of the gate view of a code action (language, code hash, limits, network flag).

## Trust boundaries

1. Agent code (hostile) to the sandbox: user, pid, net and mount namespaces on one kernel, a per-run uid, rlimits, a private working directory (`runtime/src/axis_runtime/sandbox/backends/local.py`, `runtime/src/axis_runtime/sandbox/workdir.py`).
2. Model to the code action: fixed schema, `network` is wiring and cannot be chosen by the model (`runtime/src/axis_runtime/tooldefs.py`, `runtime/src/axis_runtime/actions.py`).
3. Policy to code: the gate request carries the code hash and sizes, not the text (`runtime/src/axis_runtime/actions.py`).

## Data flow

Model emits `{language, code}` -> `CodeRunAction` -> kernel (language and network rules, PHI) -> backend creates a private workdir, forks into namespaces with limits -> stdout/stderr/artifacts captured with caps -> result event with hashes and an `isolation` map saying what protections actually applied.

## STRIDE

| Category | Threat | Mitigation (code path) | Test | Residual / NEEDS |
| --- | --- | --- | --- | --- |
| Spoofing | Code claims another run's identity or reads its files | Per-run uid and private workdir wiped after the run (`runtime/src/axis_runtime/sandbox/workdir.py`) | `runtime/tests/test_sandbox_local.py` | World-writable host directories persist (NEEDS #112) |
| Tampering | Code alters the host filesystem | Mount namespace and permissions limit writes to the workdir (`runtime/src/axis_runtime/sandbox/backends/local.py`) | `runtime/tests/test_sandbox_local.py` | No read-only root, no seccomp (NEEDS #90) |
| Tampering | Environment injection (`LD_PRELOAD`, `PYTHONPATH`, `PATH`) | These variables are refused in the spec (`runtime/src/axis_runtime/sandbox/types.py`) | `runtime/tests/test_sandbox_unit.py` | none known |
| Repudiation | Code ran without a record | The only path is `CodeRunAction` through the executor; the event keeps hashes, usage and the isolation map (`runtime/src/axis_runtime/actions.py`) | `e2e/test_phase4_tools.py`, `runtime/tests/test_bypass.py` | none known |
| Information disclosure | Code reads host files or other tenants' data | Namespaces and uid separation; the host filesystem is still readable in parts (`runtime/src/axis_runtime/sandbox/backends/local.py`) | `runtime/tests/test_sandbox_local.py` | Host filesystem readable (NEEDS #90) |
| Information disclosure | Code exfiltrates over the network | `network=false` by default, new net namespace; an outbound connect fails and the target sees no request (`runtime/src/axis_runtime/sandbox/backends/local.py`) | `e2e/test_phase4_tools.py` | Policy for `network=true` has no default rule (NEEDS #94) |
| Denial of service | CPU, memory, fork, disk and output bombs | rlimits, wall timeout, output and artifact caps, workdir size cap (`runtime/src/axis_runtime/sandbox/types.py`) | `runtime/tests/test_sandbox_unit.py`, `runtime/tests/test_sandbox_local.py` | No cgroup limits or per-tenant quota (NEEDS #91) |
| Elevation of privilege | Escape to the host through the shared kernel | Unprivileged user namespaces, no extra capabilities; the run FAILS rather than running unisolated when isolation is unavailable (`runtime/src/axis_runtime/sandbox/backends/local.py`) | `e2e/test_phase4_tools.py` | A kernel exploit defeats it; unverified on other kernels (NEEDS #89, #92) |
| Elevation of privilege | The model turns on `network` or picks a shell | `network` is wiring; the e2e policy denies shell and PHI agents (`runtime/src/axis_runtime/tooldefs.py`) | `runtime/tests/test_run_tools.py` | Policy cannot read the code text (see Tool misuse) |

## Prompt injection

Code the model writes is as untrusted as any model output. Injected text can ask for code that reads secrets or calls out; the gate decides on language, network flag, PHI and rate, and the sandbox contains what runs. The output of the code returns to the model as data. The suite treats code as a tool kind whose handler is a fixture (eval mode denies real code execution unless a suite allows a sandboxed target); the real sandbox is attacked by `runtime/tests/test_sandbox_local.py` (adversarial cases) and `e2e/test_phase4_tools.py`.

## Tool misuse

Shell metacharacters are only a problem for `shell`; the policy in the red-team pack allows exact commands and denies metacharacters (`evals/redteam/policy/pack.yaml`, category `tool-misuse`). For the real code tool the gate sees the code hash, so a content-based allowlist is impossible: policy must key on language, network, actor and data class, and anything beyond that depends on the isolation backend (NEEDS #89).
