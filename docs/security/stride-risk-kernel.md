# STRIDE: Risk Kernel

Status: Built, single instance (`docs/spec/policy-dsl-v1.md`). Earlier model with more rows and evidence names: [risk-kernel-threat-model.md](risk-kernel-threat-model.md). This file adds the code paths, the test files and the red-team results; it does not repeat every row.

## Assets

- The allow/deny decision for every tool, MCP, model, memory, message, code and browser action (integrity and availability).
- Tenant isolation of decisions, caps and kill-switch state.
- Completeness of the audit record of each decision (a decision without a record must not be returned).
- Per-tenant policy bundles (Wasm) and the approval records the kernel verifies.

## Trust boundaries

1. Runtime (untrusted for intent, trusted for transport) to kernel over gRPC: the tenant comes from the credential, never from the request (`services/risk-kernel/src/grpc.ts`).
2. Kernel to policy engine: the Wasm bundle is data from the control plane; its output is validated, anything malformed is a DENY (`services/risk-kernel/src/engine.ts`).
3. Kernel to audit store and to cap/kill-switch stores: failure denies (`services/risk-kernel/src/kernel.ts`, `services/risk-kernel/src/stores.ts`).

## Data flow

Runtime builds an `EvaluateRequest` (tool descriptor, arguments, data class, actor) -> kernel authenticates the principal -> kill-switch check -> policy evaluation (three-valued) -> gates (caps, rate, budget, staleness) with atomic reserve -> audit append -> response. The audit append happens before the response; the response is DENY if any step errored.

## STRIDE

| Category | Threat | Mitigation (code path) | Test | Residual / NEEDS |
| --- | --- | --- | --- | --- |
| Spoofing | A caller names another tenant, or the request context injects `tenant`/`agent`/`actor` to satisfy a rule | Tenant from the credential, mismatch is DENY; the kernel overwrites those context fields after spreading the request (`services/risk-kernel/src/grpc.ts`, `services/risk-kernel/src/kernel.ts`) | `services/risk-kernel/test/grpc.test.ts`, `services/risk-kernel/test/kernel.test.ts` | Static principals are dev-only (NEEDS #199) |
| Spoofing | The eval-mode marker is claimed by an ordinary caller | The kernel strips `eval_mode` before policy evaluation; its only effect is that no approval request is opened (`services/risk-kernel/src/kernel.ts`) | `e2e/test_phase8_evals.py` | Any authenticated caller can send the marker (NEEDS #325) |
| Tampering | Hostile or malformed policy output widens access | Strict result validation; unknown decision, missing approval or redaction is a DENY (`services/risk-kernel/src/engine.ts`) | `services/risk-kernel/test/kernel.test.ts` | Bundle signing is not built (NEEDS #197) |
| Tampering | Type confusion or missing fields skip a DENY rule (`"99999" > 1000`, absent field) | Three-valued semantics: a DENY rule fires on possibly-true, numeric operators need numbers, `matches` is RE2 (`packages/policy/src/compile.ts`) | `packages/policy/test/compile.test.ts`, `services/risk-kernel/test/policy-differential.test.ts` | Found by the red team: the `exists` leaf generated Rego that `opa check --strict` rejected; fixed with a failing-first test (NEEDS #3301) |
| Tampering | Caps raced by parallel requests | Atomic check-and-add `reserve` with rollback when a later gate or the audit append fails (`services/risk-kernel/src/gates.ts`) | `services/risk-kernel/test/gates.test.ts` | State is in memory, no cross-instance propagation (NEEDS #18) |
| Tampering | A policy author's allowlist is evaded by encoding (unicode, percent-encoding, entity encoding, trailing newline) | Allowlists are anchored RE2 and default is DENY, so an unrecognised spelling is not allowed; the red-team suite attacks each spelling (`evals/redteam/policy/pack.yaml`) | `evals/redteam/datasets/redteam-core.json` | Regex DLP is not encoding-proof; the red team found and fixed a `\b` boundary evasion in the fixture pack (NEEDS #3302) |
| Repudiation | A decision without a record | The audit append precedes the response, a failed append is a DENY (`services/risk-kernel/src/kernel.ts`) | `services/risk-kernel/test/kernel.test.ts` | Invalid requests with no trustworthy tenant are not chained (NEEDS #111) |
| Information disclosure | Values leak through reasons or audit rows | Reasons name rules and fields, audit stores hashes only (`services/risk-kernel/src/kernel.ts`) | `services/risk-kernel/test/kernel.test.ts` | Logger fields must stay value-free (review item) |
| Denial of service | A slow policy or store stalls every agent | Time budget then DENY; store errors DENY (`services/risk-kernel/src/engine.ts`) | `services/risk-kernel/test/kernel.test.ts` | Wasm evaluation cannot be pre-empted (NEEDS #21) |
| Denial of service | An attacker engages a kill-switch for others | A tenant credential can only switch its own tenant; global needs the platform operator (`services/risk-kernel/src/grpc.ts`) | `e2e/redteam_probes.py` | Operator credential handling is a dev mechanism (NEEDS #199) |
| Elevation of privilege | The agent bypasses the gate by calling tools or models directly | One `ActionExecutor`; bypass scanner and audit-hook test (`runtime/src/axis_runtime/executor.py`) | `runtime/tests/test_bypass.py`, `runtime/tests/test_audit_hook.py` | Heuristic, not isolation (NEEDS #23) |
| Elevation of privilege | A model persuaded by injected text attempts a dangerous action | The gate is deterministic and outside the model; default DENY; approvals for risky actions. 248 red-team verdicts with a gullible model, 0 contained failures (`evals/redteam/datasets/redteam-core.json`) | `e2e/redteam_harness.py` | Measures containment, not model robustness (NEEDS #3304) |

## Prompt injection

The kernel never reads model text: it sees the action, the arguments and the actor. An injected instruction can therefore only matter by changing what the model asks for, and every such request meets the same policy. The red-team suite runs a model that obeys every directive it is shown (direct, tool result, tool description, memory, inbox, file name, dataset row, many-shot, translated, encoded) and requires the gate decisions in `expected.decisions` of each case; the suite fails if any harmful action is performed (`evals/redteam/oracle.py`). Evidence of regression detection: `make redteam-selfcheck` bypasses the gate for chosen tools and the suite must fail (`evals/redteam/mutants.py`).

## Tool misuse

Argument smuggling, SSRF-shaped URLs, shell metacharacters and path traversal are policy matters (the kernel evaluates the arguments it is given). The pack under attack uses anchored allowlists plus priority-400 denials; the corpus covers the spellings in `evals/redteam/datasets/redteam-core.json` (category `tool-misuse` and `policy-evasion`). Arguments a tool never declared are rejected before the gate by the runtime (see [stride-runtime.md](stride-runtime.md)).
