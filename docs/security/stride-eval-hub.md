# STRIDE: Eval Hub, eval runner and the red-team suite

Status: Prototype. Earlier model with 17 threats: [eval-hub-threat-model.md](eval-hub-threat-model.md). Runner spec: `docs/spec/evals-runner.md`. This file also covers the red-team suite as a consumer (see [redteam.md](redteam.md)).

## Assets

- The integrity of "this blueprint version passed its evals" (scores, hashes, attestations).
- Tenant data in datasets and traces; reviewer independence.
- The release gate that registry and marketplace ask.

## Trust boundaries

1. Runner (registered, token plus HMAC over the body) to the hub: the hub recomputes aggregates from per-case grades and binds results to blueprint, dataset, suite and seed (`services/eval-hub/src/runs.ts`, `services/eval-hub/src/integrity.ts`).
2. Eval run to side effects: eval mode denies every non-function action and serves function tools from fixtures (`runtime/src/axis_runtime/evals/isolation.py`).
3. Model judge: a tool-less agent run through the gate and the ModelGateway (`runtime/src/axis_runtime/evals/judge_backend.py`).

## Data flow

Dataset and suite are immutable and content-hashed -> run queued for a blueprint version -> runner claims it, fetches the compiled manifest from the hub, runs each case through the real run path under the tenant's kernel policy -> graders -> signed result -> hub verification -> gate decision for registry or marketplace.

## STRIDE

| Category | Threat | Mitigation (code path) | Test | Residual / NEEDS |
| --- | --- | --- | --- | --- |
| Spoofing | Runner impersonation | Gate counts only registered, non-revoked runners; HMAC over the exact body; a runner touches only its claimed run (`services/eval-hub/src/runs.ts`, `services/eval-hub/src/authz.ts`) | `services/eval-hub/test/runner-wire.test.ts`, `e2e/test_phase8_evals.py` | Static tokens, no mTLS (NEEDS #294) |
| Tampering | Score forgery | Hub recomputes everything from per-case grades; stored runs re-verified at gate time (`services/eval-hub/src/scoring.ts`) | `services/eval-hub/test/scoring.test.ts`, `services/eval-hub/test/runs.test.ts` | A malicious runner can forge consistent grades (NEEDS #297, #326) |
| Tampering | Dataset poisoning to get an easy pass | Datasets and suites are immutable and content-hashed; runs bind to hashes (`services/eval-hub/src/catalog.ts`) | `services/eval-hub/test/catalog.test.ts` | Dataset quality is not judged (NEEDS #299) |
| Tampering | Replay of an old passing run | Gate binds content hash, suite and dataset hash, freshness, latest run decides (`services/eval-hub/src/gate.ts`) | `services/eval-hub/test/gate.test.ts` | Age-based staleness not reachable end to end (NEEDS #327) |
| Repudiation | A gate decision nobody can reconstruct | Decision audited before it is returned; failure denies (`services/eval-hub/src/gate.ts`) | `services/eval-hub/test/gate.test.ts` | none known |
| Information disclosure | PHI or secrets in datasets, traces and judge prompts | Redaction before persistence; judge sees no tool results, memory, keys or policy (`services/eval-hub/src/redact.ts`, `runtime/src/axis_runtime/evals/redact.py`) | `services/eval-hub/test/misc.test.ts`, `runtime/tests/test_evals_judge.py` | Redaction is a net |
| Denial of service | A runaway case or a huge dataset | Per-case timeout, budget caps tightened never loosened, bounded concurrency (`runtime/src/axis_runtime/evals/runner.py`) | `runtime/tests/test_evals_runner.py` | One tenant per runner process (NEEDS #320) |
| Elevation of privilege | An eval run reaches humans or side effects | Eval mode lockdown and fixtures; REQUIRE_APPROVAL opens no request (`runtime/src/axis_runtime/evals/isolation.py`) | `runtime/tests/test_evals_runner.py`, `e2e/test_phase8_evals.py` | The marker is accepted from any authenticated caller (NEEDS #325) |
| Elevation of privilege | Gate bypass by calling the registry directly | `setVersionPublic` and marketplace submit call the injected gate, default DENY_ALL (`services/registry/src/eval-gate.ts`) | `services/registry/test/eval-gate.test.ts` | Registry asks only for declared suites unless the hub adds tenant suites (NEEDS #298) |

## Prompt injection

Two places: (1) the judge: agent output is untrusted input to a model grader; the runner wraps it in per-call random-nonce fences, defangs fence lookalikes, parses a strict single-JSON verdict, and checks anchors for drift (`runtime/src/axis_runtime/evals/judge.py`, test `runtime/tests/test_evals_judge.py`; phase 8 e2e scenario 6). (2) Datasets as an injection source: a dataset row is untrusted text; the red-team corpus contains dataset-row injections (technique `eval-dataset-row` in `evals/redteam/datasets/redteam-core.json`) and the runner gives the case input to the agent exactly like a user message, under the same gate. The red-team suite uses deterministic graders only (policy decisions, performed tools, budget) so that no judge can be talked into a pass.

## Tool misuse

Function tools in an eval are fixtures (`metadata.tool_fixtures`); an unmatched call is a tool error and the real registry is never reachable. A tool fixture can declare an input schema, which the run loop enforces (see [stride-runtime.md](stride-runtime.md)). The red-team harness additionally records every handler that ran in an execution sink and fails the case if a harmful tool ran, a canary reached an argument or an undeclared argument got through (`e2e/scripts/redteam_runner.py`, `evals/redteam/oracle.py`).
