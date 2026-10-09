# STRIDE: CLI (`axis`) and the TypeScript and Python SDKs

Status: Prototype (generated from the frozen OpenAPI plus an ergonomic layer; unpublished, NEEDS #240). Spec: `docs/spec/sdk.md`, `docs/spec/cli.md`.

## Assets

- The user's API key and any bearer token (never printed, logged or sent to another origin).
- Integrity of what the client sends and shows (consent-bound marketplace installs, exit codes used by CI gates).

## Trust boundaries

1. Client to gateway: the key is sent only to the configured base origin; cross-origin redirects and https-to-http downgrades are refused (`sdk/python/src/axis_sdk/transport.py`).
2. Client to local disk: the CLI config file holding the key is written with restrictive permissions (`apps/cli/src/config.ts`).
3. Server text to the terminal: control characters and ANSI sequences from server data must not control the user's terminal (`apps/cli/src/render.ts`).

## Data flow

Command or SDK call -> request built from the generated layer -> transport (retries on idempotent calls, backoff) -> response mapped to typed errors with problem+json and the key redacted from any message (`sdk/python/src/axis_sdk/errors.py`, `sdk/python/src/axis_sdk/redact.py`).

## STRIDE

| Category               | Threat                                                                                | Mitigation (code path)                                                                                                                                        | Test                                                                     | Residual / NEEDS                             |
| ---------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | -------------------------------------------- |
| Spoofing               | The key is sent to an attacker's origin through a redirect or a pagination link       | Same-origin only for the credential; https-to-http refused (`sdk/python/src/axis_sdk/transport.py`)                                                           | `sdk/python/tests/test_transport.py`                                     | none known                                   |
| Tampering              | A server response with unexpected shape drives the client wrongly                     | Typed errors, pagination by opaque cursor, SSE parsing bounded (`sdk/python/src/axis_sdk/pagination.py`, `sdk/python/src/axis_sdk/sse.py`)                    | `sdk/python/tests/test_sse.py`, `sdk/python/tests/test_resources.py`     | No response validation built in (NEEDS #241) |
| Repudiation            | A consent-bound install without the user's consent                                    | The install call carries the consent digest of the previewed permission set (`apps/cli/src/registry.ts`)                                                      | `apps/cli/test/cli.test.ts`, `e2e/test_phase7_interfaces.py`             | none known                                   |
| Information disclosure | The key in output, errors or logs                                                     | Keys never printed; errors redact the key (`sdk/python/src/axis_sdk/redact.py`, `apps/cli/src/exit.ts`)                                                       | `sdk/python/tests/test_errors_redaction.py`, `apps/cli/test/cli.test.ts` | none known                                   |
| Denial of service      | Retry storms                                                                          | Exponential backoff with full jitter, `Retry-After` honoured, only idempotent calls or calls with an idempotency key (`sdk/python/src/axis_sdk/transport.py`) | `sdk/python/tests/test_transport.py`                                     | none known                                   |
| Elevation of privilege | A scripted CI gate is bypassed by a wrong exit code                                   | Stable exit codes (denied is 4) asserted in the e2e (`apps/cli/src/exit.ts`)                                                                                  | `apps/cli/test/evals.test.ts`, `e2e/test_phase8_evals.py`                | none known                                   |
| Elevation of privilege | The CLI parser accepts option values that change meaning (a key starting with a dash) | Documented limitation: pass `--opt=value` (`apps/cli/src/cli.ts`)                                                                                             | `apps/cli/test/cli.test.ts`                                              | Separate-argument form rejected (NEEDS #333) |

## Prompt injection

SDKs and the CLI display server data (run output, explanations) to a terminal or a program that may feed it to a model. They do not interpret it; display strips control sequences. An agent framework that uses the SDK as a tool inherits the key's scopes, which is the intended containment (narrow-scope keys, probe `rt-px-p10` in `e2e/redteam_probes.py`); output from `axis` should be treated as untrusted when fed to a model.

## Tool misuse

A model given the CLI as a shell tool could try destructive commands; the key's scopes and role at the gateway bound it, and the red-team pack denies `run-command` unless the whole string is an allowlisted word (category `tool-misuse`, technique `shell-metacharacters`). Mutating CLI commands accept idempotency keys so retries are safe.
