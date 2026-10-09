# STRIDE: Browser workers

Status: Prototype (real Chromium against a local fixture site, egress enforced in-process). Earlier model with 13 rows: [browser-threat-model.md](browser-threat-model.md). The page is hostile input; the agent is not trusted either.

## Assets

- The tenant's network position (SSRF, internal services), credentials typed into pages, session state.
- The agent's context (page text returned as data).

## Trust boundaries

1. Agent to the browser action: operation, URL and selectors are validated; the gate sees host, operation and a hash of typed text, never the text (`runtime/src/axis_runtime/browser/args.py`).
2. Browser to the network: every request, redirect hop and subresource passes the URL guard (allowlist, public addresses only, scheme allowlist) (`runtime/src/axis_runtime/browser/policy.py`, `runtime/src/axis_runtime/browser/playwright_backend.py`).
3. Page to other runs: a fresh in-memory context per run, destroyed at the end (`runtime/src/axis_runtime/browser/worker.py`).

## Data flow

`BrowserExec` -> kernel (host, operation, PHI) -> worker binds `target_url` and verifies it against the live page -> backend performs the operation with guarded routes -> extracted text capped and returned to the agent as data; screenshots stored by reference.

## STRIDE

| Category               | Threat                                                                                        | Mitigation (code path)                                                                                                                                                                                                 | Test                                                                         | Residual / NEEDS                                                   |
| ---------------------- | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Spoofing               | Gate decides on a different host than the one acted on (userinfo, backslash, odd authorities) | `target_url` bound by the worker and verified against the live page; authorities that parsers split differently are refused (`runtime/src/axis_runtime/browser/args.py`, `runtime/src/axis_runtime/browser/policy.py`) | `runtime/tests/test_browser_unit.py`, `runtime/tests/test_browser_review.py` | Non-ASCII allowlist entries not normalised (NEEDS #116)            |
| Tampering              | Redirect from an allowed host to a disallowed or private one                                  | Hop-by-hop redirect handling in the backend (`runtime/src/axis_runtime/browser/playwright_backend.py`)                                                                                                                 | `runtime/tests/test_browser_redirects.py`                                    | Redirect hops forward original headers (NEEDS #115)                |
| Repudiation            | Browser actions without a record                                                              | `BrowserExec` runs only through the executor; typed text never logged; query strings hashed (`runtime/src/axis_runtime/browser/args.py`)                                                                               | `runtime/tests/test_bypass.py`, `runtime/tests/test_browser_unit.py`         | none known                                                         |
| Information disclosure | Cross-run or cross-tenant leakage (cookies, storage)                                          | New in-memory context per run, no shared profile (`runtime/src/axis_runtime/browser/worker.py`)                                                                                                                        | `runtime/tests/test_browser_backend.py`                                      | Screenshots kept in memory (NEEDS #98)                             |
| Information disclosure | SSRF to loopback, RFC1918, link-local, metadata                                               | All resolved addresses must be public, metadata never allowlistable (`runtime/src/axis_runtime/browser/policy.py`)                                                                                                     | `runtime/tests/test_browser_backend.py`, `e2e/test_phase4_tools.py`          | DNS rebinding of an allowlisted name (NEEDS #99)                   |
| Denial of service      | Huge pages, endless redirects, popups, tab bombs                                              | Caps on bytes, requests, pages, operations and time; popups closed; dialogs dismissed (`runtime/src/axis_runtime/browser/worker.py`)                                                                                   | `runtime/tests/test_browser_backend.py`                                      | No cgroups; driver buffers a body before the cap (NEEDS #97, #100) |
| Elevation of privilege | Page script reaches other contexts or the host                                                | Context isolation; no exposed bindings; WebRTC and service workers blocked (`runtime/src/axis_runtime/browser/playwright_backend.py`)                                                                                  | `runtime/tests/test_browser_backend.py`                                      | Browser 0-day, runs in the runtime process tree (NEEDS #97)        |
| Elevation of privilege | Agent types credentials into a page the injected text chose                                   | The policy in the e2e pack denies `type`; sensitive fields are not hashed or logged (`runtime/src/axis_runtime/browser/args.py`)                                                                                       | `e2e/test_phase4_tools.py`                                                   | Allowlist home outside ABL (NEEDS #103)                            |

## Prompt injection

Page text is the classic indirect injection vector. The browser component returns extracted text verbatim (capped) as tool data and detects nothing (NEEDS #104); the containment is downstream: the page can only direct the agent to hosts on the allowlist, every navigation is gated, and typing is denied by policy. Evidence: prompt-injection scenario against a hostile fixture page in `e2e/test_phase4_tools.py` and the red-team technique `browser-page` plus SSRF URL cases (`evals/redteam/datasets/redteam-core.json`, categories `indirect-injection` and `tool-misuse`; eval mode runs the page as a function-tool fixture, the real browser is covered by the Phase 4 e2e).

## Tool misuse

Navigating to attacker-chosen URLs with tricks (userinfo, decimal and hex IPs, IPv6 literals, `file:`, `gopher:`, redirects, DNS names that resolve to private addresses) is the main misuse; the guard rules above and the policy's host allowlist apply, and the red-team pack mirrors them for URL-shaped function tools with anchored regexes (`evals/redteam/policy/pack.yaml`).
