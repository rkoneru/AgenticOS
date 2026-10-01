# Browser workers (Phase 4 / D)

Status: **Prototype** (real Chromium, local fixture server, no live-internet run, no egress proxy).
Code: `runtime/src/axis_runtime/browser/`. Tests: `runtime/tests/test_browser_*.py`. Threat model:
`docs/security/browser-threat-model.md`. Gaps: `docs/NEEDS.md` #300-#308.

## Shape

```
BrowserExec (Action, gate: browser_exec, tool.kind="browser")
   -> ActionExecutor: gate -> audit -> perform
        -> Backends.browser = BrowserWorker           (one per RUN)
             -> UrlGuard precheck (navigate)
             -> BrowserBackend.open_session(policy, guard)   (PlaywrightBackend)
                  -> fresh BrowserContext, every request -> UrlGuard
```

- `BrowserWorker` implements the existing `BrowserRunner` protocol (`run(args)`); `aclose()` destroys the run's
  context. `BrowserWorkerFactory.for_run(tenant, agent, run)` builds one with the policy from a
  `(tenant, agent) -> BrowserPolicy | None` provider; **no policy = empty allowlist = everything blocked**.
- `BrowserBackend` / `BrowserSession` are protocols (`browser/backend.py`); `PlaywrightBackend` is the only
  implementation. A failing launch, context or operation is a `BrowserError`, which the executor records as
  `Failed` (a `tool_call_result` with `ok=false`): there is no partial approval.

## Run-loop wiring (Phase 4 / E, ADR 0014)

`RunDeps.browser = BrowserWorkerFactory(PlaywrightBackend, static_policies({(tenant, agent): config}))`. `start_agent` builds one worker
per run for `(tenant, manifest name)`, installs it as `backends.browser`, builds each action with `worker.action(...)` (the page the
operation acts on comes from the worker, a model-supplied `target_url` is dropped) and `aclose()`s it when the run ends. No ABL
field carries the allowlist (frozen schema; ADR 0014 #9): it is operator configuration, `{"allowed_domains": [...], "private_hosts":
[...], ...}` as in `BrowserPolicy.from_config`; no entry = no policy = every request blocked. The e2e (real Chromium, local fixture site)
shows: an allowed read-only session; a subresource on a non-allowlisted origin blocked at the network (the other server saw nothing); a
`localhost` navigation denied by the Risk Kernel's policy while the network allowlist would have permitted it (so the decisive control
is the gate); an injected instruction in page text followed by a model that obeys it hits the gate and is denied; typing is denied;
PHI agents get no browser; the tool-scoped kill-switch stops it.

## Operations

`args = {"operation": navigate|click|type|extract|screenshot, ...}`

| operation  | args                                           | result evidence                                                                |
| ---------- | ---------------------------------------------- | ------------------------------------------------------------------------------ |
| navigate   | `url`                                          | final URL, title, status                                                       |
| click      | `selector`, `target_url`                       | final URL, title                                                               |
| type       | `selector`, `text`, `sensitive?`, `target_url` | `typed: {text_sha256, text_len}` or `{masked: true}`                           |
| extract    | `selector?`, `target_url`                      | `text` (to the agent only), `text_sha256`, `text_bytes`, `text_truncated`      |
| screenshot | `target_url`                                   | `screenshot_ref` (artifact reference), `screenshot_sha256`, `screenshot_bytes` |

Every result also carries `blocked_requests` (capped list of `{url, host, reason, type}`), `blocked_total`,
`requests`, `bytes_received`, `pages_visited`, `popups_blocked`, `dialogs_dismissed`, `downloads_blocked`.
URLs in evidence are sanitised: no userinfo, no fragment, query replaced by `?q_sha256=<16 hex>`.

`BrowserWorker.action(name, args)` builds the `BrowserExec` bound to the page it will act on
(`target_url` = the worker's current page). The executor overwrites any agent-supplied `target_url`, and the
worker refuses to run when the live page differs (`target_changed`), so the host the gate saw is the host the
operation acts on.

## What the gate sees (`args.*` of the gate context)

`operation`, `url` (sanitised), `host`, `sensitive`, `selector`, `args_hash` (SHA-256 of the canonical args),
`text_len` and `text_sha256` for typed text. **Typed text is never in the gate context or the event log.**
When the action is _sensitive_ (caller sets `sensitive: true`, or the selector looks like a credential field:
password, pwd, secret, token, otp, cvv, card, ssn, pin, 2fa, mfa), `text_len`/`text_sha256` are `null` and the
secret does not enter `args_hash` either. The backend refuses to type into a `type=password` element that
was not declared sensitive (`password_field_requires_sensitive`), so the declaration the gate saw is honoured.
The event log keeps the result minus `text` (hash + size only); the extracted text goes back to the agent.

## Isolation

- **Fresh `BrowserContext` per run** (in-memory, no storage state): cookies, localStorage, caches,
  BroadcastChannel and permissions are not shared between runs, agents or tenants. Closing the worker closes the
  context. Tested with two live contexts plus a later third.
- Downloads disabled (`accept_downloads=False`, `Content-Disposition: attachment` refused, download events
  cancelled), service workers blocked, popups closed immediately, JS dialogs dismissed, WebRTC / WebTransport
  removed, Chromium prefetch/preconnect disabled by flags.
- Caps (`BrowserPolicy`): `max_pages` navigations, `max_operations`, `max_requests`, `max_body_bytes` per
  response, `max_total_bytes`, `max_text_bytes`, `max_screenshot_bytes`, per-operation and per-session
  timeouts.

## Egress policy (network layer)

`BrowserPolicy.allowed_hosts`: exact names, `*.suffix` (needs two labels after `*.`; the apex is NOT
matched), optional `:port` (default 80/443 only). Empty = deny all. `UrlGuard.check` order: scheme
(`http`/`https`; `ws`/`wss` for sockets; `file:`, `chrome:`, `data:`, `about:`, `javascript:`, `ftp:` ... refused),
no userinfo, usable host and port, **allowlist**, then (unless an explicit `private_hosts` exception, limited to IP
literals and `localhost`, for tests/self-hosted) the endpoint SSRF logic reused from `models/endpoints.py`:
non-public IP literals, ambiguous numeric hosts, blocked names, and **every** resolved address must be public.
Cloud metadata addresses are refused even for private exceptions. Any unexpected exception is a block.

Enforcement in `PlaywrightSession`:

- `context.route("**/*")` sees main frame, iframes, scripts, styles, images, fetch/XHR, beacons. Each request is
  performed by the handler (`route.fetch`, `max_redirects=0`) and fulfilled; the handler enforces the body caps
  and refuses attachments.
- **Redirects.** Chromium does not call route handlers for redirect hops, so a fulfilled or continued 3xx
  would be followed unseen (the first version of this backend leaked exactly that way, caught by the chain test).
  The handler follows redirects itself, checking every hop. Sub-resources and iframes receive the final
  response; a main-frame redirect is aborted and `navigate`/`click` re-issue it to the verified target, so each
  hop is a fresh routed request. 307/308 on a POST navigation is refused; more than 10 hops is refused.
- `context.route_web_socket`: allowed sockets are connected, others are closed 1008 and never reach the server.
- Handler or guard errors abort the request (`handler_error`); nothing is ever continued unchecked.

Test evidence (local fixture servers, assertions on what the server saw): blocked requests never produce a
request or even a TCP connection on the disallowed server.

## Limits

Not pinned to the resolved IP, in-process enforcement, no sandbox, in-memory artifacts: see NEEDS #300-#305.
