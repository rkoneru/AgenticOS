# Browser workers: threat model (Phase 4 / D)

Scope: `runtime/src/axis_runtime/browser/`. The page is **hostile input**; the agent is not trusted either.

| # | Threat | Mitigation | Evidence / residual |
| --- | --- | --- | --- |
| 1 | Agent or injected page text steers the browser to an arbitrary host (exfiltration) | Per tenant+agent allowlist, enforced at the network layer for every request; empty allowlist denies all; gate sees host before the run | tests: non-allowlisted host, port, subresource, iframe, fetch, XHR, beacon, WebSocket; server logs show no request/connection. Residual: #300 |
| 2 | Redirect from an allowed host to a disallowed/private one | Hop-by-hop redirect handling in the backend (Chromium does not re-route redirects) | chain, host, file redirect tests; mutation-checked. Residual: #304 |
| 3 | SSRF: loopback, RFC1918, link-local, metadata | Endpoint SSRF logic reused; all resolved addresses must be public; metadata never allowlistable; private exception only for explicit IP-literal/localhost entries | unit + browser tests. Residual: DNS rebinding of an allowlisted name (#303) |
| 4 | `file://`, `chrome://`, `data:` and other schemes | Scheme allowlist in guard and session; post-operation check that the page is still http(s) | tests |
| 5 | Cross-run / cross-tenant leakage (cookies, storage, channels, cache) | New in-memory context per run, destroyed at the end; no shared profile | two live contexts + later run; mutation-checked |
| 6 | Credential leakage through logs | Typed text never logged; sensitive/credential fields not even hashed; query strings hashed in logged URLs; screenshots stored by reference | unit tests over the gate context and event log |
| 7 | Gate decides on a different host than the one acted on | `target_url` bound by the worker, overwritten by the executor, verified against the live page | unit tests; mutation-checked |
| 8 | Resource exhaustion (huge pages, endless redirects, popups, dialogs, tab bombs, long sessions) | Caps on bytes, requests, pages, operations, time; popups closed; dialogs dismissed | tests. Residual: driver buffers a body before the cap (#304), no cgroups (#301) |
| 9 | Drive-by download | Downloads disabled, attachment responses refused, events cancelled | tests |
| 10 | Page script reaches other contexts or the host | Context isolation; no `exposeBinding`/`exposeFunction`; WebRTC/WebTransport removed; service workers blocked | test: BroadcastChannel/localStorage/cookie. Residual: browser 0-day (#301) |
| 11 | Prompt injection through extracted text | Out of scope for this component: text is returned as data, size-capped, hashed in audit | #308 |
| 12 | Backend failure treated as success | Any failure is a `BrowserError` -> `Failed`; no partial result is approved | tests |
| 13 | Bypassing the gate by calling the backend directly | `BrowserExec` runs only through `ActionExecutor`; bypass scanner grants `playwright` to one module only | `test_bypass.py` |
