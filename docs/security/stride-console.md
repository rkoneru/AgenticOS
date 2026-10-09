# STRIDE: Console (Next.js, BFF)

Status: Prototype (real-stack suite green, admin pages mock-verified only, NEEDS #277). Spec: `docs/spec/console.md`.

## Assets

- The operator's session and CSRF token, and the actions the console can trigger (approve, kill switch, policy activation).
- Integrity of what the operator sees (run output, audit rows, explanations): a console that renders attacker-controlled text is an injection sink for humans.

## Trust boundaries

1. Browser to console (same origin): CSP with a per-request nonce and security headers on every response (`apps/console/proxy.ts`, `apps/console/lib/security.ts`).
2. Console BFF to gateway and control plane: an allowlist of paths, CSRF double submit, cookie and header forwarding, SSE streaming (`apps/console/lib/bff.ts`).
3. Agent-produced text (run output, tool results, event data) to the DOM: rendered as inert text (`apps/console/app`, `apps/console/components`).

## Data flow

Sign-in through the control plane SSO -> `__Host-` cookies -> pages call the same-origin BFF route -> BFF checks the path allowlist, adds the bearer from the session and the CSRF header -> gateway. Run view backfills over JSON then follows SSE; audit verification re-hashes in the browser.

## STRIDE

| Category               | Threat                                                       | Mitigation (code path)                                                                                                              | Test                                                                               | Residual / NEEDS                                                    |
| ---------------------- | ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| Spoofing               | Cross-site request forgery against the BFF                   | CSRF double submit header for unsafe methods, SameSite=Strict `__Host-` cookies (`apps/console/lib/bff.ts`)                         | `apps/console/test/bff-security.test.ts`, `apps/console/e2e-real/workflow.spec.ts` | Cookie behaviour with a real cross-site IdP unverified (NEEDS #278) |
| Tampering              | Proxy path abuse: the BFF reaches an internal route          | Path allowlist and normalisation in the BFF (`apps/console/lib/bff.ts`)                                                             | `apps/console/test/bff-security.test.ts`                                           | Admin routes mock-verified only (NEEDS #277)                        |
| Tampering              | Injected markup in agent output executes (XSS)               | Output rendered as text; CSP nonce, no inline script without nonce, `form-action` pinned (`apps/console/lib/security.ts`)           | `apps/console/e2e-real/workflow.spec.ts`, `apps/console/e2e/flows.spec.ts`         | No CSP reporting (NEEDS #258)                                       |
| Repudiation            | An operator action cannot be attributed                      | The gateway audits the mutation with the member and credential; the console adds no side channel (`apps/api-gateway/src/routes.ts`) | `apps/api-gateway/test/pipeline.test.ts`                                           | none known                                                          |
| Information disclosure | Secrets in the client bundle                                 | Bundle scan for sentinels and secret patterns in `make console-e2e` (`apps/console/lib/secret-scan.ts`)                             | `apps/console/test/secret-scan.test.ts`                                            | none known                                                          |
| Information disclosure | Cross-tenant data in the UI                                  | Tenant only from the credential at the gateway; the console holds no tenant selector (`apps/console/lib/api.ts`)                    | `apps/console/e2e-real/workflow.spec.ts`                                           | none known                                                          |
| Denial of service      | Large ABL validation or event floods                         | Body cap on the live ABL validation route, bounded SSE backfill (`apps/console/lib/sse.ts`)                                         | `apps/console/test/sse.test.ts`                                                    | No rate limit beyond the cap (NEEDS #258)                           |
| Elevation of privilege | A viewer uses an operator action by calling the BFF directly | The gateway authorises every call by role and scope; hiding a button is not the control (`apps/console/lib/roles.ts`)               | `apps/console/test/bff-security.test.ts`, `e2e/test_phase7_interfaces.py`          | none known                                                          |

## Prompt injection

The console is where a human reads what an injected agent produced. Controls: event data, tool results, explanations and approval details are rendered as text, never as HTML or markdown with remote images; the CSP forbids remote image and script origins; links in agent text are not auto-followed. The XSS scenario drives a hostile payload through a real run and checks the DOM (`apps/console/e2e-real/workflow.spec.ts`). A markdown-image beacon in agent output therefore does not load in the console; outputs rendered elsewhere (a channel reply) are covered by the policy on `send-reply` bodies (red-team category `exfiltration`, technique `markdown-beacon`). The approval screen shows the tool, risk level and arguments hash, not agent-written persuasion.

## Tool misuse

The console performs only what the authenticated operator clicks, through the same API as the SDKs; there is no agent-driven path. Dangerous actions (kill switch, policy activation, approve/deny) are separate calls with their own role checks at the gateway.
