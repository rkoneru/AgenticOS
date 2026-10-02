# Console and docs site (Phase 7 / D)

`apps/console` (Next.js 16 App Router, TypeScript, Tailwind 4), `packages/ui` (component kit), `apps/docs-site` (static docs). Status: **Prototype**.
Built and tested against a **mock control-plane API** (`apps/console/mock-api`) that follows the frozen `/v1` OpenAPI; it has not been run against
the real gateway (NEEDS #1300). ADRs 0050-0052. Gaps: `docs/NEEDS.md` #1300-#1316.

## 1. Architecture

```
browser --same-origin--> console (Next, Node)
                           |- /api/axis/[...path]  BFF: allow-list, CSRF, cookie + header forward, streams SSE
                           |- /api/abl/validate    live ABL check (real @axis/abl compiler + linter, server side)
                           |- /auth/sso/*          rewrite to the control plane (SSO start/callback land on the console origin)
                           '- proxy.ts             CSP nonce + security headers + optimistic sign-in gate
control plane / gateway (AXIS_API_URL, server-only)
```

- **One data module.** Every call goes through `lib/api.ts` (`createApi`, the `api` singleton). Types mirror `packages/contracts/openapi/axis-v1.yaml`;
  `test/spec-contract.test.ts` fails if the console calls a frozen operation (method + path) that is not in the spec. Anything not in the spec is
  marked ADDITIVE in `lib/api.ts` and listed in section 6. The SDK can replace this module without touching pages.
- **Auth.** The session is the control plane's cookie session (`__Host-axis_at`, `__Host-axis_rt`, `__Host-axis_csrf`). Sign-in is a plain GET form to
  `NEXT_PUBLIC_SSO_START_URL` (default `/auth/sso/start`); the IdP callback returns to the console origin. `proxy.ts` redirects to `/login?return_to=` when
  the session cookie is absent (an optimistic check; the API validates every call). `return_to` is only honoured when it is a same-site path.
  Dev login (`NEXT_PUBLIC_DEV_LOGIN=1`) adds a role picker that the mock IdP understands.
- **Role-aware UI** (`lib/roles.ts`, `components/session.tsx`): controls the role cannot use are hidden (nav, publish, start run, decide, activate, admin tabs).
  This is a hint only; the server re-authorises every call. e2e shows the server refusing the same actions when the UI is bypassed.

## 2. Pages

| Route                                                   | What it does                                                                                                                                                                                                                                                                                                                                                          |
| ------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/blueprints`, `/blueprints/new`, `/blueprints/[n]/[v]` | list; YAML editor with live validation (debounced 300 ms, `POST /api/abl/validate`) showing schema issues and lint findings inline as `line:column`, risk level, then publish (`POST /v1/blueprints`; 409 and 422 shown). Positions come from the YAML AST (`lib/abl-diagnostics.ts`).                                                                                |
| `/runs`, `/runs/[id]`                                   | list + state filter + start form (blueprint, JSON input); run view: state, trace link, token/cost/tool-call gauges against budgets, **live SSE timeline** (backfill via `GET /events`, then `Accept: text/event-stream`, de-duplicated by sequence), **replay scrubber** (any prefix of the log folded into state, play/pause, jump to live), pause/resume/terminate. |
| `/approvals`, `/approvals/[id]`                         | queue; detail with arguments hash, policy reason, matched rules, eligible roles, SLA countdown; approve/deny behind a confirmation dialog with comment; self-approval is disabled in the UI and refused (403) by the server.                                                                                                                                          |
| `/policies`                                             | packs, JSON policy editor, **test panel** (cases `{name, request, expect}` run through `POST /v1/policies:test`; an evaluation error is a failed case, never a pass), publish, **activation behind a diff dialog** (active vs candidate).                                                                                                                             |
| `/evals`                                                | list; shows an explicit "not available yet" state when the endpoint answers 404/405/501 (Phase 8).                                                                                                                                                                                                                                                                    |
| `/audit`                                                | filter (trace id, decision), search loaded events, detail incl. hashes, **verification**: server `POST /v1/audit/verify` AND an independent SHA-256 recomputation in the browser (`lib/hashchain.ts`, same canonical JSON as `@axis/contracts`); disagreement is flagged. A filtered view is not contiguous, so the local check is skipped and says so.               |
| `/usage`                                                | meter totals and a per-day bar chart in plain SVG (one series, validated reference palette slot 1, 2 px rounded data ends, per-bar hover/focus tooltip, table view).                                                                                                                                                                                                  |
| `/admin`                                                | members/roles, API keys (**secret shown once** in a dialog, never in lists), BYO model keys (**write-only**), budgets (soft <= hard enforced client-side and by the server), SSO/SCIM/region (SSO edit owner-only).                                                                                                                                                   |
| `/marketplace`, `/marketplace/[id]`                     | browse; install requires consent in a **permission-diff dialog** (added/removed/unchanged tools, data classes, egress, max risk); the accepted set is sent and the server must match it. Feature flag `NEXT_PUBLIC_FEATURE_MARKETPLACE`; a 404/501 shows "not available".                                                                                             |

**AGIL panel** (`Explanation` in `components/common.tsx`): beside every run, every approval, and every non-ALLOW audit event. It fetches
`GET /v1/runs/{id}/explanation`, `/v1/approvals/{id}/explanation`, `/v1/audit/events/{id}/explanation` and renders exactly `{summary, steps[], decision_refs[], remediation[]}`
as text. It never composes or infers explanation content; when the endpoint is absent it says so. AGIL stays off the decision path (invariant 2): the panel only reads.

## 3. Security

- **CSP + headers** (`lib/security.ts`, `proxy.ts`): per-request nonce, `script-src 'self' 'nonce-…' 'strict-dynamic'`, `object-src 'none'`, `frame-ancestors 'none'`,
  `connect-src 'self'`, `base-uri 'self'`, `form-action 'self'`; `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP, HSTS (production over https).
  Dev relaxes only `unsafe-eval`/`unsafe-inline`. Pages are dynamic (nonces need per-request rendering).
- **CSRF** (`lib/bff.ts`): every unsafe BFF call needs a same-origin `Origin` (or `Sec-Fetch-Site: same-origin`) AND the double-submit token header equal to the readable cookie (constant-time compare). The control plane checks the same token again.
- **BFF allow-list**: only `v1/*`, `admin/v1/*`, `auth/{me,refresh,logout}`; traversal, encoded slashes, backslashes and NULs are refused. Internal/dev/SCIM/platform routes are unreachable from the browser.
- **XSS**: no `dangerouslySetInnerHTML` anywhere (grep-enforced in review); all tool/model/policy/explanation text is a React text child. The e2e injects `<img onerror>`/`<script>` payloads through run events, audit reasons and AGIL fields and asserts nothing executes and the literal text is shown. The docs-site escapes raw HTML in markdown and drops `javascript:` links.
- **No secrets in the client**: only `NEXT_PUBLIC_*` flags are inlined (none secret). `scripts/scan-bundle.mjs` scans `.next/static` for key shapes and for the value of server-only config; `make console-e2e` runs it (0 findings, 28 assets).
- **API-key reveal / BYO keys**: the secret exists only in dialog state until closed; BYO key inputs are cleared after save and are never read back.

## 4. Accessibility and UX

Skip link, landmarks, labelled controls, focus-visible rings, keyboard-operable dialogs/tabs (Radix), `aria-live` for validation/verification results, `role=meter` gauges with text values,
tables with captions, reduced-motion, light/dark (tokens redefined for both; theme toggle persisted), responsive nav (menu button on phones, no horizontal scroll).
Automated axe (WCAG 2.0/2.1 A+AA) runs on **every page in light and dark** in the e2e, and on the component kit in jest-axe. Not done: manual screen-reader passes (NEEDS #1311).

## 5. Tests and how to run

| What           | Command                             | Result at this commit                                                                                               |
| -------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| UI kit         | `pnpm --filter @axis/ui cov`        | 16 tests incl. axe; thresholds 85/80                                                                                |
| Console logic  | `pnpm --filter @axis/console cov`   | 78 tests; `lib/` ~99% lines (threshold 85)                                                                          |
| Docs site      | `pnpm --filter @axis/docs-site cov` | 10 tests incl. a real offline, deterministic build and link check                                                   |
| Playwright e2e | `make console-e2e`                  | builds the console, scans the bundle, runs 56 tests against the mock API (Chromium from `PLAYWRIGHT_BROWSERS_PATH`) |
| Docs build     | `make docs-build`                   | `apps/docs-site/dist` (67 files)                                                                                    |

Dev: `pnpm --filter @axis/console mock-api` (port 4010) and `NEXT_PUBLIC_DEV_LOGIN=1 pnpm --filter @axis/console dev` (port 3100). Config: `AXIS_API_URL` (server-only),
`AXIS_SESSION_COOKIE`, `AXIS_INSECURE_HTTP=1` (only for http test deployments: skips HSTS and `upgrade-insecure-requests`), `NEXT_PUBLIC_SSO_START_URL`, `NEXT_PUBLIC_SSO_ORG`,
`NEXT_PUBLIC_FEATURE_{MARKETPLACE,EVALS}`, `NEXT_PUBLIC_DEV_LOGIN`.

The mock API enforces what the console relies on the server for (cookie session, CSRF double-submit, role checks, self-approval refusal, immutable versions, one-time key secrets, write-only model keys, real ABL compile on publish, a real hash chain from `@axis/contracts`). It is **not** evidence about the real services.

## 6. Additive API the console assumes (not in the frozen `/v1`)

`GET /auth/me` ({member, tenant}); `GET /v1/{runs|approvals}/{id}/explanation` and `GET /v1/audit/events/{id}/explanation` (AGIL shape above);
`GET /v1/evals/runs` (list); `/v1/marketplace/listings[/{id}[/install]]`; optional fields `requested_by`, `args_hash`, `policy_reason`, `matched_rule_ids` on `Approval`;
`policy`, `active`, `version_id` on `PolicyPack`; `/admin/v1` response shapes (snake_case, see `lib/api.ts`); `PUT /admin/v1/budgets` taking `{items}`. Each degrades to a message when the server answers 404/405/501. NEEDS #1301.

## 7. packages/ui

`Button, Input/Textarea/Select (label + hint + error wiring), Table, Dialog (Radix), Tabs (Radix), Badge, Toast (live regions), CodeEditor (textarea with gutter and diagnostics list), Timeline, DiffView (LCS line diff, markers also in words), EmptyState, ErrorBoundary`,
tokens in `src/tokens.css` (light/dark, status colours, viz series slot). Source is consumed directly (`transpilePackages`).

## 8. Docs site

`apps/docs-site/src/build.ts`: every `docs/**/*.md` (except `NEEDS.md`) -> HTML, sectioned nav, ADR index, an OpenAPI reference generated from `axis-v1.yaml` (every operation, parameters, responses), relative `.md` links rewritten, heading anchors, internal link/anchor checker. Pure and deterministic (sorted inputs, no clock, no network; the test builds twice and compares bytes, with proxies pointed at a dead port).
