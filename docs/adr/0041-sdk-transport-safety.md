# 0041. SDK transport safety rules

Status: Accepted · Date: 2026-10-02 · Related: 0040, invariant 1 (fail closed)

## Decisions

1. **Retries only when repeating is safe**: idempotent verbs, or a POST that carries an Idempotency-Key. The key is generated once per logical call and reused across attempts; callers may pass their own. Retried: network errors, 408/429/500/502/503/504 (exponential backoff, full jitter, `Retry-After` honoured, capped). Never retried: 4xx other than 408/429, any POST without a key, SSE connects (the stream layer reconnects instead).
2. **Credentials go only to the configured base origin.** Redirects are followed manually; a redirect to another origin (including https to http) is refused with an error and nothing is sent. Base URLs must be https (loopback may use http, `allow_insecure` opts out), without embedded credentials.
3. **The tenant is never a client input.** No tenant option exists; passing `tenant`/`tenant_id` raises; per-request headers named like credential, tenant or host headers are refused. The CLI has no tenant flag.
4. **Secrets never render.** Credentials live in a `Secret` (private field in TS, `__slots__` + redacting `repr`/`str`/pickle in Python); error messages and attached causes are scrubbed of the key and of `Bearer ...`/`X-Axis-Api-Key` shapes; the key is never in a URL.
5. **Errors map from problem+json** to a typed hierarchy keyed by the problem `code` (else the type URI's last segment, else the status): policy_denied, approval_required, rate_limited (with `retryAfter`), budget_exceeded, validation_failed (with `errors`), unauthenticated, forbidden, not_found, conflict, internal. Request id (`x-request-id`) and trace id (`x-trace-id`, `traceparent`, problem `trace_id`) are on every error and in `onResponse`.
6. **SSE** (`runs.stream`): spec-conformant parser (chunk splits, CR/LF/CRLF, comments, `retry:`, multi-line data, BOM); reconnect with `Last-Event-ID` and `after_sequence`, duplicate suppression by sequence, ends when the connection closes and the run is terminated, gives up after N empty/failed connections.

These rules are mutation-checked (`scripts/mutation-sdk.mjs`, 19 mutants).
