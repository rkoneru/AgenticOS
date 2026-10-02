# AXIS SDKs (TypeScript and Python)

Status: **Prototype**. Both SDKs are generated from the frozen OpenAPI (`packages/contracts/openapi/axis-v1.yaml`) plus a hand-written ergonomic layer; tested against a mock server derived from the spec, not yet against the real gateway (Phase 7 e2e; `docs/NEEDS.md` #239). Design: ADR 0040 (generator), 0041 (transport safety), 0043 (mutation checks).

|                 | TypeScript                                                                            | Python                                                                    |
| --------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Package         | `@axis/sdk` (`packages/sdk-ts`), no runtime dependencies, uses platform `fetch`       | `axis-sdk` (`sdk/python`, import `axis_sdk`), depends on `httpx` only     |
| Client          | `new Axis({ apiKey, baseUrl })`                                                       | `Axis(api_key, base_url=...)`, `AsyncAxis(...)`                           |
| Generated layer | `src/generated/` (types, operation table, one method per operationId at `axis.api.*`) | `_generated/` (TypedDicts, operation table, sync + async `api.*` methods) |

## Regenerating

```bash
node scripts/generate-sdks.mjs          # rewrite generated files
node scripts/generate-sdks.mjs --check  # exit 1 if they are stale (what the drift tests run)
```

If the spec gains paths (AGIL, registry, ...), regenerate, then add resource methods: the tests that map every `operationId` to an ergonomic call fail until you do.

## TypeScript

```ts
import { Axis, PolicyDeniedError } from "@axis/sdk";

const axis = new Axis({
  apiKey: process.env.AXIS_API_KEY,
  baseUrl: "https://api.us-east-1.axis.example/v1",
});

const run = await axis.runs.start({ blueprint: "claims-triage@1.2.0", input: { claim_id: "c-1" } });
for await (const event of axis.runs.stream(run.id)) console.log(event.sequence, event.type); // SSE, reconnects with Last-Event-ID
const done = await axis.runs.wait(run.id, { timeoutMs: 60_000 });
await axis.runs.cancel(run.id, { reason: "operator" });

for await (const a of axis.approvals.iterate({ status: "pending" }))
  await axis.approvals.approve(a.id, "ok");
const verdict = await axis.audit.verify();
await axis.killSwitches.engage("agent", "claims-triage", "incident 42");
try {
  await axis.runs.start({ blueprint: "x@1" });
} catch (e) {
  if (e instanceof PolicyDeniedError) console.log(e.traceId);
}
```

## Python

```python
from axis_sdk import Axis, PolicyDeniedError

with Axis(
    api_key=os.environ["AXIS_API_KEY"], base_url="https://api.us-east-1.axis.example/v1"
) as axis:
    run = axis.runs.start("claims-triage@1.2.0", {"claim_id": "c-1"})
    for event in axis.runs.stream(run["id"]):
        print(event["sequence"], event["type"])
    axis.runs.wait(run["id"], timeout=60)
    for approval in axis.approvals.iterate(status="pending"):
        axis.approvals.approve(approval["id"], "ok")
```

`AsyncAxis` mirrors every call with `await` / `async for`.

## Surface

`runs` (start, get, list, iterate, signal, cancel, events, all_events, wait, stream), `blueprints` (list, iterate, get, publish), `approvals` (list, iterate, decide, approve, reject), `policies` (list, iterate, publish, test), `audit` (events, iterate, verify), `kill_switches`/`killSwitches` (list, set, engage, release), `usage.get`, `evals.start`; `axis.api.<operationId>` for everything else. Python uses snake_case; the usage query parameter `from` is `from_`.

## Behaviour (all tested)

- **Retries**: network errors and 408/429/5xx, exponential backoff with full jitter, `Retry-After` honoured, only for idempotent calls or POSTs carrying an `Idempotency-Key` (auto-generated once per call and reused on retry). A POST without a key (`publishPolicyPack`) is never retried; the read-only POSTs `testPolicy` and `verifyAuditChain` are.
- **Errors**: RFC 7807 problem+json mapped to `AxisError` > `AxisApiError` > `PolicyDeniedError`, `ApprovalRequiredError`, `RateLimitError` (`retryAfter`), `BudgetExceededError`, `ValidationError` (`errors`), `AuthenticationError`, `ForbiddenError`/`PermissionError`, `NotFoundError`, `ConflictError`, `InternalServerError`; transport: `AxisConnectionError`, `AxisTimeoutError`, `AxisWaitTimeoutError`, (TS) `AxisAbortError`. Each carries `status`, `code`, `requestId`, `traceId`.
- **Ids**: `onResponse` / `on_response` receives operation id, status, request id, trace id, attempts.
- **Timeouts**: per attempt, default 30 s; per call override.
- **Security**: API key sent as `X-Axis-Api-Key` (or `Authorization: Bearer` for a token) only to the configured base origin; cross-origin and https-to-http redirects are refused; https required (loopback excepted); no tenant option (it comes from the credential); credentials are redacted from `repr`/`toString`, JSON, pickles, inspect, error messages and causes.
- **Validation**: off by default. TS accepts `validateRequest` / `validateResponse` hooks (for example Ajv over the OpenAPI schemas).

## Tests

TS: `pnpm --filter @axis/sdk cov` (vitest, 85% gate; 118+ tests). Python: `uv run pytest sdk/python` (154 tests, 99% coverage, 85% gate). Both build an in-test mock server from the OpenAPI that validates every request against the spec and answers with synthesized responses; coverage-of-spec tests assert every operationId is reachable from the generated and the ergonomic layers. Mutation check: `node scripts/mutation-sdk.mjs`.

## OpenAPI 1.2.0 additions (ADR 0053)

`ax.me()`, `approvals.get`, `policies.activate`, `registry.{namespaces,claim,keys,addKey,publish,versions,yank,resolve}`, `marketplace.{listings,listing,preview,install,installWithConsent,installs,uninstall}` (TS and Python, sync and async). `registry.publish` takes a signed bundle; the SDKs never hold a key. The Phase 7 e2e runs the SDKs against the real gateway (SSE shape confirmed: `event: run_event`, `id` = sequence, final `event: end`).
