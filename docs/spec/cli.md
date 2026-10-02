# `axis` CLI

Status: **Prototype** (built and tested against a mock server generated from the OpenAPI; not yet run against the real gateway, which the Phase 7 e2e does). Package `@axis/cli` (`apps/cli`), binary `axis`, implemented on `@axis/sdk`. See ADR 0042.

## Install and sign in

```bash
pnpm --filter @axis/cli build && node apps/cli/dist/bin.js --help   # or link the `axis` bin
echo "$AXIS_KEY" | axis login --with-key-stdin --base-url https://api.us-east-1.axis.example/v1
axis whoami
```

Credentials:

- `AXIS_API_KEY` (and optionally `AXIS_BASE_URL`, `AXIS_PROFILE`) win over the stored profile.
- `axis login` verifies the key (one authenticated read), then stores it in `$XDG_CONFIG_HOME/axis/config.json` (default `~/.config/axis/config.json`), file mode `0600` in a `0700` directory. A config file readable by group or others is refused (exit 3), like ssh does for private keys.
- There is deliberately **no `--api-key` flag** (shell history, process lists) and **no tenant flag**: the tenant is derived from the credential by the server.
- `axis login --device` is a stub: the v1 API has no device-authorization endpoint (NEEDS #236).

## Global options

`--json` (same as `--output json`), `-o/--output table|json|yaml`, `--profile`, `--base-url`, `--timeout <s>`, `--no-color` (also `NO_COLOR`; colour is only used on a TTY), `-h/--help`, `-V/--version`. Mutating commands send an auto-generated `Idempotency-Key` (override with `--idempotency-key`) and are retried safely by the SDK.

## Exit codes

| Code | Meaning                                                                                   |
| ---- | ----------------------------------------------------------------------------------------- |
| 0    | success                                                                                   |
| 1    | error: API error, validation failure, network, feature not yet available                  |
| 2    | usage error (bad command line)                                                            |
| 3    | authentication/permission failure; unsafe config file permissions                         |
| 4    | denied by policy (`policy_denied`; `policies test` returning `DENY`)                      |
| 5    | approval pending (`approval_required`, run waiting on approvals), or a `--wait` timed out |

`axis audit verify` exits 1 when the chain is broken. Errors print one line, request/trace ids and a hint; credentials are never printed (SDK redaction).

## Notes per area

- `blueprints validate` is offline: the same ABL compiler and linter as the platform, no network and no credentials. `blueprints publish` validates locally first and refuses to publish an invalid file.
- `run tail` streams SSE with automatic reconnect (`Last-Event-ID`); with `--json` it prints one event per line. `run replay` prints the full append-only event log with relative timestamps; nothing is executed.
- `policies activate`, `registry *` and `marketplace *` have no endpoint in API v1 and exit 1 with a "not yet available" message. If a regenerated spec gains a matching operation (operation id, tag or path containing `registry` / `marketplace` / `policy`+`activate`), the command calls it. `axis api <operationId>` calls any operation directly.
- Shell completions: `axis completion bash|zsh|fish`.

## Command reference

Generated from the command table by `axis docs`; `apps/cli/test/cli.test.ts` fails if this section drifts from `--help`.

<!-- reference:begin -->
### `axis login`

Store an API key for this machine

```
axis login [options]
```

The key is verified against the API, then saved under $XDG_CONFIG_HOME/axis/config.json with mode 0600. Alternatively set AXIS_API_KEY. The key is never accepted as a command-line argument (it would leak through shell history and process listings).

| Option | Description |
| --- | --- |
| `--with-key-stdin` | Read the API key from stdin |
| `--device` | Device-flow sign-in (not available yet) |
| `--no-verify` | Save without calling the API |

### `axis logout`

Remove the stored API key of a profile

```
axis logout [options]
```

### `axis whoami`

Show the active profile and check the credential

```
axis whoami [options]
```

### `axis blueprints validate`

Validate and lint ABL files locally (offline)

```
axis blueprints validate <file...> [options]
```

Uses the same compiler and linter as the platform; needs no credentials or network.

### `axis blueprints publish`

Validate locally, then publish a blueprint version

```
axis blueprints publish <file> [options]
```

| Option | Description |
| --- | --- |
| `--no-validate` | Skip the local check (the server still validates) |
| `--idempotency-key <key>` | Idempotency key (default: generated) |

### `axis blueprints list`

List blueprint versions

```
axis blueprints list [options]
```

| Option | Description |
| --- | --- |
| `--limit <n>` | Page size (1-200) |
| `--all` | Follow every page |

### `axis blueprints get`

Show one blueprint version

```
axis blueprints get <name>@<version> [options]
```

### `axis run start`

Start a run of a published blueprint

```
axis run start <name>@<version> [options]
```

| Option | Description |
| --- | --- |
| `--input <json|file>` | Run input: inline JSON object, a file path, or - for stdin |
| `--idempotency-key <key>` | Idempotency key (default: generated) |
| `--wait` | Wait for the run to terminate (exit 5 on timeout) |
| `--tail` | Stream the run's events until it terminates |
| `--wait-timeout <seconds>` | Give up waiting after this long (default 300) |

### `axis run tail`

Stream a run's events live

```
axis run tail <run-id> [options]
```

Reconnects automatically with Last-Event-ID. With --json prints one JSON event per line.

| Option | Description |
| --- | --- |
| `--after <sequence>` | Resume after this event sequence |

### `axis run get`

Show a run

```
axis run get <run-id> [options]
```

### `axis run list`

List runs

```
axis run list [options]
```

| Option | Description |
| --- | --- |
| `--limit <n>` | Page size (1-200) |
| `--all` | Follow every page |
| `--state <state>` | Filter by process state |
| `--blueprint <name>` | Filter by blueprint name |

### `axis run signal`

Send a signal to a process in a run

```
axis run signal <run-id> <PAUSE|RESUME|TERM|KILL|INTERRUPT> [options]
```

| Option | Description |
| --- | --- |
| `--pid <pid>` | Target process (default: the run's init process) |
| `--reason <text>` | Reason recorded in the audit log |

### `axis run cancel`

Stop a run (TERM; --force sends KILL)

```
axis run cancel <run-id> [options]
```

| Option | Description |
| --- | --- |
| `--force` | Send KILL instead of TERM |
| `--pid <pid>` | Target process |
| `--reason <text>` | Reason recorded in the audit log |

### `axis run replay`

Replay a finished run from its append-only event log

```
axis run replay <run-id> [options]
```

Prints the full event log in order with relative timestamps; nothing is executed.

### `axis approvals list`

List approvals

```
axis approvals list [options]
```

| Option | Description |
| --- | --- |
| `--limit <n>` | Page size (1-200) |
| `--all` | Follow every page |
| `--status <status>` | Filter by status |

### `axis approvals approve`

Approve a pending approval

```
axis approvals approve <approval-id> [options]
```

| Option | Description |
| --- | --- |
| `--comment <text>` | Comment recorded with the decision |
| `--idempotency-key <key>` | Idempotency key (default: generated) |

### `axis approvals deny`

Deny (reject) a pending approval

```
axis approvals deny <approval-id> [options]
```

| Option | Description |
| --- | --- |
| `--comment <text>` | Comment recorded with the decision |
| `--idempotency-key <key>` | Idempotency key (default: generated) |

### `axis policies list`

List policy packs

```
axis policies list [options]
```

| Option | Description |
| --- | --- |
| `--limit <n>` | Page size (1-200) |
| `--all` | Follow every page |

### `axis policies test`

Evaluate a hypothetical request against a policy file

```
axis policies test <policy-file> --request <json|file> [options]
```

Nothing is executed. Exit 4 when the decision is DENY, 5 when it is REQUIRE_APPROVAL.

| Option | Description |
| --- | --- |
| `--request <json|file>` | The request: {enforcement_point, action?, context} |

### `axis policies publish`

Validate, compile and publish a policy pack version

```
axis policies publish <policy-file> [options]
```

### `axis policies activate`

Activate a published policy pack version **(not yet available: the API has no endpoint for it)**

```
axis policies activate <name>@<version> [options]
```

### `axis audit events`

Query audit events

```
axis audit events [options]
```

| Option | Description |
| --- | --- |
| `--limit <n>` | Page size (1-200) |
| `--all` | Follow every page |
| `--trace-id <32 hex>` | Only events of this trace |
| `--decision <decision>` | Only this decision |
| `--from-seq <seq>` | Start at this sequence number |

### `axis audit verify`

Verify the hash chain (exit 1 if it is broken)

```
axis audit verify [options]
```

| Option | Description |
| --- | --- |
| `--from-seq <seq>` | First sequence to verify |
| `--to-seq <seq>` | Last sequence to verify |

### `axis audit export`

Export audit events as NDJSON

```
axis audit export [options]
```

| Option | Description |
| --- | --- |
| `--out <file>` | Write to a file (mode 0600) instead of stdout |
| `--verify` | Verify the chain first and refuse to export if it is broken |
| `--trace-id <32 hex>` | Only events of this trace |
| `--decision <decision>` | Only this decision |
| `--from-seq <seq>` | Start at this sequence number |

### `axis kill-switch on`

Engage a kill-switch

```
axis kill-switch on <tenant|agent|tool> [target] [options]
```

| Option | Description |
| --- | --- |
| `--reason <text>` | Reason recorded in the audit log |

### `axis kill-switch off`

Release a kill-switch

```
axis kill-switch off <tenant|agent|tool> [target] [options]
```

| Option | Description |
| --- | --- |
| `--reason <text>` | Reason recorded in the audit log |

### `axis kill-switch list`

List engaged kill-switches

```
axis kill-switch list [options]
```

### `axis usage`

Metered usage

```
axis usage [options]
```

| Option | Description |
| --- | --- |
| `--from <iso-time>` | Period start (default: first of this month, UTC) |
| `--to <iso-time>` | Period end (default: now) |
| `--group-by <key>` | Group rows |

### `axis evals start`

Run an eval suite against a blueprint version

```
axis evals start <suite> <name>@<version> [options]
```

### `axis registry publish`

Publish a blueprint to the registry **(not yet available: the API has no endpoint for it)**

```
axis registry publish <name>@<version> [options]
```

| Option | Description |
| --- | --- |
| `--param <name=value>` | Query parameter (repeatable) |
| `--body <json|file>` | Request body (inline JSON, a file path, or - for stdin) |

### `axis registry list`

List registry blueprints **(not yet available: the API has no endpoint for it)**

```
axis registry list [options]
```

| Option | Description |
| --- | --- |
| `--param <name=value>` | Query parameter (repeatable) |
| `--body <json|file>` | Request body (inline JSON, a file path, or - for stdin) |

### `axis registry get`

Show a registry blueprint **(not yet available: the API has no endpoint for it)**

```
axis registry get <name> [options]
```

| Option | Description |
| --- | --- |
| `--param <name=value>` | Query parameter (repeatable) |
| `--body <json|file>` | Request body (inline JSON, a file path, or - for stdin) |

### `axis marketplace search`

Search marketplace listings **(not yet available: the API has no endpoint for it)**

```
axis marketplace search [query] [options]
```

| Option | Description |
| --- | --- |
| `--param <name=value>` | Query parameter (repeatable) |
| `--body <json|file>` | Request body (inline JSON, a file path, or - for stdin) |

### `axis marketplace install`

Install a marketplace listing **(not yet available: the API has no endpoint for it)**

```
axis marketplace install <listing-id> [options]
```

| Option | Description |
| --- | --- |
| `--param <name=value>` | Query parameter (repeatable) |
| `--body <json|file>` | Request body (inline JSON, a file path, or - for stdin) |

### `axis api`

Call any API operation by operationId

```
axis api <operationId> [path args...] [options]
```

Escape hatch for endpoints without a dedicated command. Path parameters are positional, in order.

| Option | Description |
| --- | --- |
| `--param <name=value>` | Query parameter (repeatable) |
| `--body <json|file>` | Request body (inline JSON, a file path, or - for stdin) |

### `axis completion`

Print a shell completion script

```
axis completion <bash|zsh|fish> [options]
```
<!-- reference:end -->
