# `axis` CLI

Status: **Prototype** (unit-tested against a mock server generated from the OpenAPI; the Phase 7 e2e (`make e2e-phase7`) drives the real gateway through the spawned `axis` binary). Package `@axis/cli` (`apps/cli`), binary `axis`, implemented on `@axis/sdk`. See ADR 0042.

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
- `policies activate`, `registry *` and `marketplace *` call the OpenAPI 1.2.0 operations (ADR 0053). `registry sign` / `keygen` are OFFLINE: the Ed25519 key is a local 0600 PEM file that is never sent anywhere, and the provenance carries the platform compiler's own lint results. `marketplace install` never installs without consent: no `--yes` / `--consent-digest` prints the permission diff and exits 2; the install echoes the version, hash and digest of the PREVIEW, never caller-typed values. `whoami` calls `GET /v1/me` (tenant, role, credential kind, scopes). `axis api <operationId>` calls any operation directly.
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

| Option             | Description                             |
| ------------------ | --------------------------------------- |
| `--with-key-stdin` | Read the API key from stdin             |
| `--device`         | Device-flow sign-in (not available yet) |
| `--no-verify`      | Save without calling the API            |

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

| Option                    | Description                                       |
| ------------------------- | ------------------------------------------------- |
| `--no-validate`           | Skip the local check (the server still validates) |
| `--idempotency-key <key>` | Idempotency key (default: generated)              |

### `axis blueprints list`

List blueprint versions

```
axis blueprints list [options]
```

| Option        | Description       |
| ------------- | ----------------- |
| `--limit <n>` | Page size (1-200) |
| `--all`       | Follow every page |

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

| Option                     | Description                                       |
| -------------------------- | ------------------------------------------------- |
| `--input <json             | file>`                                            | Run input: inline JSON object, a file path, or - for stdin |
| `--idempotency-key <key>`  | Idempotency key (default: generated)              |
| `--wait`                   | Wait for the run to terminate (exit 5 on timeout) |
| `--tail`                   | Stream the run's events until it terminates       |
| `--wait-timeout <seconds>` | Give up waiting after this long (default 300)     |

### `axis run tail`

Stream a run's events live

```
axis run tail <run-id> [options]
```

Reconnects automatically with Last-Event-ID. With --json prints one JSON event per line.

| Option               | Description                      |
| -------------------- | -------------------------------- |
| `--after <sequence>` | Resume after this event sequence |

### `axis run get`

Show a run

```
axis run get <run-id> [options]
```

### `axis run explain`

Explain a run from its audit trail (AGIL; read-only)

```
axis run explain <run-id> [options]
```

### `axis run list`

List runs

```
axis run list [options]
```

| Option               | Description              |
| -------------------- | ------------------------ |
| `--limit <n>`        | Page size (1-200)        |
| `--all`              | Follow every page        |
| `--state <state>`    | Filter by process state  |
| `--blueprint <name>` | Filter by blueprint name |

### `axis run signal`

Send a signal to a process in a run

```
axis run signal <run-id> <PAUSE|RESUME|TERM|KILL|INTERRUPT> [options]
```

| Option            | Description                                      |
| ----------------- | ------------------------------------------------ |
| `--pid <pid>`     | Target process (default: the run's init process) |
| `--reason <text>` | Reason recorded in the audit log                 |

### `axis run cancel`

Stop a run (TERM; --force sends KILL)

```
axis run cancel <run-id> [options]
```

| Option            | Description                      |
| ----------------- | -------------------------------- |
| `--force`         | Send KILL instead of TERM        |
| `--pid <pid>`     | Target process                   |
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

| Option              | Description       |
| ------------------- | ----------------- |
| `--limit <n>`       | Page size (1-200) |
| `--all`             | Follow every page |
| `--status <status>` | Filter by status  |

### `axis approvals get`

Show one approval

```
axis approvals get <approval-id> [options]
```

### `axis approvals approve`

Approve a pending approval

```
axis approvals approve <approval-id> [options]
```

| Option                    | Description                          |
| ------------------------- | ------------------------------------ |
| `--comment <text>`        | Comment recorded with the decision   |
| `--idempotency-key <key>` | Idempotency key (default: generated) |

### `axis approvals deny`

Deny (reject) a pending approval

```
axis approvals deny <approval-id> [options]
```

| Option                    | Description                          |
| ------------------------- | ------------------------------------ |
| `--comment <text>`        | Comment recorded with the decision   |
| `--idempotency-key <key>` | Idempotency key (default: generated) |

### `axis policies list`

List policy packs

```
axis policies list [options]
```

| Option        | Description       |
| ------------- | ----------------- |
| `--limit <n>` | Page size (1-200) |
| `--all`       | Follow every page |

### `axis policies test`

Evaluate a hypothetical request against a policy file

```
axis policies test <policy-file> --request <json|file> [options]
```

Nothing is executed. Exit 4 when the decision is DENY, 5 when it is REQUIRE_APPROVAL.

| Option           | Description |
| ---------------- | ----------- |
| `--request <json | file>`      | The request: {enforcement_point, action?, context} |

### `axis policies publish`

Validate, compile and publish a policy pack version

```
axis policies publish <policy-file> [options]
```

### `axis policies activate`

Activate a published policy pack version

```
axis policies activate <name>@<version | version-id> [options]
```

Makes the published version the tenant's active version of that pack; the Risk Kernel enforces it from then on.

### `axis audit events`

Query audit events

```
axis audit events [options]
```

| Option                  | Description                   |
| ----------------------- | ----------------------------- |
| `--limit <n>`           | Page size (1-200)             |
| `--all`                 | Follow every page             |
| `--trace-id <32 hex>`   | Only events of this trace     |
| `--decision <decision>` | Only this decision            |
| `--from-seq <seq>`      | Start at this sequence number |

### `axis audit explain`

Explain one audited decision (AGIL; read-only)

```
axis audit explain <seq> [options]
```

### `axis audit verify`

Verify the hash chain (exit 1 if it is broken)

```
axis audit verify [options]
```

| Option             | Description              |
| ------------------ | ------------------------ |
| `--from-seq <seq>` | First sequence to verify |
| `--to-seq <seq>`   | Last sequence to verify  |

### `axis audit export`

Export audit events as NDJSON

```
axis audit export [options]
```

| Option                  | Description                                                 |
| ----------------------- | ----------------------------------------------------------- |
| `--out <file>`          | Write to a file (mode 0600) instead of stdout               |
| `--verify`              | Verify the chain first and refuse to export if it is broken |
| `--trace-id <32 hex>`   | Only events of this trace                                   |
| `--decision <decision>` | Only this decision                                          |
| `--from-seq <seq>`      | Start at this sequence number                               |

### `axis kill-switch on`

Engage a kill-switch

```
axis kill-switch on <tenant|agent|tool> [target] [options]
```

| Option            | Description                      |
| ----------------- | -------------------------------- |
| `--reason <text>` | Reason recorded in the audit log |

### `axis kill-switch off`

Release a kill-switch

```
axis kill-switch off <tenant|agent|tool> [target] [options]
```

| Option            | Description                      |
| ----------------- | -------------------------------- |
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

| Option              | Description                                      |
| ------------------- | ------------------------------------------------ |
| `--from <iso-time>` | Period start (default: first of this month, UTC) |
| `--to <iso-time>`   | Period end (default: now)                        |
| `--group-by <key>`  | Group rows                                       |

### `axis evals run`

Queue an eval run of a suite against a blueprint version

```
axis evals run <suite> <[namespace/]name@version> [options]
```

The run is bound to the version's content hash and executed by a registered runner. With --wait the exit code is 0 only if the run passed.

| Option                     | Description                                                          |
| -------------------------- | -------------------------------------------------------------------- |
| `--mode <mode>`            | Run mode (default ci)                                                |
| `--idempotency-key <key>`  | Idempotency key (default: generated)                                 |
| `--wait`                   | Wait for the run to finish (exit 1 if it did not pass, 5 on timeout) |
| `--wait-timeout <seconds>` | Give up waiting after this long (default 300)                        |

### `axis evals start`

Alias of `evals run`

```
axis evals start <suite> <[namespace/]name@version> [options]
```

| Option                     | Description                                                          |
| -------------------------- | -------------------------------------------------------------------- |
| `--mode <mode>`            | Run mode (default ci)                                                |
| `--idempotency-key <key>`  | Idempotency key (default: generated)                                 |
| `--wait`                   | Wait for the run to finish (exit 1 if it did not pass, 5 on timeout) |
| `--wait-timeout <seconds>` | Give up waiting after this long (default 300)                        |

### `axis evals get`

Show one eval run with its scores

```
axis evals get <eval-run-id> [options]
```

### `axis evals wait`

Wait for an eval run to finish

```
axis evals wait <eval-run-id> [options]
```

| Option                     | Description                                   |
| -------------------------- | --------------------------------------------- |
| `--wait-timeout <seconds>` | Give up waiting after this long (default 300) |

### `axis evals list`

List eval runs, newest first

```
axis evals list [options]
```

| Option               | Description              |
| -------------------- | ------------------------ |
| `--limit <n>`        | Page size (1-200)        |
| `--all`              | Follow every page        |
| `--suite <ref>`      | Only this suite          |
| `--blueprint <name>` | Only this blueprint name |
| `--status <status>`  | Only this status         |

### `axis evals compare`

Compare a run with the baseline (delta, regression, paired significance)

```
axis evals compare <eval-run-id> [options]
```

Exits 4 when the run regressed beyond the suite's tolerance.

### `axis evals gate`

Ask the release gate whether a blueprint version may be released

```
axis evals gate <[namespace/]name@version> [options]
```

Fail-closed: exits 0 only when every required suite has a fresh, intact, passing run of this exact content hash by a registered runner with no regression against the baseline. Exits 4 and lists every reason otherwise.

| Option                      | Description                                                                           |
| --------------------------- | ------------------------------------------------------------------------------------- |
| `--suite <ref[:threshold]>` | An additional required suite (the blueprint's own spec.evals.suites are always asked) |

### `axis evals datasets list`

List dataset versions

```
axis evals datasets list [options]
```

| Option          | Description       |
| --------------- | ----------------- |
| `--name <name>` | Only this dataset |

### `axis evals datasets get`

Show a dataset version

```
axis evals datasets get <name> [version|latest] [options]
```

### `axis evals datasets create`

Create the next version of a dataset from a YAML/JSON file

```
axis evals datasets create <file|-> [options]
```

The file holds {name, cases: [{id, input, expected?, tags?, metadata?}], phi?, description?}. A phi dataset is redacted before it is stored.

| Option                    | Description                          |
| ------------------------- | ------------------------------------ |
| `--idempotency-key <key>` | Idempotency key (default: generated) |

### `axis evals suites list`

List suites

```
axis evals suites list [options]
```

### `axis evals suites get`

Show a suite

```
axis evals suites get <name@version> [options]
```

### `axis evals suites create`

Create a suite from a YAML/JSON file

```
axis evals suites create <file|-> [options]
```

The file holds {ref, dataset_ref, graders, pass_threshold, tolerance?, min_case_score?, settings?, ...}.

| Option                    | Description                          |
| ------------------------- | ------------------------------------ |
| `--idempotency-key <key>` | Idempotency key (default: generated) |

### `axis evals baseline list`

Baseline history

```
axis evals baseline list <blueprint-name> <suite> [options]
```

### `axis evals baseline set`

Make a passed run the baseline (admin)

```
axis evals baseline set <eval-run-id> [options]
```

| Option                    | Description                          |
| ------------------------- | ------------------------------------ |
| `--idempotency-key <key>` | Idempotency key (default: generated) |

### `axis evals review tasks`

Tasks you may work on

```
axis evals review tasks [options]
```

| Option                | Description     |
| --------------------- | --------------- |
| `--state <state>`     | Only this state |
| `--run <eval-run-id>` | Only this run   |

### `axis evals review claim`

Claim a task

```
axis evals review claim <task-id> [options]
```

### `axis evals review grade`

Grade a claimed task

```
axis evals review grade <task-id> --score <0-1> --comment <text> [options]
```

| Option             | Description                                          |
| ------------------ | ---------------------------------------------------- |
| `--score <0-1>`    | Your score                                           |
| `--comment <text>` | Why (redacted for personal data before it is stored) |

### `axis evals review skip`

Give a claimed task back

```
axis evals review skip <task-id> --reason <text> [options]
```

| Option            | Description     |
| ----------------- | --------------- |
| `--reason <text>` | Why you skip it |

### `axis evals sampling list`

Sampling configurations

```
axis evals sampling list [options]
```

### `axis evals sampling put`

Create or replace a sampling configuration (admin)

```
axis evals sampling put <sampling-id> <file|-> [options]
```

### `axis evals sampling summary`

History and alert state of the samples

```
axis evals sampling summary [options]
```

| Option               | Description         |
| -------------------- | ------------------- |
| `--blueprint <name>` | Only this blueprint |
| `--suite <ref>`      | Only this suite     |

### `axis evals runners list`

Registered runners

```
axis evals runners list [options]
```

### `axis evals runners register`

Register a runner id (admin)

```
axis evals runners register <runner-id> [options]
```

| Option                 | Description |
| ---------------------- | ----------- |
| `--description <text>` | What it is  |

### `axis evals runners revoke`

Revoke a runner (admin, one-way)

```
axis evals runners revoke <runner-id> [options]
```

### `axis registry keygen`

Create an Ed25519 publisher key pair (offline)

```
axis registry keygen [options]
```

The private key is written to a local file and never sent anywhere. Register the printed public key with `axis registry add-key`.

| Option         | Description                                                 |
| -------------- | ----------------------------------------------------------- |
| `--out <file>` | Private key file to create (PEM, mode 0600; must not exist) |

### `axis registry namespaces`

List the namespaces your tenant owns

```
axis registry namespaces [options]
```

### `axis registry claim`

Claim a namespace for your tenant (admin)

```
axis registry claim <namespace> [options]
```

### `axis registry keys`

List a namespace's publisher keys

```
axis registry keys <namespace> [options]
```

### `axis registry add-key`

Register a publisher public key for a namespace (admin)

```
axis registry add-key <namespace> (--public-key <b64url> | --key <pem>) [options]
```

| Option                  | Description                                      |
| ----------------------- | ------------------------------------------------ |
| `--public-key <b64url>` | Raw Ed25519 public key, base64url                |
| `--key <pem>`           | Derive the public key from this private key file |

### `axis registry sign`

Sign an ABL file offline: detached signature plus provenance attestation

```
axis registry sign <abl-file> [options]
```

Validates and lints the file with the platform compiler, then signs with the local key. Output is the bundle `registry publish` accepts.

| Option               | Description                                    |
| -------------------- | ---------------------------------------------- |
| `--namespace <ns>`   | Registry namespace (yours)                     |
| `--key <pem>`        | Ed25519 private key file (PKCS#8 PEM)          |
| `--builder <id>`     | Builder id recorded in the provenance          |
| `--source-ref <ref>` | Source reference recorded in the provenance    |
| `--out <file>`       | Write the signed bundle here instead of stdout |

### `axis registry publish`

Publish a signed blueprint version (immutable; verified before it is stored)

```
axis registry publish <bundle.json | abl-file> [options]
```

| Option               | Description                                 |
| -------------------- | ------------------------------------------- |
| `--namespace <ns>`   | Registry namespace (yours)                  |
| `--key <pem>`        | Ed25519 private key file (PKCS#8 PEM)       |
| `--builder <id>`     | Builder id recorded in the provenance       |
| `--source-ref <ref>` | Source reference recorded in the provenance |

### `axis registry versions`

List the versions of a blueprint with their state

```
axis registry versions <namespace>/<name> [options]
```

### `axis registry yank`

Yank a version so it stops resolving (admin)

```
axis registry yank <namespace>/<name>@<version> [options]
```

| Option            | Description    |
| ----------------- | -------------- |
| `--reason <text>` | Why (recorded) |

### `axis registry resolve`

Resolve namespace/name@range and verify it (hash, signature, provenance)

```
axis registry resolve <namespace>/<name>@<range> [options]
```

Exit 1 with the failed check codes when the best version does not verify; it never falls back to an older one.

### `axis marketplace search`

Search the catalog

```
axis marketplace search [query] [options]
```

| Option              | Description        |
| ------------------- | ------------------ |
| `--category <name>` | Only this category |

### `axis marketplace show`

Show one listing

```
axis marketplace show <namespace>/<name> [options]
```

### `axis marketplace preview`

Show what installing would grant: permission diff, findings, consent digest (admin)

```
axis marketplace preview <namespace>/<name>[@range] [options]
```

### `axis marketplace install`

Install a listing with explicit consent to the permission diff (admin)

```
axis marketplace install <namespace>/<name>[@range] [options]
```

Without --yes or --consent-digest the preview is printed and nothing is installed (exit 2).

| Option                      | Description                                      |
| --------------------------- | ------------------------------------------------ |
| `--yes`                     | Consent to the permissions listed by the preview |
| `--consent-digest <digest>` | Consent to exactly the diff with this digest     |

### `axis marketplace installs`

List your tenant's installs

```
axis marketplace installs [options]
```

### `axis marketplace uninstall`

Uninstall a listing (admin)

```
axis marketplace uninstall <namespace>/<name> [options]
```

### `axis api`

Call any API operation by operationId

```
axis api <operationId> [path args...] [options]
```

Escape hatch for endpoints without a dedicated command. Path parameters are positional, in order.

| Option                 | Description                  |
| ---------------------- | ---------------------------- |
| `--param <name=value>` | Query parameter (repeatable) |
| `--body <json          | file>`                       | Request body (inline JSON, a file path, or - for stdin) |

### `axis completion`

Print a shell completion script

```
axis completion <bash|zsh|fish> [options]
```

<!-- reference:end -->
