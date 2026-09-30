# ABL v1 — AXIS Blueprint Language

Status: **Frozen (v1)** · Schema: `packages/abl/schema/abl-v1.schema.json` · Examples: `packages/abl/examples/`

An ABL document is a YAML (or JSON) agent blueprint: the declarative "executable format" of AXIS. The compiler
(Phase 2) turns it into a runtime manifest. This spec defines the **document**; semantics of compilation are in Phase 2.
Origin: derived from the master prompt; the original `ABL-SPEC.md` was not available (see `docs/NEEDS.md` #1).

## Shape

```yaml
apiVersion: abl.axis.dev/v1 # const
kind: Agent # const
metadata: { name, version, description?, owner?, labels? }
spec:
  riskClassification: # REQUIRED (EU AI Act)
  model: { primary, fallbacks? } # REQUIRED
  instructions: { system } # REQUIRED
  routing?, tools?, memory?, budgets?, process?, policy?, channels?, data?, evals?
```

Unknown fields are errors (`additionalProperties: false` everywhere) so typos cannot silently weaken governance.

## Rules worth knowing

- **Risk classification is mandatory.** `level` ∈ `minimal | limited | high`. `unacceptable` (prohibited practices) is not
  expressible; such a blueprint cannot be published. `limited` and `high` require `transparencyNotice`. `high` additionally
  requires `humanOversight.required: true` with at least one `approverRoles` entry.
- **Names** are DNS-label style (`^[a-z][a-z0-9-]{1,62}$`). **Versions** are SemVer 2.0. **Refs** are `name[/scope]@range`.
- **Tools** declare `kind` (`function | mcp | code | browser | channel | agent`) and `sideEffects`
  (`none | read | write | external`; omitted means `write`). `mcp` tools require `mcpServer`. Declaring a tool grants nothing:
  every call is still gated by the Risk Kernel (default-deny).
- **Models** are provider-neutral (`anthropic | openai | google | azure-openai | bedrock | openai-compatible`). Keys are never in ABL;
  they come from the tenant's BYO secret store.
- **Routing** lists NEXUS stages in order (`cache, rules, mpm, rag, llm`); the first to resolve short-circuits.
- **Budgets** have `soft` (warn/notify) and `hard` (TKI terminates with `budget_exceeded`) caps.
- **Process** configures restart policy and supervision (`one-for-one | one-for-all | rest-for-one`).

## Versioning rules

- `apiVersion` is the language version. **Additive, backwards-compatible changes** (new optional field, new enum value
  that old runtimes may reject safely) bump the schema `$id` minor within `v1` and require an ADR after the freeze.
- **Breaking changes** create `abl.axis.dev/v2` with a new schema file; v1 documents keep compiling for at least two minor platform releases.
- `metadata.version` is the blueprint's own SemVer. Published versions are **immutable** (DB trigger); publishing the same
  version twice is a conflict.

## Validation

`@axis/abl` exports `validateAbl` / `validateAblYaml`. Every example under `examples/invalid/` is paired in tests with the
specific keyword and path it must fail on.

## Compilation and lint rules

`compileAbl(doc)` (also `compileAblYaml(text)`) turns a document into a **RuntimeManifest v1** (shape fixed in
`docs/plans/phase-2.md`; JSON Schema in `packages/abl/manifest/runtime-manifest-v1.schema.json`, checked by
`validateManifest`). Steps: schema validation, then lint, then mapping.

- **Result.** `{ ok: true, manifest, findings }` (findings are warnings only), or `{ ok: false, issues, findings }`.
  `issues` are schema violations; `findings` are lint results. Any `error` finding makes the result `ok: false`.
- **Pure and deterministic.** No I/O, no clock, input never mutated, output shares no references with input. The same
  document yields a byte-identical manifest regardless of YAML/JSON key order. Array order is significant (tools, stages).
- **Keys** are snake_case (`cost_usd`, `long_term`, `max_output_tokens`). Every field is always present; defaults are applied:
  tool `side_effects` = `write`, tool `timeout_seconds` = 60, `routing.stages` = `["llm"]`, `memory.run` = true (others false),
  `process` = `never` / 0 restarts / 0 children / `one-for-one`, each budget metric `{soft: null, hard: null}`, `data.phi` = false,
  absent optionals (`endpoint`, `ref`, `mcp_server`, `transparency_notice`, `residency`, `process.timeout_seconds`) = `null`.
  Tool `description` and blueprint `metadata` other than name/version are not carried into the manifest.
- **`blueprint.content_hash`** is the sha256 (hex) of the canonical JSON of the _source ABL document_: keys sorted, no whitespace.
  `@axis/contracts` `canonicalize` rejects non-integers, but ABL has floats (`temperature: 0.1`, `costUsd: 2.5`), so `@axis/abl`
  has its own `canonicalJson` that writes numbers with ECMAScript `JSON.stringify` (shortest round-trip, deterministic).
- **Messages.** `formatIssues(issues)` renders schema issues as lines such as
  `spec.riskClassification.level: must be one of minimal, limited, high (got "unacceptable")`; `formatFindings` renders lint findings.
- **CLI.** `abl-lint <file...>` compiles each file, prints issues and findings, exits 1 if any file has errors (or is unreadable),
  2 on bad usage, else 0. Warnings print to stdout and do not affect the exit code.

### Lint codes

Codes are stable and never reused. `lintAbl(doc)` returns `{ code, severity, path, message }[]` (`path` is a JSON pointer);
it returns nothing for a schema-invalid document, so run `compileAbl` to get schema issues first.

| Code   | Severity | Rule                                     | Fires when                                                                           |
| ------ | -------- | ---------------------------------------- | ------------------------------------------------------------------------------------ |
| ABL001 | error    | `duplicate-tool-name`                    | two tools share a `name` (reported on each later one)                                |
| ABL002 | error    | `budget-soft-exceeds-hard`               | a budget has `soft` > `hard`                                                         |
| ABL003 | error    | `fallback-equals-primary`                | a fallback has the same provider, model and endpoint as the primary                  |
| ABL004 | error    | `high-risk-without-evals`                | `riskClassification.level` is `high` and `evals.suites` is missing or empty          |
| ABL005 | error    | `phi-without-residency`                  | `data.phi` is true and `data.residency` is unset                                     |
| ABL006 | error    | `agent-tool-self-reference`              | a tool of kind `agent` is named, or refs, the blueprint itself                       |
| ABL101 | warning  | `knowledge-bases-without-rag`            | `memory.knowledgeBases` is non-empty and `routing.stages` lacks `rag`                |
| ABL102 | warning  | `side-effect-tools-without-policy-packs` | a tool has `write`/`external` effects (omitted counts as `write`), no `policy.packs` |
| ABL103 | warning  | `no-hard-budget`                         | no budget metric has a `hard` limit                                                  |
| ABL104 | warning  | `voice-without-transparency-notice`      | `channels` has `voice` and there is no `transparencyNotice`                          |
| ABL105 | warning  | `rag-stage-without-knowledge-bases`      | `routing.stages` has `rag` and `memory.knowledgeBases` is empty                      |
| ABL106 | warning  | `routing-without-llm-stage`              | `routing.stages` is set but has no `llm` stage                                       |
| ABL107 | warning  | `max-restarts-ignored`                   | `maxRestarts` > 0 while `restartPolicy` is `never` (or omitted)                      |
| ABL108 | warning  | `duplicate-fallback`                     | the same fallback model is listed twice                                              |

The `mpm` routing stage is accepted by the compiler (the MPM component itself is a stub).
