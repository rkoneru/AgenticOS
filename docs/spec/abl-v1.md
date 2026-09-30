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
