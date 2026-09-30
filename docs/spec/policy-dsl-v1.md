# Policy DSL v1

Status: **Frozen (v1)** · Schema: `packages/contracts/schemas/policy-v1.schema.json` · Examples: `packages/contracts/examples/policy/`

A `PolicyPack` is YAML that the policy compiler (Phase 2) turns into Rego (see ADR-0004). It generalises the six fixed
trading gates of the original Risk Kernel into tenant-configurable gate types.

## Decision model

| Outcome                | Meaning                                                                        |
| ---------------------- | ------------------------------------------------------------------------------ |
| `ALLOW`                | Action may proceed.                                                            |
| `DENY`                 | Action is refused.                                                             |
| `REQUIRE_APPROVAL`     | Action is parked in the approval queue; proceeds only on approval within SLA.  |
| `ALLOW_WITH_REDACTION` | Action proceeds with the listed fields/detectors redacted from inputs/outputs. |

**Fail-closed.** `spec.defaultDecision` can only be `DENY`. The result is `DENY` when no rule matches, when evaluation errors or
times out, when a referenced gate fails, when a policy is missing, and when a consumer receives an unknown/unspecified decision.
An approval that times out is `DENY` (`onTimeout` accepts only `DENY`).

## Enforcement points

`tool_call`, `mcp_call`, `model_call`, `memory_write`, `message_send`, `code_exec`, `browser_exec`. A rule lists the points it applies to.

## Rules

`when` is a condition tree: `all` / `any` / `not` / leaf `{field, op, value}` with ops
`eq neq in not_in gt gte lt lte matches exists`. Fields are dot-paths over the request context (`tool.name`, `args.amount`,
`tenant.id`, `data.phi`, …). A rule without `when` matches every request at its enforcement points.

**Conflict resolution** (compiler must implement; golden-tested in Phase 2): among matching rules the highest `priority` wins
(default 100); at equal priority the most restrictive wins: `DENY > REQUIRE_APPROVAL > ALLOW_WITH_REDACTION > ALLOW`.
If the winner is an ALLOW-family decision and any gate listed in its `gates` fails, the result is `DENY`.
Schema-level consistency: `REQUIRE_APPROVAL` needs `approval`; `ALLOW_WITH_REDACTION` needs `redact`; `ALLOW`/`DENY` carry neither.

## Gates

| Type          | Generalises    | Params                                                  |
| ------------- | -------------- | ------------------------------------------------------- |
| `kill_switch` | kill-switch    | `scope`: global, tenant, agent, tool                    |
| `staleness`   | data staleness | `field`, `maxAgeSeconds`                                |
| `amount_cap`  | order size     | `field`, `max`                                          |
| `target_cap`  | venue cap      | `field`, `max`, `perTarget`                             |
| `budget`      | drawdown       | `metric`, `window`, `hard`/`soft`                       |
| `rate_limit`  | rate-of-fire   | `max`, `windowSeconds`, `key` (tenant/agent/tool/actor) |

Kill-switch state is evaluated by the gate before policy evaluation and is not part of the Rego bundle (ADR-0004).

## Versioning

Same rules as ABL: additive changes within `v1` (ADR required post-freeze), breaking changes create `policy.axis.dev/v2`.
Published pack versions are immutable (DB trigger); `metadata.version` is strict `x.y.z`.

## Gate semantics (Risk Kernel, Phase 2)

Gates are evaluated by the kernel, not by Rego. A gate that cannot be evaluated (missing or wrong-typed field, unknown type,
store error) **fails**, which forces `DENY`.

- `kill_switch`: fails while a kill-switch is engaged at the gate's `scope` (global, tenant, agent, tool). Engaged kill-switches
  also deny before policy evaluation, regardless of which gates a rule lists.
- `staleness`: the value at `field` (ISO-8601 string or epoch milliseconds) must be no older than `maxAgeSeconds` (and not in the future by more than 5 s).
- `amount_cap`: the numeric value at `field` must be <= `max`.
- `target_cap`: cumulative sum of the numeric value at `field` per target (target = `args.target`, else `tool.name`) per tenant
  and agent per UTC day must stay <= `max`; `perTarget: false` uses one counter across targets. Capacity is **reserved
  atomically** when the gate evaluates (a single check-and-add, so parallel requests cannot jointly exceed the cap) and
  **rolled back** if a later gate fails or the audit append fails, so a denied request never consumes capacity.
- `budget`: the spent amount of `metric` in `window` (maintained by TKI) must be below `hard`; crossing `soft` passes with a warning reason.
- `rate_limit`: sliding window of `windowSeconds`; the request fails when it would make more than `max` hits for the `key` (tenant, agent, tool or actor).

## Missing and mistyped data (three-valued semantics)

Conditions are evaluated with three values: **true**, **false** and **unknown**. A leaf over a field that is absent, or
present with a type the operator cannot judge (a string under `gt`, a number under `matches`), is _unknown_. `exists` is always
definite. `not` of unknown is unknown; `all` is false if any operand is false, else unknown if any is unknown; `any` is true if
any operand is true, else unknown if any is unknown.

A rule matches when its condition is **definitely true** - except `DENY` rules, which match when the condition is **possibly
true** (true or unknown). So missing data can only push a request toward `DENY`: an `ALLOW`, `ALLOW_WITH_REDACTION` or
`REQUIRE_APPROVAL` rule never matches on unknown data, and a `DENY` rule is never skipped because a field was absent. Example:
`deny when args.region neq "EU"` denies a request with no `args.region` at all.

Consequence: "less data never gains an allow and never loses a deny" for every operator except `exists` (which is definite,
so "allow only if the field is absent" is expressible). This is property-tested against an independent reference evaluator
and differentially against real OPA.

## `matches` uses RE2 semantics

Policies run in OPA, whose regular expressions are Go **RE2**, not JavaScript. The compiler validates every `matches` pattern with
a real RE2 parser (`re2js`, which agrees with OPA's `regex.is_valid` on every pattern we probed) and rejects patterns RE2 rejects:
lookaround, backreferences, `\\e`, repeat counts over 1000, `[a-\\d]`, JS escapes such as `\\u0041`, and so on. Accepted patterns
have **RE2 meaning**: POSIX classes (`[[:alpha:]]`), `\\A` / `\\z`, `\\Q..\\E`, inline flags `(?i)`, named groups, and `.` excluding
only `\\n`. Do not assume JavaScript behaviour. RE2 guarantees linear-time matching, so ReDoS is not a concern.

As defence in depth the generated Rego guards every `matches` with `regex.is_valid(pattern)`: if OPA ever disagrees with the
compile-time check, the leaf is UNKNOWN at runtime (a DENY rule fires, an ALLOW rule does not) instead of silently not matching.

## Types, priority and pack composition

- `eq`, `neq`, `in` and `not_in` are judged only when the field's type matches the value's type (or one of the listed values'
  types). A field of another type (an array, object, `null`, a number where a string is expected) is UNKNOWN, not "not equal".
  So `args.dest not_in ["evil.com"]` does **not** match `dest: ["evil.com"]`, and a `deny when amount eq 100` fires for `"100"`.
- **Priority is not overridden by unknown data.** A possibly-true `DENY` at priority 100 is outranked by a definitely-true `ALLOW`
  at priority 200; give deny rules the priority they need. Among equal priorities the most restrictive decision wins.
- Packs compose in one flat namespace (`<pack>/<rule>`): all rules from all loaded packs compete by priority, so a higher-priority
  ALLOW in one pack can outrank a DENY in another. Review pack priorities together.
- Field paths are compiled with bracket notation (`input["args"]["in"]`), so any segment, including Rego keywords, is safe.
