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
