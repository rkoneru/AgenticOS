# ADR 0012: Phase 3 integration (approvals round-trip, TKI-supervised children, NEXUS in the run)

Status: accepted · Phase 3 component D · **No frozen contract changed** (`packages/contracts/FREEZE.json` untouched)

## Context

TKI, NEXUS and the approvals service were built as libraries against the frozen contracts. The Phase 3 exit needs one run in
which a parent spawns children under a supervisor with enforced budgets, routing stages show up in a trace, and a
`REQUIRE_APPROVAL` is granted, denied or expired by a human, end to end through the real Risk Kernel and audit chain.

## Decisions

1. **The kernel opens approval requests through an injected port, and re-gates approved actions.** `RiskKernel` takes optional
   `ApprovalRequester`, `ApprovalVerifier` and `ConsumedApprovals` ports (structural; the kernel does not import the approvals
   package and vice versa; the process entry point joins them via `kernelApprovalPorts`). After kill-switches, DENY policies and
   every gate have passed, a `REQUIRE_APPROVAL` outcome either (a) opens a request (the service appends `approval.requested` to the
   tenant's chain first) and returns its id in the existing `approval_id` field, or (b) if the caller presents a signed decision
   record in the existing `context` Struct (`context.approval`), verifies it for exactly this tenant, run (`context.run.id`), tool
   (`action`) and argument hash (`hashJson(context.args)`, computed by the kernel, never supplied by the caller), consumes it
   (single use) and answers ALLOW. Requester absent: unchanged behaviour (empty id, clients DENY). Requester failure, a record that
   fails verification, a replayed record, a missing run id, any exception: DENY. A consumption is released if the kernel's own
   audit append fails, so an unrecorded decision never burns an approval. The record is stripped from the policy input.
   - Why not let the runtime decide that an approved action may run? Because then the approval would be a bypass: a cap
     (`target_cap`), a kill-switch engaged after the decision, or a DENY policy must still win. The e2e proves exactly that.
   - No proto change: `approval_id` and the open `context` Struct already carry everything.
2. **Runtime resume is an executor re-submit, never a skip.** `ActionExecutor` with an `ApprovalResolver` waits for the decision
   and re-submits the same action with the record. A DENIED/EXPIRED/unresolvable/mismatched record, or a kernel that does not
   accept it, performs nothing and does not loop. Without a resolver the run still parks (`awaiting_approval`).
3. **Transport: a loopback dev bridge, not a new API.** The runtime and the approver reach the in-process approvals service over
   `services/approvals/src/dev-bridge.ts` (HTTP/JSON on 127.0.0.1, tenant derived from the bearer token, approver principal trusted
   from the body). It exists so the e2e and local dev work without a post-freeze proto/OpenAPI change, and is documented as
   non-production (NEEDS #62, #50). The runtime's HTTP client is allowlisted in the bypass scanner as a control-plane read.
4. **TKI supervises in-run children via an injected spawner.** `RunDeps.child_spawner` replaces the built-in one-for-one loop;
   `TkiChildSpawner` starts each child as a TKI process under a `Supervisor` running a real agent (own run id on the parent's
   trace; budgets from the child's ABL; its account hangs under the parent's, so spend rolls up). A hard-cap trip ends only that
   child with `budget_exceeded` and surfaces to the parent as a failed tool call. Every child action goes through the same
   gate-wrapped `ActionExecutor`, so the bypass guard is unchanged.
5. **NEXUS is wired by factory, telemetry goes into the run log as two additive run-event types.** `RunDeps.nexus_factory(ctx)`
   builds the router (its LLM stage is the run's gated runner). `nexus_stage` and `nexus_route` are new `EventType`s folded into
   `RunState`. Run-event types are not part of any frozen file (`FREEZE.json` lists the audit event schema, process model, IPC
   envelope, ABL/policy schemas, protos, OpenAPI and migrations; `run_events.type` is free text), so no freeze procedure applies;
   the change is additive for readers that know it and a hard error for older runtimes replaying such a log (forward-only, same as
   any new event type). They are **not** appended to the audit chain: that contract is frozen and a cache/rules hit has no gate
   decision (NEEDS #45, #65). `InMemoryTracer.export()` provides the trace; the e2e asserts stage name, hit/miss and cost on it.
6. **Cache and rules hits are not actions and are not gated.** Only the LLM stage is a `ModelCall`. Recorded as a known gap
   (NEEDS #65). The cache key now covers the whole conversation and tool set so a hit is only ever replayed for an identical call.
7. **ABL `maxOutputTokens` reaches the runtime.** The compiler emits `max_output_tokens`; the runtime now maps it to the
   `max_tokens` the adapters and TKI estimate read (it was silently ignored).

## Consequences

- Approval single-use and the request table are in memory, single instance (NEEDS #52, #63). The dev bridge must not be exposed.
- Children of one parent run sequentially (the agent loop dispatches tool calls one at a time).
- The Temporal activity path is unchanged: approvals still park there, and NEXUS/TKI are not wired into it (NEEDS #66).
