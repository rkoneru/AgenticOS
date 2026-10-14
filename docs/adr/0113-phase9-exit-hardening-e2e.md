# 0113. Phase 9 exit: free-text PHI net on the run log, and how the hardening scenarios are proven together

Status: Accepted · Date: 2026-10-14 · Related: 0080-0083 (data governance), 0090 (red team), 0100-0103 (NFR, chaos, DR), 0110-0112

## Context

Phase 9 delivered compliance records, data governance, a red team and load/chaos/DR as separate components, each with its own tests. The exit
criterion is that they hold TOGETHER on the real stack. Building that proof found one gap the components could not close alone: NEEDS 363 said
that run input and tool arguments are redacted "by policy paths only" - an `ALLOW_WITH_REDACTION` rule a tenant wrote - with no free-text net
under it, unlike memory (`services/memory/src/redact.ts`), channels (`services/channels/src/redact.ts`), the voice transcript and the Eval Hub.

## Decisions

1. **The run log gets a free-text net at its single sealing point.** `RunRecorder.record` is the only code that seals and appends a run event
   (the Temporal activity path resumes a recorder; `run_action` does too). When the run is a PHI run (`run_started.phi`, from the blueprint's
   `data.phi`), `axis_runtime.phi_net.scrub_event_data` redacts every string value of the event payload BEFORE the event is sealed: fullwidth
   digits, zero-width characters, labelled identifiers (MRN, SSN), SSN/phone/email shapes - the same heuristic net as the voice transcript and
   the Eval Hub (`voice.phi.redact_transcript`), plus credential scrubbing. The hash chain is therefore computed over the redacted event: replay
   verifies, and the raw value never exists in the log. A resumed recorder re-derives the flag from the first event.
   - Structural values are exempt (ids, hashes, versions, enumerations, UUID/hex-looking strings), because the net also matches long digit runs
     and dates and an all-digit UUID must not be mangled. The exemption is by key name and by value shape; tool results, errors, outputs and
     any other key are scrubbed.
   - Consequence, accepted: the output of a PHI run as served from the log (API, SSE, replay) is the redacted form. The live caller of an
     in-process run still gets the raw text; a client that needs the raw words must not use a PHI blueprint. This matches the voice
     transcript rule ("raw text exists only in memory for the live agent turn").
   - Tool arguments are not stored by the run log or the audit chain at all (the kernel stores `args_hash`); what persists is a tool's
     result, its error text (which often echoes the argument) and the model's answer. These are the paths covered and tested.
2. **One test module proves the scenarios together** (`e2e/test_phase9_hardening.py`, `make e2e-phase9`). It reuses the Phase 7/8 interfaces
   stack and extends the stack process with the real channels gateway (signed Slack webhooks, tenant routing, identity, conversation log) and
   the real memory service. It reuses, rather than copies: the governance world of `test_governance.py`, the red-team campaign of
   `redteam_harness.py` (now able to ask the registry for the release), and the chaos suite's own tests for the three chaos properties.
3. **Seams are declared.** The `runs`, `run_events` and `approvals` Postgres tables have no writer on the dev stack (the run service keeps
   events in memory; the approvals bridge is in memory), so a subject's rows there are inserted by SQL as the table owner and the DSAR engine
   is proven against the real tables. Re-homing a tenant (`tenant/set-region`) and setting PHI mode are operator acts done by ops hooks.
4. **Model residency is proven at the ModelGateway, not in a run.** Nothing in the run path sets `ModelTarget.region` or passes
   `allowed_regions`; enabling the policy for real runs would deny every model call (fail-closed). The test runs the real gateway class with
   the pinned tenant's allowed regions read from its database region. Wiring is NEEDS 417.
5. **The DR scenario asserts the committed drill result** against the targets parsed from `docs/nfr.md` (it does not re-run the drill: that
   needs PostgreSQL binaries and root; `make dr-drill` produces the file).
6. **Every wiring guard has a mutant** (`e2e/mutation_phase9.py`, 14 mutants) that must make a named scenario fail.

## Alternatives considered

- A net on every persistence path inside each tool backend: rejected, one choke point is auditable and cannot be forgotten by a new tool.
- Redacting the live prompt as well: rejected, the agent needs the words to do its job (the same rule as channels and voice).
- Exempting nothing structural and redacting everything: rejected, it corrupted all-digit audit ids in a unit test written for exactly this.

## Consequences

PHI runs are safe to persist and replay; PHI run output via the API is redacted; the net is a heuristic (names without an introduction, free-form
addresses and non-US formats are not caught: NEEDS 363, 414). The proof of the exit scenarios is one command, 23 tests, about 100 seconds.
