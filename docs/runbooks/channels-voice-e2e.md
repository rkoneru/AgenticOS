# Runbook: Phase 5 channels and voice e2e (`make e2e-phase5`)

Status: runs locally, **CI job `e2e-phase5` unrun remotely** (NEEDS #3, #154). Spec: `docs/spec/{channels,voice}.md`, ADR 0015-0017.

## Prerequisites

Node 22 + pnpm, `uv sync --all-packages`, `pnpm build` (the target does it), `opa` on PATH (the policy bundle is compiled from
`e2e/policies/phase5-channels`), Postgres 16 + pgvector (`infra/scripts/with-pg.sh` or `PG_ADMIN_URL`). No namespaces, no Chromium.

## What it starts

Per module: a throwaway database (migrated, three tenants: customer A, customer B, and a platform tenant that audits requests naming
no known route), the Risk Kernel (gRPC, OPA Wasm), and `e2e/scripts/channels-stack.mjs` (the real channels gateway + dev server on
Postgres, with RECORDING provider transports on a second loopback port: `GET /sent`). Per test: the agent runner of each tenant
(`ChannelAgentRunner` polling the inbox with the tenant's token), the scripted LLM, and for voice a loopback call whose STT/TTS go
through the ModelGateway speech plane and the gate.

## Writing a scenario

1. Build a signed provider request (`slack_req`, `sms_req`, `email_req`, `web_req`; they sign exactly as the providers do).
2. `await ask(world, req)` posts it, drains the runner and returns the `RunResult` (`.reply.status` is `sent`, `denied` or `failed`).
3. Check what left (`delivered`, `world.sent()`), the conversation log (`messages_of`), and the audit chain (`trace_rows`, `chain_ok`).

## Reading a failure

- `pytest -q e2e/test_phase5_channels.py -x -s` prints the per-trace audit rows of the whole-picture test (one trace per chat turn,
  one per call). Kernel and channels stderr are `kernel.err` / `channels.err` in the pytest tmp dir (`/tmp/pytest-of-*/pytest-*/e2e5*`).
- A webhook that should verify returns 401: the harness secret differs from the route in the test, or the clock moved (Slack/email
  accept 5 minutes).
- `ChannelUnavailable ... 400 (INVALID)` from a voice call: a transcript event failed the service's strict validation
  (`services/channels/src/transcript-events.ts`); the call ends by design (no audit row, no transcript).
- Voice tests run on the system clock; a timeout waiting for a turn on a very loaded machine is a test-environment problem (NEEDS #153).

## Mutation check

`uv run python e2e/mutation_phase5.py [name-substring ...]` breaks one safety line of the new wiring at a time (gate skipped on the
reply, unverified inbound accepted, replay accepted, tenant dropped from the inbox, raw PHI transcript on a channel and on voice, voice
transcript not mirrored, history not given to the agent, outbound call allowlist off, consent skipped), rebuilds the TS service where
needed and requires a test to FAIL. 11/11 killed when this was written; run by hand (NEEDS #154). It edits and restores source files:
do not run it with uncommitted edits to those files.
