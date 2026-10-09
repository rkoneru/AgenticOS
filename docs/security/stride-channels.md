# STRIDE: Channels service (web, Slack, Teams, SMS, email, WhatsApp)

Status: Prototype (fakes only, loopback dev surface). Earlier model with 17 controls: [channels-threat-model.md](channels-threat-model.md).

## Assets

- Tenant isolation of conversations and identities; who-said-what integrity in transcripts.
- The outbound send path (spam, impersonation, data egress) and provider credentials.
- End users' personal data in messages.

## Trust boundaries

1. Provider webhook (hostile) to the gateway: signature per route secret, replay window, idempotency (`services/channels/src/gateway.ts`, `services/channels/src/replay.ts`).
2. Inbound text to the agent: quoted as untrusted data (`runtime/src/axis_runtime/untrusted.py`, `runtime/src/axis_runtime/channel_runner.py`).
3. Agent to the outside: only through a gated `MessageSend` (`runtime/src/axis_runtime/channels.py`); the service audits before sending (`services/channels/src/transport.ts`).

## Data flow

Webhook -> verify signature and timestamp -> route (tenant from the route) -> identity resolution -> inbox -> run with fenced user text -> `channel.reply` or other message tool -> kernel decision -> service audit -> guarded transport.

## STRIDE

| Category               | Threat                                                 | Mitigation (code path)                                                                                                                                                            | Test                                                                                | Residual / NEEDS                                                                                          |
| ---------------------- | ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Spoofing               | Forged or replayed webhook                             | Provider signature, constant-time compare, timestamp window, idempotency plus a durable message-log check (`services/channels/src/gateway.ts`, `services/channels/src/replay.ts`) | `services/channels/test/gateway.test.ts`, `services/channels/test/adapters.test.ts` | Per-instance replay store (NEEDS #124)                                                                    |
| Spoofing               | Identity takeover by a claim, thread hijack            | No merge on claims; link needs a single-use code from a verified identity, same tenant (`services/channels/src/identity.ts`)                                                      | `services/channels/test/identity.test.ts`                                           | Redeemer history merge (NEEDS #157)                                                                       |
| Tampering              | Header, mention or markup injection in outbound        | Strict addresses, control-character checks, generated headers, Slack escaping (`services/channels/src/email-compose.ts`)                                                          | `services/channels/test/adapters.test.ts`                                           | none known                                                                                                |
| Tampering              | Cross-tenant routing by message content                | Tenant read from the route after verification, adapter output re-checked (`services/channels/src/routing.ts`)                                                                     | `services/channels/test/gateway.test.ts`                                            | A leaked route secret compromises that tenant                                                             |
| Repudiation            | Transcript says something nobody said                  | Audit holds keyed digests and sizes; insert-only message log (`services/channels/src/transcript-events.ts`, `packages/db/migrations/0007_channels.sql`)                           | `services/channels/test/pg-store.test.ts`                                           | Digest key is an env secret (NEEDS #156)                                                                  |
| Information disclosure | PHI or secrets in transcripts and replies              | PHI forces redaction before storage; a policy denies SSN-shaped replies (`services/channels/src/redact.ts`)                                                                       | `services/channels/test/wire.test.ts`, `e2e/test_phase5_channels.py`                | Redaction is a net (NEEDS #129)                                                                           |
| Information disclosure | SSRF through attachment or outbound URLs               | Attachments are metadata only; outbound targets are fixed provider hosts via a guarded transport (`services/channels/src/transport.ts`)                                           | `services/channels/test/util.test.ts`                                               | Name-based guard only (NEEDS #158)                                                                        |
| Denial of service      | Webhook flood or audit flooding                        | Per-tenant and per-route rate limits; rejection audits rate limited (`services/channels/src/limits.ts`)                                                                           | `services/channels/test/gateway.test.ts`                                            | Unauthenticated surfaces have no abuse budget beyond rate limits (NEEDS #159)                             |
| Elevation of privilege | Outbound without the gate, or a model-chosen recipient | Runtime reaches the sender only via `MessageSend` after a kernel ALLOW; the policy denies model-composed messages (`runtime/src/axis_runtime/channels.py`)                        | `runtime/tests/test_channels.py`, `e2e/test_phase5_channels.py`                     | A channel tool lets the model choose recipients (NEEDS #161); bearer holders bypass the gate (NEEDS #126) |

## Prompt injection

Inbound messages are the most direct injection path into a production agent: any end user, and anyone who can email or message the agent, controls the text. Controls: the user message is placed in a fence that the text cannot close and conversation history is collapsed to single lines so it cannot forge speaker turns (`runtime/src/axis_runtime/untrusted.py`); the reply is a gated `channel.reply` whose body is checked by policy (SSN-shaped numbers, links in the red-team pack); a model-composed message to another recipient is denied; the identity of the sender decides memory access, not their claims. Evidence: injection scenarios in `e2e/test_phase5_channels.py` and the red-team categories `indirect-injection` (technique `inbound-message`, cases in `evals/redteam/datasets/redteam-core.json`) and `exfiltration` (technique `markdown-beacon`). The scripted model obeys the injection on purpose; the assertion is on what the platform allows (NEEDS #152).

## Tool misuse

Outbound spam is limited to known identities unless a route opts in, with a per-route outbound limit (`services/channels/src/limits.ts`). Markdown or HTML beacons in a reply are denied by policy in the red-team pack; without such a rule a reply body is the tenant's responsibility (NEEDS #398).
