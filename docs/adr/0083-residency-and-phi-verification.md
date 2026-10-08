# 0083. Residency enforcement and PHI-mode verification

Status: Accepted · Date: 2026-10-08 · Related: 0006, 0080

## Residency

`ResidencyPolicy` (`@axis/data-governance/residency`, dependency-free) answers "may this instance, in region R, write/send this tenant's data?".
It is **fail-closed**: unknown tenant, empty/undefined region, empty allow-list or a resolver error all refuse; there is no default-allow. Allowed
regions = the tenant's home region plus any extra regions the resolver returns (today only the home region exists in the control plane).
Enforcement points: an optional `residency: WriteGuard` option on `PgMemoryService` (write, ingestDocument), `PgConversationStore` (resolveIdentity,
createConversation, appendMessage), `PgDocStore` (insert, update: eval hub), `PgUsageLedger.append`, `PgRegistryStore.insertVersion`; the DSAR
bundle destination (`assertEgress`, audited DENY on refusal); and `TenantModelPolicy.allowed_regions` in the runtime `ModelGateway` (a target must declare
`region`; non-matching targets are refused before any network call with `ErrorKind.CONFIGURATION`, so a fallback in an allowed region is still tried).
Limits: no real multi-region deployment exists; the guard enforces the decision, not the network. Services that do not pass a guard are unguarded.

## PHI verification

A canary harness (`src/phi-canary.ts`) writes PHI-shaped values (SSN plain/spaced/fullwidth/zero-width/dotted/labelled, MRN, emails, phones) through the
memory, eval-dataset, channel-message and voice-event ingresses of a `phi_mode` tenant and scans a text dump of every tenant table, captured logs and error
messages. It found two real leaks, fixed in their owners: channels' redaction net missed Unicode digits, zero-width characters and MRN labels (now the same
construction as the memory net), and the eval dataset `description` was persisted unredacted in PHI mode. The runtime half (`runtime/tests/test_phi_canary.py`)
covers voice transcript and eval redaction. Names have no pattern: they are only removed when the tenant supplies a DLP hook (NEEDS 363).
