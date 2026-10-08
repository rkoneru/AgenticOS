# Threat model: compliance service (records, documentation, matrix)

Scope: `services/compliance`, migration 0016, the gateway routes and adapters, the console pages. STRIDE per asset. Each threat names the mitigation
and the test that exercises it. Designed for / evidence-ready; the service produces evidence and must not be mistaken for a control that makes
anything compliant.

## Assets and trust boundaries

Inventory and assessment records (tenant data); generated documents (evidence handed to auditors and regulators); the seal key; the control matrix
in the repository; the audit chain they write to. Trust boundary: the gateway authenticates and decides `api.compliance.*`; the service takes
tenant, subject and role from the principal only; the database enforces tenant and immutability rules independently of the service.

## Threats

| id  | STRIDE | threat                                                                   | mitigation                                                                                                                                           | test                                                                                                             |
| --- | ------ | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| C1  | S      | A caller names another tenant in a body, query or path                   | tenant is the credential's; foreign ids are 404; the dev server rejects a mismatching `tenant_id`                                                    | `apps/api-gateway/test/compliance.test.ts` (another tenant), `services/compliance/test/dev-server.test.ts`       |
| C2  | E      | Reading or writing another tenant's rows through a service bug           | forced RLS, `tenant_id = axis.current_tenant()` for read and write; no platform path                                                                 | `services/compliance/test/stores.test.ts` (Postgres as `axis_app`), `test/properties.test.ts` (tenant isolation) |
| C3  | E      | An author approves their own impact assessment                           | service refuses author, contributors and submitter; a database CHECK states the same rule; both are mutation checked                                 | `test/records.test.ts`, `test/stores.test.ts`, `test/properties.test.ts` (reviewer is never the author)          |
| C4  | T      | A reviewed assessment, a stored document or a version snapshot is edited | trigger forbids UPDATE of approved/rejected assessments and of append-only collections, and every DELETE                                             | `test/stores.test.ts`                                                                                            |
| C5  | T      | A generated document is altered after sealing                            | hash of the body, Markdown re-rendered and hashed, signature over `{content_hash, meta}`; verified on every read; any single changed value fails     | `test/properties.test.ts` (tamper detection), `test/docgen.test.ts`                                              |
| C6  | R      | An action on a record leaves no trace                                    | authorise, record, perform, record; a failed append means the mutation is not performed; refusals are DENY rows                                      | `test/records.test.ts`, `test/docgen.test.ts` (audit)                                                            |
| C7  | I      | A document leaks secrets or another tenant's data                        | sources are called with the caller's actor; system instructions appear as a hash; source error text is never copied; text fields are tenant-authored | `test/docgen.test.ts`, `apps/api-gateway/test/compliance.test.ts`                                                |
| C8  | I      | Hostile text in records or documents attacks a reader                    | console renders text only (no HTML injection), CSP from the BFF; CLI prints server text inert                                                        | `apps/console/e2e/flows.spec.ts` (compliance XSS), `apps/cli/test/compliance.test.ts`                            |
| C9  | D      | A huge document or list exhausts the service                             | field and list caps (100 items, 4000 characters), body limit, audit window of 10 000 events, rate limits at the gateway and in the dev server        | `test/records.test.ts` (validation), `test/dev-server.test.ts`                                                   |
| C10 | T      | The document claims more than the platform knows                         | gaps are first-class; a failed chain verification or registry verification is reported; coverage is derived from section status                      | `test/docgen.test.ts`, `test/properties.test.ts` (no source silently omitted)                                    |
| C11 | S/T    | A forged document is presented as ours                                   | seal under a key the deployment holds; an unknown key id fails `seal_key`; symmetric key limits (NEEDS #349)                                         | `test/docgen.test.ts` (seal and verification)                                                                    |
| C12 | R/T    | The control matrix is edited to claim more than exists                   | `make compliance-check`: cited evidence must exist, `Built` needs executable evidence, forbidden wording, required rows, stale Markdown              | `test/matrix.test.ts` (including the real repository)                                                            |
| C13 | E      | A role without the right generates or reviews                            | pack decides `api.compliance.*`, scopes bound API keys, the service checks the role again                                                            | `services/control-plane/test/api-authz.test.ts`, `test/records.test.ts` (roles)                                  |
| C14 | T      | The gateway is wired without the service and answers an empty success    | `UnavailableCompliance` answers 503 for every operation                                                                                              | `apps/api-gateway/test/compliance.test.ts`                                                                       |

## Residual risks

Symmetric seal key (NEEDS #349); document sources are only as honest as the components behind them (NEEDS #347); reviewer independence is by
member id (NEEDS #355); free text is not redacted (NEEDS #361); the matrix proves existence, not adequacy (NEEDS #352).
