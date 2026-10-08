<!-- GENERATED from docs/compliance/matrix/soc2.yaml by `make compliance-check ARGS=--write`. Do not edit by hand. -->

# SOC 2 Trust Services Criteria control matrix

> Designed for / evidence-ready. This matrix maps requirements to AXIS mechanisms and to evidence that exists in this repository. It is not a certification, an attestation or a statement of conformity.

Maps the Trust Services Criteria that apply to a multi-tenant SaaS (Common Criteria CC1-CC9, Availability, Confidentiality, Processing Integrity, Privacy) to AXIS technical mechanisms and to evidence that exists in this repository. AXIS is designed for and evidence-ready toward a SOC 2 examination; no examination has been performed and no report exists. Organisational criteria that no code can satisfy (hiring, training, board oversight) are listed as gaps.

Matrix version 1. Rows: 47 (Built 11, Prototype 21, Designed 5, Gap 10).

| id         | requirement                                                                                                            | status    | evidence                                                                                                                                      |
| ---------- | ---------------------------------------------------------------------------------------------------------------------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| SOC2-CC1.1 | The entity demonstrates a commitment to integrity and ethical values that guide how the system is built and run.       | Designed  | `docs/adr/0001-record-architecture-decisions.md`                                                                                              |
| SOC2-CC1.2 | Oversight of internal control is exercised by a body independent of management.                                        | Gap       | none                                                                                                                                          |
| SOC2-CC2.1 | The entity obtains and uses relevant, quality information to support internal control.                                 | Built     | `services/audit/test/pg.test.ts`<br>`services/agil/test/architecture.test.ts`                                                                 |
| SOC2-CC2.2 | Internal control information and responsibilities are communicated within the entity.                                  | Designed  | `docs/runbooks/audit.md`<br>`docs/spec/audit-log.md`                                                                                          |
| SOC2-CC2.3 | The entity communicates with external parties about matters affecting internal control.                                | Prototype | `docs-build`                                                                                                                                  |
| SOC2-CC3.1 | Objectives are specified clearly enough to identify and assess risks to them.                                          | Designed  | `PHASE_PLAN.md`                                                                                                                               |
| SOC2-CC3.2 | Risks to the achievement of objectives are identified and analysed, including threats from outside the entity.         | Designed  | `docs/security/risk-kernel-threat-model.md`<br>`docs/security/control-plane-threat-model.md`                                                  |
| SOC2-CC3.4 | The entity identifies and assesses changes that could significantly affect internal control.                           | Built     | `packages/contracts/test/freeze.test.ts`<br>`packages/contracts/test/drift.test.ts`                                                           |
| SOC2-CC4.1 | The entity selects and performs ongoing evaluations to confirm that controls are present and functioning.              | Prototype | `e2e-phase8`<br>`services/eval-hub/test/gate.test.ts`                                                                                         |
| SOC2-CC4.2 | Control deficiencies are evaluated and communicated to those responsible for corrective action.                        | Designed  | `docs/NEEDS.md`                                                                                                                               |
| SOC2-CC5.1 | Control activities that mitigate risks are selected and developed.                                                     | Built     | `services/risk-kernel/test/kernel.test.ts`<br>`runtime/tests/test_gate.py`<br>`e2e-core`                                                      |
| SOC2-CC5.2 | The entity selects and develops general technology controls to support achievement of objectives.                      | Built     | `runtime/tests/test_bypass.py`<br>`runtime/tests/test_audit_hook.py`                                                                          |
| SOC2-CC5.3 | Control activities are deployed through policies that establish expectations and procedures that put them into action. | Built     | `policy-test`<br>`packages/policy/test/compile.test.ts`                                                                                       |
| SOC2-CC6.1 | Logical access security measures protect information assets from unauthorised access.                                  | Built     | `packages/db/test/tenancy.test.ts`<br>`services/control-plane/test/authz.test.ts`<br>`apps/api-gateway/test/security.test.ts`                 |
| SOC2-CC6.2 | New users are registered and authorised before credentials are issued, and access is removed when no longer needed.    | Prototype | `services/control-plane/test/scim.test.ts`<br>`services/control-plane/test/sessions.test.ts`<br>`services/control-plane/test/apikeys.test.ts` |
| SOC2-CC6.3 | Access is granted, modified and removed based on roles and the principle of least privilege and segregation of duties. | Built     | `services/control-plane/test/api-authz.test.ts`<br>`services/approvals/test/service.test.ts`<br>`policy-test`                                 |
| SOC2-CC6.4 | Physical access to facilities and protected information assets is restricted.                                          | Gap       | none                                                                                                                                          |
| SOC2-CC6.5 | Logical and physical protections are applied when assets are disposed of.                                              | Gap       | none                                                                                                                                          |
| SOC2-CC6.6 | Logical access security measures protect against threats from sources outside the system boundaries.                   | Prototype | `apps/api-gateway/test/hardening.test.ts`<br>`runtime/tests/test_browser_redirects.py`                                                        |
| SOC2-CC6.7 | The transmission, movement and removal of information is restricted to authorised parties and protected in transit.    | Prototype | `apps/console/test/bff-security.test.ts`<br>`services/channels/test/crypto.test.ts`                                                           |
| SOC2-CC6.8 | Controls prevent or detect the introduction of unauthorised or malicious software.                                     | Prototype | `services/marketplace/test/hardening.test.ts`<br>`services/registry/test/verify.test.ts`<br>`runtime/tests/test_sandbox_local.py`             |
| SOC2-CC7.1 | Detection and monitoring procedures identify configuration changes and newly introduced vulnerabilities.               | Prototype | `apps/console/test/secret-scan.test.ts`                                                                                                       |
| SOC2-CC7.2 | The entity monitors system components for anomalies that indicate malicious acts, errors or failures.                  | Prototype | `services/agil/test/classify.test.ts`                                                                                                         |
| SOC2-CC7.3 | Security events are evaluated to determine whether they are incidents.                                                 | Prototype | `services/audit/test/export.test.ts`<br>`docs/runbooks/audit.md`                                                                              |
| SOC2-CC7.4 | The entity responds to identified security incidents through a defined programme.                                      | Prototype | `services/risk-kernel/test/kernel.test.ts`<br>`docs/runbooks/risk-kernel.md`                                                                  |
| SOC2-CC7.5 | The entity identifies, develops and implements activities to recover from security incidents.                          | Gap       | none                                                                                                                                          |
| SOC2-CC8.1 | Changes to infrastructure, data, software and procedures are authorised, designed, tested, approved and implemented.   | Built     | `packages/db/test/migrate.test.ts`<br>`packages/contracts/test/freeze.test.ts`                                                                |
| SOC2-CC9.1 | The entity identifies, selects and develops risk mitigation activities for business disruptions.                       | Gap       | none                                                                                                                                          |
| SOC2-CC9.2 | The entity assesses and manages risks associated with vendors and business partners.                                   | Prototype | `services/control-plane/test/modelkeys.test.ts`<br>`services/marketplace/test/flows.test.ts`                                                  |
| SOC2-A1.1  | The entity maintains, monitors and evaluates current processing capacity and use of system components.                 | Prototype | `runtime/tests/test_tki_budget.py`                                                                                                            |
| SOC2-A1.2  | Environmental protections, software, data backup processes and recovery infrastructure are designed and operated.      | Gap       | none                                                                                                                                          |
| SOC2-A1.3  | Recovery plan procedures supporting system recovery are tested.                                                        | Gap       | none                                                                                                                                          |
| SOC2-C1.1  | Confidential information is identified and maintained to meet confidentiality objectives.                              | Prototype | `services/memory/test/redact.test.ts`<br>`packages/abl/test/lint.test.ts`                                                                     |
| SOC2-C1.2  | Confidential information is disposed of to meet confidentiality objectives.                                            | Gap       | none                                                                                                                                          |
| SOC2-PI1.1 | The entity obtains or generates relevant, quality information about processing definitions and objectives.             | Built     | `packages/abl/test/compile.test.ts`                                                                                                           |
| SOC2-PI1.2 | System inputs are complete, accurate and timely, with controls over input validation.                                  | Built     | `apps/api-gateway/test/contract.test.ts`<br>`services/eval-hub/test/runs.test.ts`                                                             |
| SOC2-PI1.3 | System processing is complete, accurate, timely and authorised.                                                        | Prototype | `services/billing/test/service.test.ts`<br>`e2e-phase6`                                                                                       |
| SOC2-PI1.4 | System output is complete, accurate and distributed only to intended recipients.                                       | Prototype | `e2e-phase5`<br>`services/channels/test/gateway.test.ts`                                                                                      |
| SOC2-PI1.5 | Stored data is complete and accurate and protected from unauthorised modification.                                     | Built     | `services/audit/test/checkpoint.test.ts`<br>`packages/db/test/hardening.test.ts`                                                              |
| SOC2-P1.1  | The entity provides notice about its privacy practices to data subjects.                                               | Prototype | `runtime/tests/test_voice_compliance.py`<br>`packages/abl/test/lint.test.ts`                                                                  |
| SOC2-P2.1  | The entity communicates choices to data subjects and obtains consent where required.                                   | Prototype | `runtime/tests/test_voice_compliance.py`<br>`services/channels/test/identity.test.ts`                                                         |
| SOC2-P3.1  | Personal information is collected consistent with the entity's objectives and notice.                                  | Prototype | `services/memory/test/isolation.test.ts`                                                                                                      |
| SOC2-P4.1  | Personal information is used, retained and disposed of consistent with the entity's objectives.                        | Prototype | `services/control-plane/test/admin.test.ts`                                                                                                   |
| SOC2-P5.1  | Data subjects can access their personal information and request corrections.                                           | Gap       | none                                                                                                                                          |
| SOC2-P6.1  | Personal information is disclosed to third parties only as authorised, and disclosures are recorded.                   | Prototype | `runtime/tests/test_browser_redirects.py`<br>`runtime/tests/test_endpoints.py`                                                                |
| SOC2-P7.1  | Personal information is accurate, complete and relevant for the purposes for which it is used.                         | Gap       | none                                                                                                                                          |
| SOC2-P8.1  | The entity monitors compliance with privacy commitments and handles inquiries and complaints.                          | Prototype | `services/compliance/test/records.test.ts`                                                                                                    |

## Controls

### SOC2-CC1.1

- **Requirement (paraphrased):** The entity demonstrates a commitment to integrity and ethical values that guide how the system is built and run.
- **AXIS mechanism:** Engineering invariants (fail-closed, tenant isolation, auditability, honest status labels) are written down and enforced by tests; every architectural decision is an ADR.
- **Code:** `CLAUDE.md`
- **Config / flags:** none
- **Evidence:** doc: `docs/adr/0001-record-architecture-decisions.md`
- **Status:** Designed
- **Notes and limits:** Written invariants and an ADR habit are not a code of conduct, ethics training or sanctions process; none exists in the repository.

### SOC2-CC1.2

- **Requirement (paraphrased):** Oversight of internal control is exercised by a body independent of management.
- **AXIS mechanism:** None in the product. Governance of the company is outside the platform.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** No board, audit committee or independent oversight is represented in this repository; it is an organisational control to be supplied by the operator.

### SOC2-CC2.1

- **Requirement (paraphrased):** The entity obtains and uses relevant, quality information to support internal control.
- **AXIS mechanism:** Every decision is written to an append-only, hash-chained audit log with trace ids; AGIL derives explanations only from those rows; Eval Hub keeps immutable, hashed run records.
- **Code:** `services/audit/src/chain.ts`, `services/agil/src/explain.ts`, `services/eval-hub/src/integrity.ts`
- **Config / flags:** none
- **Evidence:** test: `services/audit/test/pg.test.ts`; test: `services/agil/test/architecture.test.ts`
- **Status:** Built
- **Notes and limits:** The audit service is a library with no network surface in this tree; tenants read their chain through the gateway composition only.

### SOC2-CC2.2

- **Requirement (paraphrased):** Internal control information and responsibilities are communicated within the entity.
- **AXIS mechanism:** Runbooks per service, specs per component and a CLAUDE.md working memory describe responsibilities and procedures.
- **Code:** none
- **Config / flags:** none
- **Evidence:** doc: `docs/runbooks/audit.md`; doc: `docs/spec/audit-log.md`
- **Status:** Designed
- **Notes and limits:** Documents exist; there is no evidence of their communication to staff or of acknowledgement.

### SOC2-CC2.3

- **Requirement (paraphrased):** The entity communicates with external parties about matters affecting internal control.
- **AXIS mechanism:** The documentation site is built from the specs, ADRs and the OpenAPI reference; the public API is versioned and frozen.
- **Code:** `apps/docs-site`
- **Config / flags:** none
- **Evidence:** make: `docs-build`
- **Status:** Prototype
- **Notes and limits:** The site is static and offline; nothing is published, and there is no customer-facing status page or security contact process.

### SOC2-CC3.1

- **Requirement (paraphrased):** Objectives are specified clearly enough to identify and assess risks to them.
- **AXIS mechanism:** The master prompt, phase plans and component status table state objectives and gate each phase on evidence.
- **Code:** none
- **Config / flags:** none
- **Evidence:** doc: `PHASE_PLAN.md`
- **Status:** Designed
- **Notes and limits:** Objectives are engineering objectives; business and service-level objectives for customers are not defined in the repository.

### SOC2-CC3.2

- **Requirement (paraphrased):** Risks to the achievement of objectives are identified and analysed, including threats from outside the entity.
- **AXIS mechanism:** Per-service STRIDE-style threat models list threats, mitigations and the tests that cover them.
- **Code:** none
- **Config / flags:** none
- **Evidence:** doc: `docs/security/risk-kernel-threat-model.md`; doc: `docs/security/control-plane-threat-model.md`
- **Status:** Designed
- **Notes and limits:** Threat models exist for eight components as documents; the remaining services are scheduled in Phase 9 and have none yet, and no risk register or periodic review is recorded.

### SOC2-CC3.4

- **Requirement (paraphrased):** The entity identifies and assesses changes that could significantly affect internal control.
- **AXIS mechanism:** Contract changes after the freeze need an ADR and regenerate a frozen manifest; a drift test fails when the OpenAPI, SDKs or schemas change without it.
- **Code:** `packages/contracts/FREEZE.json`, `packages/contracts/scripts/freeze.ts`
- **Config / flags:** none
- **Evidence:** test: `packages/contracts/test/freeze.test.ts`; test: `packages/contracts/test/drift.test.ts`
- **Status:** Built
- **Notes and limits:** Covers API and schema contracts only, not changes to infrastructure or to people and process.

### SOC2-CC4.1

- **Requirement (paraphrased):** The entity selects and performs ongoing evaluations to confirm that controls are present and functioning.
- **AXIS mechanism:** Unit, integration and end-to-end suites run on a real Postgres and a real Risk Kernel; safety-critical logic is mutation checked; the Eval Hub gates releases of blueprints on evaluation results.
- **Code:** `services/eval-hub/src/gate.ts`, `e2e/mutation_phase8.py`
- **Config / flags:** `.github/workflows/ci.yml`
- **Evidence:** make: `e2e-phase8`; test: `services/eval-hub/test/gate.test.ts`
- **Status:** Prototype
- **Notes and limits:** The CI workflow has not run on a remote runner (see the status table in CLAUDE.md); mutation checks are not part of CI.

### SOC2-CC4.2

- **Requirement (paraphrased):** Control deficiencies are evaluated and communicated to those responsible for corrective action.
- **AXIS mechanism:** Gaps and limitations are recorded as numbered items in NEEDS.md with the file that carries them; fixes are tracked to the entry.
- **Code:** none
- **Config / flags:** none
- **Evidence:** doc: `docs/NEEDS.md`
- **Status:** Designed
- **Notes and limits:** A register is not a remediation workflow; there are no owners, due dates or escalation.

### SOC2-CC5.1

- **Requirement (paraphrased):** Control activities that mitigate risks are selected and developed.
- **AXIS mechanism:** The Risk Kernel is the single decision point for tools, MCP, browser, code, memory writes and outbound messages; the default is DENY and any error, timeout or missing policy is a DENY.
- **Code:** `services/risk-kernel/src/kernel.ts`, `services/risk-kernel/src/gates.ts`, `runtime/src/axis_runtime/gate.py`
- **Config / flags:** `policies/baseline-deny/pack.yaml`
- **Evidence:** test: `services/risk-kernel/test/kernel.test.ts`; test: `runtime/tests/test_gate.py`; make: `e2e-core`
- **Status:** Built
- **Notes and limits:** Kernel state (kill switches, counters) is in memory on a single instance; cross-instance propagation is not built.

### SOC2-CC5.2

- **Requirement (paraphrased):** The entity selects and develops general technology controls to support achievement of objectives.
- **AXIS mechanism:** A bypass guard fails the build when runtime code performs a governed action without the gate, and an audit hook test checks the same at run time.
- **Code:** `runtime/tests/bypass_scan.py`
- **Config / flags:** none
- **Evidence:** test: `runtime/tests/test_bypass.py`; test: `runtime/tests/test_audit_hook.py`
- **Status:** Built
- **Notes and limits:** The guard is an allowlist scanner and a heuristic; it is a regression net, not proof or isolation.

### SOC2-CC5.3

- **Requirement (paraphrased):** Control activities are deployed through policies that establish expectations and procedures that put them into action.
- **AXIS mechanism:** Policies are written in a DSL, compiled to Rego and Wasm, checked against golden cases with a real OPA, and activated per tenant through the control plane.
- **Code:** `packages/policy/src/compile.ts`, `services/control-plane/src/policies.ts`
- **Config / flags:** `policies/baseline-deny/baseline-deny.cases.yaml`
- **Evidence:** make: `policy-test`; test: `packages/policy/test/compile.test.ts`
- **Status:** Built
- **Notes and limits:** Policy authors are tenant members with the policies.publish permission; there is no four-eyes approval on activation.

### SOC2-CC6.1

- **Requirement (paraphrased):** Logical access security measures protect information assets from unauthorised access.
- **AXIS mechanism:** Tenant isolation is enforced in the database with forced row-level security on every tenant table; the tenant comes from the credential only; API keys carry scopes; roles are decided by a policy pack.
- **Code:** `packages/db/migrations/0001_tenancy_and_rls.sql`, `services/control-plane/src/authz.ts`
- **Config / flags:** `policies/control-plane/pack.yaml`
- **Evidence:** test: `packages/db/test/tenancy.test.ts`; test: `services/control-plane/test/authz.test.ts`; test: `apps/api-gateway/test/security.test.ts`
- **Status:** Built
- **Notes and limits:** Authentication in tests uses a fake identity provider; WorkOS is not connected and no production IdP has been exercised.

### SOC2-CC6.2

- **Requirement (paraphrased):** New users are registered and authorised before credentials are issued, and access is removed when no longer needed.
- **AXIS mechanism:** SSO sign-in with just-in-time provisioning, SCIM provisioning and deprovisioning, session revocation and API key revocation, all audited in the tenant chain.
- **Code:** `services/control-plane/src/sso.ts`, `services/control-plane/src/scim.ts`, `services/control-plane/src/sessions.ts`, `services/control-plane/src/apikeys.ts`
- **Config / flags:** none
- **Evidence:** test: `services/control-plane/test/scim.test.ts`; test: `services/control-plane/test/sessions.test.ts`; test: `services/control-plane/test/apikeys.test.ts`
- **Status:** Prototype
- **Notes and limits:** Exercised against a fake IdP only; there is no periodic access review report.

### SOC2-CC6.3

- **Requirement (paraphrased):** Access is granted, modified and removed based on roles and the principle of least privilege and segregation of duties.
- **AXIS mechanism:** Seven roles with a ceiling rule (no one grants above their own rank); API actions are decided by the same pack; approvers cannot approve their own requests; reviewers are independent of authors.
- **Code:** `services/control-plane/src/roles.ts`, `policies/control-plane/pack.yaml`, `services/approvals/src/service.ts`
- **Config / flags:** `policies/control-plane/authz.cases.yaml`
- **Evidence:** test: `services/control-plane/test/api-authz.test.ts`; test: `services/approvals/test/service.test.ts`; make: `policy-test`
- **Status:** Built
- **Notes and limits:** Roles are fixed; tenants cannot define custom roles.

### SOC2-CC6.4

- **Requirement (paraphrased):** Physical access to facilities and protected information assets is restricted.
- **AXIS mechanism:** None in the product; the platform runs on a cloud provider's facilities.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** No cloud account is used and nothing has been deployed; the provider's physical controls would be inherited and must be evidenced by the provider's own reports.

### SOC2-CC6.5

- **Requirement (paraphrased):** Logical and physical protections are applied when assets are disposed of.
- **AXIS mechanism:** Nothing is deleted in the audit, registry or eval stores by design; tenant data deletion and crypto-shredding are not implemented.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** Retention settings are stored per tenant but no job purges data; disposal procedures for media belong to the infrastructure provider.

### SOC2-CC6.6

- **Requirement (paraphrased):** Logical access security measures protect against threats from sources outside the system boundaries.
- **AXIS mechanism:** The API gateway authenticates every call, rate limits per tenant and per remote address, bounds body sizes, validates responses against the OpenAPI, and applies SSRF guards on provider endpoints and browser egress.
- **Code:** `apps/api-gateway/src/limits.ts`, `apps/api-gateway/src/server.ts`, `runtime/src/axis_runtime/browser`
- **Config / flags:** none
- **Evidence:** test: `apps/api-gateway/test/hardening.test.ts`; test: `runtime/tests/test_browser_redirects.py`
- **Status:** Prototype
- **Notes and limits:** The gateway is a dev composition on a loopback port; there is no WAF, DDoS protection or network segmentation in the repository.

### SOC2-CC6.7

- **Requirement (paraphrased):** The transmission, movement and removal of information is restricted to authorised parties and protected in transit.
- **AXIS mechanism:** The gateway can send HSTS behind TLS termination, webhooks are signature checked and replay protected, and the console BFF sets a strict CSP, CSRF checks and secure cookies.
- **Code:** `apps/console/proxy.ts`, `services/channels/src/crypto.ts`
- **Config / flags:** none
- **Evidence:** test: `apps/console/test/bff-security.test.ts`; test: `services/channels/test/crypto.test.ts`
- **Status:** Prototype
- **Notes and limits:** TLS termination, certificates and service-to-service mTLS are not part of the repository; internal HTTP surfaces are loopback dev servers.

### SOC2-CC6.8

- **Requirement (paraphrased):** Controls prevent or detect the introduction of unauthorised or malicious software.
- **AXIS mechanism:** Marketplace submissions are scanned and need digest-bound consent; blueprints are signed and verified on resolve; generated code runs in a namespace sandbox with the gate in front.
- **Code:** `services/marketplace/src/scan.ts`, `services/registry/src/verify.ts`, `runtime/src/axis_runtime/sandbox`
- **Config / flags:** none
- **Evidence:** test: `services/marketplace/test/hardening.test.ts`; test: `services/registry/test/verify.test.ts`; test: `runtime/tests/test_sandbox_local.py`
- **Status:** Prototype
- **Notes and limits:** The sandbox is process-level isolation on one kernel, not a security boundary; there is no software composition analysis of dependencies.

### SOC2-CC7.1

- **Requirement (paraphrased):** Detection and monitoring procedures identify configuration changes and newly introduced vulnerabilities.
- **AXIS mechanism:** Lint, type checks, secret scanning of the console bundle, and a frozen-contract drift test run in the test suites.
- **Code:** `apps/console/lib/secret-scan.ts`
- **Config / flags:** none
- **Evidence:** test: `apps/console/test/secret-scan.test.ts`
- **Status:** Prototype
- **Notes and limits:** No dependency vulnerability scanning, container scanning or penetration test exists; the Phase 9 red-team suite is separate work.

### SOC2-CC7.2

- **Requirement (paraphrased):** The entity monitors system components for anomalies that indicate malicious acts, errors or failures.
- **AXIS mechanism:** Denials, kill-switch actions and failed verifications are audit events; AGIL explains denials from the chain; OpenTelemetry collectors are configured in the compose stack.
- **Code:** `services/agil/src/classify.ts`, `infra/compose/otel`
- **Config / flags:** `infra/compose/docker-compose.yml`
- **Evidence:** test: `services/agil/test/classify.test.ts`
- **Status:** Prototype
- **Notes and limits:** No alert rules, paging or dashboards beyond the compose Grafana stub are defined; the compose stack was never started.

### SOC2-CC7.3

- **Requirement (paraphrased):** Security events are evaluated to determine whether they are incidents.
- **AXIS mechanism:** Runbooks describe how to read the audit chain and verify it; the audit export produces a verifiable bundle.
- **Code:** `services/audit/src/export.ts`
- **Config / flags:** none
- **Evidence:** test: `services/audit/test/export.test.ts`; doc: `docs/runbooks/audit.md`
- **Status:** Prototype
- **Notes and limits:** There is no incident classification procedure or on-call process.

### SOC2-CC7.4

- **Requirement (paraphrased):** The entity responds to identified security incidents through a defined programme.
- **AXIS mechanism:** Kill switches stop an agent, tenant or tool at the next gate decision; approvals can be denied or expired; the chain is verified after the event.
- **Code:** `services/risk-kernel/src/stores.ts`, `apps/api-gateway/src/routes.ts`
- **Config / flags:** none
- **Evidence:** test: `services/risk-kernel/test/kernel.test.ts`; doc: `docs/runbooks/risk-kernel.md`
- **Status:** Prototype
- **Notes and limits:** Kill-switch state is per kernel instance; no breach communication, forensics or post-incident review process exists.

### SOC2-CC7.5

- **Requirement (paraphrased):** The entity identifies, develops and implements activities to recover from security incidents.
- **AXIS mechanism:** None yet; backup, restore and disaster recovery are planned in Phase 9 and not present in this tree.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** No backup or restore procedure has been exercised; RPO and RTO have never been measured.

### SOC2-CC8.1

- **Requirement (paraphrased):** Changes to infrastructure, data, software and procedures are authorised, designed, tested, approved and implemented.
- **AXIS mechanism:** Small conventional commits, ADRs for decisions, frozen contracts, additive-only migrations with checksum verification, and CI that runs lint, typecheck, coverage and the policy tests.
- **Code:** `packages/db/src/index.ts`, `.github/workflows/ci.yml`
- **Config / flags:** `packages/contracts/FREEZE.json`
- **Evidence:** test: `packages/db/test/migrate.test.ts`; test: `packages/contracts/test/freeze.test.ts`
- **Status:** Built
- **Notes and limits:** No branch protection or required reviewers are configured in the repository; the CI workflow has not run remotely.

### SOC2-CC9.1

- **Requirement (paraphrased):** The entity identifies, selects and develops risk mitigation activities for business disruptions.
- **AXIS mechanism:** None in the product beyond fail-closed behaviour; business continuity planning is not represented.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** Fail-closed denial protects safety but reduces availability when the kernel or audit log is down; no continuity plan exists.

### SOC2-CC9.2

- **Requirement (paraphrased):** The entity assesses and manages risks associated with vendors and business partners.
- **AXIS mechanism:** Only the ModelGateway talks to model providers, with bring-your-own keys per tenant held sealed under a KMS interface; the marketplace review and consent flow governs third-party blueprints.
- **Code:** `services/control-plane/src/modelkeys.ts`, `services/marketplace/src/reviews.ts`
- **Config / flags:** none
- **Evidence:** test: `services/control-plane/test/modelkeys.test.ts`; test: `services/marketplace/test/flows.test.ts`
- **Status:** Prototype
- **Notes and limits:** No vendor inventory, due diligence or contract review exists; the KMS is a local fake and no live provider call has been made.

### SOC2-A1.1

- **Requirement (paraphrased):** The entity maintains, monitors and evaluates current processing capacity and use of system components.
- **AXIS mechanism:** Per-tenant rate limits and TKI budgets bound consumption; capacity targets and load tests are planned in Phase 9.
- **Code:** `apps/api-gateway/src/limits.ts`, `runtime/src/axis_runtime/tki`
- **Config / flags:** none
- **Evidence:** test: `runtime/tests/test_tki_budget.py`
- **Status:** Prototype
- **Notes and limits:** No service-level objectives, load test or capacity monitoring exist yet.

### SOC2-A1.2

- **Requirement (paraphrased):** Environmental protections, software, data backup processes and recovery infrastructure are designed and operated.
- **AXIS mechanism:** None yet; Terraform, Helm and k3s directories are empty placeholders.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** No infrastructure as code or backup configuration exists, and applying any is a hard stop that needs the owner.

### SOC2-A1.3

- **Requirement (paraphrased):** Recovery plan procedures supporting system recovery are tested.
- **AXIS mechanism:** None yet.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** A tested restore with audit-chain verification is planned in Phase 9; no test has been run.

### SOC2-C1.1

- **Requirement (paraphrased):** Confidential information is identified and maintained to meet confidentiality objectives.
- **AXIS mechanism:** Data classifications travel with decisions; the PHI flag in a blueprint forces redaction before persistence and requires a residency declaration; secrets are never printed by SDKs or stored in ABL.
- **Code:** `services/memory/src/redact.ts`, `packages/abl/src/lint.ts`
- **Config / flags:** none
- **Evidence:** test: `services/memory/test/redact.test.ts`; test: `packages/abl/test/lint.test.ts`
- **Status:** Prototype
- **Notes and limits:** Redaction is pattern based; a cross-store canary test is planned in Phase 9 and is not in this tree.

### SOC2-C1.2

- **Requirement (paraphrased):** Confidential information is disposed of to meet confidentiality objectives.
- **AXIS mechanism:** None; see CC6.5.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** Retention days are stored per tenant, but no job enforces them and nothing deletes data.

### SOC2-PI1.1

- **Requirement (paraphrased):** The entity obtains or generates relevant, quality information about processing definitions and objectives.
- **AXIS mechanism:** Blueprints are validated against a frozen schema; unknown fields are errors; the compiled manifest is deterministic and hashed.
- **Code:** `packages/abl/src/validate.ts`, `packages/abl/src/manifest.ts`
- **Config / flags:** `packages/abl/schema/abl-v1.schema.json`
- **Evidence:** test: `packages/abl/test/compile.test.ts`
- **Status:** Built
- **Notes and limits:** Covers agent definitions only, not customer business process definitions.

### SOC2-PI1.2

- **Requirement (paraphrased):** System inputs are complete, accurate and timely, with controls over input validation.
- **AXIS mechanism:** The gateway validates every request and response against the OpenAPI document; ABL, policy DSL and audit events have JSON schemas; eval results are recomputed by the hub before acceptance.
- **Code:** `apps/api-gateway/src/server.ts`, `services/eval-hub/src/integrity.ts`
- **Config / flags:** `packages/contracts/openapi/axis-v1.yaml`
- **Evidence:** test: `apps/api-gateway/test/contract.test.ts`; test: `services/eval-hub/test/runs.test.ts`
- **Status:** Built
- **Notes and limits:** Runner-side grading is trusted for raw grades (the hub recomputes aggregates only).

### SOC2-PI1.3

- **Requirement (paraphrased):** System processing is complete, accurate, timely and authorised.
- **AXIS mechanism:** Usage metering is reconciled against an independent recomputation from the audit and run logs; billing periods are sealed; the Phase 6 end-to-end test requires ledger equality.
- **Code:** `services/billing/src/reconcile.ts`, `services/billing/src/seal.ts`
- **Config / flags:** none
- **Evidence:** test: `services/billing/test/service.test.ts`; make: `e2e-phase6`
- **Status:** Prototype
- **Notes and limits:** Against a Stripe fake only; no live payment processor, ClickHouse store or tax handling.

### SOC2-PI1.4

- **Requirement (paraphrased):** System output is complete, accurate and distributed only to intended recipients.
- **AXIS mechanism:** Every outbound message and call is a gated action with a decision row; replies are routed by linked identity; cross-tenant routing is impossible by construction.
- **Code:** `services/channels/src/gateway.ts`, `runtime/src/axis_runtime/channel_runner.py`
- **Config / flags:** none
- **Evidence:** make: `e2e-phase5`; test: `services/channels/test/gateway.test.ts`
- **Status:** Prototype
- **Notes and limits:** Provider transports are fakes; no live channel provider has been used.

### SOC2-PI1.5

- **Requirement (paraphrased):** Stored data is complete and accurate and protected from unauthorised modification.
- **AXIS mechanism:** Audit, registry versions, eval runs and billing seals are append-only or immutable by database triggers; the audit chain is hash linked with signed checkpoints.
- **Code:** `packages/db/migrations/0005_audit_checkpoints.sql`, `services/audit/src/checkpoint.ts`
- **Config / flags:** none
- **Evidence:** test: `services/audit/test/checkpoint.test.ts`; test: `packages/db/test/hardening.test.ts`
- **Status:** Built
- **Notes and limits:** The checkpoint signer is a local Ed25519 key; a KMS signer and WORM object storage are not built.

### SOC2-P1.1

- **Requirement (paraphrased):** The entity provides notice about its privacy practices to data subjects.
- **AXIS mechanism:** Blueprints at limited or high risk must carry a transparency notice; a voice session plays its notice first; the lint warns when voice has none.
- **Code:** `packages/abl/src/lint.ts`, `runtime/src/axis_runtime/voice`
- **Config / flags:** none
- **Evidence:** test: `runtime/tests/test_voice_compliance.py`; test: `packages/abl/test/lint.test.ts`
- **Status:** Prototype
- **Notes and limits:** A privacy notice for the SaaS itself (as controller or processor) is not in the repository.

### SOC2-P2.1

- **Requirement (paraphrased):** The entity communicates choices to data subjects and obtains consent where required.
- **AXIS mechanism:** A voice session requires consent or a played notice before speech reaches the agent; channel identities are linked only with an explicit step.
- **Code:** `runtime/src/axis_runtime/voice`, `services/channels/src/identity.ts`
- **Config / flags:** none
- **Evidence:** test: `runtime/tests/test_voice_compliance.py`; test: `services/channels/test/identity.test.ts`
- **Status:** Prototype
- **Notes and limits:** There is no consent store, withdrawal flow or consent receipt for other processing.

### SOC2-P3.1

- **Requirement (paraphrased):** Personal information is collected consistent with the entity's objectives and notice.
- **AXIS mechanism:** Minimal collection by design; PHI mode redacts before persistence; memory scopes (run, session, long term) are explicit opt-in.
- **Code:** `services/memory/src/store.ts`, `services/memory/src/acl.ts`
- **Config / flags:** none
- **Evidence:** test: `services/memory/test/isolation.test.ts`
- **Status:** Prototype
- **Notes and limits:** No data inventory of personal data fields per store exists apart from the new AI system inventory records.

### SOC2-P4.1

- **Requirement (paraphrased):** Personal information is used, retained and disposed of consistent with the entity's objectives.
- **AXIS mechanism:** Retention days exist as tenant settings, and the audit retention can only be lengthened; enforcement jobs do not exist.
- **Code:** `services/control-plane/src/admin.ts`
- **Config / flags:** none
- **Evidence:** test: `services/control-plane/test/admin.test.ts`
- **Status:** Prototype
- **Notes and limits:** Settings are validated and audited, but no purge job, legal hold or disposal evidence exists.

### SOC2-P5.1

- **Requirement (paraphrased):** Data subjects can access their personal information and request corrections.
- **AXIS mechanism:** None yet; subject access export and correction are planned in Phase 9 and are not present in this tree.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** No data subject request tooling exists in any store.

### SOC2-P6.1

- **Requirement (paraphrased):** Personal information is disclosed to third parties only as authorised, and disclosures are recorded.
- **AXIS mechanism:** Egress for tools and browser workers is allowlisted and gated; model calls go through one gateway that records the provider and model per call; PHI-flagged runs refuse providers outside the declared residency.
- **Code:** `runtime/src/axis_runtime/models`, `runtime/src/axis_runtime/browser`
- **Config / flags:** none
- **Evidence:** test: `runtime/tests/test_browser_redirects.py`; test: `runtime/tests/test_endpoints.py`
- **Status:** Prototype
- **Notes and limits:** Provider region constraints are not enforced on write paths; data processing agreements with providers do not exist.

### SOC2-P7.1

- **Requirement (paraphrased):** Personal information is accurate, complete and relevant for the purposes for which it is used.
- **AXIS mechanism:** None specific; memory entries carry provenance and ACLs, but there is no correction workflow.
- **Code:** `services/memory/src/types.ts`
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** Depends on the data subject request tooling that does not exist yet.

### SOC2-P8.1

- **Requirement (paraphrased):** The entity monitors compliance with privacy commitments and handles inquiries and complaints.
- **AXIS mechanism:** Audit events and the new compliance inventory record privacy-relevant decisions; no complaint handling exists.
- **Code:** `services/compliance/src/records/assessments.ts`
- **Config / flags:** none
- **Evidence:** test: `services/compliance/test/records.test.ts`
- **Status:** Prototype
- **Notes and limits:** Monitoring of privacy commitments is limited to impact assessment review dates; there is no complaint or inquiry process.
