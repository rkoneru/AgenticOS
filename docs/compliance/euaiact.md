<!-- GENERATED from docs/compliance/matrix/euaiact.yaml by `make compliance-check ARGS=--write`. Do not edit by hand. -->

# EU AI Act high-risk obligations control matrix

> Designed for / evidence-ready. This matrix maps requirements to AXIS mechanisms and to evidence that exists in this repository. It is not a certification, an attestation or a statement of conformity.

Maps the obligations of Regulation (EU) 2024/1689 that fall on providers of high-risk AI systems (Articles 9 to 15), on deployers (Articles 26 and 27), on transparency (Articles 13 and 50) and on post-market monitoring and incident reporting (Articles 72 and 73) to AXIS mechanisms and to evidence in this repository. AXIS is designed for and evidence-ready toward these obligations. It does not classify a customer's use case, does not perform a conformity assessment and is not legal advice; classification and conformity remain the responsibility of the provider and deployer.

Matrix version 1. Rows: 14 (Built 3, Prototype 8, Designed 0, Gap 3).

| id | requirement | status | evidence |
| --- | --- | --- | --- |
| EUAIACT-Art9 | A risk management system is established, documented and maintained across the lifecycle of a high-risk system. | Prototype | `packages/abl/test/lint.test.ts`<br>`services/compliance/test/records.test.ts` |
| EUAIACT-Art10 | Training, validation and testing data meet quality and governance criteria, including examination for bias. | Prototype | `services/eval-hub/test/catalog.test.ts` |
| EUAIACT-Art11 | Technical documentation per Annex IV is drawn up before placing on the market and kept up to date. | Built | `services/compliance/test/docgen.test.ts`<br>`services/compliance/test/properties.test.ts` |
| EUAIACT-Art12 | High-risk systems technically allow automatic recording of events over their lifetime. | Built | `services/audit/test/pg.test.ts`<br>`runtime/tests/test_events.py`<br>`e2e-core` |
| EUAIACT-Art13 | Systems are transparent enough for deployers to interpret output and use it appropriately, with instructions for use. | Prototype | `services/agil/test/explain.test.ts`<br>`services/compliance/test/docgen.test.ts` |
| EUAIACT-Art14 | High-risk systems can be effectively overseen by natural people, including the ability to intervene or stop the system. | Built | `services/approvals/test/service.test.ts`<br>`services/risk-kernel/test/approvals.test.ts`<br>`e2e-phase3` |
| EUAIACT-Art15 | Systems reach an appropriate level of accuracy, robustness and cybersecurity and perform consistently. | Prototype | `services/eval-hub/test/gate.test.ts`<br>`services/eval-hub/test/scoring.test.ts`<br>`e2e-phase8` |
| EUAIACT-Art17 | Providers operate a quality management system covering design, testing, data, risk management and post-market monitoring. | Gap | none |
| EUAIACT-Art26 | Deployers use systems per the instructions, assign human oversight, monitor operation, keep logs and inform affected persons. | Prototype | `services/audit/test/export.test.ts`<br>`packages/abl/test/lint.test.ts` |
| EUAIACT-Art27 | Certain deployers assess the impact on fundamental rights before first use of a high-risk system. | Prototype | `services/compliance/test/records.test.ts`<br>`services/compliance/test/properties.test.ts` |
| EUAIACT-Art43 | High-risk systems undergo the applicable conformity assessment procedure before being placed on the market. | Gap | none |
| EUAIACT-Art50 | People are told they are interacting with an AI system, and synthetic content is marked, unless obvious. | Prototype | `packages/abl/test/compile.test.ts`<br>`runtime/tests/test_voice_compliance.py` |
| EUAIACT-Art72 | Providers establish a post-market monitoring system proportionate to the risk and collect and analyse relevant data. | Prototype | `services/eval-hub/test/online.test.ts`<br>`e2e-phase8` |
| EUAIACT-Art73 | Serious incidents are reported to the market surveillance authorities within the set deadlines. | Gap | none |

## Controls

### EUAIACT-Art9

- **Requirement (paraphrased):** A risk management system is established, documented and maintained across the lifecycle of a high-risk system.
- **AXIS mechanism:** Risk classification is mandatory in every blueprint with a rationale; a prohibited level cannot be expressed; high risk requires evals and human oversight (lint ABL004); AI impact assessments record risks, mitigations and review dates.
- **Code:** `packages/abl/schema/abl-v1.schema.json`, `packages/abl/src/lint.ts`, `services/compliance/src/records/assessments.ts`
- **Config / flags:** none
- **Evidence:** test: `packages/abl/test/lint.test.ts`; test: `services/compliance/test/records.test.ts`
- **Status:** Prototype
- **Notes and limits:** A risk management process is more than records; testing against prior defined metrics and residual risk acceptance are the provider's.

### EUAIACT-Art10

- **Requirement (paraphrased):** Training, validation and testing data meet quality and governance criteria, including examination for bias.
- **AXIS mechanism:** Eval datasets are immutable, hashed and versioned; PHI datasets are redacted; blueprints declare data and residency. Training data governance of third-party models is outside the platform.
- **Code:** `services/eval-hub/src/catalog.ts`, `services/eval-hub/src/canonical.ts`
- **Config / flags:** none
- **Evidence:** test: `services/eval-hub/test/catalog.test.ts`
- **Status:** Prototype
- **Notes and limits:** Dataset quality and bias are not judged (NEEDS records the gap); foundation model training data is not visible to AXIS.

### EUAIACT-Art11

- **Requirement (paraphrased):** Technical documentation per Annex IV is drawn up before placing on the market and kept up to date.
- **AXIS mechanism:** The Annex IV generator assembles a versioned, hash-sealed document per blueprint version from the ABL manifest, registry provenance and verification, eval runs, attestations and gate verdicts, active policy packs, human oversight configuration and audit statistics. Sources that are missing are listed as gaps; nothing is invented.
- **Code:** `services/compliance/src/docgen/assemble.ts`, `services/compliance/src/docgen/documents.ts`, `services/compliance/src/docgen/verify.ts`
- **Config / flags:** none
- **Evidence:** test: `services/compliance/test/docgen.test.ts`; test: `services/compliance/test/properties.test.ts`
- **Status:** Built
- **Notes and limits:** The generator documents what the platform can evidence. Hardware, harmonised standards applied and the declaration of conformity are always listed as gaps; the provider must complete the documentation.

### EUAIACT-Art12

- **Requirement (paraphrased):** High-risk systems technically allow automatic recording of events over their lifetime.
- **AXIS mechanism:** Append-only, hash-chained audit events with trace ids for every decision and administrative action; runs are replayable from event-sourced logs; chain verification and export.
- **Code:** `services/audit/src/chain.ts`, `runtime/src/axis_runtime/events.py`
- **Config / flags:** none
- **Evidence:** test: `services/audit/test/pg.test.ts`; test: `runtime/tests/test_events.py`; make: `e2e-core`
- **Status:** Built
- **Notes and limits:** Log retention periods are tenant settings that no job enforces; the audit service has no network surface of its own in this tree.

### EUAIACT-Art13

- **Requirement (paraphrased):** Systems are transparent enough for deployers to interpret output and use it appropriately, with instructions for use.
- **AXIS mechanism:** The technical documentation lists capabilities, limits, evaluation results and known limitations; AGIL explains runs and denials from audit rows; blueprints carry intended purpose and transparency notices.
- **Code:** `services/agil/src/explain.ts`, `services/compliance/src/docgen/limitations.ts`
- **Config / flags:** none
- **Evidence:** test: `services/agil/test/explain.test.ts`; test: `services/compliance/test/docgen.test.ts`
- **Status:** Prototype
- **Notes and limits:** Instructions for use for deployers are not generated; the explainer is deterministic and does not describe model internals.

### EUAIACT-Art14

- **Requirement (paraphrased):** High-risk systems can be effectively overseen by natural people, including the ability to intervene or stop the system.
- **AXIS mechanism:** High-risk blueprints must declare required human oversight with approver roles; the Risk Kernel routes to approval and the run waits; approvers cannot approve their own requests; kill switches stop an agent, tool or tenant.
- **Code:** `packages/abl/schema/abl-v1.schema.json`, `services/approvals/src/service.ts`, `services/risk-kernel/src/approvals.ts`
- **Config / flags:** none
- **Evidence:** test: `services/approvals/test/service.test.ts`; test: `services/risk-kernel/test/approvals.test.ts`; make: `e2e-phase3`
- **Status:** Built
- **Notes and limits:** Automation bias and operator competence are not measured; approvals use an in-memory store and a dev-only loopback bridge.

### EUAIACT-Art15

- **Requirement (paraphrased):** Systems reach an appropriate level of accuracy, robustness and cybersecurity and perform consistently.
- **AXIS mechanism:** Eval Hub suites with thresholds, regression and significance checks gate release; signed attestations bind results to a blueprint hash; the kernel, sandbox, SSRF guards and bypass guard address cybersecurity; a red-team suite is planned in Phase 9.
- **Code:** `services/eval-hub/src/gate.ts`, `services/eval-hub/src/scoring.ts`, `services/eval-hub/src/attest.ts`
- **Config / flags:** none
- **Evidence:** test: `services/eval-hub/test/gate.test.ts`; test: `services/eval-hub/test/scoring.test.ts`; make: `e2e-phase8`
- **Status:** Prototype
- **Notes and limits:** No live model has been evaluated; the red-team and robustness suites required for cybersecurity evidence do not exist yet.

### EUAIACT-Art17

- **Requirement (paraphrased):** Providers operate a quality management system covering design, testing, data, risk management and post-market monitoring.
- **AXIS mechanism:** None as a system. ADRs, phase plans and review subagents are engineering practice, not a quality management system.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** Policies, roles, procedures and records for a QMS are the provider's organisational responsibility.

### EUAIACT-Art26

- **Requirement (paraphrased):** Deployers use systems per the instructions, assign human oversight, monitor operation, keep logs and inform affected persons.
- **AXIS mechanism:** Tenant-scoped audit with verification supports log keeping and monitoring; approver roles assign oversight; transparency notices inform affected persons on supported channels.
- **Code:** `services/audit/src/export.ts`, `services/approvals/src/service.ts`, `packages/abl/src/lint.ts`
- **Config / flags:** none
- **Evidence:** test: `services/audit/test/export.test.ts`; test: `packages/abl/test/lint.test.ts`
- **Status:** Prototype
- **Notes and limits:** Six-month minimum log retention is not enforced; no workplace notification tooling; duties to cooperate with authorities are organisational.

### EUAIACT-Art27

- **Requirement (paraphrased):** Certain deployers assess the impact on fundamental rights before first use of a high-risk system.
- **AXIS mechanism:** AI impact assessment records capture the intended use, affected groups, risks, mitigations, stakeholders and review date, with versioning and independent approval; the console lists them read-only.
- **Code:** `services/compliance/src/records/assessments.ts`, `apps/console/app`
- **Config / flags:** none
- **Evidence:** test: `services/compliance/test/records.test.ts`; test: `services/compliance/test/properties.test.ts`
- **Status:** Prototype
- **Notes and limits:** Notification of the market surveillance authority and the official template are not modelled.

### EUAIACT-Art43

- **Requirement (paraphrased):** High-risk systems undergo the applicable conformity assessment procedure before being placed on the market.
- **AXIS mechanism:** None. The platform supplies evidence only.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** Conformity assessment, CE marking and registration in the EU database are the provider's.

### EUAIACT-Art50

- **Requirement (paraphrased):** People are told they are interacting with an AI system, and synthetic content is marked, unless obvious.
- **AXIS mechanism:** Limited and high risk blueprints must have a transparency notice (schema rule); a voice session plays its notice before anything else; the lint warns on voice without a notice.
- **Code:** `packages/abl/schema/abl-v1.schema.json`, `packages/abl/src/lint.ts`, `runtime/src/axis_runtime/voice`
- **Config / flags:** none
- **Evidence:** test: `packages/abl/test/compile.test.ts`; test: `runtime/tests/test_voice_compliance.py`
- **Status:** Prototype
- **Notes and limits:** Machine-readable marking of generated content is not implemented.

### EUAIACT-Art72

- **Requirement (paraphrased):** Providers establish a post-market monitoring system proportionate to the risk and collect and analyse relevant data.
- **AXIS mechanism:** Eval Hub online sampling runs production traffic through graders with human review of pending items; the Annex IV document reports sampling configurations; run logs are exposed through a read-only reader.
- **Code:** `services/eval-hub/src/online.ts`, `services/eval-hub/src/reviews.ts`
- **Config / flags:** none
- **Evidence:** test: `services/eval-hub/test/online.test.ts`; make: `e2e-phase8`
- **Status:** Prototype
- **Notes and limits:** No plan template, no aggregated analysis across deployers and no live production traffic has been sampled.

### EUAIACT-Art73

- **Requirement (paraphrased):** Serious incidents are reported to the market surveillance authorities within the set deadlines.
- **AXIS mechanism:** None beyond the audit trail that supports an investigation.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** No incident classification, deadline tracking or reporting template exists.

