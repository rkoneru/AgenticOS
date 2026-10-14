<!-- GENERATED from docs/compliance/matrix/gdpr.yaml by `make compliance-check ARGS=--write`. Do not edit by hand. -->

# GDPR control matrix

> Designed for / evidence-ready. This matrix maps requirements to AXIS mechanisms and to evidence that exists in this repository. It is not a certification, an attestation or a statement of conformity.

Maps the articles of Regulation (EU) 2016/679 that a processor or controller of an agent platform must address (principles, lawful basis and consent hooks, data subject rights, data protection by design, processors, records of processing, security, breach notification, impact assessment, transfers) to AXIS mechanisms and to evidence in this repository. AXIS is designed for and evidence-ready toward these obligations. It is not legal advice, and whether a deployment meets the Regulation depends on the operator's own role, contracts and procedures. Data subject export, erasure and restriction and retention enforcement exist as a dev-stack prototype (services/data-governance) and are proven end to end in `make e2e-phase9`; correction (Art. 16) is not built.

Matrix version 1. Rows: 15 (Built 2, Prototype 9, Designed 3, Gap 1).

| id | requirement | status | evidence |
| --- | --- | --- | --- |
| GDPR-Art5 | Personal data is processed lawfully, fairly and transparently, for specified purposes, minimised, accurate, kept no longer than needed, and protected, and the controller can demonstrate this. | Prototype | `services/memory/test/redact.test.ts`<br>`services/audit/test/pg.test.ts` |
| GDPR-Art6-7 | Processing needs a lawful basis; where consent is the basis it must be freely given, specific, demonstrable and as easy to withdraw as to give. | Prototype | `runtime/tests/test_voice_compliance.py`<br>`services/channels/test/identity.test.ts` |
| GDPR-Art12-14 | Information about the processing is given to data subjects in a concise, transparent and accessible form. | Prototype | `packages/abl/test/lint.test.ts`<br>`services/compliance/test/docgen.test.ts` |
| GDPR-Art15 | A data subject can obtain confirmation of processing and a copy of their personal data. | Prototype | `services/data-governance/test/dsar.test.ts`<br>`e2e/test_governance.py`<br>`e2e/test_phase9_hardening.py`<br>`e2e-phase9` |
| GDPR-Art16 | A data subject can have inaccurate personal data corrected. | Gap | none |
| GDPR-Art17 | A data subject can have personal data erased where the grounds apply. | Prototype | `services/data-governance/test/dsar.test.ts`<br>`services/data-governance/test/kit.pg.test.ts`<br>`e2e/test_phase9_hardening.py`<br>`e2e-phase9` |
| GDPR-Art18-21 | A data subject can restrict processing, is notified of rectification or erasure, can port their data and can object to processing. | Prototype | `services/data-governance/test/dsar.test.ts`<br>`e2e/test_governance.py` |
| GDPR-Art22 | A data subject is not subject to a decision based solely on automated processing with legal or similarly significant effect, without safeguards. | Built | `services/approvals/test/service.test.ts`<br>`e2e-phase3` |
| GDPR-Art25 | Data protection is built into the design and defaults of processing. | Built | `packages/db/test/tenancy.test.ts`<br>`services/memory/test/isolation.test.ts`<br>`e2e-phase4` |
| GDPR-Art28 | A processor acts only on documented instructions and is bound by a contract that covers security, sub-processors, assistance and deletion. | Designed | `services/control-plane/test/modelkeys.test.ts` |
| GDPR-Art30 | Records of processing activities are maintained and available to the supervisory authority. | Prototype | `services/compliance/test/records.test.ts`<br>`services/compliance/test/stores.test.ts` |
| GDPR-Art32 | Technical and organisational measures give a level of security appropriate to the risk. | Prototype | `services/control-plane/test/crypto.test.ts`<br>`services/audit/test/checkpoint.test.ts`<br>`e2e-phase6` |
| GDPR-Art33-34 | A personal data breach is notified to the supervisory authority within 72 hours and, where risk is high, to the data subjects. | Designed | `docs/runbooks/audit.md` |
| GDPR-Art35 | A data protection impact assessment is made before processing that is likely to result in a high risk. | Prototype | `e2e-compliance`<br>`services/compliance/test/records.test.ts`<br>`services/compliance/test/properties.test.ts` |
| GDPR-Art44-49 | Personal data is transferred outside the EEA only under an adequacy decision, safeguards or a listed derogation. | Designed | `packages/abl/test/lint.test.ts` |

## Controls

### GDPR-Art5

- **Requirement (paraphrased):** Personal data is processed lawfully, fairly and transparently, for specified purposes, minimised, accurate, kept no longer than needed, and protected, and the controller can demonstrate this.
- **AXIS mechanism:** Purpose is declared per blueprint (intended purpose and data section); memory scopes are opt-in; PHI mode redacts before persistence; every action is auditable and the chain can be verified to demonstrate what happened.
- **Code:** `packages/abl/schema/abl-v1.schema.json`, `services/memory/src/redact.ts`, `services/audit/src/chain.ts`
- **Config / flags:** none
- **Evidence:** test: `services/memory/test/redact.test.ts`; test: `services/audit/test/pg.test.ts`
- **Status:** Prototype
- **Notes and limits:** Accuracy is not enforced by tooling (no correction workflow); storage limitation has a retention engine with legal holds that is proven in `make e2e-phase9` but is an operator-run job, not a scheduler. Redaction is pattern based.

### GDPR-Art6-7

- **Requirement (paraphrased):** Processing needs a lawful basis; where consent is the basis it must be freely given, specific, demonstrable and as easy to withdraw as to give.
- **AXIS mechanism:** Consent hooks exist where a channel needs them: a voice session plays the notice before anything else, refuses to continue without required consent, and sends no speech to the agent before it; channel identities link only through an explicit linking step.
- **Code:** `runtime/src/axis_runtime/voice`, `services/channels/src/identity.ts`
- **Config / flags:** none
- **Evidence:** test: `runtime/tests/test_voice_compliance.py`; test: `services/channels/test/identity.test.ts`
- **Status:** Prototype
- **Notes and limits:** There is no consent registry, no withdrawal flow and no lawful-basis field per processing activity; the operator must supply them.

### GDPR-Art12-14

- **Requirement (paraphrased):** Information about the processing is given to data subjects in a concise, transparent and accessible form.
- **AXIS mechanism:** Blueprints at limited or high risk must carry a transparency notice that the runtime shows; the lint warns when a voice channel has none; the Annex IV generator records the notice in the technical documentation.
- **Code:** `packages/abl/src/lint.ts`, `services/compliance/src/docgen/assemble.ts`
- **Config / flags:** none
- **Evidence:** test: `packages/abl/test/lint.test.ts`; test: `services/compliance/test/docgen.test.ts`
- **Status:** Prototype
- **Notes and limits:** A privacy notice for the operator's own processing is the operator's document; nothing here generates one.

### GDPR-Art15

- **Requirement (paraphrased):** A data subject can obtain confirmation of processing and a copy of their personal data.
- **AXIS mechanism:** A privacy officer opens a request for a person; an independent owner or admin attests the requester's identity (dual control); the export runs every registered subject-data provider (control-plane members, channels and voice transcripts, memory, Eval Hub cases and results, run logs, approvals, billing references) and returns a bundle with an Ed25519 signature, per-store counts and hashes.
- **Code:** `services/data-governance/src/dsar.ts`, `services/data-governance/src/bundle.ts`, `services/data-governance/src/verifier.ts`, `apps/api-gateway/src/adapters/governance.ts`
- **Config / flags:** none
- **Evidence:** test: `services/data-governance/test/dsar.test.ts`; test: `e2e/test_governance.py`; test: `e2e/test_phase9_hardening.py`; make: `e2e-phase9`
- **Status:** Prototype
- **Notes and limits:** Discovery is exact-match on identifiers the requester supplies (NEEDS 364); requester identity proofing is out of band and its master key a dev stand-in (NEEDS 407); the run service's in-memory run log is outside the export (NEEDS 413).

### GDPR-Art16

- **Requirement (paraphrased):** A data subject can have inaccurate personal data corrected.
- **AXIS mechanism:** None yet.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** Memory entries are not editable by subject reference; no correction audit trail exists.

### GDPR-Art17

- **Requirement (paraphrased):** A data subject can have personal data erased where the grounds apply.
- **AXIS mechanism:** Erasure is idempotent and resumable per provider, then a verification pass re-queries every provider and any residual stops the request; the audit chain keeps hashes and pseudonymous references only (a guard refuses an event that would carry a raw identifier), the sealed identifiers are crypto-shredded, and a legal hold suspends the erasure until released.
- **Code:** `services/data-governance/src/dsar.ts`, `services/data-governance/src/audit.ts`, `services/data-governance/src/holds.ts`, `services/data-governance/src/providers/memory.ts`, `services/data-governance/src/providers/channels.ts`
- **Config / flags:** none
- **Evidence:** test: `services/data-governance/test/dsar.test.ts`; test: `services/data-governance/test/kit.pg.test.ts`; test: `e2e/test_phase9_hardening.py`; make: `e2e-phase9`
- **Status:** Prototype
- **Notes and limits:** Backups are not covered (NEEDS 371); rows that must be kept for accountability are pseudonymised, not deleted (member, billing and approval rows); erasure runs inside one HTTP request (NEEDS 410).

### GDPR-Art18-21

- **Requirement (paraphrased):** A data subject can restrict processing, is notified of rectification or erasure, can port their data and can object to processing.
- **AXIS mechanism:** Restriction is recorded as a hold that processing paths consult (HoldRegistry.isRestricted); portability is the signed JSON export of the subject's records; notification of recipients and objection handling are not built.
- **Code:** `services/data-governance/src/holds.ts`, `services/data-governance/src/registry.ts`, `services/data-governance/src/bundle.ts`
- **Config / flags:** none
- **Evidence:** test: `services/data-governance/test/dsar.test.ts`; test: `e2e/test_governance.py`
- **Status:** Prototype
- **Notes and limits:** No service calls the restriction check on its processing path yet (NEEDS 362); the export format is a JSON bundle, not a standard portability schema; objection handling is undefined.

### GDPR-Art22

- **Requirement (paraphrased):** A data subject is not subject to a decision based solely on automated processing with legal or similarly significant effect, without safeguards.
- **AXIS mechanism:** A high-risk blueprint must require human oversight with named approver roles; the Risk Kernel returns REQUIRE_APPROVAL, the action waits for an approver who is not the requester, and the decision is audited.
- **Code:** `packages/abl/schema/abl-v1.schema.json`, `services/approvals/src/service.ts`, `services/risk-kernel/src/approvals.ts`
- **Config / flags:** none
- **Evidence:** test: `services/approvals/test/service.test.ts`; make: `e2e-phase3`
- **Status:** Built
- **Notes and limits:** Whether a given use is solely automated is a judgement for the operator; the platform enforces the oversight a blueprint declares, nothing more.

### GDPR-Art25

- **Requirement (paraphrased):** Data protection is built into the design and defaults of processing.
- **AXIS mechanism:** Default deny in the Risk Kernel, tenant isolation in the database, PHI redaction before persistence, memory scopes off unless declared, and secrets kept out of blueprints and logs.
- **Code:** `services/risk-kernel/src/kernel.ts`, `packages/db/migrations/0001_tenancy_and_rls.sql`, `services/memory/src/acl.ts`
- **Config / flags:** `policies/baseline-deny/pack.yaml`
- **Evidence:** test: `packages/db/test/tenancy.test.ts`; test: `services/memory/test/isolation.test.ts`; make: `e2e-phase4`
- **Status:** Built
- **Notes and limits:** Covers the platform's own defaults; the operator's blueprints and policy packs still decide what an agent may do with personal data.

### GDPR-Art28

- **Requirement (paraphrased):** A processor acts only on documented instructions and is bound by a contract that covers security, sub-processors, assistance and deletion.
- **AXIS mechanism:** Technical enablers only: tenant isolation, bring-your-own model keys, a single model gateway and an audit chain that records gated actions. The contract itself is not a repository artifact.
- **Code:** `services/control-plane/src/modelkeys.ts`, `runtime/src/axis_runtime/models`
- **Config / flags:** none
- **Evidence:** test: `services/control-plane/test/modelkeys.test.ts`
- **Status:** Designed
- **Notes and limits:** No data processing agreement template, sub-processor list or customer instruction log exists; no live provider has been called.

### GDPR-Art30

- **Requirement (paraphrased):** Records of processing activities are maintained and available to the supervisory authority.
- **AXIS mechanism:** The AI system inventory records purpose, owner, risk level, data categories and stakeholders per system and version; blueprints declare data and residency; the audit chain records what ran.
- **Code:** `services/compliance/src/records/inventory.ts`, `packages/db/migrations/0014_compliance.sql`
- **Config / flags:** none
- **Evidence:** test: `services/compliance/test/records.test.ts`; test: `services/compliance/test/stores.test.ts`
- **Status:** Prototype
- **Notes and limits:** The inventory is a record per AI system, not a full Article 30 register (no recipients, transfers or retention periods per activity); it is exposed read-only in the console.

### GDPR-Art32

- **Requirement (paraphrased):** Technical and organisational measures give a level of security appropriate to the risk.
- **AXIS mechanism:** Pseudonymisation and redaction before persistence, sealed storage of tenant keys, access control, an append-only verified audit chain, tenant isolation, resilience through fail-closed design, and regular testing through the end-to-end suites.
- **Code:** `services/control-plane/src/crypto.ts`, `services/audit/src/checkpoint.ts`, `packages/db/migrations/0001_tenancy_and_rls.sql`
- **Config / flags:** none
- **Evidence:** test: `services/control-plane/test/crypto.test.ts`; test: `services/audit/test/checkpoint.test.ts`; make: `e2e-phase6`
- **Status:** Prototype
- **Notes and limits:** No encryption at rest is configured by the repository, key management uses a fake KMS, and there is no tested restore or penetration test.

### GDPR-Art33-34

- **Requirement (paraphrased):** A personal data breach is notified to the supervisory authority within 72 hours and, where risk is high, to the data subjects.
- **AXIS mechanism:** The audit chain and its verification support establishing what was accessed and when; the runbooks describe how to read and verify it. There is no breach workflow.
- **Code:** `services/audit/src/export.ts`
- **Config / flags:** none
- **Evidence:** doc: `docs/runbooks/audit.md`
- **Status:** Designed
- **Notes and limits:** No breach register, notification templates, severity assessment or clock tracking exists.

### GDPR-Art35

- **Requirement (paraphrased):** A data protection impact assessment is made before processing that is likely to result in a high risk.
- **AXIS mechanism:** AI impact assessment records link a system and its blueprint versions to affected groups, risks, mitigations and a review date, with an independent reviewer and overdue detection.
- **Code:** `services/compliance/src/records/assessments.ts`, `services/compliance/src/records/states.ts`
- **Config / flags:** none
- **Evidence:** make: `e2e-compliance`; test: `services/compliance/test/records.test.ts`; test: `services/compliance/test/properties.test.ts`
- **Status:** Prototype
- **Notes and limits:** The record is an AI impact assessment, not a templated DPIA; prior consultation with the authority and DPO advice are not modelled.

### GDPR-Art44-49

- **Requirement (paraphrased):** Personal data is transferred outside the EEA only under an adequacy decision, safeguards or a listed derogation.
- **AXIS mechanism:** Blueprints declare a data residency, PHI blueprints must declare one (lint ABL005), and tenants have a home region. Enforcement of the region on write paths and in model provider selection is planned in Phase 9.
- **Code:** `packages/abl/src/lint.ts`, `packages/db/migrations/0001_tenancy_and_rls.sql`
- **Config / flags:** none
- **Evidence:** test: `packages/abl/test/lint.test.ts`
- **Status:** Designed
- **Notes and limits:** Residency is declared but not enforced, no transfer mechanism (SCCs) is recorded, and no regional deployment exists.

