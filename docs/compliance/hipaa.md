<!-- GENERATED from docs/compliance/matrix/hipaa.yaml by `make compliance-check ARGS=--write`. Do not edit by hand. -->

# HIPAA Security Rule and Privacy Rule control matrix

> Designed for / evidence-ready. This matrix maps requirements to AXIS mechanisms and to evidence that exists in this repository. It is not a certification, an attestation or a statement of conformity.

Maps the administrative, physical and technical safeguards of the HIPAA Security Rule, and the Privacy Rule requirements that affect a platform which may handle protected health information, to AXIS mechanisms and to evidence in this repository. AXIS is designed for and evidence-ready toward use by a covered entity or business associate. No business associate agreement has been signed with anyone, no PHI has been processed, and no assessment has been performed; PHI mode is a technical control, not an authorisation to process PHI.

Matrix version 1. Rows: 19 (Built 3, Prototype 6, Designed 2, Gap 8).

| id                | requirement                                                                                                                                                              | status    | evidence                                                                                                     |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------ |
| HIPAA-164.308a1   | A security management process includes risk analysis, risk management, sanction policy and review of information system activity.                                        | Prototype | `docs/security/risk-kernel-threat-model.md`<br>`services/agil/test/explain.test.ts`                          |
| HIPAA-164.308a2   | A security official is identified and responsible for the security programme.                                                                                            | Gap       | none                                                                                                         |
| HIPAA-164.308a3   | Workforce access to ePHI is authorised, supervised and terminated appropriately.                                                                                         | Prototype | `services/control-plane/test/scim.test.ts`<br>`services/control-plane/test/admin.test.ts`                    |
| HIPAA-164.308a4   | Information access management restricts access to ePHI to authorised persons and applications.                                                                           | Built     | `services/memory/test/isolation.test.ts`<br>`services/control-plane/test/api-authz.test.ts`<br>`policy-test` |
| HIPAA-164.308a5   | A security awareness and training programme exists for the workforce.                                                                                                    | Gap       | none                                                                                                         |
| HIPAA-164.308a6   | Security incidents are identified, responded to, mitigated and documented.                                                                                               | Designed  | `services/audit/test/export.test.ts`<br>`docs/runbooks/risk-kernel.md`                                       |
| HIPAA-164.308a7   | A contingency plan covers data backup, disaster recovery and emergency mode operation, and is tested.                                                                    | Gap       | none                                                                                                         |
| HIPAA-164.308a8   | Periodic technical and non-technical evaluation of the security programme is performed.                                                                                  | Prototype | `e2e-phase6`<br>`e2e-phase4`                                                                                 |
| HIPAA-164.308b    | A business associate contract is in place before a business associate creates, receives, maintains or transmits ePHI.                                                    | Gap       | none                                                                                                         |
| HIPAA-164.310a    | Facility access controls limit physical access to systems that hold ePHI.                                                                                                | Gap       | none                                                                                                         |
| HIPAA-164.310bc   | Workstation use and security are specified and implemented.                                                                                                              | Gap       | none                                                                                                         |
| HIPAA-164.310d    | Hardware and media containing ePHI are controlled on receipt, movement, re-use and disposal.                                                                             | Gap       | none                                                                                                         |
| HIPAA-164.312a1   | Technical access control allows only authorised persons and software to access ePHI, with unique user identification, emergency access, automatic logoff and encryption. | Prototype | `services/control-plane/test/sessions.test.ts`<br>`packages/db/test/tenancy.test.ts`                         |
| HIPAA-164.312b    | Audit controls record and examine activity in systems that contain or use ePHI.                                                                                          | Built     | `services/audit/test/pg.test.ts`<br>`packages/contracts/test/audit-chain.test.ts`<br>`e2e-core`              |
| HIPAA-164.312c    | Policies protect ePHI from improper alteration or destruction, and mechanisms authenticate ePHI.                                                                         | Built     | `services/audit/test/checkpoint.test.ts`<br>`packages/db/test/hardening.test.ts`                             |
| HIPAA-164.312d    | Persons or entities seeking access to ePHI are authenticated.                                                                                                            | Prototype | `services/control-plane/test/sso.test.ts`<br>`services/channels/test/jwt.test.ts`                            |
| HIPAA-164.312e    | Transmission security guards ePHI against unauthorised access in transit, including integrity controls and encryption.                                                   | Designed  | `apps/api-gateway/test/hardening.test.ts`<br>`services/channels/test/crypto.test.ts`                         |
| HIPAA-164.514d    | Uses and disclosures of PHI are limited to the minimum necessary, with redaction and role-based limits.                                                                  | Prototype | `services/memory/test/redact.test.ts`<br>`runtime/tests/test_redaction_tools.py`<br>`e2e-phase5`             |
| HIPAA-164.404-408 | Breaches of unsecured PHI are notified to individuals, the regulator and in some cases the media, without unreasonable delay.                                            | Gap       | none                                                                                                         |

## Controls

### HIPAA-164.308a1

- **Requirement (paraphrased):** A security management process includes risk analysis, risk management, sanction policy and review of information system activity.
- **AXIS mechanism:** Per-service threat models record risks and mitigations; the audit chain and AGIL support activity review; sanctions are an organisational matter.
- **Code:** `services/agil/src/explain.ts`
- **Config / flags:** none
- **Evidence:** doc: `docs/security/risk-kernel-threat-model.md`; test: `services/agil/test/explain.test.ts`
- **Status:** Prototype
- **Notes and limits:** No formal risk analysis of an operator's PHI environment exists, and there is no sanction policy or activity review schedule.

### HIPAA-164.308a2

- **Requirement (paraphrased):** A security official is identified and responsible for the security programme.
- **AXIS mechanism:** None in the product.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** An organisational designation by the operator.

### HIPAA-164.308a3

- **Requirement (paraphrased):** Workforce access to ePHI is authorised, supervised and terminated appropriately.
- **AXIS mechanism:** Role-based membership with SCIM deprovisioning, session and key revocation, and tenant-scoped audit of membership changes.
- **Code:** `services/control-plane/src/scim.ts`, `services/control-plane/src/sessions.ts`, `services/control-plane/src/admin.ts`
- **Config / flags:** none
- **Evidence:** test: `services/control-plane/test/scim.test.ts`; test: `services/control-plane/test/admin.test.ts`
- **Status:** Prototype
- **Notes and limits:** Workforce clearance procedures and supervision are not modelled; tested against a fake IdP only.

### HIPAA-164.308a4

- **Requirement (paraphrased):** Information access management restricts access to ePHI to authorised persons and applications.
- **AXIS mechanism:** Roles decided by a policy pack, API key scopes, memory ACLs, PHI deny rules in policy, and tenant isolation in the database.
- **Code:** `policies/phi-redaction/pack.yaml`, `services/memory/src/acl.ts`, `services/control-plane/src/authz.ts`
- **Config / flags:** `policies/phi-redaction/composition.cases.yaml`
- **Evidence:** test: `services/memory/test/isolation.test.ts`; test: `services/control-plane/test/api-authz.test.ts`; make: `policy-test`
- **Status:** Built
- **Notes and limits:** Access to ePHI outside the platform (the operator's own systems) is out of scope.

### HIPAA-164.308a5

- **Requirement (paraphrased):** A security awareness and training programme exists for the workforce.
- **AXIS mechanism:** None in the product.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** An organisational control for the operator.

### HIPAA-164.308a6

- **Requirement (paraphrased):** Security incidents are identified, responded to, mitigated and documented.
- **AXIS mechanism:** Kill switches, the append-only audit chain and the export for forensics give technical means; the response procedure is not written.
- **Code:** `services/risk-kernel/src/stores.ts`, `services/audit/src/export.ts`
- **Config / flags:** none
- **Evidence:** test: `services/audit/test/export.test.ts`; doc: `docs/runbooks/risk-kernel.md`
- **Status:** Designed
- **Notes and limits:** No incident response plan, roles or tabletop exercise exists.

### HIPAA-164.308a7

- **Requirement (paraphrased):** A contingency plan covers data backup, disaster recovery and emergency mode operation, and is tested.
- **AXIS mechanism:** None yet; backup and tested restore are planned in Phase 9.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** No backup has been taken or restored; fail-closed behaviour is the only emergency-mode property.

### HIPAA-164.308a8

- **Requirement (paraphrased):** Periodic technical and non-technical evaluation of the security programme is performed.
- **AXIS mechanism:** End-to-end suites, mutation checks of safety logic and eval gates are run per phase; a separate review audits each phase exit.
- **Code:** `e2e/mutation_phase8.py`
- **Config / flags:** none
- **Evidence:** make: `e2e-phase6`; make: `e2e-phase4`
- **Status:** Prototype
- **Notes and limits:** Internal evaluations only; no independent assessment or penetration test.

### HIPAA-164.308b

- **Requirement (paraphrased):** A business associate contract is in place before a business associate creates, receives, maintains or transmits ePHI.
- **AXIS mechanism:** None in the product. Technical controls support the obligations a BAA would impose.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** No BAA exists with any party, including model providers, channel providers and cloud providers. PHI must not be sent to a model provider or a channel provider without one; the platform cannot check that a BAA exists.

### HIPAA-164.310a

- **Requirement (paraphrased):** Facility access controls limit physical access to systems that hold ePHI.
- **AXIS mechanism:** None in the product; inherited from the hosting provider.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** Nothing is hosted yet.

### HIPAA-164.310bc

- **Requirement (paraphrased):** Workstation use and security are specified and implemented.
- **AXIS mechanism:** None in the product.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** An organisational control for the operator's workforce.

### HIPAA-164.310d

- **Requirement (paraphrased):** Hardware and media containing ePHI are controlled on receipt, movement, re-use and disposal.
- **AXIS mechanism:** None in the product.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** Inherited from the hosting provider; no disposal procedure is represented.

### HIPAA-164.312a1

- **Requirement (paraphrased):** Technical access control allows only authorised persons and software to access ePHI, with unique user identification, emergency access, automatic logoff and encryption.
- **AXIS mechanism:** Unique member identity per session or key, sessions that expire and can be revoked, tenant row-level security, and sealed storage of tenant secrets.
- **Code:** `services/control-plane/src/sessions.ts`, `services/control-plane/src/crypto.ts`, `packages/db/migrations/0001_tenancy_and_rls.sql`
- **Config / flags:** none
- **Evidence:** test: `services/control-plane/test/sessions.test.ts`; test: `packages/db/test/tenancy.test.ts`
- **Status:** Prototype
- **Notes and limits:** No emergency access procedure; encryption at rest of the database is not configured by the repository and key management is a fake KMS.

### HIPAA-164.312b

- **Requirement (paraphrased):** Audit controls record and examine activity in systems that contain or use ePHI.
- **AXIS mechanism:** Every governed action has a decision row in an append-only, hash-chained log with trace ids; the chain can be verified and exported; runs are replayable from events.
- **Code:** `services/audit/src/chain.ts`, `services/audit/src/export.ts`, `packages/contracts/src/audit-chain.ts`
- **Config / flags:** none
- **Evidence:** test: `services/audit/test/pg.test.ts`; test: `packages/contracts/test/audit-chain.test.ts`; make: `e2e-core`
- **Status:** Built
- **Notes and limits:** Inputs and outputs are stored as hashes; the log proves what was decided, not the PHI itself. KMS signing and WORM export are not built.

### HIPAA-164.312c

- **Requirement (paraphrased):** Policies protect ePHI from improper alteration or destruction, and mechanisms authenticate ePHI.
- **AXIS mechanism:** Append-only tables with database triggers, hash-chained events with signed checkpoints, signed blueprints and verified provenance, content hashes on eval runs.
- **Code:** `packages/db/migrations/0005_audit_checkpoints.sql`, `services/audit/src/checkpoint.ts`
- **Config / flags:** none
- **Evidence:** test: `services/audit/test/checkpoint.test.ts`; test: `packages/db/test/hardening.test.ts`
- **Status:** Built
- **Notes and limits:** Protects the platform's records; integrity of the operator's source systems is out of scope.

### HIPAA-164.312d

- **Requirement (paraphrased):** Persons or entities seeking access to ePHI are authenticated.
- **AXIS mechanism:** SSO with verified assertions, session tokens stored as hashes, API keys stored as hashes, signed webhooks for channels.
- **Code:** `services/control-plane/src/sso.ts`, `services/control-plane/src/apikeys.ts`, `services/channels/src/jwt.ts`
- **Config / flags:** none
- **Evidence:** test: `services/control-plane/test/sso.test.ts`; test: `services/channels/test/jwt.test.ts`
- **Status:** Prototype
- **Notes and limits:** Fake IdP only; no multi-factor requirement is enforced by the platform.

### HIPAA-164.312e

- **Requirement (paraphrased):** Transmission security guards ePHI against unauthorised access in transit, including integrity controls and encryption.
- **AXIS mechanism:** Webhook signatures and replay protection, HSTS support in the gateway behind TLS termination, strict CSP and CSRF checks in the console. TLS termination itself is not in the repository.
- **Code:** `apps/api-gateway/src/server.ts`, `services/channels/src/crypto.ts`
- **Config / flags:** none
- **Evidence:** test: `apps/api-gateway/test/hardening.test.ts`; test: `services/channels/test/crypto.test.ts`
- **Status:** Designed
- **Notes and limits:** Internal service links are loopback HTTP or gRPC without TLS in the dev composition; encryption in transit between services is not designed for production yet.

### HIPAA-164.514d

- **Requirement (paraphrased):** Uses and disclosures of PHI are limited to the minimum necessary, with redaction and role-based limits.
- **AXIS mechanism:** PHI mode redacts before persistence in memory and channels, PHI-flagged datasets are redacted by the Eval Hub, policy rules deny PHI to disallowed destinations, and ABL requires a residency declaration for PHI blueprints.
- **Code:** `services/memory/src/redact.ts`, `services/channels/src/redact.ts`, `services/eval-hub/src/redact.ts`, `policies/phi-redaction/pack.yaml`
- **Config / flags:** none
- **Evidence:** test: `services/memory/test/redact.test.ts`; test: `runtime/tests/test_redaction_tools.py`; make: `e2e-phase5`
- **Status:** Prototype
- **Notes and limits:** Redaction is pattern based and has false negatives; a cross-store PHI canary test is planned in Phase 9 and is not in this tree.

### HIPAA-164.404-408

- **Requirement (paraphrased):** Breaches of unsecured PHI are notified to individuals, the regulator and in some cases the media, without unreasonable delay.
- **AXIS mechanism:** None in the product beyond the audit trail that supports the investigation.
- **Code:** none
- **Config / flags:** none
- **Evidence:** none
- **Status:** Gap
- **Notes and limits:** No breach risk assessment, register or notification templates exist.
