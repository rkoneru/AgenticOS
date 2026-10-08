# Runbook: compliance records and documentation

Designed for / evidence-ready. None of this is a certification. Spec: `docs/spec/compliance.md`; threat model:
`docs/security/compliance-threat-model.md`.

## Check the control matrix

```bash
make compliance-check               # fails on a missing path / test / make target, Built without evidence, forbidden wording, stale Markdown
make compliance-check ARGS=--write  # re-render docs/compliance/*.md from the YAML (never edits the YAML)
```

A finding names the code, the framework, the row and the reason (`M012 soc2 SOC2-CC6.1: test evidence does not exist: ...`). To change a status,
change the evidence first: `Built` needs a test, a make target or an audit query that exists. Do not delete a Gap to improve a count; the
required rows are listed in `services/compliance/src/matrix/required.ts` and the checker fails when one is removed.

## Generate and verify technical documentation

```bash
axis compliance documents generate claims-triage@2.3.1      # 201: stored as the next version; 200: unchanged since the latest
axis compliance documents list --blueprint claims-triage
axis compliance documents get cdoc-... --markdown --out doc.md   # exit 1 if hash, Markdown or seal do not verify
```

Read the **Gaps** section first. Typical gaps and what they mean:

| gap                                                                     | meaning and action                                                                                             |
| ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `sources / blueprint`                                                   | the blueprint is neither in the tenant store nor in a registry namespace of the tenant; check name and version |
| `development / registry_provenance`                                     | the blueprint is tenant-local; publish it through the registry to get a signature and provenance               |
| `development / registry_verification`                                   | the registry re-verification failed: the document lists the failed checks; do not release the version          |
| `performance / suite:...`                                               | a declared eval suite has no passing run for this content hash; run it                                         |
| `performance / gate:...`                                                | the release gate does not pass for that suite                                                                  |
| `record_keeping / audit_chain`                                          | chain verification failed in the window: run `axis audit verify` and follow `docs/runbooks/audit.md`           |
| `post_market / online_sampling`                                         | no enabled production sampling configuration                                                                   |
| `general / hardware_and_deployer_instructions` and Annex IV points 7, 8 | always a gap: the provider supplies them                                                                       |

A verification failure on read (`seal_signature`, `content_hash`, `markdown`) means the stored bytes were changed or the document was sealed with
a key this deployment no longer trusts. Do not hand it to an auditor; regenerate (the old row stays, append-only) and investigate with the audit
chain (`compliance.document.generate` events carry the blueprint name and version).

Seal key: the standalone gateway derives an HMAC key from `GW_SEAL_KEY`. Changing that key makes every earlier document fail `seal_signature`.
Rotate by adding the old sealer to `trustedSealers` in the composition (NEEDS #3103).

## Impact assessments

```bash
axis compliance systems create --file system.yaml
axis compliance assessments create --file assessment.yaml        # draft v1
axis compliance assessments submit <id> --expected-version 1
axis compliance assessments review <id> --expected-version 1 --decision approve --comment "..."   # a different person
axis compliance assessments list --overdue                        # review date passed, or waiting for a reviewer > 14 days
```

- "reviewer refused" (403): the member authored, edited or submitted that version. Ask someone else with the role owner, admin or auditor.
- "changed since it was read" (409): another member changed it; read it again and pass the new `--expected-version`.
- A reviewed version is frozen. `axis compliance assessments revise <id> --expected-version N --file patch.yaml` starts version N+1 as a draft.
- Every step is in the tenant's audit chain (`compliance.assessment.*`).

## Tenant isolation spot check

```sql
-- as axis_app with no tenant set: nothing is visible
BEGIN; SET LOCAL ROLE axis_app; SELECT count(*) FROM compliance_docs; ROLLBACK;   -- 0
```

## Dev server

```bash
AXIS_COMPLIANCE_DATABASE_URL=... AXIS_COMPLIANCE_SEAL_SECRET=<16+ chars> \
AXIS_COMPLIANCE_TOKENS='{"tok":{"tenantId":"<uuid>","subject":"u1","role":"admin"}}' node services/compliance/dist/main.js
```

Loopback only; the token fixes tenant, subject and role; refuses `NODE_ENV=production`. In this mode every document source is a gap.
