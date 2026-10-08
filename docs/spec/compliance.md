# Compliance service

Status: **Prototype** (built against memory and real Postgres 16; wired into the gateway, both SDKs, the CLI and the console; fakes for the IdP and KMS)
· Package: `services/compliance` (`@axis/compliance`) · ADRs 0070-0074 · OpenAPI 1.5.0 · Matrix: `docs/compliance/`

AXIS is **designed for and evidence-ready toward** SOC 2, GDPR, HIPAA, the EU AI Act and ISO/IEC 42001. Nothing here is a certification, an
attestation or a statement that any system meets a standard. The service produces three things: a checked **control matrix**, sealed **technical
documentation** per blueprint version (EU AI Act Annex IV structure), and ISO/IEC 42001 **records** (AI system inventory and AI impact
assessments with an independent review).

## 1. Control matrix

`docs/compliance/matrix/<framework>.yaml`, one file per framework (`soc2`, `gdpr`, `hipaa`, `euaiact`, `iso42001`). A row:

```yaml
- id: SOC2-CC6.1 # framework prefix + control reference
  requirement: paraphrase, never copied text
  mechanism: how AXIS addresses it
  code: [services/control-plane/src/authz.ts] # files or directories that exist
  config: [policies/control-plane/pack.yaml] # `path#needle`: the needle must appear in the file
  evidence: # test | make | doc | file | audit_query
    - { kind: test, ref: packages/db/test/tenancy.test.ts }
    - { kind: make, ref: policy-test }
    - {
        kind: audit_query,
        ref: services/compliance/src/records/assessments.ts#compliance.assessment.review,
      }
  status: Built # Built | Prototype | Designed | Gap
  notes: limits and what is missing
```

`make compliance-check` (also `pnpm --filter @axis/compliance check`) fails when:

| code    | finding                                                                                             |
| ------- | --------------------------------------------------------------------------------------------------- |
| M001    | a file does not parse or a row has the wrong shape (unknown keys are errors)                        |
| M002/04 | duplicate framework or row id; a row id without the framework prefix                                |
| M005    | a required row (listed in `src/matrix/required.ts`) or framework file is missing                    |
| M010-11 | a cited code path or config path/needle does not exist, or leaves the repository                    |
| M012-14 | evidence does not exist (test, doc, file, make target, audit query), a test file holds no test case |
| M020    | `Built` without a test, make or audit-query evidence                                                |
| M021    | `Built` or `Prototype` without a code path                                                          |
| M022    | `Gap` or `Designed` without notes saying what is missing                                            |
| M030    | wording that claims attainment (certified, compliant, "guarantees compliance", ...)                 |
| M040    | the rendered Markdown (`docs/compliance/<framework>.md`, `summary.md`) differs from the YAML        |

`make compliance-check ARGS=--write` rewrites the Markdown first. The same check runs inside the package tests against the real repository.
Labelling rules are in `docs/compliance/README.md`. The checker proves that cited evidence exists and has the right shape; it does not run
the tests and cannot judge adequacy (NEEDS #352).

## 2. Technical documentation (Annex IV structure)

`POST /v1/compliance/documents {blueprint: {name, version}}` (`ax.compliance.documents.generate`, `axis compliance documents generate name@version`).

**Sources** (ports, each asked for the caller's tenant, subject and role):

| source      | provides                                                                                          | gateway implementation                |
| ----------- | ------------------------------------------------------------------------------------------------- | ------------------------------------- |
| blueprints  | ABL document, content hash, registry provenance and a fresh verification, other versions          | tenant blueprint store, then registry |
| evals       | runs of this content hash, signed attestations (verified), release-gate verdicts, online sampling | Eval Hub and registry                 |
| policies    | policy packs active for the tenant                                                                | control-plane policy port             |
| audit       | event counts by decision and enforcement point, head, window, chain verification                  | audit port                            |
| limitations | known limitations of the platform                                                                 | numbered rows of `docs/NEEDS.md`      |

**Document.** `{body, content_hash, meta, markdown, seal}`. `body.sections` has ten sections (general, development, oversight, risk_management,
data_governance, performance, lifecycle, record_keeping, post_market, limitations), each `complete`, `partial` or `gap` with the Annex IV points
it carries; `body.annex_iv_coverage` lists every Annex IV point as evidenced, partial or gap; `body.gaps` lists everything the generator could not
evidence, with the reason. A source that is unavailable, throws or fails verification becomes a gap (the error text is not copied). The system
instructions of a blueprint appear only as a hash and a length. Hardware, harmonised standards applied and the declaration of conformity are
always gaps.

**Determinism.** `assemble` is a pure function; arrays are sorted with a total order; the body holds no timestamps. Identical sources give an
identical `content_hash`, and then no new version is stored (`created: false`, HTTP 200; a new version is 201). The generation time lives in
`meta`.

**Seal.** `content_hash` = SHA-256 of the canonical JSON of `body`. `seal.sig` signs `{content_hash, meta}`, and `meta.markdown_sha256` binds the
Markdown. `GET /v1/compliance/documents/{id}` recomputes the body hash, re-renders and compares the Markdown, and verifies the signature on
every read: `verification: {ok, failed[]}` with `failed` among `content_hash`, `markdown`, `seal_key`, `seal_signature`. HMAC-SHA256 and Ed25519
sealers are implemented (both deterministic).

## 3. AI system inventory and impact assessments (ISO/IEC 42001)

**Inventory** (`/v1/compliance/systems`): `{system_id, version, name, purpose, owner, risk_level, lifecycle_stage, blueprints[], data_categories[],
stakeholders[]}`. `PUT` with `expected_version` writes the next version; every version stays readable (`?version=`); nothing is deleted
(`lifecycle_stage: retired`).

**Impact assessments** (`/v1/compliance/impact-assessments`): `{assessment_id, version, system_id, title, state, risk_rating, intended_use,
blueprints[], affected_groups[], risks[], stakeholders[], review_due, author, contributors[], submitted_by, reviewed_by, review_comment,
supersedes}` plus derived `overdue`, `overdue_reason`, `superseded`.

```
draft --submit--> in_review --approve--> approved   (final for this version)
                     |  \--reject---> rejected      (final; a comment is required)
                     \--withdraw--> draft
approved | rejected --revise--> a NEW version (draft, authored by the reviser)
```

- A draft is edited in place; every editor becomes a contributor. A version in review cannot be edited.
- **The reviewer is never the author, a contributor or the member who submitted that version.** The service refuses (403, audited DENY) and the
  database constraint states the same rule for approved and rejected rows.
- `overdue`: an approved latest version is overdue after the end of its `review_due` day; a version waiting for a reviewer is overdue after 14
  days. A superseded version is never overdue. `GET ...?overdue=true` lists them.
- Every mutation is audited into the tenant's chain: `compliance.system.{create,update}`, `compliance.assessment.{create,revise,submit,withdraw,review}`,
  `compliance.document.generate`, each with `.done` or `.failed`, and a DENY row for a refused call.

## 4. Access

`api.compliance.read|write|review` (ADR 0072). Reads: every role but billing. Write (inventory, drafts, submit, withdraw, generate): owner, admin,
builder. Review: owner, admin, auditor. API-key scopes `compliance:read` and `compliance:write` (write covers review). Another tenant's ids are a 404.

## 5. Surfaces

| surface | where                                                                                                                 |
| ------- | --------------------------------------------------------------------------------------------------------------------- |
| API     | 14 operations, tag `Compliance`, OpenAPI 1.5.0                                                                        |
| TS SDK  | `ax.compliance.systems.*`, `.assessments.*` (`approve`, `reject`), `.documents.*`                                     |
| Python  | `ax.compliance.systems.*` (sync and async)                                                                            |
| CLI     | `axis compliance systems\|assessments\|documents ...` (`documents get` exits 1 when the document does not verify)     |
| Console | `/compliance`, `/compliance/assessments`, `/compliance/documents`, `/compliance/documents/{id}` (read-only)           |
| Dev     | `node services/compliance/dist/main.js` (loopback, bearer token fixes tenant and role, refuses `NODE_ENV=production`) |

## 6. Tests

`services/compliance`: 120+ tests, memory and real Postgres 16 as the application role; property tests for determinism, seal tamper detection
(every single value of a document), tenant isolation and reviewer independence; mutation script with about 55 safety mutants. Gateway: the
contract test covers all 75 operations; `test/compliance.test.ts` covers the workflow, scopes, tenancy and the sources. `make e2e-compliance` runs the workflow on the real stack (Postgres 16 with forced RLS, the standalone gateway, the registry, the Eval Hub, the audit chain) through the TS SDK, the Python SDK and the CLI, including a document altered behind the service; `apps/console/e2e-real/compliance.spec.ts` covers the console pages on the same stack. See also
`docs/runbooks/compliance.md` and `docs/security/compliance-threat-model.md`.
