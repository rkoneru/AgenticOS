# 0071. OpenAPI 1.5.0: compliance operations (additive)

Status: Accepted · Date: 2026-10-08 · Related: 0053, 0059, 0070, 0072

## Context

The inventory, impact assessments and generated technical documentation must be reachable from the SDKs, the CLI and the console like every other
resource.

## Decision

`info.version` 1.4.0 -> 1.5.0, FREEZE regenerated, both SDKs regenerated. Fourteen operations, tag `Compliance`:

- systems: `listComplianceSystems`, `createComplianceSystem`, `getComplianceSystem` (`?version=`), `updateComplianceSystem` (PUT, `expected_version`)
- assessments: `listComplianceImpactAssessments` (`system_id`, `state`, `overdue`), `createComplianceImpactAssessment`,
  `getComplianceImpactAssessment`, `reviseComplianceImpactAssessment`, `submit...`, `withdraw...`, `review...` (`decision`, `comment`)
- documents: `generateComplianceDocument` (201 stored, 200 unchanged), `listComplianceDocuments`, `getComplianceDocument` (with a fresh verification)

Choices that are deliberate: path parameters are strings (ids), never integers (the version is a query parameter), so mocks and clients do not
need typed path coercion; updates carry `expected_version` and a stale one is a 409; `ComplianceSealedDocument.body` is an open object because
its shape is the document's, versioned by `body.schema`; the schema text never says a system is certified or compliant.

Ergonomic wrappers in both SDKs (`ax.compliance.systems|assessments|documents`) put the concurrency token in an argument rather than inside the
patch; `axis compliance systems|assessments|documents ...` exposes them (`--revision` rather than `--version`, which is the global flag). The
mock servers of both SDKs learn boolean query coercion and one new date pattern sample. The console reads four of the operations and writes none.

## Consequences

The gateway route table is 75 operations (was 61). A gateway wired without the compliance service answers 503 for all of them (fail-closed),
never an empty success.
