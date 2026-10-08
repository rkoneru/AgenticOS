# Compliance

AXIS is **designed for** and **evidence-ready toward** SOC 2, GDPR, HIPAA, the EU AI Act and ISO/IEC 42001. It is **not** certified, attested or audited against any of them, and nothing in this directory says it is. A deployment meets (or does not meet) a framework only through the operator's own scope, contracts, procedures and an independent assessment.

## Labelling rules

These rules apply to every document under `docs/compliance/`, to the matrix YAML, and to anything generated from them. `make compliance-check` enforces the machine-checkable ones.

1. Use "designed for", "evidence-ready", "supports", "maps to". Never write that AXIS, a customer, or a system is "certified" or "compliant", and never "guarantees compliance". The checker rejects those words in matrix rows (finding `M030`).
2. A status is a claim about evidence, not intent:
   - **Built**: a mechanism exists and a test, make target or audit query in this repository exercises it. The checker requires at least one such artifact (finding `M020`) and at least one code path (`M021`).
   - **Prototype**: the mechanism exists but is tested only against fakes, runs on a single instance, or covers part of the requirement. Notes say which.
   - **Designed**: a design or document exists; nothing executes it.
   - **Gap**: nothing exists. Notes say what is missing. Gaps are never removed to make a table look better; the checker keeps a list of required rows (`M005`).
3. Every row cites things that exist: code paths, config, and evidence (test file, make target, audit query, document). `make compliance-check` fails when any cited path, test, needle or make target does not exist (`M010` to `M014`).
4. Requirement text is paraphrased, never copied from a standard. Standards are copyrighted; the regulations are public but their wording here is a summary and not legal text.
5. Organisational controls (training, board oversight, contracts, physical security) are listed as gaps unless a repository artifact supports them. The platform cannot satisfy them.
6. Limits are stated in the row's notes. A fake IdP, a fake KMS, a single-instance kernel, a missing retention job: all are said out loud.

## Files

| File                           | What it is                                                             |
| ------------------------------ | ---------------------------------------------------------------------- |
| `matrix/*.yaml`                | The source of truth: one machine-readable control matrix per framework |
| `summary.md`                   | Generated: counts by status per framework                              |
| `soc2.md` `gdpr.md` `hipaa.md` | Generated from the YAML: one block per control                         |
| `euaiact.md` `iso42001.md`     | Generated from the YAML                                                |

The Markdown is generated (`make compliance-check ARGS=--write`) and checked for drift; edit the YAML, never the Markdown.

## Row format

```yaml
- id: SOC2-CC6.1 # framework prefix + control reference
  requirement: paraphrase of what the control asks for
  mechanism: how AXIS addresses it
  code: [path, ...] # files or directories that exist
  config: [path#needle, ...] # config files; `#needle` must appear in the file
  evidence: # at least one executable item for Built
    - { kind: test, ref: path/to/test.ts } # test | make | doc | file | audit_query
  status: Built # Built | Prototype | Designed | Gap
  notes: limits, caveats and what is missing
```

`audit_query` evidence is `path#action`: the source file that emits an audit action and the action string, for example `services/compliance/src/records/assessments.ts#compliance.assessment.review`.

## What generates evidence

- `services/compliance` builds the EU AI Act Annex IV technical documentation for a blueprint version from platform records (ABL manifest, registry provenance, eval runs and attestations, policy packs, human oversight configuration, audit statistics). The document is versioned, hash-sealed and lists what it could not evidence. See `docs/spec/compliance.md`.
- The same service keeps the ISO/IEC 42001 AI system inventory and AI impact assessment records, with an independent-reviewer workflow.
- The audit log, the eval attestations and the registry signatures are the primary evidence sources; the matrix points at the tests that prove they work.

## Operating it

See `docs/runbooks/compliance.md` and the threat model in `docs/security/compliance-threat-model.md`.
