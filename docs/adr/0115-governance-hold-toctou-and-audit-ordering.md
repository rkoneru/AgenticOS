# ADR 0115: Legal-hold TOCTOU and audit-before-purge ordering in data governance

Status: accepted. Additive (no schema or contract change); fixes two Phase 9 review findings in `services/data-governance`.

## Findings

1. **Legal-hold TOCTOU in erase/retention.** `DsarEngine.erase` read active holds ONCE before iterating providers, and
   `RetentionEngine.run` read them ONCE before iterating classes. A hold placed by a second privacy-officer request while the
   first erase/purge was already running (e.g. from inside a provider's own erase/purge call, or genuinely concurrently) was
   invisible to the rest of that run: later providers/classes went ahead and erased/purged data the hold was meant to protect.
   Fix: holds are now re-read immediately before each provider (erase) and each class (retention), so a hold placed mid-run
   takes effect on every step still to come.
2. **Audit recorded after the purge, not before.** `RetentionEngine.run` purged every matching provider for a class and only
   emitted the governance audit record at the very end of the whole run. If the audit sink was down, the purge had already
   happened and was never recorded — a silent, unaudited deletion, which breaks the audit invariant ("every destructive action
   is auditable, fail-closed") for retention purges specifically (DSAR erase already records per-provider steps before its
   final summary). Fix: a `retention.class.purge.started` / `retention.class.dry_run.started` audit event is now emitted
   immediately before a class's providers are purged, inside the same try/catch as the purge calls; a down audit sink throws
   there and the class is marked `error` with nothing purged, instead of purging first and failing to record it after.

Both are proven by `services/data-governance/test/review.test.ts` (reverting either fix makes its test fail; confirmed by hand).

## Finding 3 (added): compliance matrix checker symlink escape

`services/compliance/src/matrix/repo.ts` (`nodeFs`) validated an evidence path with `safePath` (no `..`, no leading `/`) but then
read it with plain `existsSync`/`readFileSync`, which follow symlinks. A symlink committed inside the repo under an evidence path
(`src/escape.ts -> /some/outside/file`) made `checkMatrix` treat outside-the-repo content as if it were the cited, reviewable
source: `exists`/`isFile` now resolve the real path with `realpathSync` and refuse (treat as not-found) anything that resolves
outside the repository root. Proven by `services/compliance/test/matrix.test.ts` ("a symlink inside the repo pointing outside it
is not treated as valid evidence"); reverting the `insideRoot` gate makes that test fail (confirmed by hand).
