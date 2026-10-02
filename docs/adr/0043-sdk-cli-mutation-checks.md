# 0043. Mutation checks for SDK and CLI safety logic

Status: Accepted · Date: 2026-10-02

`scripts/mutation-sdk.mjs` applies 19 single-line mutants (retry of non-idempotent POST, keyed-retry rule, cross-origin redirect, secret rendering and pickling, error cause leakage, tenant headers/options, bearer+key header, config file modes, key echo on login, skipped local validation, dropped idempotency key) and runs the relevant suite (vitest or pytest); every mutant must make it fail. The source is restored after each run. Result at introduction: 19/19 killed (two survivors found first and fixed with tests). Run it after changing transport or CLI safety code: `node scripts/mutation-sdk.mjs`.
