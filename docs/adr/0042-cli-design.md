# 0042. `axis` CLI design

Status: Accepted · Date: 2026-10-02 · Related: 0040, 0041, `docs/spec/cli.md`

## Decisions

- `@axis/cli` is a thin layer on `@axis/sdk` with a hand-written argv parser and a single command table that drives `--help`, shell completions and the Markdown reference (`axis docs`, checked against `docs/spec/cli.md` by a test). No third-party CLI framework.
- `run(argv, deps)` is a pure function of injected IO (stdout/stderr, env, fetch, stdin), so every command is tested in-process against the OpenAPI-derived mock server.
- Credentials: `AXIS_API_KEY` env or a profile in `$XDG_CONFIG_HOME/axis/config.json` (0600 file, 0700 dir, group/other-readable file refused). The key is read from stdin or a hidden prompt, never from argv. `login` verifies with one authenticated read before saving. Device-flow login is a stub (no endpoint). `whoami` has no identity endpoint to call, so it reports profile, base URL, key fingerprint (sha256 prefix) and an authenticated read.
- `blueprints validate` is offline (ABL compiler + linter); `publish` validates locally first.
- Exit codes: 0 ok, 1 error, 2 usage, 3 auth, 4 policy denied, 5 approval pending / wait timeout. `policies test` maps DENY to 4 and REQUIRE_APPROVAL to 5; `audit verify` returns 1 on a broken chain.
- `policies activate`, `registry *`, `marketplace *` have no endpoint in v1: they exit 1 with a clear message, and call a matching operation if a regenerated spec has one. `axis api <operationId>` is the generic escape hatch.
