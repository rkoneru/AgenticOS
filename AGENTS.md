# AGENTS

Subagent roster. After the Phase 1 freeze, independent services are built in separate git worktrees.
Each brief includes: contract files, service scope, Definition of Done (`AXIS_MASTER_PROMPT.md` §6).

| Agent                             | Scope                                                                              | Merge gate                            |
| --------------------------------- | ---------------------------------------------------------------------------------- | ------------------------------------- |
| service-builder (one per service) | One service under `services/` or `runtime/`                                        | Its CI green; coverage thresholds met |
| phase-reviewer                    | Did not write the code; audits a phase against exit criteria and the master prompt | All findings fixed                    |
| security-reviewer                 | STRIDE entries, bypass test, tenant isolation                                      | No open high findings                 |

<!-- BEGIN:turborepo-agent-rules -->

# This is NOT the Turborepo you know

Turborepo configuration, task behavior, and CLI commands can vary between installed versions and may differ from your training data. Resolve the `turbo` package from this file's directory or relevant workspace; in monorepos, it may not be visible from the repository root. For example, run `node -p "require.resolve('turbo/package.json')"` from a workspace that depends on `turbo`.

Read `docs/README.md` inside that installed package first, then read the relevant pages from its `docs/` directory before changing Turborepo configuration or commands. Heed deprecation notices. These bundled docs match the installed package version and are available without network access.

This block is written and re-added by `turbo` before repository-scoped commands when an AI agent is detected. In the Turborepo source repository, its template is defined in `crates/turborepo-cli/src/cli/agent_guidance.rs`. Removing the managed block while updates are enabled means a later qualifying invocation will add it again. Set `"agentGuidance": false` in the root `turbo.json` or `turbo.jsonc` to opt out; this does not remove an existing block. Keep the block committed with your work to avoid an uncommitted change on the next agent invocation.
<!-- END:turborepo-agent-rules -->
