# 0110. The Risk Kernel classifies a tool's side effects; a blueprint's own label is advisory

Status: Accepted · Date: 2026-10-09 · Related: 0090, NEEDS 399

## Context

The platform baseline (`policies/baseline-deny`) has one broad allow, `allow-read-tools`, for any `tool_call`/`mcp_call` whose `tool.side_effects` is `none` or `read`.
`tool.side_effects` came from the blueprint (ABL `tools[].sideEffects`) through the runtime. The red team (`redteam-mislabel`, selfcheck mutant `drop-negated-denies`)
showed that a blueprint can name a tool `send-email`, `http-request`, `run-command` or `write-file`, declare `sideEffects: read`, and ride that baseline allow with any
arguments unless the tenant happened to write deny-by-negation rules for each tool. A blueprint comes from a registry or marketplace (supply chain), so its label is attacker input.

## Decision

The kernel computes the label the policy sees (`services/risk-kernel/src/capability.ts`):

1. If the **tenant's tool catalog** has an entry for the tool name, that value is used, in both directions (authoritative: the tenant pre-registered or approved it).
2. Otherwise the label is the **strictest** of the declared label and a deterministic inference from the tool NAME (words, camelCase aware: `send`, `post`, `exec`, `wire`,
   `delete`, `save` ...), the tool KIND (`code`, `browser`, `channel`, `voice`, `mcp` are external) and the ARGUMENT KEYS (`to`, `bcc`, `url`, `webhook`, `command`, ...
   external; a content key beside a path or id key: write). An unknown or malformed declared label counts as `external`.

The policy input carries `tool.side_effects` (effective), `tool.declared_side_effects` and `tool.side_effects_source` (`catalog | declared | inferred`). The baseline pack is
unchanged: it still allows `none|read`, now on the effective value. A catalog that throws (bad file) makes the policy step fail, which is DENY. Catalog: `KernelDeps.toolCatalog`;
the kernel process reads `AXIS_RK_TOOL_CATALOG_FILE` (`{tenant: {tool: effect}}`, re-read on change).

## Consequences

- A read-looking tool that takes a destination (`url`, `to`, ...) no longer rides the baseline; the tenant allows it by an explicit rule (the red-team fixture already does: `allow-fetch-page`)
  or registers it in the catalog. This is intended. A tenant that registers a mislabelled tool as `read` in its own catalog accepts that (selfcheck mutant `catalog-trusts-labels`).
- The inference is a net, not proof: a hostile tool with an innocuous name and argument keys, declared `read`, still gets the baseline allow unless the tenant catalog says otherwise.
  The robust control is the catalog; the registry/marketplace capability scan (NEEDS 260-274) is the other half. Recorded as NEEDS 407.
- The red-team fixture pack lost its four deny-by-negation rules (email, http, command, write): the platform now contains the mislabelled tools by itself.

## Revision 2 (Phase 9 integration): false positives on legitimate tools

The first version of the classifier denied legitimate tools in the real stacks: `make e2e-phase3` (a child-agent spawn `delegate-a`: "delegate" is an external word),
`make e2e-phase4` (a read-only MCP lookup `kb/lookup`: kind `mcp` was a blanket external floor). Changes, each with a failing-first test and a mutation check
(`services/risk-kernel/test/capability.test.ts`):

1. **`kind: agent`** is not inferred from the name or the arguments: the runtime executes that kind as a spawn and nothing else, and what the child may do is decided by
   the child's own gated actions. The declared label stands (an unknown label is still `external`).
2. **`kind: mcp`** has no blanket floor any more; the tool name (`server/tool`, judged on the tool part) and the argument keys decide, like a function tool.
   `code`, `browser`, `channel` and `voice` remain external by kind. A catalog entry stays authoritative for MCP servers whose tool names say nothing.
3. **A leading read verb** (`get`, `list`, `lookup`, `read`, `search`, `find`, `query`, `describe`, `show`, `view`, `count`, `check`, `recall`, `inspect`, `browse`) makes the
   remaining ambiguous object nouns (`message`, `request`, `email`, `http`, `payment`, ... ) objects of the read, not verbs: `get-message`, `listRequests`,
   `lookup-payment-status` stay `none`. Real verbs (`send`, `post`, `delete`, `exec`, ...) keep their meaning wherever they stand, and any connector word
   (`and`, `then`, `to`, `via`, `with`, ...) switches the carve-out off (`get-and-send`, `read-then-reply` stay external). Argument keys (`to`, `url`, `command`, ...) are unchanged.

Not weakened: the red-team `mislabel` suite passes WITHOUT deny-by-negation rules in the fixture pack, and the self-check mutant `catalog-trusts-labels` is still detected
(every mislabelled tool there is a `function` tool led by a write or external verb). The inference remains a net, not proof. For ecosystems where names are ambiguous the
robust control is the tenant catalog (`AXIS_RK_TOOL_CATALOG_FILE`), which the e2e harnesses use where inference is inherently ambiguous. NEEDS 399 is resolved in part (the
classifier is the net, the catalog is the control); the rest is NEEDS 407 and the registry/marketplace capability scan.
