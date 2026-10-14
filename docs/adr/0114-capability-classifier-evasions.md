# ADR 0114: Capability classifier evasions found in the Phase 9 review

Status: accepted. Extends ADR 0110 (additive; no frozen contract changes beyond an optional `tool.ref` string in the gate context).

## Findings

1. **Alias bypass.** A function tool `{name: lookup, sideEffects: read, ref: send_email}` is executed as `send_email` (`ToolCall._execute` calls `tools.call(ref or name)`), but the gate saw only `lookup`. The classifier and the tenant catalog now use the executed `ref` (sent as the optional `tool.ref`), and inference reads every name the call has (name, ref, action).
2. **Glued / digit / unicode names.** `sendemail`, `deleterecord`, `send2user`, `s<cyrillic e>nd`, `se<ZWSP>nd` were classified `none`. Names are NFKC-folded with zero-width and combining characters removed; digit boundaries split words; unambiguous verbs are matched inside glued words (read-led names keep their object nouns and inflections: `get_updated_items`); a name that still holds non-ASCII after folding, or is over 256 characters, is `external` (the tenant catalog is the way to admit such a tool).
3. **Argument keys.** Only top-level exact keys were read. Nested keys (`params.url`), camelCase (`webhookUrl`, `recipientEmail`) and deep trees now count (bounded depth and key count; a truncated scan is `external`).
4. **Word list gaps.** destroy, wipe, replace, overwrite, upsert, kill, terminate, dispatch, trigger, submit, broadcast, chat-platform and remote-shell names added.

The classifier remains a net, not proof; the tenant catalog is the control (NEEDS 422).
