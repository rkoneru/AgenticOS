#!/usr/bin/env node
/**
 * Mutation check for the SDK/CLI safety logic (ADR 0043). Each mutant breaks one safety property in the source;
 * the named test command must then FAIL (mutant killed). The source is always restored. Exit 1 if any survives.
 *   node scripts/mutation-sdk.mjs
 */
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const TS = "pnpm --filter @axis/sdk exec vitest run";
const CLI = "pnpm --filter @axis/cli exec vitest run";
const PY = "uv run pytest sdk/python -q -x -p no:cacheprovider --no-cov";

const M = [
  ["ts retry: non-idempotent POST retried", "packages/sdk-ts/src/transport.ts", 'return op.idempotent === "always" || (op.idempotent === "with-key" && key !== undefined);', "return true;", TS],
  ["ts retry: keyed rule ignores the key", "packages/sdk-ts/src/transport.ts", '(op.idempotent === "with-key" && key !== undefined)', '(op.idempotent !== "never" && key !== undefined) || op.idempotent === "never"', TS],
  ["ts redirect: cross-origin followed", "packages/sdk-ts/src/transport.ts", "next.origin !== this.#base.origin", "false", TS],
  ["ts redact: Secret.toString reveals", "packages/sdk-ts/src/redact.ts", "  toString(): string {\n    return REDACTED;", "  toString(): string {\n    return this.#value;", TS],
  ["ts redact: error cause keeps raw message", "packages/sdk-ts/src/transport.ts", "const safe = new Error(this.#scrub(err.message));", "const safe = new Error(err.message);", TS],
  ["ts tenant: header allowed per request", "packages/sdk-ts/src/transport.ts", "x-axis-tenant[a-z-]*|x-tenant[a-z-]*|", "", TS],
  ["ts tenant: client option accepted", "packages/sdk-ts/src/client.ts", "if (TENANT_KEYS.test(k))", "if (false)", TS],
  ["ts auth: key header sent on bearer path too", "packages/sdk-ts/src/transport.ts", 'else if (this.#token) h.set("authorization"', 'if (this.#token) h.set("authorization"', TS],
  ["py retry: non-idempotent POST retried", "sdk/python/src/axis_sdk/transport.py", 'return op.idempotent == "always" or (', "return True or (", PY],
  ["py redirect: cross-origin followed", "sdk/python/src/axis_sdk/transport.py", "if origin(nxt) != origin(self.base):", "if False:", PY],
  ["py redact: Secret.__str__ reveals", "sdk/python/src/axis_sdk/redact.py", "    def __str__(self) -> str:\n        return REDACTED", "    def __str__(self) -> str:\n        return self._value", PY],
  ["py redact: Secret pickles the value", "sdk/python/src/axis_sdk/redact.py", "return (Secret, (REDACTED,))", "return (Secret, (self._value,))", PY],
  ["py tenant: header allowed per request", "sdk/python/src/axis_sdk/transport.py", "x-axis-tenant[a-z-]*|x-tenant[a-z-]*|", "", PY],
  ["py tenant: client kwarg accepted", "sdk/python/src/axis_sdk/client.py", "if k.lower() in _TENANT_KEYS:", "if False:", PY],
  ["py key: regenerated per attempt is fine, but key dropped on retry", "sdk/python/src/axis_sdk/transport.py", "headers[\"idempotency-key\"] = key", "pass", PY],
  ["cli config: world-readable file accepted", "apps/cli/src/config.ts", "if ((mode & 0o077) !== 0) {", "if (false) {", CLI],
  ["cli config: saved with 0644", "apps/cli/src/config.ts", "{ mode: 0o600 });\n  chmodSync(tmp, 0o600);", "{ mode: 0o644 });\n  chmodSync(tmp, 0o644);", CLI],
  ["cli login: key echoed in output", "apps/cli/src/commands.ts", "saved to ${path} (key fingerprint", "saved to ${path} (key ${key} fingerprint", CLI],
  ["cli publish: skips the local validation", "apps/cli/src/commands.ts", "if (!ctx.bool(\"no-validate\")) {", "if (false) {", CLI],
];

let survived = 0;
for (const [name, file, from, to, cmd] of M) {
  const src = readFileSync(file, "utf8");
  if (!src.includes(from)) {
    console.log(`SKIP     ${name} (pattern not found in ${file})`);
    survived++;
    continue;
  }
  writeFileSync(file, src.replace(from, to));
  let r;
  try {
    r = spawnSync("bash", ["-c", cmd], { encoding: "utf8" });
  } finally {
    writeFileSync(file, src);
  }
  const killed = r.status !== 0;
  if (!killed) survived++;
  console.log(`${killed ? "killed  " : "SURVIVED"} ${name}`);
}
console.log(`${M.length - survived}/${M.length} mutants killed`);
process.exit(survived ? 1 : 0);
