// Mutation check of the gateway's safety logic: each mutant breaks one guard; the suite MUST fail. Restores files afterwards.
// Equivalent (not mutated): the explicit tenant_id body/query refusals duplicate additionalProperties:false in the schemas (defence in depth).
// usage: node scripts-mutation.mjs     (exit 1 if any mutant survives)
import { execFileSync } from "node:child_process";
import { console } from "node:console";
import process from "node:process";
import { readFileSync, writeFileSync } from "node:fs";

const M = [
  [
    "src/server.ts",
    "if (TENANT_HEADER.test(h))",
    "if (false && TENANT_HEADER.test(h))",
    "tenant header accepted",
  ],
  ["src/server.ts", "if (!rl.ok) throw", "if (false) throw", "rate limit ignored"],
  ["src/server.ts", "if (!decision.allowed) {", "if (false) {", "authorization ignored"],
  [
    "src/server.ts",
    "`${principal.tenantId}\\u0000${principal.memberId}`",
    "`${principal.memberId}`",
    "idempotency scope drops the tenant",
  ],
  ["src/server.ts", 'if (b.kind === "mismatch")', "if (false)", "idempotency key reuse accepted"],
  ["src/server.ts", "unauth.take(remote, 0).remaining < 1", "false", "failed-auth limiter off"],
  [
    "src/server.ts",
    "if (!p || p.tenantId !== ctx.tenantId || p.memberId !== ctx.principal.memberId) stop();",
    "",
    "SSE credential recheck off",
  ],
  [
    "src/server.ts",
    "if (issues && issues.length > 0) {",
    "if (false) {",
    "response validation off",
  ],
  [
    "src/server.ts",
    "origin !== undefined && origins.has(origin)) {\n      res.setHeader",
    "origin !== undefined) {\n      res.setHeader",
    "CORS reflects any origin",
  ],
  [
    "src/server.ts",
    "if (auth !== undefined && key !== undefined)",
    "if (false)",
    "two credentials accepted",
  ],
  [
    "src/server.ts",
    'throw unavailable("the audit log is unavailable; the operation was not performed")',
    "void 0",
    "mutation runs without audit",
  ],
  [
    "src/limits.ts",
    "`${tenantId}\\u0000${resource}\\u0000${body}`",
    "`${body}`",
    "cursor not bound to tenant",
  ],
  [
    "src/spec.ts",
    'additionalProperties: loc === "header"',
    "additionalProperties: true",
    "unknown query params accepted",
  ],
  [
    "src/routes.ts",
    "if (r.tenant_id !== undefined && r.tenant_id !== c.tenantId) {",
    "if (false) {",
    "foreign run relayed",
  ],
  [
    "src/routes.ts",
    "const mine = batch.filter((e) => e.tenant_id === c.tenantId);",
    "const mine = batch;",
    "audit list relays other tenants",
  ],
  [
    "src/adapters/approvals.ts",
    "return { tenant_id: p.tenantId, id: p.memberId, roles: [p.role] };",
    "return { tenant_id: p.tenantId, id: p.memberId, roles: ['owner'] };",
    "approver role escalated",
  ],
  [
    "src/adapters/kernel.ts",
    "await this.kernel.apply({ tenantId: p.tenantId, ...r });",
    "",
    "kill-switch not sent to the kernel",
  ],
];

let survived = 0;
for (const [file, from, to, name] of M) {
  const src = readFileSync(file, "utf8");
  if (!src.includes(from)) {
    console.log(`SKIP  ${name}: pattern not found in ${file}`);
    survived++;
    continue;
  }
  writeFileSync(file, src.replace(from, to));
  let killed = false;
  try {
    execFileSync("pnpm", ["exec", "vitest", "run", "--bail", "1"], { stdio: "pipe" });
  } catch {
    killed = true;
  } finally {
    writeFileSync(file, src);
  }
  console.log(`${killed ? "KILLED" : "SURVIVED"}  ${name}`);
  if (!killed) survived++;
}
console.log(survived === 0 ? `all ${M.length} mutants killed` : `${survived} mutant(s) survived`);
process.exit(survived === 0 ? 0 : 1);
