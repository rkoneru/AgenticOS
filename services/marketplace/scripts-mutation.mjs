/* global console, process */
// Mutation check for the marketplace safety logic: apply one targeted edit at a time, run the tests, and require a FAILURE.
// A surviving mutant means a safety property is untested. Usage (from services/marketplace, through `pnpm mutation`, which provides
// a throwaway Postgres): node scripts-mutation.mjs [substring ...]. Paths are relative to services/marketplace.
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const MIG = "../../packages/db/migrations/0011_marketplace.sql";
const M = [
  // --- review: reviewer != publisher, severity rules, pinning, republish
  ["src/reviews.ts", "r.subject === cur.data.submittedBy ||", "false ||"],
  ["src/reviews.ts", "r.tenantId === tenantId ||", "false ||"],
  ["src/reviews.ts", "pub?.data.subjects.includes(r.subject)", "false"],
  ["src/reviews.ts", "if (missing.length)", "if (false)"],
  ["src/reviews.ts", "if (bp.contentHash !== cur.data.contentHash)", "if (false)"],
  ["src/reviews.ts", 'if (pub?.data.state !== "verified")', "if (false)"],
  [
    "src/reviews.ts",
    "sevRank(scan.maxSeverity) <= sevRank(",
    "sevRank(scan.maxSeverity) >= sevRank(",
  ],
  ["src/reviews.ts", 'if (scan.maxSeverity === "critical") {', "if (false) {"],
  ["src/states.ts", "  approved: [],", '  approved: ["in_review"],'],
  ["src/reviews.ts", "if (bp.contentHash !== cur.data.contentHash)", "if (false)"],
  ["src/states.ts", 'submitted: ["automated_scan"],', 'submitted: ["automated_scan", "approved"],'],
  [
    "src/states.ts",
    'rejected: ["pending"], // resubmission',
    'rejected: ["pending", "verified"], // resubmission',
  ],
  // --- publisher verification
  [
    "src/publishers.ts",
    "r.tenantId === publisherTenantId || cur.data.subjects.includes(r.subject)",
    "false",
  ],
  ["src/publishers.ts", 'latest("domain_dns_txt")?.result !== "passed" ||', "false ||"],
  ["src/publishers.ts", 'latest("identity")?.result !== "passed"', "false"],
  // --- listing / install: only approved + pinned + listed, consent, widening, rollback
  ["src/installs.ts", "if (digest !== pv.consentDigest)", "if (false)"],
  ["src/installs.ts", "if (contentHash !== pv.contentHash)", "if (false)"],
  ["src/installs.ts", "if (pv.diff.widening) {", "if (false) {"],
  ["src/installs.ts", "input.allowDowngrade !== true", "false"],
  ["src/installs.ts", "if (bp.contentHash !== contentHash)", "if (false)"],
  [
    "src/installs.ts",
    'if (cur && cur.data.state !== "uninstalled") throw conflict(',
    "if (false) throw conflict(",
  ],
  ["src/capabilities.ts", "else if (level > prev) added.push(", "else if (false) added.push("],
  ["src/capabilities.ts", "widening: added.length > 0", "widening: false"],
  ["src/policy-stub.ts", 'defaultDecision: "DENY"', 'defaultDecision: "ALLOW"'],
  [
    "src/policy-stub.ts",
    "priority: 900,\n          enforcementPoints: toolPoints,\n          when:",
    "priority: 1,\n          enforcementPoints: toolPoints,\n          when:",
  ],
  // --- review hardening (test/hardening.test.ts)
  ["src/installs.ts", "await this.stillInstallable(p.tenantId, doc, rec);", ""],
  [
    "src/installs.ts",
    "`marketplace-install:${who}:${installKey(rec.namespace, rec.name)}`",
    "`marketplace-install:${rec.id}`",
  ],
  ["src/scan.ts", "...(abl.spec.tools ?? []).flatMap((t, i) =>", "...([]).flatMap((t, i) =>"],
  ["src/scan.ts", 'u.hostname.startsWith("[")', "false"],
  ["src/scan.ts", '.normalize("NFKC")', ""],
  ["src/listings.ts", "else if (NOT_PLAIN_TEXT.test(v))", "else if (false)"],
  // --- takedown
  ["src/listings.ts", "for (const v of versions)", "for (const v of [])"],
  ["src/listings.ts", 'state: "flagged",', 'state: "active",'],
  ["src/listings.ts", 'status: "taken_down"', 'status: "listed"'],
  // --- isolation: store (memory), database
  [
    "src/docstore.ts",
    'if (scope.kind === "tenant" && scope.tenantId === d.tenantId) return true;',
    'if (scope.kind === "tenant") return true;',
  ],
  [
    "src/docstore.ts",
    'return scope.kind === "platform" || (scope.kind === "tenant" && scope.tenantId === tenantId);',
    "return true;",
  ],
  [
    "src/docstore.ts",
    'coll === "listings" && data["status"] === "listed";',
    'coll === "listings";',
  ],
  [
    MIG,
    "CREATE POLICY docs_tenant ON marketplace_docs USING (tenant_id = axis.current_tenant()) WITH CHECK (tenant_id = axis.current_tenant());",
    "CREATE POLICY docs_tenant ON marketplace_docs USING (true) WITH CHECK (true);",
  ],
  [
    MIG,
    "CREATE POLICY docs_catalog ON marketplace_docs FOR SELECT USING (coll = 'listings' AND data ->> 'status' = 'listed');",
    "CREATE POLICY docs_catalog ON marketplace_docs FOR SELECT USING (true);",
  ],
  [
    MIG,
    "CREATE POLICY docs_platform ON marketplace_docs USING (axis.is_platform()) WITH CHECK (axis.is_platform());",
    "CREATE POLICY docs_platform ON marketplace_docs USING (true) WITH CHECK (true);",
  ],
  [MIG, "IF OLD.coll IN ('events', 'evidence', 'takedowns') THEN", "IF false THEN"],
  // --- auth + audit + http
  ["src/ctx.ts", "if (have === undefined || have < MIN_RANK[need])", "if (false)"],
  ["src/ctx.ts", "if (p?.kind !== kind ||", "if (false ||"],
  ["src/dev-server.ts", '(q.has("tenant_id") && q.get("tenant_id") !== a.tenantId) ||', "false ||"],
  ["src/dev-server.ts", "wait = strict.check(who)", "wait = 0"],
];

const only = process.argv.slice(2);
const sel = M.filter(
  ([f, from]) => only.length === 0 || only.some((s) => f.includes(s) || from.includes(s)),
);
let survived = 0;
for (const [file, from, to] of sel) {
  const orig = readFileSync(file, "utf8");
  if (!orig.includes(from)) {
    console.log(`SKIP (pattern gone): ${file}: ${from.slice(0, 50)}`);
    survived++;
    continue;
  }
  writeFileSync(file, orig.replace(from, to));
  const r = spawnSync("pnpm", ["exec", "vitest", "run", "--bail", "1"], { encoding: "utf8" });
  writeFileSync(file, orig);
  const killed = r.status !== 0;
  if (!killed) survived++;
  console.log(
    `${killed ? "killed  " : "SURVIVED"} ${file}: ${from.slice(0, 60).replace(/\n/g, " ")}`,
  );
}
console.log(`${sel.length - survived}/${sel.length} mutants killed`);
process.exit(survived ? 1 : 0);
