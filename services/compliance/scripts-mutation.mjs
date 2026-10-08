/* global console, process */
// Mutation check for the compliance safety logic: apply ONE targeted edit at a time, run the tests of this package, and require a
// FAILURE. A surviving mutant means a safety property is untested (docs/adr/0073).
// Usage (from services/compliance): node scripts-mutation.mjs [substring ...]   (run through `pnpm mutation`, which provides Postgres).
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const MIG = "../../packages/db/migrations/0016_compliance.sql";
// [file, from, to]
const M = [
  // --- matrix checker: evidence must exist and mean something
  ["src/matrix/check.ts", "if (!i.fs.exists(path)) return add(", "if (false) return add("], // skip the existence check of cited paths
  ["src/matrix/check.ts", "if (!i.fs.read(path).includes(needle))", "if (false)"], // needles are not looked for
  ["src/matrix/check.ts", "if (!i.makeTargets.has(e.ref))", "if (false)"], // make targets are not checked
  ["src/matrix/check.ts", "!TEST_CASE.test(i.fs.read(path))", "false"], // a test file without tests is fine
  ["src/matrix/check.ts", 'row.status === "Built" && executable.length === 0', "false"], // Built without evidence is accepted
  [
    "src/matrix/check.ts",
    '(row.status === "Built" || row.status === "Prototype") && row.code.length === 0',
    "false",
  ],
  ["src/matrix/check.ts", "FORBIDDEN.find((w) => w.test(text))?.source", "undefined"], // 'certified' is allowed again
  ["src/matrix/check.ts", "if (!seen.has(req))", "if (false)"], // a deleted required row is not noticed
  ["src/matrix/check.ts", '!p.split("/").includes("..")', "true"], // paths may leave the repository
  ["src/matrix/check.ts", "if (seen.has(row.id))", "if (false)"], // duplicate ids
  ["src/matrix/run.ts", "return findings.length === 0 ? 0 : 1;", "return 0;"], // the CLI always passes
  ["src/matrix/repo.ts", 'readFileSync(abs, "utf8") !== text', "false"], // stale rendered Markdown is not noticed
  // --- document assembly: deterministic, and gaps are never silently dropped
  ["src/docgen/assemble.ts", ".sort((a, b) => cmp(a.k, b.k) || cmp(a.j, b.j))", ".sort(() => 0)"], // arrays keep input order
  [
    "src/docgen/assemble.ts",
    "schema: DOC_SCHEMA,\n    disclaimer",
    "schema: DOC_SCHEMA,\n    nonce: Math.random(),\n    disclaimer",
  ], // nondeterministic output
  [
    "src/docgen/assemble.ts",
    'if (!s.ok) b.gaps.push({ section: "sources", item: name, reason: s.reason });',
    "",
  ], // a missing source is not listed as a gap
  ["src/docgen/assemble.ts", 'status: s.ok ? "ok" : "gap"', 'status: "ok"'],
  [
    "src/docgen/assemble.ts",
    'forceGap || data === null ? "gap" : gaps.length > 0 ? "partial" : "complete"',
    '"complete"',
  ],
  ["src/docgen/assemble.ts", "if (!a.chain.verified)", "if (false)"], // a failed chain verification is hidden
  [
    "src/docgen/assemble.ts",
    'status === "complete" ? "evidenced"',
    'status !== "gap" ? "evidenced"',
  ],
  ["src/canonical.ts", "Object.keys(o)\n        .sort()", "Object.keys(o)"], // key order matters to the hash
  // --- sealing and verification
  ["src/docgen/verify.ts", "if (hash === null || hash !== doc.content_hash)", "if (false)"],
  ["src/docgen/verify.ts", "md !== doc.markdown ||", "false ||"],
  ["src/docgen/verify.ts", "!key.verify(payload, doc.seal.sig)", "false"], // any signature passes
  [
    "src/docgen/verify.ts",
    "canonicalJson({ content_hash, meta })",
    "canonicalJson({ content_hash })",
  ], // metadata is not sealed
  ["src/docgen/verify.ts", "k.keyId === doc.seal.key_id && k.alg === doc.seal.alg", "true"], // any trusted key
  ["src/docgen/seal.ts", "return a.length === b.length && timingSafeEqual(a, b);", "return true;"],
  ["src/docgen/documents.ts", "last.content_hash === doc.content_hash", "false"], // every regeneration stores a new version
  [
    "src/docgen/documents.ts",
    "this.ports.audit.statistics(p)",
    'this.ports.audit.statistics({ ...p, tenantId: "00000000-0000-4000-8000-00000000ffff" })',
  ], // another tenant's sources
  // --- review state machine and independence
  ["src/records/states.ts", "approved: {},", 'approved: { submit: "in_review" },'],
  ["src/records/states.ts", 'draft: { submit: "in_review" },', 'draft: { submit: "approved" },'],
  ["src/records/states.ts", "if (a.author === reviewer)", "if (false)"], // the author may review
  ["src/records/states.ts", "if (a.contributors.includes(reviewer))", "if (false)"], // a contributor may review
  ["src/records/states.ts", "if (a.submitted_by === reviewer)", "if (false)"],
  [
    "src/records/states.ts",
    '< now.getTime())\n    return "review_due_passed"',
    '<= now.getTime() + 86400000)\n    return "review_due_passed"',
  ],
  ["src/records/states.ts", "now.getTime() - Date.parse(a.submitted_at) > graceMs", "false"],
  [
    "src/records/assessments.ts",
    "const why = reviewerConflict(cur, p.subject);",
    "const why = null as string | null;",
  ],
  [
    "src/records/assessments.ts",
    'if (cur.version !== expectedVersion) throw conflict("assessment changed since it was read");\n    if (cur.state === "in_review")',
    'if (cur.state === "in_review")',
  ],
  ["src/records/assessments.ts", "if (fresh)", "if (false)"], // a reviewed version is edited in place
  [
    "src/docstore.ts",
    'if (coll === "assessments") return data["state"] === "approved" || data["state"] === "rejected";',
    "return false;",
  ], // reviewed versions stay editable (memory store)
  ["src/docstore.ts", 'if (data["author"] === reviewer) return false;', ""], // memory store accepts reviewer == author
  [MIG, "AND data ->> 'reviewed_by' IS DISTINCT FROM data ->> 'author'", "AND true"], // the database accepts reviewer == author
  [
    MIG,
    "AND NOT (coalesce(data -> 'contributors', '[]'::jsonb) ? (data ->> 'reviewed_by'))",
    "AND true",
  ],
  [
    MIG,
    "IF OLD.coll = 'assessments' AND OLD.data ->> 'state' IN ('approved', 'rejected') THEN",
    "IF false THEN",
  ],
  [MIG, "IF OLD.coll IN ('system_versions', 'documents') THEN", "IF false THEN"],
  // --- authorization and audit
  [
    "src/authz.ts",
    '"compliance.review": ["owner", "admin", "auditor"],',
    '"compliance.review": ["owner", "admin", "auditor", "builder"],',
  ],
  [
    "src/authz.ts",
    '"compliance.write": ["owner", "admin", "builder"],',
    '"compliance.write": ["owner", "admin", "builder", "viewer"],',
  ],
  ["src/authz.ts", "!roles.includes(p.role)", "false"],
  ["src/audit.ts", 'throw unavailable("audit log unavailable");', "return undefined as never;"], // a mutation proceeds without its audit record
  [
    "src/context.ts",
    'decision: "ALLOW",\n    reason: "authorized",',
    'decision: "DENY",\n    reason: "authorized",',
  ],
  // --- tenant isolation: the stores and the database
  [
    "src/docstore.ts",
    "(d) => d.tenantId === tenantId && d.coll === coll && matches(d.data, filter),",
    "(d) => d.coll === coll && matches(d.data, filter),",
  ], // cross-tenant read
  [
    "src/docstore.ts",
    'private k = (t: string, c: string, key: string): string => [t, c, key].join("\\u0000");',
    'private k = (_t: string, c: string, key: string): string => [c, key].join("\\u0000");',
  ],
  [
    MIG,
    "CREATE POLICY compliance_docs_tenant ON compliance_docs USING (tenant_id = axis.current_tenant()) WITH CHECK (tenant_id = axis.current_tenant());",
    "CREATE POLICY compliance_docs_tenant ON compliance_docs USING (true) WITH CHECK (true);",
  ],
  [MIG, "ALTER TABLE compliance_docs FORCE ROW LEVEL SECURITY;", ""],
  [
    "src/records/inventory.ts",
    'this.c.docs.get<SystemRecord>(p.tenantId, "systems", systemId)',
    'this.c.docs.get<SystemRecord>("t-1", "systems", systemId)',
  ],
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
