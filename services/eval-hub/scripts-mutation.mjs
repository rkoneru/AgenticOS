/* global console, process */
// Mutation check for the Eval Hub safety logic (and the gate hooks in the registry and the marketplace): apply ONE targeted edit at a
// time, run the tests of the package the file belongs to, and require a FAILURE. A surviving mutant means a safety property is untested.
// Usage (from services/eval-hub): node scripts-mutation.mjs [substring ...]   (run through `pnpm mutation`, which provides Postgres).
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const MIG = "../../packages/db/migrations/0013_eval_hub.sql";
const REG = "../registry"; // tests of the registry (import its own src)
const MKT = "../marketplace"; // tests of the marketplace
// [file, from, to, cwd of the tests that must fail]
const M = [
  // --- the gate: every check must matter
  ["src/gate.ts", "sameSuite.filter((r) => r.content_hash === bp.content_hash)", "sameSuite", "."], // skip the content-hash binding
  [
    "src/gate.ts",
    'fail("missing_run", `no finished run of ${ref} for this blueprint version`);',
    "void 0;",
    ".",
  ], // allow on a missing run
  ["src/gate.ts", "else if (cmp.blocking)", "else if (false)", "."], // skip the regression check
  ["src/gate.ts", "if (age > suite.max_age_days * DAY_MS)", "if (false)", "."], // allow a stale run
  [
    "src/gate.ts",
    "if (r.runner_id !== null && (await this.runs.runnerActive(tenantId, r.runner_id)))",
    "if (true)",
    ".",
  ], // trust any runner
  ["src/gate.ts", "if (overall < required)", "if (false)", "."], // ignore the threshold
  ["src/gate.ts", "const latest = trusted[0];", "const latest = trusted[trusted.length - 1];", "."], // oldest run decides
  ["src/gate.ts", 'if (latest.status === "errored") {', "if (false) {", "."],
  ["src/gate.ts", "if (latest.sample_size < needed)", "if (false)", "."], // allow a low-sample run
  [
    "src/gate.ts",
    'if (bad.length > 0) {\n      fail("integrity_failed"',
    'if (false) {\n      fail("integrity_failed"',
    ".",
  ], // do not re-verify the stored run
  ["src/gate.ts", "if (!cmp.comparable)", "if (false)", "."],
  [
    "src/gate.ts",
    'tenantId,\n      actor: actorOf(p),\n      action: "evals.gate",',
    'tenantId: "00000000-0000-4000-8000-00000000ffff",\n      actor: actorOf(p),\n      action: "evals.gate",',
    ".",
  ], // audit into the wrong chain
  [
    "src/integrity.ts",
    'run.record_hash !== recordHashOf(run)) bad.push("record_hash");',
    'false) bad.push("record_hash");',
    ".",
  ],
  ["src/integrity.ts", "      bad.push(`recompute.${m}`);", "      void m;", "."],
  ["src/integrity.ts", 'if (run.suite_hash !== suite.suite_hash) bad.push("suite_hash");', "", "."],
  // --- the hub recomputes; a runner's aggregate is only a claim
  [
    "src/runs.ts",
    "if (bad.length > 0)\n          throw integrityFailed(",
    "if (false)\n          throw integrityFailed(",
    ".",
  ], // trust the runner's aggregate
  ["src/runs.ts", "if (v !== undefined && v !== null)", "if (false)", "."], // a runner supplies a human score
  ["src/runs.ts", "if (missing.length > 0)", "if (false)", "."], // partial datasets
  [
    "src/runs.ts",
    'if (d.data.runner_id !== r.runnerId) throw forbidden("run belongs to another runner");\n      const { suite, dataset }',
    "const { suite, dataset }",
    ".",
  ], // another runner submits
  [
    "src/runs.ts",
    "const passed = scores.overall >= suite.pass_threshold;",
    "const passed = true;",
    ".",
  ],
  [
    "src/scoring.ts",
    "const regression = delta < -o.tolerance - 1e-9;",
    "const regression = false;",
    ".",
  ],
  [
    "src/scoring.ts",
    "blocking: regression && (!o.requiresSignificance || significance.significant),",
    "blocking: false,",
    ".",
  ],
  [
    "src/scoring.ts",
    "if (cand.suite_hash !== base.suite_hash || cand.dataset_hash !== base.dataset_hash) return empty;",
    "",
    ".",
  ],
  ["src/baselines.ts", "b.record_hash !== base.record_hash ||", "false ||", "."], // baseline tampering
  [
    "src/baselines.ts",
    'if (run.status !== "passed") throw conflict("only a passed run can be a baseline");',
    "",
    ".",
  ],
  // --- human review: reviewer != publisher / starter, distinct double graders, live claims
  ["src/reviews.ts", "if (t.conflicts.includes(who))", "if (false)", "."], // allow reviewer == publisher
  ["src/reviews.ts", "!x.conflicts.includes(t.subject) &&", "", "."],
  [
    "src/reviews.ts",
    "if (t.grades.some((g) => g.reviewer === who)) return",
    "if (false) return",
    ".",
  ],
  ["src/reviews.ts", "if (this.claimLive(t) && t.claimed_by !== who.subject)", "if (false)", "."],
  [
    "src/reviews.ts",
    "if (!(t.claimed_by === who.subject && this.claimLive(t)))",
    "if (false)",
    ".",
  ],
  ["src/reviews.ts", "Math.abs(a.score - b.score) <= t.agreement_tolerance + 1e-12", "true", "."],
  // --- datasets: PHI
  [
    "src/catalog.ts",
    "const stored = phi ? (redactJson(cases, this.c.redact) as EvalCase[]) : cases;",
    "const stored = cases;",
    ".",
  ],
  [
    "src/catalog.ts",
    "input.phi === true || prior.some((d) => d.data.phi)",
    "input.phi === true",
    ".",
  ],
  // --- online results stay separate and capped
  ["src/online.ts", "if (recent.length >= cfg.max_per_hour)", "if (false)", "."],
  // --- authz
  ["src/authz.ts", "if (!REVIEWER_ACTIONS.includes(action))", "if (false)", "."],
  ["src/authz.ts", "have < need)", "false)", "."],
  // --- tenant isolation: the store and the database
  [
    "src/docstore.ts",
    "(d) => d.tenantId === tenantId && d.coll === coll && matches(d.data, filter),",
    "(d) => d.coll === coll && matches(d.data, filter),",
    ".",
  ], // cross-tenant read
  [
    MIG,
    "CREATE POLICY eval_docs_tenant ON eval_hub_docs USING (tenant_id = axis.current_tenant()) WITH CHECK (tenant_id = axis.current_tenant());",
    "CREATE POLICY eval_docs_tenant ON eval_hub_docs USING (true) WITH CHECK (true);",
    ".",
  ],
  [MIG, "ALTER TABLE eval_hub_docs FORCE ROW LEVEL SECURITY;", "", "."],
  [
    MIG,
    "CREATE TRIGGER eval_hub_docs_guard BEFORE UPDATE OR DELETE ON eval_hub_docs FOR EACH ROW EXECUTE FUNCTION axis.eval_hub_docs_guard();",
    "",
    ".",
  ],
  [
    MIG,
    "IF OLD.coll = 'runs' AND OLD.data ->> 'status' NOT IN ('queued', 'running') THEN",
    "IF false THEN",
    ".",
  ],
  // --- the registry and the marketplace call the gate, and the default refuses
  [
    "../registry/src/eval-gate.ts",
    '      allowed: false,\n      reasons: [{ code: "gate_unavailable"',
    '      allowed: true,\n      reasons: [{ code: "gate_unavailable"',
    REG,
  ], // gate port default allow
  [
    "../registry/src/service.ts",
    "if (suites.length === 0) return undefined;",
    "return undefined;",
    REG,
  ], // never gate
  ["../registry/src/service.ts", "if (r && r.allowed === true) return;", "if (true) return;", REG],
  [
    "../registry/src/service.ts",
    "await this.requireEvalGate({\n      tenantId: owner,",
    "void ({\n      tenantId: owner,",
    REG,
  ], // setVersionPublic skips the gate
  [
    "../registry/src/service.ts",
    "subj?.name !== `${ref.namespace}/${ref.name}@${ref.version}` ||\n      subj.digest.sha256 !== row.record.contentHash",
    "false",
    REG,
  ],
  [
    "../marketplace/src/reviews.ts",
    "await this.registry().requireEvalGate({\n      tenantId: p.tenantId,",
    "void ({\n      tenantId: p.tenantId,",
    MKT,
  ], // submit skips the gate
  [
    "../marketplace/src/reviews.ts",
    "await this.registry().requireEvalGate({\n            tenantId,",
    "void ({\n            tenantId,",
    MKT,
  ], // approval skips the gate
];

const only = process.argv.slice(2);
const sel = M.filter(
  ([f, from]) => only.length === 0 || only.some((s) => f.includes(s) || from.includes(s)),
);
let survived = 0;
for (const [file, from, to, cwd] of sel) {
  const orig = readFileSync(file, "utf8");
  if (!orig.includes(from)) {
    console.log(`SKIP (pattern gone): ${file}: ${from.slice(0, 50)}`);
    survived++;
    continue;
  }
  writeFileSync(file, orig.replace(from, to));
  const r = spawnSync("pnpm", ["exec", "vitest", "run", "--bail", "1"], { encoding: "utf8", cwd });
  writeFileSync(file, orig);
  const killed = r.status !== 0;
  if (!killed) survived++;
  console.log(
    `${killed ? "killed  " : "SURVIVED"} ${file}: ${from.slice(0, 60).replace(/\n/g, " ")}`,
  );
}
console.log(`${sel.length - survived}/${sel.length} mutants killed`);
process.exit(survived ? 1 : 0);
