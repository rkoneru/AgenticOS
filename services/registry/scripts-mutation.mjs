/* global console, process */
// Mutation check for the registry safety logic: apply one targeted edit at a time, run the tests, and require a FAILURE.
// A surviving mutant means a safety property is untested. Usage (from services/registry): node scripts-mutation.mjs [substring ...]
// (run through `pnpm mutation`, which provides a throwaway Postgres). Files may live outside this package; paths are relative to it.
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const MIG = "../../packages/db/migrations/0010_registry.sql";
const MIG12 = "../../packages/db/migrations/0012_registry_public_versions.sql";
const M = [
  // --- verification: every check must matter
  ["src/verify.ts", "if (!verifyDetached(key.publicKey, msg, sig.sig)) fail(", "if (false) fail("],
  ["src/verify.ts", "if (hash !== rec.contentHash)", "if (false)"],
  ["src/verify.ts", "if (!good) fail(", "if (false) fail("],
  [
    "src/verify.ts",
    "if (!keyTrustedAt(key, rec.publishedAt).ok || !keyTrustedAt(key, signedAt).ok)",
    "if (false)",
  ],
  ["src/verify.ts", "if (canonicalJson(doc) !== rec.abl)", "if (false)"],
  ["src/verify.ts", "if (abl.metadata.version !== rec.version)", "if (false)"],
  [
    "src/verify.ts",
    "if (signedAt.getTime() > rec.publishedAt.getTime() + MAX_SKEW_MS)",
    "if (false)",
  ],
  ["src/verify.ts", "p.lint.warnings !== warn.length ||", "false ||"],
  // --- keys, strict encodings
  ["src/signing.ts", 'if (key.revokeReason === "compromised")', "if (false)"],
  ["src/signing.ts", "if (key.revokedAt && at.getTime() >= key.revokedAt.getTime())", "if (false)"],
  ["src/signing.ts", 'if (b.toString("base64url") !== s) return undefined;', ""],
  ["src/signing.ts", 'return b.toString("base64") === s ? b : undefined;', "return b;"],
  // --- resolve / publish rules
  ["src/service.ts", 'opts.allowYanked === true || x.status.state !== "yanked"', "true"],
  ["src/service.ts", "if (sv.build.length > 0) throw", "if (false) throw"],
  ["src/service.ts", "if (key === self) throw", "if (false) throw"],
  ["src/service.ts", "opts.notBelow !== undefined &&", "false &&"],
  [
    "src/service.ts",
    "if (!verdict.ok) {\n      if (viewer.tenantId",
    "if (false) {\n      if (viewer.tenantId",
  ],
  ["src/service.ts", "if (RESERVED_NAMESPACES.some(", "if (false && RESERVED_NAMESPACES.some("],
  [
    "src/service.ts",
    'if (row.status.state === "yanked") throw conflict(',
    "if (false) throw conflict(",
  ],
  ["src/service.ts", "throw invalid(`dependency ${key} is not in a public namespace`)", "void 0"],
  ["src/types.ts", '.replaceAll("rn", "m")', ""],
  [
    "src/semver.ts",
    "return set.some((c) => c.v.prerelease.length > 0 && sameTuple(c.v, v));",
    "return true;",
  ],
  [
    "src/semver.ts",
    "if (major > 0 || minor === undefined) hi = v3(major + 1, 0, 0);",
    "if (major >= 0) hi = v3(major + 1, 0, 0);",
  ],
  // --- tenant isolation, in both stores and in the database
  [
    "src/memory-store.ts",
    "return this.pub.has(namespace) || (viewer.tenantId !== null && viewer.tenantId === owner);",
    "return true;",
  ],
  [
    MIG,
    "CREATE POLICY versions_insert ON registry_versions FOR INSERT WITH CHECK (axis.registry_owns(namespace, tenant_id));",
    "CREATE POLICY versions_insert ON registry_versions FOR INSERT WITH CHECK (tenant_id = axis.current_tenant());",
  ],
  [
    MIG,
    "CREATE TRIGGER registry_versions_immutable BEFORE UPDATE OR DELETE ON registry_versions\n  FOR EACH ROW EXECUTE FUNCTION axis.forbid_mutation();",
    "",
  ],
  [
    MIG,
    "CREATE POLICY keys_read ON registry_keys FOR SELECT USING (axis.registry_visible(namespace, tenant_id));",
    "CREATE POLICY keys_read ON registry_keys FOR SELECT USING (true);",
  ],
  // --- per-version release (migration 0012, ADR 0055)
  ["src/memory-store.ts", "this.pubVersions.has(k(r.namespace, r.name, r.version))", "true"],
  [
    MIG12,
    "CREATE POLICY versions_read ON registry_versions FOR SELECT USING (axis.registry_version_visible(namespace, name, version, tenant_id));",
    "CREATE POLICY versions_read ON registry_versions FOR SELECT USING (axis.registry_visible(namespace, tenant_id));",
  ],
  [
    MIG12,
    "CREATE POLICY names_read ON registry_names FOR SELECT USING (axis.registry_name_visible(namespace, name, tenant_id));",
    "CREATE POLICY names_read ON registry_names FOR SELECT USING (true);",
  ],
  [
    MIG12,
    "CREATE POLICY events_read ON registry_version_events FOR SELECT USING (axis.registry_version_visible(namespace, name, version, tenant_id));",
    "CREATE POLICY events_read ON registry_version_events FOR SELECT USING (true);",
  ],
  ["src/service.ts", "if (anon?.version !== res.version)", "if (false)"],
  // --- audit fail-closed, rate limits, dev server tenant binding
  ["src/audit.ts", 'throw unavailable("audit log unavailable");', "return undefined as never;"],
  ["src/http-kit.ts", "if (live.length >= this.max) {", "if (false) {"],
  [
    "src/dev-server.ts",
    'if (q.has("tenant_id") && q.get("tenant_id") !== p.tenantId)',
    "if (false)",
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
