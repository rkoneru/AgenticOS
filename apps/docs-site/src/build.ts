/** Static docs build: docs/**.md + OpenAPI -> apps/docs-site/dist. Offline and deterministic. */
import { mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";
import { checkLinks } from "./linkcheck";
import { buildSite, type SourcePage } from "./site";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..", "..");
const docsDir = join(repo, "docs");
const outDir = process.env["DOCS_OUT_DIR"] ?? join(here, "..", "dist");

function* walk(d: string): Generator<string> {
  for (const n of readdirSync(d).sort()) {
    const p = join(d, n);
    if (statSync(p).isDirectory()) yield* walk(p);
    else if (n.endsWith(".md")) yield p;
  }
}

const sources: SourcePage[] = [...walk(docsDir)].map((p) => ({
  path: relative(docsDir, p).split(sep).join("/"),
  markdown: readFileSync(p, "utf8"),
}));
const openapi = parse(
  readFileSync(join(repo, "packages/contracts/openapi/axis-v1.yaml"), "utf8"),
) as Record<string, unknown>;
const site = buildSite(sources, openapi);

const problems = checkLinks(site);
// Links from source docs to files outside docs/ (code, configs) are reported but do not fail the build;
// `pnpm test` enforces zero broken links among generated pages for the curated sections.
rmSync(outDir, { recursive: true, force: true });
for (const [p, c] of site) {
  const f = join(outDir, p);
  mkdirSync(dirname(f), { recursive: true });
  writeFileSync(f, c);
}
console.log(
  `docs-site: ${site.size} files written to ${outDir}; ${problems.length} unresolved link(s)`,
);
if (process.env["DOCS_STRICT_LINKS"] === "1" && problems.length) {
  for (const p of problems.slice(0, 50)) console.error(`${p.page}: ${p.href} (${p.problem})`);
  process.exit(1);
}
