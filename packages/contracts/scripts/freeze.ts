/* Regenerates FREEZE.json. Requires an ADR for any change to a frozen file (docs/adr/0007). */
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = fileURLToPath(new URL("../../../", import.meta.url));

/** Files and directories (relative to repo root) that make up the frozen contract surface. */
export const FROZEN_PATHS = [
  "packages/abl/schema",
  "packages/contracts/schemas",
  "packages/contracts/process-model.json",
  "packages/contracts/openapi",
  "proto",
  "packages/db/migrations",
];

function walk(p: string, out: string[]): void {
  if (statSync(p).isDirectory()) {
    for (const f of readdirSync(p).sort()) walk(join(p, f), out);
  } else {
    out.push(p);
  }
}

export function currentHashes(): Record<string, string> {
  const files: string[] = [];
  for (const p of FROZEN_PATHS) walk(join(ROOT, p), files);
  const out: Record<string, string> = {};
  for (const f of files) {
    out[relative(ROOT, f)] = createHash("sha256").update(readFileSync(f)).digest("hex");
  }
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const manifest = {
    note: "Frozen contracts. Do not edit by hand; see docs/adr/0007-contracts-freeze.md.",
    files: currentHashes(),
  };
  writeFileSync(
    join(ROOT, "packages/contracts/FREEZE.json"),
    JSON.stringify(manifest, null, 2) + "\n",
  );
  console.log(`froze ${Object.keys(manifest.files).length} files`);
}
