// usage: node compile-abl.mjs <file.abl.yaml>  -> prints the RuntimeManifest JSON (exit 1 with findings on error)
import { readFileSync } from "node:fs";
import { compileAblYaml } from "@axis/abl";

const r = compileAblYaml(readFileSync(process.argv[2], "utf8"));
if (!r.ok) {
  console.error(JSON.stringify({ issues: r.issues, findings: r.findings }));
  process.exit(1);
}
console.log(JSON.stringify(r.manifest));
