#!/usr/bin/env node
/* global console, process */
// Fails (exit 1) when built client assets contain secrets or values of server-only environment variables.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { PATTERNS } from "../lib/secret-patterns.mjs";

const root = process.argv[2] ?? ".next/static";
const sentinels = (process.env.AXIS_SCAN_SENTINELS ?? "").split(",").filter(Boolean);
function* walk(d) {
  for (const n of readdirSync(d)) {
    const p = join(d, n);
    if (statSync(p).isDirectory()) yield* walk(p);
    else yield p;
  }
}
let bad = 0;
let files = 0;
for (const f of walk(root)) {
  if (!/\.(js|css|html|map|json|txt)$/.test(f)) continue;
  files++;
  const t = readFileSync(f, "utf8");
  for (const { rule, re } of PATTERNS)
    if (re.test(t)) {
      console.error(`SECRET PATTERN ${rule} in ${f}`);
      bad++;
    }
  for (const s of sentinels)
    if (t.includes(s)) {
      console.error(`SERVER-ONLY VALUE leaked into ${f}`);
      bad++;
    }
}
console.log(`scanned ${files} client assets, ${bad} finding(s)`);
process.exit(bad ? 1 : 0);
