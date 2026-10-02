#!/usr/bin/env node
// Fails (exit 1) when built client assets contain secrets or values of server-only environment variables.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const root = process.argv[2] ?? ".next/static";
const sentinels = (process.env.AXIS_SCAN_SENTINELS ?? "").split(",").filter(Boolean);
const patterns = [
  /axk_[0-9a-f]{16}_[A-Za-z0-9_-]{20,}/,
  /axs_[0-9a-f]{16}_[A-Za-z0-9_-]{20,}/,
  /sk-ant-[A-Za-z0-9_-]{20,}/,
  /AKIA[0-9A-Z]{16}/,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
];
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
  for (const re of patterns)
    if (re.test(t)) {
      console.error(`SECRET PATTERN ${re} in ${f}`);
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
