#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { parse } from "yaml";
import { compilePolicySet } from "./compile.js";
import { opaBuildWasm } from "./opa.js";
import { findCaseFiles, runCaseFile } from "./run-tests.js";

/** `axis-policy compile <pack.yaml...> [-o out.rego]` and `axis-policy test <dir>`. Returns the exit code. */
export function main(argv: string[], out: (s: string) => void = console.log): number {
  const [cmd, ...rest] = argv;
  if (cmd === "compile") {
    const oi = rest.indexOf("-o");
    const outFile = oi >= 0 ? rest[oi + 1] : undefined;
    const files = rest.filter((_, i) => oi < 0 || (i !== oi && i !== oi + 1));
    if (files.length === 0) {
      out("usage: axis-policy compile <pack.yaml...> [-o out.rego]");
      return 2;
    }
    const r = compilePolicySet(files.map((f) => parse(readFileSync(f, "utf8")) as unknown));
    if (!r.ok) {
      for (const i of r.issues) out(`error ${i.code} ${i.path}: ${i.message}`);
      return 1;
    }
    for (const w of r.warnings) out(`warning ${w.code} ${w.path}: ${w.message}`);
    if (outFile) writeFileSync(outFile, r.rego);
    else out(r.rego);
    return 0;
  }
  if (cmd === "bundle") {
    const oi = rest.indexOf("-o");
    const outFile = oi >= 0 ? rest[oi + 1] : undefined;
    const files = rest.filter((_, i) => oi < 0 || (i !== oi && i !== oi + 1));
    if (!outFile || files.length === 0) {
      out("usage: axis-policy bundle <pack.yaml...> -o bundle.tar.gz");
      return 2;
    }
    const r = compilePolicySet(files.map((f) => parse(readFileSync(f, "utf8")) as unknown));
    if (!r.ok) {
      for (const i of r.issues) out(`error ${i.code} ${i.path}: ${i.message}`);
      return 1;
    }
    writeFileSync(outFile, opaBuildWasm(r.rego));
    out(`wrote ${outFile} (${r.policyVersion})`);
    return 0;
  }
  if (cmd === "test") {
    const root = rest[0] ?? "policies";
    const files = findCaseFiles(root);
    if (files.length === 0) {
      out(`no *.cases.yaml files under ${root}`);
      return 1;
    }
    let bad = 0;
    for (const f of files) {
      const r = runCaseFile(f);
      out(`${r.ok ? "PASS" : "FAIL"} ${f} (${r.cases} cases)`);
      if (!r.ok) {
        bad++;
        out(r.output);
      }
    }
    return bad === 0 ? 0 : 1;
  }
  out("usage: axis-policy compile|bundle|test ...");
  return 2;
}

if (import.meta.url === `file://${process.argv[1]}`) process.exit(main(process.argv.slice(2)));
