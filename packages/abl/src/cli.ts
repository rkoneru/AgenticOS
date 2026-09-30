#!/usr/bin/env node
import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { formatFindings, formatIssues } from "./format.js";
import { compileAblYaml } from "./manifest.js";

export interface CliIo {
  out: (line: string) => void;
  err: (line: string) => void;
}

const USAGE =
  "usage: abl-lint <file...>   (exit 0 clean or warnings only, 1 on errors, 2 on bad usage)";

/** Lint and compile each file. Returns the process exit code. */
export function main(args: readonly string[], io: CliIo): number {
  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    io.err(USAGE);
    return 2;
  }
  let failed = 0;
  let warnings = 0;
  for (const file of args) {
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch (err) {
      io.err(`${file}: cannot read file (${String((err as NodeJS.ErrnoException).code)})`);
      failed++;
      continue;
    }
    const r = compileAblYaml(text);
    formatIssues(r.ok ? [] : r.issues).forEach((l) => io.err(`${file}: error ${l}`));
    formatFindings(r.findings).forEach((l) => {
      const isError = l.startsWith("error");
      (isError ? io.err : io.out)(`${file}: ${l}`);
      if (!isError) warnings++;
    });
    if (!r.ok) failed++;
    else io.out(`${file}: ok`);
  }
  io.out(`${args.length} file(s), ${failed} failed, ${warnings} warning(s)`);
  return failed > 0 ? 1 : 0;
}

/* v8 ignore start -- process entry point, exercised by the spawn test in test/cli.test.ts */
if (
  process.argv[1] !== undefined &&
  realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  process.exitCode = main(process.argv.slice(2), {
    out: (l) => console.log(l),
    err: (l) => console.error(l),
  });
}
/* v8 ignore stop */
