import { driftFindings, loadAndCheck, writeRendered } from "./repo.js";
import type { Finding } from "./check.js";

export interface RunIo {
  out(line: string): void;
  err(line: string): void;
}

/**
 * `check [--root DIR] [--write]`. Exit 0 only when every row cites paths, tests and make targets that exist, no `Built` row lacks
 * executable evidence, the labelling rules hold, required rows exist and the rendered Markdown matches the YAML.
 * `--write` rewrites the Markdown first (it never edits the YAML).
 */
export function runCheck(argv: readonly string[], io: RunIo, defaultRoot = process.cwd()): number {
  const args = [...argv];
  if (args[0] === "check") args.shift();
  let root = defaultRoot;
  let write = false;
  for (let k = 0; k < args.length; k++) {
    const a = args[k] as string;
    if (a === "--write") write = true;
    else if (a === "--root" && args[k + 1] !== undefined) root = args[++k] as string;
    else {
      io.err(`usage: axis-compliance-check check [--root DIR] [--write] (unknown argument ${a})`);
      return 2;
    }
  }
  const res = loadAndCheck(root);
  if (write && res.findings.filter((f) => f.code !== "M040").length === 0)
    writeRendered(root, res.rendered);
  const findings: Finding[] = [...res.findings, ...driftFindings(root, res.rendered)];
  for (const f of findings)
    io.err(`${f.code} ${f.framework}${f.row ? ` ${f.row}` : ""}: ${f.message}`);
  for (const [fw, c] of Object.entries(res.counts))
    io.out(
      `${fw}: ${Object.entries(c)
        .map(([s, n]) => `${s} ${n}`)
        .join(", ")}`,
    );
  io.out(
    findings.length === 0
      ? "compliance matrix: OK"
      : `compliance matrix: ${findings.length} finding(s)`,
  );
  return findings.length === 0 ? 0 : 1;
}
