import {
  existsSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import {
  checkMatrix,
  makeTargetsOf,
  type CheckResult,
  type Finding,
  type RepoFs,
} from "./check.js";
import { renderFramework, renderSummary } from "./render.js";
import { REQUIRED_ROWS } from "./required.js";

export const MATRIX_DIR = "docs/compliance/matrix";
export const RENDER_DIR = "docs/compliance";

/**
 * A symlink the repo (or a dependency the build pulled in) contains, whose target resolves outside `root`, must never count as
 * evidence: its content is not something the checker (or a reviewer reading the repo on GitHub) can see or audit. `realpathSync`
 * follows every symlink on the path; a path that still exists after that but no longer resolves under `rootReal` is treated as
 * absent (found in review: `safePath`'s `..`/absolute-path checks only look at the written path, not where a symlink inside the
 * repo actually points).
 */
export function nodeFs(root: string): RepoFs {
  const rootAbs = resolve(root);
  const abs = (rel: string): string => join(rootAbs, rel);
  const insideRoot = (p: string): boolean => {
    let real: string;
    try {
      real = realpathSync(p);
    } catch {
      return false;
    }
    const rootReal = (() => {
      try {
        return realpathSync(rootAbs);
      } catch {
        return rootAbs;
      }
    })();
    if (real === rootReal) return true;
    const rel = relative(rootReal, real);
    return rel !== "" && rel !== ".." && !rel.startsWith(`..${sep}`);
  };
  return {
    exists: (rel) => existsSync(abs(rel)) && insideRoot(abs(rel)),
    isFile: (rel) => existsSync(abs(rel)) && insideRoot(abs(rel)) && statSync(abs(rel)).isFile(),
    read: (rel) => readFileSync(abs(rel), "utf8"),
  };
}

export interface RepoCheck extends CheckResult {
  /** Files that should exist / be rewritten: path -> expected text. */
  rendered: Record<string, string>;
}

/** Loads the matrix from `<root>/docs/compliance/matrix/*.yaml`, checks it, and renders the Markdown the repository must contain. */
export function loadAndCheck(root: string, required = REQUIRED_ROWS): RepoCheck {
  const dir = join(resolve(root), MATRIX_DIR);
  const files: Record<string, string> = {};
  if (existsSync(dir))
    for (const f of readdirSync(dir)
      .filter((x) => x.endsWith(".yaml"))
      .sort())
      files[f] = readFileSync(join(dir, f), "utf8");
  const fs = nodeFs(root);
  const makeTargets = fs.exists("Makefile")
    ? makeTargetsOf(fs.read("Makefile"))
    : new Set<string>();
  const res = checkMatrix({ files, fs, makeTargets, required });
  const rendered: Record<string, string> = {};
  const names: Record<string, string> = {};
  for (const fw of res.frameworks) {
    const src =
      Object.keys(files).find((f) => f === `${fw.framework}.yaml`) ?? `${fw.framework}.yaml`;
    const out = `${fw.framework}.md`;
    names[fw.framework] = out;
    rendered[`${RENDER_DIR}/${out}`] = renderFramework(fw, `${MATRIX_DIR}/${src}`);
  }
  rendered[`${RENDER_DIR}/summary.md`] = renderSummary(res.frameworks, names);
  return { ...res, rendered };
}

/** Findings for rendered files that are missing or stale (the YAML is the source of truth). */
export function driftFindings(root: string, rendered: Record<string, string>): Finding[] {
  const out: Finding[] = [];
  for (const [path, text] of Object.entries(rendered)) {
    const abs = join(resolve(root), path);
    if (!existsSync(abs))
      out.push({ framework: path, row: null, code: "M040", message: "rendered file is missing" });
    else if (readFileSync(abs, "utf8") !== text)
      out.push({
        framework: path,
        row: null,
        code: "M040",
        message: "rendered file is out of date with the YAML",
      });
  }
  return out;
}

export function writeRendered(root: string, rendered: Record<string, string>): void {
  for (const [path, text] of Object.entries(rendered))
    writeFileSync(join(resolve(root), path), text);
}
