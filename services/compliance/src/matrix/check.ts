import {
  EXECUTABLE_KINDS,
  parseFramework,
  type Evidence,
  type Framework,
  type Row,
} from "./schema.js";

/** Read-only view of the repository the checker verifies against. Paths are repository-relative. */
export interface RepoFs {
  exists(rel: string): boolean;
  isFile(rel: string): boolean;
  read(rel: string): string;
}

export interface Finding {
  framework: string;
  row: string | null;
  code: string;
  message: string;
}

export interface CheckInput {
  /** file name -> YAML text */
  files: Record<string, string>;
  fs: RepoFs;
  /** Targets of the Makefile. */
  makeTargets: ReadonlySet<string>;
  /** Row ids every framework must keep (a deleted row is a finding). */
  required: Readonly<Record<string, readonly string[]>>;
}

export interface CheckResult {
  findings: Finding[];
  frameworks: Framework[];
  counts: Record<string, Record<string, number>>;
}

/** Words that would turn a "designed for / evidence-ready" statement into a claim of attainment. */
const FORBIDDEN = [
  /\bcertified\b/i,
  /\bcertification (?:achieved|obtained|granted)\b/i,
  /\bcompliant\b/i,
  /\bfully compliant\b/i,
  /\bguarantee[sd]? compliance\b/i,
  /\battested by (?:an )?auditor\b/i,
];

const forbiddenIn = (text: string): string | undefined =>
  FORBIDDEN.find((w) => w.test(text))?.source;

const TEST_CASE =
  /\b(?:it|test|describe)\s*(?:\.\w+)?\s*\(|^\s*(?:async\s+)?def test_|^\s*(?:async\s+)?def test\b/m;

const splitRef = (ref: string): { path: string; needle: string | null } => {
  const i = ref.indexOf("#");
  return i < 0 ? { path: ref, needle: null } : { path: ref.slice(0, i), needle: ref.slice(i + 1) };
};

const safePath = (p: string): boolean =>
  p !== "" &&
  !p.startsWith("/") &&
  !p.split("/").includes("..") &&
  !p.includes("\\") &&
  !p.includes("\0");

/** Make targets: `name:` at the start of a line (not a variable assignment), plus names listed in `.PHONY`. */
export function makeTargetsOf(makefile: string): Set<string> {
  const out = new Set<string>();
  for (const line of makefile.split("\n")) {
    const m = /^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*:(?!=)/.exec(line);
    if (m && m[1] !== ".PHONY") out.add(m[1] as string);
  }
  return out;
}

export function checkMatrix(i: CheckInput): CheckResult {
  const findings: Finding[] = [];
  const frameworks: Framework[] = [];
  const add = (framework: string, row: string | null, code: string, message: string): void => {
    findings.push({ framework, row, code, message });
  };

  const checkPath = (fw: string, row: Row, label: string, ref: string, code: string): void => {
    const { path, needle } = splitRef(ref);
    if (!safePath(path))
      return add(fw, row.id, code, `${label} path is not repository-relative: ${ref}`);
    if (!i.fs.exists(path)) return add(fw, row.id, code, `${label} does not exist: ${path}`);
    if (needle !== null) {
      if (needle === "") return add(fw, row.id, code, `${label} has an empty #needle: ${ref}`);
      if (!i.fs.isFile(path))
        return add(fw, row.id, code, `${label} #needle needs a file: ${path}`);
      if (!i.fs.read(path).includes(needle))
        add(fw, row.id, code, `${label} ${path} does not contain "${needle}"`);
    }
  };

  const checkEvidence = (fw: string, row: Row, e: Evidence): void => {
    if (e.kind === "make") {
      if (!i.makeTargets.has(e.ref))
        add(fw, row.id, "M012", `make target does not exist: ${e.ref}`);
      return;
    }
    const before = findings.length;
    checkPath(fw, row, `${e.kind} evidence`, e.ref, "M012");
    if (findings.length > before) return;
    const { path, needle } = splitRef(e.ref);
    if (!i.fs.isFile(path))
      return add(fw, row.id, "M012", `${e.kind} evidence must be a file: ${path}`);
    if (e.kind === "test" && !TEST_CASE.test(i.fs.read(path)))
      add(fw, row.id, "M013", `test evidence contains no test case: ${path}`);
    if (e.kind === "audit_query" && needle === null)
      add(fw, row.id, "M014", `audit_query evidence needs path#action: ${e.ref}`);
  };

  const names = new Set<string>();
  const counts: Record<string, Record<string, number>> = {};
  for (const [file, text] of Object.entries(i.files).sort(([a], [b]) => (a < b ? -1 : 1))) {
    const { framework, problems } = parseFramework(text, file);
    for (const p of problems) add(file, p.row, "M001", p.message);
    if (!framework) continue;
    frameworks.push(framework);
    const fw = framework.framework;
    if (names.has(fw)) add(file, null, "M002", `duplicate framework ${fw}`);
    names.add(fw);
    const tally: Record<string, number> = { Built: 0, Prototype: 0, Designed: 0, Gap: 0 };
    counts[fw] = tally;
    const seen = new Set<string>();
    const hitScope = forbiddenIn(framework.scope) ?? forbiddenIn(framework.title);
    if (hitScope) add(fw, null, "M030", `scope/title uses forbidden wording ${hitScope}`);
    for (const row of framework.rows) {
      tally[row.status] = (tally[row.status] ?? 0) + 1;
      if (seen.has(row.id)) add(fw, row.id, "M002", "duplicate row id");
      seen.add(row.id);
      const prefix = `${fw.toUpperCase()}-`;
      if (!row.id.startsWith(prefix)) add(fw, row.id, "M004", `row id must start with ${prefix}`);
      for (const f of ["requirement", "mechanism", "notes"] as const) {
        const hit = forbiddenIn(row[f]);
        if (hit) add(fw, row.id, "M030", `${f} uses forbidden wording ${hit}`);
      }
      for (const c of row.code) checkPath(fw, row, "code path", c, "M010");
      for (const c of row.config) checkPath(fw, row, "config", c, "M011");
      for (const e of row.evidence) checkEvidence(fw, row, e);
      const executable = row.evidence.filter((e) => EXECUTABLE_KINDS.includes(e.kind));
      if (row.status === "Built" && executable.length === 0)
        add(
          fw,
          row.id,
          "M020",
          "status Built needs at least one test, make or audit_query evidence artifact",
        );
      if ((row.status === "Built" || row.status === "Prototype") && row.code.length === 0)
        add(fw, row.id, "M021", `status ${row.status} needs at least one code path`);
      if ((row.status === "Gap" || row.status === "Designed") && row.notes.trim().length < 20)
        add(fw, row.id, "M022", `status ${row.status} needs notes saying what is missing`);
    }
    for (const req of i.required[fw] ?? [])
      if (!seen.has(req)) add(fw, req, "M005", "required control row is missing");
  }
  for (const fw of Object.keys(i.required))
    if (!names.has(fw))
      add(fw, null, "M005", `required framework file is missing or invalid: ${fw}`);
  return { findings, frameworks, counts };
}
