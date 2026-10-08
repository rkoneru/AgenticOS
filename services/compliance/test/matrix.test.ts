import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  REQUIRED_ROWS,
  checkMatrix,
  loadAndCheck,
  driftFindings,
  makeTargetsOf,
  nodeFs,
  parseFramework,
  renderFramework,
  renderSummary,
  runCheck,
  writeRendered,
  type RepoFs,
} from "../src/index.js";

const FILES: Record<string, string> = {
  "src/a.ts": "export const a = 1;\nconst NEEDLE_TEXT = 'audit.action.x';\n",
  "test/a.test.ts": "import {it} from 'vitest';\nit('works', () => {});\n",
  "test/empty.test.ts": "// nothing here\n",
  "test/a_test.py": "def test_something():\n    pass\n",
  "docs/a.md": "# doc\n",
  "config/dir/x": "x",
};
const fsOf = (files: Record<string, string>): RepoFs => ({
  exists: (r) => r in files || Object.keys(files).some((k) => k.startsWith(`${r}/`)),
  isFile: (r) => r in files,
  read: (r) => files[r] ?? "",
});

const row = (over: Record<string, unknown> = {}): string => {
  const base = {
    id: "T-1",
    requirement: "Keep records of access decisions",
    mechanism: "The kernel appends a hash-chained event per decision",
    code: ["src/a.ts"],
    config: [],
    evidence: [{ kind: "test", ref: "test/a.test.ts" }],
    status: "Built",
    notes: "Single instance; see the audit runbook for limits.",
    ...over,
  };
  return JSON.stringify(base);
};
const fw = (rows: string[], over: Record<string, unknown> = {}): string =>
  JSON.stringify({
    framework: "t",
    title: "Test",
    version: 1,
    scope: "Designed for a test.",
    rows: JSON.parse(`[${rows.join(",")}]`),
    ...over,
  });

const check = (
  files: Record<string, string>,
  repo = FILES,
  required: Record<string, string[]> = {},
  make = ["e2e"],
) => checkMatrix({ files, fs: fsOf(repo), makeTargets: new Set(make), required });
const codes = (r: ReturnType<typeof check>): string[] => r.findings.map((f) => f.code);

describe("matrix checker", () => {
  it("accepts a row whose code, config and evidence exist", () => {
    const r = check({
      "t.yaml": fw([
        row({
          config: ["src/a.ts#NEEDLE_TEXT", "config/dir"],
          evidence: [
            { kind: "test", ref: "test/a.test.ts#works" },
            { kind: "test", ref: "test/a_test.py" },
            { kind: "make", ref: "e2e" },
            { kind: "audit_query", ref: "src/a.ts#audit.action.x" },
            { kind: "doc", ref: "docs/a.md" },
            { kind: "file", ref: "config/dir/x" },
          ],
        }),
      ]),
    });
    expect(r.findings).toEqual([]);
    expect(r.counts["t"]).toEqual({ Built: 1, Prototype: 0, Designed: 0, Gap: 0 });
  });

  it("FAILS when a cited code path does not exist (M010)", () => {
    expect(codes(check({ "t.yaml": fw([row({ code: ["src/missing.ts"] })]) }))).toEqual(["M010"]);
  });
  it("FAILS when a config path or needle does not exist (M011)", () => {
    expect(codes(check({ "t.yaml": fw([row({ config: ["nope.yaml"] })]) }))).toEqual(["M011"]);
    expect(codes(check({ "t.yaml": fw([row({ config: ["src/a.ts#no such text"] })]) }))).toEqual([
      "M011",
    ]);
    expect(codes(check({ "t.yaml": fw([row({ config: ["src/a.ts#"] })]) }))).toEqual(["M011"]);
    expect(codes(check({ "t.yaml": fw([row({ config: ["config/dir#x"] })]) }))).toEqual(["M011"]);
  });
  it("FAILS when evidence does not exist: test, doc, file, make target, audit query (M012)", () => {
    for (const e of [
      { kind: "test", ref: "test/missing.test.ts" },
      { kind: "doc", ref: "docs/missing.md" },
      { kind: "file", ref: "nope" },
      { kind: "make", ref: "no-such-target" },
      { kind: "test", ref: "test/a.test.ts#a test that does not exist" },
      { kind: "audit_query", ref: "src/a.ts#not.an.action" },
      { kind: "doc", ref: "config/dir" },
    ])
      expect(
        codes(
          check({
            "t.yaml": fw([row({ evidence: [{ kind: "test", ref: "test/a.test.ts" }, e] })]),
          }),
        ),
        JSON.stringify(e),
      ).toContain("M012");
  });
  it("FAILS when test evidence contains no test (M013) or an audit query has no action (M014)", () => {
    expect(
      codes(
        check({ "t.yaml": fw([row({ evidence: [{ kind: "test", ref: "test/empty.test.ts" }] })]) }),
      ),
    ).toEqual(["M013"]);
    expect(
      codes(
        check({ "t.yaml": fw([row({ evidence: [{ kind: "audit_query", ref: "src/a.ts" }] })]) }),
      ),
    ).toEqual(["M014"]);
  });
  it("FAILS when a path escapes the repository, even when something exists there", () => {
    const repo = {
      ...FILES,
      "../outside": "x",
      "/etc/passwd": "x",
      "a\\b": "x",
      "src/../../x": "x",
      "src/../a.ts": "x",
    };
    for (const p of ["../outside", "/etc/passwd", "a\\b", "src/../../x", "src/../a.ts"]) {
      const r = check({ "t.yaml": fw([row({ code: [p] })]) }, repo);
      expect(
        r.findings.map((f) => f.message),
        p,
      ).toEqual([`code path path is not repository-relative: ${p}`]);
    }
  });
  it("FAILS a Built row without executable evidence (M020), with only documents, or without code (M021)", () => {
    expect(codes(check({ "t.yaml": fw([row({ evidence: [] })]) }))).toEqual(["M020"]);
    expect(
      codes(check({ "t.yaml": fw([row({ evidence: [{ kind: "doc", ref: "docs/a.md" }] })]) })),
    ).toEqual(["M020"]);
    expect(
      codes(check({ "t.yaml": fw([row({ evidence: [{ kind: "file", ref: "src/a.ts" }] })]) })),
    ).toEqual(["M020"]);
    expect(codes(check({ "t.yaml": fw([row({ code: [] })]) }))).toEqual(["M021"]);
    expect(
      codes(check({ "t.yaml": fw([row({ status: "Prototype", code: [], evidence: [] })]) })),
    ).toEqual(["M021"]);
  });
  it("lets Prototype, Designed and Gap rows have documents only; Gap and Designed need real notes (M022)", () => {
    expect(
      check({
        "t.yaml": fw([row({ status: "Prototype", evidence: [{ kind: "doc", ref: "docs/a.md" }] })]),
      }).findings,
    ).toEqual([]);
    expect(
      check({
        "t.yaml": fw([
          row({
            status: "Designed",
            code: [],
            evidence: [],
            notes: "Designed in docs/a.md; nothing built yet.",
          }),
        ]),
      }).findings,
    ).toEqual([]);
    expect(
      codes(
        check({ "t.yaml": fw([row({ status: "Gap", code: [], evidence: [], notes: "todo" })]) }),
      ),
    ).toEqual(["M022"]);
    expect(
      codes(
        check({
          "t.yaml": fw([row({ status: "Designed", code: [], evidence: [], notes: "short" })]),
        }),
      ),
    ).toEqual(["M022"]);
  });
  it("FAILS wording that claims attainment (M030)", () => {
    for (const bad of [
      "We are certified",
      "fully compliant",
      "guarantees compliance",
      "SOC 2 certification achieved",
    ])
      expect(codes(check({ "t.yaml": fw([row({ mechanism: bad })]) }))).toEqual(["M030"]);
    expect(codes(check({ "t.yaml": fw([row({ requirement: "A compliant thing" })]) }))).toEqual([
      "M030",
    ]);
    expect(
      codes(check({ "t.yaml": fw([row({ notes: "Attested by an auditor, certified." })]) })),
    ).toEqual(["M030"]);
    expect(codes(check({ "t.yaml": fw([row()], { scope: "certified scope" }) }))).toEqual(["M030"]);
    expect(codes(check({ "t.yaml": fw([row()], { title: "compliant title" }) }))).toEqual(["M030"]);
    expect(
      check({
        "t.yaml": fw([row({ mechanism: "Designed for and evidence-ready toward the criteria" })]),
      }).findings,
    ).toEqual([]);
  });
  it("FAILS duplicate ids, a wrong id prefix and duplicate frameworks (M002, M004)", () => {
    expect(codes(check({ "t.yaml": fw([row(), row()]) }))).toEqual(["M002"]);
    expect(codes(check({ "t.yaml": fw([row({ id: "X-1" })]) }))).toEqual(["M004"]);
    expect(codes(check({ "a.yaml": fw([row()]), "b.yaml": fw([row()]) }))).toEqual(["M002"]);
  });
  it("FAILS a missing required row or framework (M005)", () => {
    expect(codes(check({ "t.yaml": fw([row()]) }, FILES, { t: ["T-1", "T-2"] }))).toEqual(["M005"]);
    expect(codes(check({}, FILES, { other: ["O-1"] }))).toEqual(["M005"]);
    expect(codes(check({ "t.yaml": "rows: []" }, FILES, { t: ["T-1"] }))).toEqual(
      expect.arrayContaining(["M001", "M005"]),
    );
  });
  it("FAILS malformed files with the reason (M001)", () => {
    const cases: [string, string][] = [
      ["{{{", "YAML does not parse"],
      ["- a\n- b", "must be a YAML mapping"],
      [fw([row()], { extra: 1 }), "unknown key extra"],
      [fw([row()], { version: "1" }), "version must be an integer"],
      [fw([row()], { framework: "" }), "framework must be"],
      [fw([row()], { title: 5 }), "title must be"],
      [fw([row()], { scope: "" }), "scope must be"],
      [fw([]), "rows must be a non-empty list"],
      [fw([row({ id: "" })]), "id must be"],
      [fw([row({ extra: 1 })]), "unknown key extra"],
      [fw([row({ requirement: "" })]), "requirement must be"],
      [fw([row({ code: "src/a.ts" })]), "code must be a list"],
      [fw([row({ config: [1] })]), "config must be a list"],
      [fw([row({ evidence: "x" })]), "evidence must be a list"],
      [fw([row({ evidence: [{ kind: "video", ref: "x" }] })]), "evidence #0 must be"],
      [fw([row({ evidence: [{ kind: "test", ref: "" }] })]), "evidence #0 must be"],
      [
        fw([row({ evidence: [{ kind: "test", ref: "test/a.test.ts", why: 1 }] })]),
        "unknown key why",
      ],
      [fw([row({ status: "Done" })]), "status must be one of"],
    ];
    for (const [text, msg] of cases) {
      const r = check({ "t.yaml": text });
      expect(r.findings.map((f) => f.message).join("\n"), text.slice(0, 40)).toContain(msg);
      expect(codes(r)).toContain("M001");
    }
    expect(JSON.stringify(check({ "t.yaml": "rows:\n  - 5\n" }).findings)).toContain(
      "row must be a mapping",
    );
    expect(parseFramework("rows: 5", "f").framework).toBeNull();
  });
  it("makeTargetsOf reads targets, not variables or .PHONY", () => {
    const t = makeTargetsOf(".PHONY: a b\nCOMPOSE := x\nfoo-bar:\n\techo\nbaz: dep\nX = y\n");
    expect([...t].sort()).toEqual(["baz", "foo-bar"]);
  });
});

describe("rendering", () => {
  const parsed = parseFramework(
    fw([
      row(),
      row({
        id: "T-2",
        status: "Gap",
        code: [],
        evidence: [],
        notes: "Nothing built; see the plan.",
      }),
    ]),
    "t.yaml",
  ).framework!;
  it("is deterministic and complete", () => {
    const md = renderFramework(parsed, "docs/compliance/matrix/t.yaml");
    expect(md).toBe(renderFramework(parsed, "docs/compliance/matrix/t.yaml"));
    expect(md).toContain("### T-1");
    expect(md).toContain("### T-2");
    expect(md).toContain("Built 1, Prototype 0, Designed 0, Gap 1");
    expect(md).toContain("GENERATED from docs/compliance/matrix/t.yaml");
    expect(md).toContain("Designed for / evidence-ready");
    const s = renderSummary([parsed], { t: "t.md" });
    expect(s).toContain("| Test | 2 | 1 | 0 | 0 | 1 | [t.md](t.md) |");
    expect(renderSummary([parsed], {})).toContain("[t](t)");
  });
});

describe("repository runner", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });
  function repo(matrix: Record<string, string>): string {
    const d = mkdtempSync(join(tmpdir(), "axis-matrix-"));
    dirs.push(d);
    mkdirSync(join(d, "docs/compliance/matrix"), { recursive: true });
    mkdirSync(join(d, "src"), { recursive: true });
    mkdirSync(join(d, "test"), { recursive: true });
    writeFileSync(join(d, "Makefile"), "e2e:\n\ttrue\n");
    writeFileSync(join(d, "src/a.ts"), FILES["src/a.ts"] as string);
    writeFileSync(join(d, "test/a.test.ts"), FILES["test/a.test.ts"] as string);
    for (const [k, v] of Object.entries(matrix))
      writeFileSync(join(d, "docs/compliance/matrix", k), v);
    return d;
  }
  const io = () => {
    const out: string[] = [];
    const err: string[] = [];
    return { out: (l: string) => out.push(l), err: (l: string) => err.push(l), o: out, e: err };
  };

  it("--write renders the Markdown, then check passes; editing the YAML afterwards is drift", () => {
    const d = repo({ "t.yaml": fw([row()]) });
    const a = io();
    // required rows come from the real matrix; this scratch repo has none
    expect(loadAndCheck(d, {}).findings).toEqual([]);
    const res = loadAndCheck(d, {});
    expect(driftFindings(d, res.rendered).map((f) => f.code)).toEqual(["M040", "M040"]);
    writeRendered(d, res.rendered);
    expect(driftFindings(d, res.rendered)).toEqual([]);
    writeFileSync(
      join(d, "docs/compliance/t.md"),
      readFileSync(join(d, "docs/compliance/t.md"), "utf8") + "edited",
    );
    expect(driftFindings(d, res.rendered).map((f) => f.message)).toEqual([
      "rendered file is out of date with the YAML",
    ]);
    // the CLI against the real required list reports the missing frameworks
    expect(runCheck(["check", "--root", d], a)).toBe(1);
    expect(a.e.join("\n")).toContain("M005");
  });

  it("CLI: usage errors exit 2; a missing directory is a finding, not a crash", () => {
    const a = io();
    expect(runCheck(["--bogus"], a)).toBe(2);
    expect(runCheck(["check", "--root"], a)).toBe(2);
    const empty = mkdtempSync(join(tmpdir(), "axis-matrix-"));
    dirs.push(empty);
    expect(runCheck(["--root", empty], io())).toBe(1);
    expect(Object.keys(REQUIRED_ROWS).length).toBeGreaterThanOrEqual(5);
    expect(nodeFs(empty).exists("Makefile")).toBe(false);
    expect(nodeFs(empty).isFile("Makefile")).toBe(false);
  });

  it("--write does not render over a matrix that has findings", () => {
    const d = repo({ "t.yaml": fw([row({ code: ["src/missing.ts"] })]) });
    const a = io();
    expect(runCheck(["--root", d, "--write"], a)).toBe(1);
    expect(a.e.join("\n")).toContain("M010");
  });
});

describe("the real repository matrix", () => {
  it("passes every check (this is the same check as `make compliance-check`)", () => {
    const root = new URL("../../..", import.meta.url).pathname;
    const res = loadAndCheck(root);
    const drift = driftFindings(root, res.rendered);
    expect([...res.findings, ...drift]).toEqual([]);
    for (const fwName of Object.keys(REQUIRED_ROWS)) expect(res.counts[fwName]).toBeTruthy();
  });
});
