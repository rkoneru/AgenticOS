import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { stringify } from "yaml";
import { ablLintMain } from "../src/index.js";
import { main } from "../src/cli.js";
import { baseDoc, exampleDir } from "./helpers.js";

const tmp = mkdtempSync(join(tmpdir(), "abl-cli-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const ex = (p: string, f: string) => fileURLToPath(new URL(f, exampleDir(p)));
function write(name: string, doc: unknown): string {
  const p = join(tmp, name);
  writeFileSync(p, stringify(doc));
  return p;
}
function run(args: string[]) {
  const out: string[] = [];
  const err: string[] = [];
  const code = main(args, { out: (l) => out.push(l), err: (l) => err.push(l) });
  return { code, out, err };
}

describe("abl-lint main()", () => {
  it("is exported from the package index", () => {
    expect(ablLintMain).toBe(main);
  });

  it("exits 0 for a clean file and says so", () => {
    const r = run([ex("valid", "claims-triage.yaml")]);
    expect(r.code).toBe(0);
    expect(r.err).toEqual([]);
    expect(r.out).toContain(`${ex("valid", "claims-triage.yaml")}: ok`);
    expect(r.out.at(-1)).toBe("1 file(s), 0 failed, 0 warning(s)");
  });

  it("prints warnings to stdout and still exits 0", () => {
    const r = run([ex("valid", "minimal.yaml")]);
    expect(r.code).toBe(0);
    expect(r.out.some((l) => l.includes("warning ABL103 spec.budgets"))).toBe(true);
    expect(r.out.at(-1)).toBe("1 file(s), 0 failed, 1 warning(s)");
  });

  it("exits 1 and prints schema errors in human form", () => {
    const f = ex("invalid", "unacceptable-risk.yaml");
    const r = run([f]);
    expect(r.code).toBe(1);
    expect(r.err).toEqual([
      `${f}: error spec.riskClassification.level: must be one of minimal, limited, high (got "unacceptable")`,
    ]);
    expect(r.out.at(-1)).toBe("1 file(s), 1 failed, 0 warning(s)");
  });

  it("exits 1 on lint errors and prints them with their code", () => {
    const d = baseDoc();
    d.spec.data = { phi: true };
    const f = write("phi.yaml", d);
    const r = run([f]);
    expect(r.code).toBe(1);
    expect(r.err).toEqual([
      `${f}: error ABL005 spec.data: data.phi is true but data.residency is not set`,
    ]);
  });

  it("checks every file, fails if any fails, and counts them", () => {
    const r = run([
      ex("valid", "minimal.yaml"),
      ex("invalid", "bad-version.yaml"),
      ex("valid", "claims-triage.yaml"),
    ]);
    expect(r.code).toBe(1);
    expect(r.out.at(-1)).toBe("3 file(s), 1 failed, 1 warning(s)");
  });

  it("reports an unreadable file and exits 1", () => {
    const f = join(tmp, "does-not-exist.yaml");
    const r = run([f]);
    expect(r.code).toBe(1);
    expect(r.err).toEqual([`${f}: cannot read file (ENOENT)`]);
  });

  it("reports a directory given as a file", () => {
    const r = run([tmp]);
    expect(r.code).toBe(1);
    expect(r.err[0]).toBe(`${tmp}: cannot read file (EISDIR)`);
  });

  it("reports YAML syntax errors", () => {
    const p = join(tmp, "broken.yaml");
    writeFileSync(p, "a: [unclosed");
    const r = run([p]);
    expect(r.code).toBe(1);
    expect(r.err[0]).toMatch(/^.*broken\.yaml: error \(root\): /);
  });

  it("prints usage and exits 2 without arguments or with --help", () => {
    for (const args of [[], ["--help"], ["-h"]]) {
      const r = run(args);
      expect(r.code).toBe(2);
      expect(r.err[0]).toMatch(/^usage: abl-lint/);
    }
  });
});

describe("abl-lint as a process", () => {
  const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
  const cwd = fileURLToPath(new URL("..", import.meta.url));
  const spawn = (script: string, args: string[]) =>
    spawnSync(process.execPath, ["--import", "tsx", script, ...args], { cwd, encoding: "utf8" });

  it("exits 0 on a valid file", () => {
    const r = spawn(cli, [ex("valid", "claims-triage.yaml")]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("ok");
  });

  it("exits 1 on an invalid file and writes the message to stderr", () => {
    const r = spawn(cli, [ex("invalid", "high-without-oversight.yaml")]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("spec.riskClassification.humanOversight: is required");
  });

  it("runs when invoked through a symlink (how a package-manager bin is laid out)", () => {
    const link = join(tmp, "abl-lint");
    symlinkSync(cli, link);
    const r = spawn(link, [ex("invalid", "unknown-field.yaml")]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("spec.surprise: unknown property");
  });
});
