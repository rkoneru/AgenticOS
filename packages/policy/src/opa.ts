import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { REGO_ENTRYPOINT, REGO_QUERY } from "./compile.js";

const bin = (): string => process.env["OPA_BIN"] ?? "opa";

export class OpaError extends Error {}

function run(args: string[], input?: string): string {
  try {
    // A hard stop for a pathological input: `opa` is superlinear in the size of the generated Rego and this call is synchronous.
    return execFileSync(bin(), args, {
      encoding: "utf8",
      input,
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 60_000,
    });
  } catch (err) {
    const e = err as { code?: string; stderr?: string; stdout?: string };
    if (e.code === "ENOENT")
      throw new OpaError(`opa binary not found (set OPA_BIN or install OPA >= 0.70): ${bin()}`);
    throw new OpaError(`${e.stdout ?? ""}${e.stderr ?? ""}`.trim() || String(err));
  }
}

/** Write `files` to a temp dir, run `fn(dir)`, always clean up. */
export function withTempDir<T>(files: Record<string, string>, fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), "axis-policy-"));
  try {
    for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** `opa check --strict`: syntax, types, unused/unsafe vars. */
export function opaCheck(rego: string): void {
  withTempDir(
    { "policy.rego": rego },
    (d) => void run(["check", "--strict", "--v1-compatible", d]),
  );
}

/** Builds a Wasm bundle (proves the output avoids non-Wasm built-ins, ADR-0004). Returns the bundle tarball bytes. */
export function opaBuildWasm(rego: string): Buffer {
  return withTempDir({ "policy.rego": rego }, (d) => {
    const out = join(d, "bundle.tar.gz");
    run([
      "build",
      "-t",
      "wasm",
      "-e",
      REGO_ENTRYPOINT,
      "--v1-compatible",
      "-o",
      out,
      join(d, "policy.rego"),
    ]);
    return execFileSync("cat", [out]);
  });
}

/** Evaluates `data.axis.policy.result` with the given input using the real OPA. */
export function opaEval(rego: string, input: unknown): Record<string, unknown> {
  return withTempDir({ "policy.rego": rego }, (d) => {
    const out = run(
      [
        "eval",
        "--v1-compatible",
        "-d",
        join(d, "policy.rego"),
        "--stdin-input",
        "--format",
        "json",
        REGO_QUERY,
      ],
      JSON.stringify(input),
    );
    const parsed = JSON.parse(out) as {
      result?: { expressions: { value: Record<string, unknown> }[] }[];
    };
    const value = parsed.result?.[0]?.expressions[0]?.value;
    if (!value) throw new OpaError("policy produced no result");
    return value;
  });
}

/** Runs `opa test` over a directory's rego files; throws with OPA's report on failure. */
export function opaTest(files: Record<string, string>): string {
  return withTempDir(files, (d) => run(["test", "--v1-compatible", d, "-v"]));
}
