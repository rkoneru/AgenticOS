import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const src = fileURLToPath(new URL("../src/", import.meta.url));
const files = readdirSync(src).filter((f) => f.endsWith(".ts"));
const imports = files.flatMap((f) =>
  [...readFileSync(src + f, "utf8").matchAll(/(?:from|import)\s+["']([^"']+)["']/g)].map(
    (m) => [f, m[1] as string] as const,
  ),
);

/**
 * Invariant 2: AGIL never governs. It reads the audit log and nothing else, so it must not even be able to NAME the kernel, the gate,
 * the approvals service, the policy engine, the control plane or an eval harness. This is a lint over the package's imports and
 * manifest; the type-level guarantee is that `Explainer` takes an `AuditReader` (a read-only interface), never a store or a gate.
 */
describe("AGIL is read-only and off the decision path", () => {
  const ALLOWED = new Set(["@axis/audit", "@axis/contracts"]);
  it("imports only relative modules, node builtins' absence, @axis/audit and @axis/contracts", () => {
    const bad = imports.filter(([, spec]) => !spec.startsWith("./") && !ALLOWED.has(spec));
    expect(bad).toEqual([]);
  });
  it("never imports kernel, gate, approvals, policy, control-plane, billing, transport or eval code", () => {
    const FORBIDDEN =
      /risk-kernel|approvals|@axis\/policy|control-plane|billing|grpc|eval|child_process|node:(http|https|net|fs)/i;
    expect(imports.filter(([, s]) => FORBIDDEN.test(s))).toEqual([]);
    // Code (strings and comments stripped) must not reach for IO or any write-like call either.
    const code = (f: string): string =>
      readFileSync(src + f, "utf8")
        .replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, "")
        .replace(/"[^"\n]*"|`[^`]*`/g, "");
    const IO = /\bfetch\(|\.append\(|\.write\(|\.insert\(|\.put\(|process\.env|require\(/;
    expect(files.filter((f) => IO.test(code(f)))).toEqual([]);
  });
  it("declares no dependency that could reach a decision", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
      dependencies: Record<string, string>;
    };
    expect(Object.keys(pkg.dependencies).sort()).toEqual(["@axis/audit", "@axis/contracts"]);
  });
  it("only imports TYPES from @axis/audit (no runtime coupling to a store)", () => {
    const runtime = files.flatMap((f) =>
      [
        ...readFileSync(src + f, "utf8").matchAll(
          /^import\s+(?!type)[^;]*from\s+["']@axis\/audit["']/gm,
        ),
      ].map(() => f),
    );
    expect(runtime).toEqual([]);
  });
});
