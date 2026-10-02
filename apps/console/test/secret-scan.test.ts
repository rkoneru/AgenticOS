import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { scanText } from "@/lib/secret-scan";

describe("secret scan", () => {
  it("finds known secret shapes", () => {
    const f = scanText(
      "a.js",
      `x="axk_0123456789abcdef_${"A".repeat(43)}"; y="sk-ant-${"b".repeat(30)}"; z="AKIAABCDEFGHIJKLMNOP"`,
    );
    expect(f.map((x) => x.rule).sort()).toEqual([
      "anthropic-key",
      "aws-access-key",
      "axis-api-key",
    ]);
  });
  it("finds the other shapes and never prints the full secret", () => {
    const f = scanText(
      "a.js",
      `-----BEGIN PRIVATE KEY----- axs_0123456789abcdef_${"x".repeat(30)} sk-${"a".repeat(40)} Bearer ${"t".repeat(40)}`,
    );
    expect(f.map((x) => x.rule).sort()).toEqual([
      "axis-scim-token",
      "bearer-literal",
      "openai-style-key",
      "private-key",
    ]);
    expect(f.every((x) => x.excerpt.length <= 9)).toBe(true);
  });
  it("finds sentinel values and ignores short ones", () => {
    expect(
      scanText("a.js", "host=internal.secret.example", ["internal.secret.example"])[0]!.rule,
    ).toBe("sentinel");
    expect(scanText("a.js", "abc", ["abc"])).toEqual([]);
  });
  it("passes clean text", () => {
    expect(scanText("a.js", "const a = 1; // axk_ prefix documented")).toEqual([]);
  });
});

describe("the build gate (scripts/scan-bundle.mjs) is the tested scanner, not a second list", () => {
  const gate = (text: string, env: Record<string, string> = {}) => {
    const dir = mkdtempSync(join(tmpdir(), "axis-bundle-"));
    writeFileSync(join(dir, "app.js"), text);
    return spawnSync(process.execPath, ["scripts/scan-bundle.mjs", dir], {
      encoding: "utf8",
      env: { ...process.env, ...env },
    });
  };
  it("fails on every shape the unit-tested scanner knows, including OpenAI-style keys and bearer literals", () => {
    for (const leak of [
      `k="axk_0123456789abcdef_${"A".repeat(43)}"`,
      `k="axs_0123456789abcdef_${"x".repeat(30)}"`,
      `k="sk-ant-${"b".repeat(30)}"`,
      `k="sk-${"a".repeat(40)}"`,
      `k="AKIAABCDEFGHIJKLMNOP"`,
      "-----BEGIN PRIVATE KEY-----",
      `h="Bearer ${"t".repeat(40)}"`,
    ]) {
      expect(gate(leak).status, leak.slice(0, 20)).toBe(1);
    }
  });
  it("passes clean assets and fails a server-only sentinel", () => {
    expect(gate("const a = 1;").status).toBe(0);
    expect(gate("host=127.0.0.1:4010", { AXIS_SCAN_SENTINELS: "127.0.0.1:4010" }).status).toBe(1);
  });
});
