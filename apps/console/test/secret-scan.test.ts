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
