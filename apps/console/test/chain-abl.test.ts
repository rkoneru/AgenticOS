import { describe, expect, it } from "vitest";
import { sealEvent, type AuditEvent as CAuditEvent, type UnsealedEvent } from "@axis/contracts";
import * as abl from "@axis/abl";
import { canonicalize, reasonText, sha256Hex, sortBySeq, verifyChainLocal } from "@/lib/hashchain";
import { checkAbl, pointerToPath, STARTER_ABL, MAX_ABL_BYTES } from "@/lib/abl-diagnostics";
import type { AuditEvent } from "@/lib/api";

const base = (i: number): UnsealedEvent => ({
  schema_version: 1,
  id: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`,
  tenant_id: "11111111-1111-4111-8111-111111111111",
  ts: "2026-01-01T00:00:00.000Z",
  trace_id: "a".repeat(32),
  actor: { type: "human", id: "u" },
  blueprint: { name: "b", version: "1.0.0" },
  policy_version: "p1",
  enforcement_point: "tool_call",
  action: "kb.search",
  decision: "ALLOW",
  inputs_hash: "b".repeat(64),
  outputs_hash: "c".repeat(64),
});
function chain(n: number): AuditEvent[] {
  const out: CAuditEvent[] = [];
  for (let i = 1; i <= n; i++) out.push(sealEvent(base(i), out[out.length - 1]));
  return out as AuditEvent[];
}

describe("client-side hash chain", () => {
  it("agrees with the contracts reference implementation", async () => {
    const c = chain(5);
    const v = await verifyChainLocal(c);
    expect(v).toEqual({ ok: true, length: 5, firstSeq: 1, lastSeq: 5 });
  });
  it("verifies a slice with an anchor and an empty slice", async () => {
    const c = chain(5);
    expect((await verifyChainLocal(c.slice(2), { seq: 2, hash: c[1]!.hash })).ok).toBe(true);
    expect(await verifyChainLocal([])).toEqual({ ok: true, length: 0 });
  });
  it("detects every kind of tampering", async () => {
    const c = chain(4);
    const tampered = c.map((e) => ({ ...e }));
    tampered[2] = { ...tampered[2]!, action: "x.delete" };
    expect(await verifyChainLocal(tampered)).toEqual({
      ok: false,
      brokenAtSeq: 3,
      reason: "hash_mismatch",
    });
    expect(await verifyChainLocal([c[0]!, c[2]!, c[3]!])).toEqual({
      ok: false,
      brokenAtSeq: 3,
      reason: "seq_gap",
    });
    expect(await verifyChainLocal(c.slice(1))).toEqual({
      ok: false,
      brokenAtSeq: 2,
      reason: "seq_gap",
    });
    const relinked = [c[0]!, { ...c[1]!, prev_hash: "f".repeat(64) }, c[2]!];
    expect(await verifyChainLocal(relinked)).toEqual({
      ok: false,
      brokenAtSeq: 2,
      reason: "prev_hash_mismatch",
    });
    const other = [c[0]!, { ...c[1]!, tenant_id: "22222222-2222-4222-8222-222222222222" }];
    expect(await verifyChainLocal(other)).toEqual({
      ok: false,
      brokenAtSeq: 2,
      reason: "tenant_mismatch",
    });
    const floaty = [{ ...c[0]!, extra: 1.5 } as unknown as AuditEvent];
    expect(await verifyChainLocal(floaty)).toEqual({
      ok: false,
      brokenAtSeq: 1,
      reason: "malformed",
    });
  });
  it("canonicalises like the reference and rejects unsupported values", async () => {
    expect(canonicalize({ b: [1, true, null, "x"], a: 2 })).toBe('{"a":2,"b":[1,true,null,"x"]}');
    expect(() => canonicalize(1.5)).toThrow();
    expect(() => canonicalize(undefined)).toThrow();
    expect(await sha256Hex("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
  it("sorts and explains", () => {
    const c = chain(3);
    expect(sortBySeq([c[2]!, c[0]!, c[1]!]).map((e) => e.seq)).toEqual([1, 2, 3]);
    for (const r of [
      "tenant_mismatch",
      "seq_gap",
      "prev_hash_mismatch",
      "hash_mismatch",
      "malformed",
      "other",
    ])
      expect(reasonText(r).length).toBeGreaterThan(0);
  });
});

describe("ABL diagnostics", () => {
  const engine = abl as unknown as Parameters<typeof checkAbl>[1];
  it("accepts the starter document", () => {
    const r = checkAbl(STARTER_ABL, engine);
    expect(r).toMatchObject({
      ok: true,
      name: "hello-agent",
      version: "1.0.0",
      riskLevel: "minimal",
    });
    expect(r.doc).toBeDefined();
  });
  it("reports YAML syntax errors with a line number", () => {
    const r = checkAbl("a: [1, 2\nb: : :", engine);
    expect(r.ok).toBe(false);
    expect(r.diagnostics[0]).toMatchObject({ severity: "error" });
    expect(r.diagnostics[0]!.line).toBeGreaterThanOrEqual(1);
  });
  it("places schema errors at the offending line and column", () => {
    const text = STARTER_ABL.replace("level: minimal", "level: tiny");
    const r = checkAbl(text, engine);
    expect(r.ok).toBe(false);
    const line = text.split("\n").findIndex((l) => l.includes("level: tiny")) + 1;
    const d = r.diagnostics.find((x) => x.path.endsWith("/level"));
    expect(d).toBeDefined();
    expect(d!.line).toBe(line);
    expect(d!.column).toBeGreaterThan(1);
    expect(d!.code).toMatch(/^schema\./);
  });
  it("falls back to the nearest parent for missing properties and to 1:1 for the root", () => {
    const r = checkAbl(
      "apiVersion: abl.axis.dev/v1\nkind: Agent\nmetadata:\n  name: x\n  version: 1.0.0\nspec: {}\n",
      engine,
    );
    expect(r.ok).toBe(false);
    expect(r.diagnostics.every((d) => d.line >= 1 && d.column >= 1)).toBe(true);
    const root = checkAbl("42", engine);
    expect(root.diagnostics[0]).toMatchObject({ line: 1, column: 1 });
  });
  it("surfaces lint findings with their severity and position", () => {
    const text = STARTER_ABL + "  budgets:\n    tokens: { soft: 10, hard: 5 }\n";
    const r = checkAbl(text, engine);
    const d = r.diagnostics.find((x) => x.code === "ABL002");
    expect(d).toMatchObject({ severity: "error", path: "/spec/budgets/tokens" });
    expect(d!.line).toBe(text.split("\n").findIndex((l) => l.includes("tokens:")) + 1);
    expect(r.ok).toBe(false);
    expect(r.doc).toBeUndefined();
  });
  it("rejects oversized input", () => {
    const r = checkAbl("a".repeat(MAX_ABL_BYTES + 1), engine);
    expect(r.diagnostics[0]!.code).toBe("too_large");
  });
  it("accepts a warning-only document (ok stays true)", () => {
    const fake = {
      validateAbl: (d: unknown) => ({ ok: true as const, doc: d }),
      lintAbl: () => [
        { code: "W1", severity: "warning" as const, path: "/spec", message: "careful" },
      ],
    };
    const r = checkAbl("spec:\n  x: 1\n", fake);
    expect(r.ok).toBe(true);
    expect(r.diagnostics[0]).toMatchObject({ severity: "warning", line: 2, column: 3 });
  });
  it("maps JSON pointers", () => {
    expect(pointerToPath("/")).toEqual([]);
    expect(pointerToPath("")).toEqual([]);
    expect(pointerToPath("/spec/tools/1/a~1b~0c")).toEqual(["spec", "tools", 1, "a/b~c"]);
  });
});
