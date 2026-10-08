import { randomBytes } from "node:crypto";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { MasterKeyProvider, Pseudonymiser, Sealer, normalizeIds, valuesOf } from "../src/index.js";

const T1 = "11111111-1111-4111-8111-111111111111";
const T2 = "22222222-2222-4222-8222-222222222222";

describe("pseudonymisation", () => {
  const keys = new MasterKeyProvider(Buffer.alloc(32, 7));
  const ps = new Pseudonymiser(keys);
  it("is deterministic per tenant and normalised, and differs across tenants and kinds", async () => {
    const a = await ps.lookup(T1, { kind: "email", value: "Jane@Example.com " });
    expect(a).toBe(await ps.lookup(T1, { kind: "email", value: "jane@example.com" }));
    expect(a).not.toBe(await ps.lookup(T2, { kind: "email", value: "jane@example.com" }));
    expect(a).not.toBe(await ps.lookup(T1, { kind: "subject_key", value: "jane@example.com" }));
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(await ps.subjectRef(T1, "s1")).toMatch(/^sub_[0-9a-f]{32}$/);
    expect(await ps.subjectRef(T1, "s1")).not.toBe(await ps.subjectRef(T2, "s1"));
  });
  it("tokens depend on the per-subject salt: a different (or shredded) salt cannot reproduce them", async () => {
    const id = { kind: "email" as const, value: "jane@example.com" };
    const s1 = randomBytes(32);
    const s2 = randomBytes(32);
    const t1 = await ps.tokenFor(T1, s1, id);
    expect(t1).toMatch(/^anon_[0-9a-f]{24}$/);
    expect(t1).toBe(await ps.tokenFor(T1, s1, id));
    expect(t1).not.toBe(await ps.tokenFor(T1, s2, id));
    expect(t1).not.toBe(await ps.tokenFor(T2, s1, id));
  });
  it("different master keys give different pseudonyms; short masters are refused", async () => {
    const other = new Pseudonymiser(new MasterKeyProvider(Buffer.alloc(32, 8)));
    expect(await other.lookup(T1, { kind: "email", value: "a@b.co" })).not.toBe(
      await ps.lookup(T1, { kind: "email", value: "a@b.co" }),
    );
    expect(() => new MasterKeyProvider(Buffer.alloc(8))).toThrow(/32 bytes/);
  });
});

describe("Sealer", () => {
  const s = new Sealer(new MasterKeyProvider());
  it("round-trips, binds to the tenant and detects tampering", async () => {
    const blob = await s.seal(T1, { identifiers: [{ kind: "email", value: "x@y.z" }] });
    expect(await s.open(T1, blob)).toEqual({ identifiers: [{ kind: "email", value: "x@y.z" }] });
    await expect(s.open(T2, blob)).rejects.toMatchObject({ code: "invalid" });
    const bad = Buffer.from(blob);
    bad[bad.length - 1] = (bad[bad.length - 1] ?? 0) ^ 1;
    await expect(s.open(T1, bad)).rejects.toMatchObject({ code: "invalid" });
    await expect(s.open(T1, Buffer.alloc(5))).rejects.toMatchObject({ code: "invalid" });
    expect(blob.includes(Buffer.from("x@y.z"))).toBe(false);
  });
  it("property: any JSON round-trips", async () => {
    await fc.assert(
      fc.asyncProperty(fc.jsonValue(), async (v) => {
        expect(await s.open(T1, await s.seal(T1, v))).toEqual(JSON.parse(JSON.stringify(v)));
      }),
      { numRuns: 40 },
    );
  });
});

describe("normalizeIds", () => {
  it("dedupes, normalises and sorts", () => {
    const n = normalizeIds([
      { kind: "email", value: " A@X.org " },
      { kind: "email", value: "a@x.org" },
      { kind: "phone", value: "+1 (555) 010-9999" },
      { kind: "end_user_id", value: "ABCDEF" },
      { kind: "user_ref", value: "u1" },
    ]);
    expect(n).toEqual([
      { kind: "email", value: "a@x.org" },
      { kind: "end_user_id", value: "abcdef" },
      { kind: "phone", value: "+15550109999" },
      { kind: "user_ref", value: "u1" },
    ]);
    expect(valuesOf(n, "email", "user_ref")).toEqual(["a@x.org", "u1"]);
    expect(() => normalizeIds([{ kind: "email", value: "x".repeat(600) }])).toThrow(/512/);
  });
});
