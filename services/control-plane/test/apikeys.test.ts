import { createHash } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CpError } from "../src/index.js";
import { KINDS, makeWorld, type World } from "./world.js";

const code = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "ok";
  } catch (e) {
    return e instanceof CpError ? e.code : "other";
  }
};

describe.each(KINDS)("API keys (%s store)", (kind) => {
  let w: World;
  beforeAll(async () => {
    w = await makeWorld(kind);
  });
  afterAll(() => w.close());

  it("creates 256-bit keys, shows the secret once and never stores it", async () => {
    const t = await w.tenant();
    const k = await w.cp.apiKeys.create(t.owner, { name: "ci", scopes: ["runs:write", "runs:read"] });
    expect(k.secret).toMatch(/^axk_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(k.secret.split("_")[2]!, "base64url")).toHaveLength(32);
    expect(JSON.stringify(k.key)).not.toContain(k.secret.split("_")[2]!);
    expect("keyHash" in k.key).toBe(false);
    const rec = (await w.store.getApiKey(t.tenantId, k.key.id))!;
    // only a keyed hash is stored: neither the key, its secret half, nor a plain SHA-256 of it
    const stored = rec.keyHash.toString("hex");
    expect(stored).toHaveLength(64);
    expect(stored).not.toBe(createHash("sha256").update(k.secret).digest("hex"));
    expect(Buffer.from(JSON.stringify(rec)).includes(k.secret.split("_")[2]!)).toBe(false);
    const listed = await w.cp.apiKeys.list(t.owner);
    expect(JSON.stringify(listed)).not.toContain(k.secret.split("_")[2]!);
    expect(k.key.expiresAt!.getTime()).toBeGreaterThan(w.clock.now().getTime());
  });

  it("verifies a good key and resolves tenant, member, role and scopes from the key record", async () => {
    const t = await w.tenant();
    const bld = await w.member(t.tenantId, "builder");
    const k = await w.cp.apiKeys.create(bld.principal, { name: "svc", scopes: ["policies:read"] });
    const p = await w.cp.apiKeys.verify(k.secret);
    expect(p).toMatchObject({ tenantId: t.tenantId, memberId: bld.memberId, role: "builder", credential: "api_key", apiKeyId: k.key.id, scopes: ["policies:read"] });
  });

  it("rejects unknown, malformed, truncated, case-changed and other-prefix keys with the same answer", async () => {
    const t = await w.tenant();
    const k = await w.cp.apiKeys.create(t.owner, { name: "x", scopes: ["*"] });
    const [axk, prefix, secret] = k.secret.split("_") as [string, string, string];
    const bad = [
      "", "axk_", "nonsense", k.secret.slice(0, -1), `${k.secret}x`, `${axk}_${prefix}_${secret.replace(/./, (c) => (c === "A" ? "B" : "A"))}`,
      `${axk}_${"0".repeat(16)}_${secret}`, `${axk}_${prefix}_${"A".repeat(43)}`, k.secret.toUpperCase(), ` ${k.secret}`, `${k.secret}\n`,
    ];
    for (const b of bad) expect(await w.cp.apiKeys.verify(b), b).toBeUndefined();
  });

  it("rejects revoked and expired keys and keys whose owner is no longer active", async () => {
    const t = await w.tenant();
    const k = await w.cp.apiKeys.create(t.owner, { name: "x", scopes: ["*"], expiresInDays: 1 });
    expect(await w.cp.apiKeys.verify(k.secret)).toBeDefined();
    w.clock.advance(86_400 + 1);
    expect(await w.cp.apiKeys.verify(k.secret)).toBeUndefined();
    const k2 = await w.cp.apiKeys.create(t.owner, { name: "y", scopes: ["*"] });
    await w.cp.apiKeys.revoke(t.owner, k2.key.id);
    expect(await w.cp.apiKeys.verify(k2.secret)).toBeUndefined();
    const m = await w.member(t.tenantId, "builder");
    const k3 = await w.cp.apiKeys.create(m.principal, { name: "z", scopes: ["*"] });
    await w.store.updateMember(t.tenantId, m.memberId, { status: "deprovisioned" }, w.clock.now());
    expect(await w.cp.apiKeys.verify(k3.secret)).toBeUndefined();
  });

  it("tracks last use at a bounded write rate", async () => {
    const t = await w.tenant();
    const k = await w.cp.apiKeys.create(t.owner, { name: "x", scopes: ["*"] });
    expect((await w.store.getApiKey(t.tenantId, k.key.id))?.lastUsedAt).toBeUndefined();
    await w.cp.apiKeys.verify(k.secret);
    const first = (await w.store.getApiKey(t.tenantId, k.key.id))!.lastUsedAt!;
    w.clock.advance(5);
    await w.cp.apiKeys.verify(k.secret);
    expect((await w.store.getApiKey(t.tenantId, k.key.id))!.lastUsedAt).toEqual(first);
    w.clock.advance(61);
    await w.cp.apiKeys.verify(k.secret);
    expect((await w.store.getApiKey(t.tenantId, k.key.id))!.lastUsedAt!.getTime()).toBeGreaterThan(first.getTime());
  });

  it("rotate returns a new key and kills the old; revoked keys cannot be rotated; ids are tenant scoped", async () => {
    const a = await w.tenant();
    const b = await w.tenant();
    const k = await w.cp.apiKeys.create(a.owner, { name: "x", scopes: ["runs:read"], environment: "staging", expiresInDays: 30 });
    const r = await w.cp.apiKeys.rotate(a.owner, k.key.id);
    expect(r.key).toMatchObject({ name: "x", scopes: ["runs:read"], environment: "staging", rotatedFrom: k.key.id });
    expect(await w.cp.apiKeys.verify(k.secret)).toBeUndefined();
    expect(await w.cp.apiKeys.verify(r.secret)).toBeDefined();
    expect(await code(w.cp.apiKeys.rotate(a.owner, k.key.id))).toBe("conflict");
    expect(await code(w.cp.apiKeys.rotate(b.owner, r.key.id))).toBe("not_found");
    expect(await code(w.cp.apiKeys.revoke(b.owner, r.key.id))).toBe("not_found");
    expect((await w.cp.apiKeys.list(b.owner)).items).toHaveLength(0);
  });

  it("validates input", async () => {
    const t = await w.tenant();
    const bad: [string, Parameters<typeof w.cp.apiKeys.create>[1]][] = [
      ["name", { name: "", scopes: ["*"] }],
      ["name2", { name: "a<b>", scopes: ["*"] }],
      ["scopes", { name: "x", scopes: [] }],
      ["scopes2", { name: "x", scopes: ["admin"] }],
      ["scopes3", { name: "x", scopes: ["runs:delete"] }],
      ["days", { name: "x", scopes: ["*"], expiresInDays: 0 }],
      ["days2", { name: "x", scopes: ["*"], expiresInDays: 366 }],
      ["days3", { name: "x", scopes: ["*"], expiresInDays: Number.NaN }],
      ["env", { name: "x", scopes: ["*"], environment: "qa" as "dev" }],
    ];
    for (const [n, i] of bad) expect(await code(w.cp.apiKeys.create(t.owner, i)), n).toBe("invalid");
    const many = Array.from({ length: 33 }, (_, i) => `r${i}x:read`);
    expect(await code(w.cp.apiKeys.create(t.owner, { name: "x", scopes: many }))).toBe("invalid");
  });

  it("keys from different tenants never resolve to each other (prefix is not a tenant oracle)", async () => {
    const a = await w.tenant();
    const b = await w.tenant();
    const ka = await w.cp.apiKeys.create(a.owner, { name: "a", scopes: ["*"] });
    const kb = await w.cp.apiKeys.create(b.owner, { name: "b", scopes: ["*"] });
    expect((await w.cp.apiKeys.verify(ka.secret))?.tenantId).toBe(a.tenantId);
    expect((await w.cp.apiKeys.verify(kb.secret))?.tenantId).toBe(b.tenantId);
    // a key with A's prefix but B's secret is nothing
    const franken = `axk_${ka.secret.split("_")[1]}_${kb.secret.split("_")[2]}`;
    expect(await w.cp.apiKeys.verify(franken)).toBeUndefined();
  });

  it("requires a strong pepper", async () => {
    const { ApiKeyService } = await import("../src/index.js");
    expect(() => new ApiKeyService({ store: w.store, pepper: Buffer.alloc(4) })).toThrow(/pepper/);
  });
});
