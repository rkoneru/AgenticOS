import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CpError, runtimeAuthFromTokens } from "../src/index.js";
import { KINDS, eventsOf, makeWorld, type World } from "./world.js";

const code = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "ok";
  } catch (e) {
    return e instanceof CpError ? e.code : "other";
  }
};
const SECRET = "sk-ant-api03-VERY-SECRET-0123456789";

describe.each(KINDS)("BYO model keys (%s store)", (kind) => {
  let w: World;
  beforeAll(async () => {
    w = await makeWorld(kind);
  });
  afterAll(() => w.close());

  it("encrypts under a per-tenant wrapped data key; plaintext is neither stored, returned, audited nor in errors", async () => {
    const t = await w.tenant();
    const r = await w.cp.admin.putModelKey(t.owner, "anthropic", "default", SECRET);
    expect(JSON.stringify(r)).not.toContain("SECRET");
    expect(Object.keys(r).sort()).toEqual(["createdAt", "id", "label", "provider"]);
    const stored = (await w.store.getModelCredential(t.tenantId, "anthropic", "default"))!;
    expect(stored.nonceAndCiphertext.includes(Buffer.from(SECRET))).toBe(false);
    expect(JSON.stringify(stored)).not.toContain("SECRET");
    const tk = (await w.store.getActiveTenantKey(t.tenantId))!;
    expect(tk.kmsKeyId).toBe("kms-1");
    expect(tk.wrappedDek).toHaveLength(12 + 32 + 16); // sealed 256-bit key, not the key itself
    expect(JSON.stringify(await w.cp.admin.listModelKeys(t.owner))).not.toContain("SECRET");
    expect(JSON.stringify(await eventsOf(w, t.tenantId))).not.toContain("SECRET");
    expect(await w.cp.modelKeys.revealForRuntime(t.tenantId, "anthropic", "default")).toBe(SECRET);
    // errors do not echo the value
    const bad = await w.cp.admin.putModelKey(t.owner, "Bad Provider", "x", SECRET).catch((e: Error) => e.message);
    expect(String(bad)).not.toContain("SECRET");
  });

  it("rotates a key in place (same row, rotated_at set) and deletes it", async () => {
    const t = await w.tenant();
    const a = await w.cp.admin.putModelKey(t.owner, "openai", "prod", "first");
    w.clock.advance(10);
    const b = await w.cp.admin.putModelKey(t.owner, "openai", "prod", "second");
    expect(b.id).toBe(a.id);
    expect(b.rotatedAt).toBeDefined();
    expect(await w.cp.modelKeys.revealForRuntime(t.tenantId, "openai", "prod")).toBe("second");
    await w.cp.admin.deleteModelKey(t.owner, "openai", "prod");
    expect(await w.cp.modelKeys.revealForRuntime(t.tenantId, "openai", "prod")).toBeUndefined();
    expect(await code(w.cp.admin.deleteModelKey(t.owner, "openai", "prod"))).toBe("not_found");
  });

  it("tenants are cryptographically and logically separated", async () => {
    const a = await w.tenant();
    const b = await w.tenant();
    await w.cp.admin.putModelKey(a.owner, "anthropic", "default", "A-secret");
    await w.cp.admin.putModelKey(b.owner, "anthropic", "default", "B-secret");
    expect(await w.cp.modelKeys.revealForRuntime(a.tenantId, "anthropic", "default")).toBe("A-secret");
    expect(await w.cp.modelKeys.revealForRuntime(b.tenantId, "anthropic", "default")).toBe("B-secret");
    expect(await w.cp.modelKeys.revealForRuntime(b.tenantId, "anthropic", "nope")).toBeUndefined();
    expect((await w.cp.admin.listModelKeys(a.owner)).length).toBe(1);
    // a ciphertext moved to another tenant/row fails to decrypt (AAD binds tenant, provider, label)
    const ca = (await w.store.getModelCredential(a.tenantId, "anthropic", "default"))!;
    await w.store.putModelCredential({ ...ca, tenantId: b.tenantId, label: "moved", id: "00000000-0000-4000-8000-0000000000aa" });
    expect(await w.cp.modelKeys.revealForRuntime(b.tenantId, "anthropic", "moved")).toBeUndefined();
    // within one tenant, a ciphertext copied to another label (or provider) is also refused: the AAD binds both
    await w.store.putModelCredential({ ...ca, label: "copied", id: "00000000-0000-4000-8000-0000000000ab" });
    await w.store.putModelCredential({ ...ca, provider: "other", id: "00000000-0000-4000-8000-0000000000ac" });
    expect(await w.cp.modelKeys.revealForRuntime(a.tenantId, "anthropic", "copied")).toBeUndefined();
    expect(await w.cp.modelKeys.revealForRuntime(a.tenantId, "other", "default")).toBeUndefined();
    // a data key wrapped for A cannot be unwrapped for B
    const ka = (await w.store.getActiveTenantKey(a.tenantId))!;
    await expect(w.kms.unwrap(b.tenantId, ka.kmsKeyId, ka.wrappedDek)).rejects.toThrow();
  });

  it("only roles with modelkeys.* rights, and builders only for keys they own", async () => {
    const t = await w.tenant();
    const v = await w.member(t.tenantId, "viewer");
    const bld = await w.member(t.tenantId, "builder");
    const aud = await w.member(t.tenantId, "auditor");
    expect(await code(w.cp.admin.putModelKey(v.principal, "anthropic", "x", "s"))).toBe("forbidden");
    expect(await code(w.cp.admin.listModelKeys(v.principal))).toBe("forbidden");
    expect(await code(w.cp.admin.putModelKey(bld.principal, "anthropic", "x", "s"))).toBe("ok");
    expect(await code(w.cp.admin.listModelKeys(aud.principal))).toBe("ok");
    expect(await code(w.cp.admin.putModelKey(aud.principal, "anthropic", "x", "s"))).toBe("forbidden");
    expect(await code(w.cp.admin.deleteModelKey(aud.principal, "anthropic", "x"))).toBe("forbidden");
  });

  it("validates provider, label and secret", async () => {
    const t = await w.tenant();
    expect(await code(w.cp.admin.putModelKey(t.owner, "A", "x", "s"))).toBe("invalid");
    expect(await code(w.cp.admin.putModelKey(t.owner, "anthropic", "-bad", "s"))).toBe("invalid");
    expect(await code(w.cp.admin.putModelKey(t.owner, "anthropic", "x", ""))).toBe("invalid");
    expect(await code(w.cp.admin.putModelKey(t.owner, "anthropic", "x", "s".repeat(9000)))).toBe("invalid");
    expect(await code(w.cp.admin.putModelKey(t.owner, "anthropic", "x", 5 as unknown as string))).toBe("invalid");
  });

  it("reuses the tenant data key across secrets and survives a concurrent first write", async () => {
    const t = await w.tenant();
    await Promise.all([w.cp.admin.putModelKey(t.owner, "anthropic", "a", "1"), w.cp.admin.putModelKey(t.owner, "openai", "b", "2")]);
    expect(await w.cp.modelKeys.revealForRuntime(t.tenantId, "anthropic", "a")).toBe("1");
    expect(await w.cp.modelKeys.revealForRuntime(t.tenantId, "openai", "b")).toBe("2");
    expect((await w.store.getActiveTenantKey(t.tenantId))?.version).toBe(1);
  });

  it("runtime bridge auth maps bearer tokens to tenants", () => {
    const auth = runtimeAuthFromTokens({ "tenant-a": "tok-a", "tenant-b": "tok-b" });
    expect(auth("Bearer tok-a")).toBe("tenant-a");
    expect(auth("Bearer tok-b")).toBe("tenant-b");
    expect(auth("Bearer nope")).toBeUndefined();
    expect(auth(undefined)).toBeUndefined();
    expect(auth("tok-a")).toBeUndefined();
  });
});
