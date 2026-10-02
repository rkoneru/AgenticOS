import { mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ReloadingTokenTable, TenantBundleEngine } from "../src/index.js";
import { T1, T2, compileDefault } from "./helpers.js";

const input = (tenant: unknown): Record<string, unknown> => ({
  enforcement_point: "tool_call",
  tenant: { id: tenant },
  tool: { name: "anything", kind: "function", side_effects: "read" },
  args: {},
  actor: { type: "agent", id: "a" },
  agent: { name: "a", version: "1" },
});
const decision = async (e: TenantBundleEngine, tenant: unknown): Promise<string | undefined> =>
  ((await e.evaluate(input(tenant))) as { decision?: string }).decision;
const version = async (e: TenantBundleEngine, tenant: unknown): Promise<string | undefined> =>
  ((await e.evaluate(input(tenant))) as { policy_version?: string }).policy_version;

describe("TenantBundleEngine (per-tenant policy from the control plane's bundle files)", () => {
  let dir: string;
  let bundle: Buffer;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "rk-bundles-"));
    bundle = compileDefault().bundle;
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  const put = (tenant: string, bytes: Buffer | string): void => {
    const tmp = join(dir, `.${tenant}.tmp`);
    writeFileSync(tmp, bytes);
    renameSync(tmp, join(dir, `${tenant}.tar.gz`));
  };

  it("serves each tenant its own bundle and denies a tenant with none (fail-closed, no fallback)", async () => {
    put(T1, bundle);
    const e = new TenantBundleEngine(dir);
    expect(await decision(e, T1)).toMatch(/^(ALLOW|DENY|REQUIRE_APPROVAL)/);
    expect(await version(e, T1)).toBe(compileDefault().policyVersion);
    await expect(e.evaluate(input(T2))).rejects.toThrow(/no policy bundle/);
  });

  it("refuses a missing or non-UUID tenant (no path traversal)", async () => {
    const e = new TenantBundleEngine(dir);
    for (const bad of [
      undefined,
      5,
      "../etc/passwd",
      `${T1}/../x`,
      "ABCDEF12-1111-4111-8111-111111111111",
    ])
      await expect(e.evaluate(input(bad))).rejects.toThrow(/no valid tenant/);
    await expect(e.evaluate({})).rejects.toThrow(/no valid tenant/);
  });

  it("reloads when the file is replaced, and a corrupt replacement denies instead of serving the stale engine", async () => {
    put(T2, bundle);
    const e = new TenantBundleEngine(dir);
    expect(await version(e, T2)).toBe(compileDefault().policyVersion);
    put(T2, "not a bundle");
    await expect(e.evaluate(input(T2))).rejects.toThrow();
    await expect(e.evaluate(input(T2))).rejects.toThrow(); // still denied, nothing stale cached
    put(T2, bundle);
    expect(await version(e, T2)).toBe(compileDefault().policyVersion); // recovers when a good bundle arrives
    rmSync(join(dir, `${T2}.tar.gz`));
    await expect(e.evaluate(input(T2))).rejects.toThrow(/no policy bundle/); // removal denies too
  });

  it("concurrent first evaluations share one load", async () => {
    put(T1, bundle);
    const e = new TenantBundleEngine(dir);
    const r = await Promise.all([version(e, T1), version(e, T1), version(e, T1)]);
    expect(new Set(r)).toEqual(new Set([compileDefault().policyVersion]));
  });
});

describe("ReloadingTokenTable", () => {
  it("re-reads the file when it changes and authenticates nobody when it is unreadable", () => {
    const dir = mkdtempSync(join(tmpdir(), "rk-tokens-"));
    const f = join(dir, "tokens.json");
    const t = new ReloadingTokenTable<{ tenantId: string }>(f);
    expect(t.get("a")).toBeUndefined(); // no file yet
    writeFileSync(f, JSON.stringify({ a: { tenantId: T1 } }));
    expect(t.get("a")).toEqual({ tenantId: T1 });
    expect(t.get("b")).toBeUndefined();
    expect(t.get("__proto__")).toBeUndefined();
    const tmp = join(dir, "t2");
    writeFileSync(tmp, JSON.stringify({ a: { tenantId: T1 }, b: { tenantId: T2 } }));
    renameSync(tmp, f);
    expect(t.get("b")).toEqual({ tenantId: T2 });
    writeFileSync(tmp, "{broken");
    renameSync(tmp, f);
    expect(t.get("a")).toBeUndefined();
    rmSync(dir, { recursive: true, force: true });
  });
});
