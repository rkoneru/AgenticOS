import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CpError } from "../src/index.js";
import { KINDS, eventsOf, makeWorld, type World } from "./world.js";

const code = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "ok";
  } catch (e) {
    return e instanceof CpError ? e.code : `other:${String(e)}`;
  }
};

const pack = (name: string, version: string, extra: Record<string, unknown> = {}) => ({
  apiVersion: "policy.axis.dev/v1",
  kind: "PolicyPack",
  metadata: { name, version },
  spec: {
    defaultDecision: "DENY",
    rules: [
      {
        id: "allow-reads",
        enforcementPoints: ["tool_call"],
        when: { field: "tool.side_effects", op: "eq", value: "read" },
        decision: "ALLOW",
      },
    ],
    ...extra,
  },
});

describe.each(KINDS)("policy pack assignment (%s store)", (kind) => {
  let w: World;
  beforeAll(async () => {
    w = await makeWorld(kind);
  });
  afterAll(() => w.close());

  it("new tenants get baseline-deny installed and active", async () => {
    const t = await w.tenant();
    const list = await w.cp.admin.listPolicies(t.owner);
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ pack: "baseline-deny", version: "1.0.0", active: true });
    const eff = await w.cp.policies.effective(t.tenantId);
    expect(eff.packs).toEqual(["baseline-deny"]);
    expect(eff.rego).toContain("package axis.policy");
  });

  it("publishes only packs that compile; versions are immutable; activation is audited and replaces the old version", async () => {
    const t = await w.tenant();
    expect(await code(w.cp.admin.publishPolicy(t.owner, { nope: true }))).toBe("invalid");
    expect(
      await code(
        w.cp.admin.publishPolicy(
          t.owner,
          pack("custom", "1.0.0", {
            rules: [
              {
                id: "r",
                enforcementPoints: ["tool_call"],
                when: { field: "tool.name", op: "matches", value: "(" },
                decision: "ALLOW",
              },
            ],
          }),
        ),
      ),
    ).toBe("invalid");
    expect(
      await code(
        w.cp.admin.publishPolicy(
          t.owner,
          pack("custom", "1.0.0", {
            rules: [
              {
                id: "r",
                enforcementPoints: ["tool_call"],
                when: { field: "evil.name", op: "eq", value: "x" },
                decision: "ALLOW",
              },
            ],
          }),
        ),
      ),
    ).toBe("invalid");
    const v1 = await w.cp.admin.publishPolicy(t.owner, pack("custom", "1.0.0"));
    expect(v1.active).toBe(false);
    expect(await code(w.cp.admin.publishPolicy(t.owner, pack("custom", "1.0.0")))).toBe("conflict");
    const act = await w.cp.admin.activatePolicy(t.owner, v1.versionId);
    expect(act.policyVersion).toBe("baseline-deny@1.0.0,custom@1.0.0");
    const v2 = await w.cp.admin.publishPolicy(t.owner, pack("custom", "1.1.0"));
    await w.cp.admin.activatePolicy(t.owner, v2.versionId);
    const list = await w.cp.admin.listPolicies(t.owner);
    expect(
      list
        .filter((p) => p.active)
        .map((p) => `${p.pack}@${p.version}`)
        .sort(),
    ).toEqual(["baseline-deny@1.0.0", "custom@1.1.0"]);
    expect((await w.cp.policies.effective(t.tenantId)).policyVersion).toBe(
      "baseline-deny@1.0.0,custom@1.1.0",
    );
    const ev = (await eventsOf(w, t.tenantId)).filter((e) => e.action.startsWith("admin.policies"));
    expect(ev.map((e) => `${e.action}:${e.decision}`)).toEqual(
      expect.arrayContaining([
        "admin.policies.publish:ALLOW",
        "admin.policies.activate:ALLOW",
        "admin.policies.activate.result:ALLOW",
      ]),
    );
  });

  it("refuses to activate a set that does not compile and keeps the previous set in force", async () => {
    const t = await w.tenant();
    // two packs may not define the same pack name twice; craft a pack whose gate reference is unknown at ACTIVATION time only via a stored bad version
    const good = await w.cp.admin.publishPolicy(t.owner, pack("extra", "1.0.0"));
    await w.cp.admin.activatePolicy(t.owner, good.versionId);
    const before = (await w.cp.policies.effective(t.tenantId)).policyVersion;
    // simulate a version that was valid when published but whose set no longer validates (validator changed): use a failing validator
    const { PolicyPackService } = await import("../src/index.js");
    const strict = new PolicyPackService({
      store: w.store,
      validator: (docs) =>
        docs.length > 2
          ? { ok: true, policyVersion: "x", rego: "" }
          : { ok: false, issues: [{ doc: 0, path: "/", code: "X", message: "m" }] },
    });
    const v2 = await w.cp.policies.publish(t.owner, pack("extra", "2.0.0")).catch(() => undefined);
    void v2;
    await expect(strict.activate(t.owner, good.versionId)).rejects.toThrow(/does not validate/);
    expect((await w.cp.policies.effective(t.tenantId)).policyVersion).toBe(before);
  });

  it("the baseline-deny pack cannot be deactivated; other packs can", async () => {
    const t = await w.tenant();
    expect(await code(w.cp.admin.deactivatePolicy(t.owner, "baseline-deny"))).toBe("conflict");
    expect(await code(w.cp.admin.deactivatePolicy(t.owner, "ghost"))).toBe("not_found");
    const v = await w.cp.admin.publishPolicy(t.owner, pack("temp", "1.0.0"));
    await w.cp.admin.activatePolicy(t.owner, v.versionId);
    await w.cp.admin.deactivatePolicy(t.owner, "temp");
    expect((await w.cp.policies.effective(t.tenantId)).packs).toEqual(["baseline-deny"]);
  });

  it("is tenant scoped and role gated", async () => {
    const a = await w.tenant();
    const b = await w.tenant();
    const va = await w.cp.admin.publishPolicy(a.owner, pack("only-a", "1.0.0"));
    expect(await code(w.cp.admin.activatePolicy(b.owner, va.versionId))).toBe("not_found");
    expect((await w.cp.admin.listPolicies(b.owner)).some((p) => p.pack === "only-a")).toBe(false);
    const bld = await w.member(a.tenantId, "builder");
    const v = await w.member(a.tenantId, "viewer");
    expect(await code(w.cp.admin.publishPolicy(bld.principal, pack("by-builder", "1.0.0")))).toBe(
      "ok",
    );
    expect(await code(w.cp.admin.activatePolicy(bld.principal, va.versionId))).toBe("forbidden");
    expect(await code(w.cp.admin.listPolicies(v.principal))).toBe("ok");
    expect(await code(w.cp.admin.publishPolicy(v.principal, pack("by-viewer", "1.0.0")))).toBe(
      "forbidden",
    );
    expect(await code(w.cp.admin.activatePolicy(a.owner, "not-a-uuid"))).toBe("not_found");
  });
});
