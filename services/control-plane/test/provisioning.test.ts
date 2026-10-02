import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CpError, Provisioner, AdminAudit } from "../src/index.js";
import { KINDS, eventsOf, makeWorld, cachedValidator, type World } from "./world.js";

const code = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "ok";
  } catch (e) {
    return e instanceof CpError ? e.code : `other:${String(e)}`;
  }
};

describe.each(KINDS)("signup / provisioning (%s store)", (kind) => {
  let w: World;
  beforeAll(async () => {
    w = await makeWorld(kind);
  });
  afterAll(() => w.close());

  it("creates tenant, owner, baseline policy, default budgets, settings, placement and the genesis audit event", async () => {
    const r = await w.cp.provisioner.signup({ slug: `acme-${kind}`, name: "Acme", ownerEmail: "Boss@Acme.test", region: "us-east-1", phiMode: true });
    expect(await w.store.getTenant(r.tenantId)).toMatchObject({ slug: `acme-${kind}`, region: "us-east-1", phiMode: true, status: "active" });
    expect(await w.store.getMember(r.tenantId, r.ownerMemberId)).toMatchObject({ role: "owner", email: "boss@acme.test", status: "active" });
    expect((await w.store.listBudgets(r.tenantId)).length).toBe(4);
    expect(await w.store.getSettings(r.tenantId)).toMatchObject({ retentionAuditDays: 2555, retentionTranscriptDays: 30, retentionMemoryDays: 365 });
    expect(await w.store.getPlacement(r.tenantId)).toMatchObject({ isolationTier: "shared_rls" });
    expect(r.policyVersion).toBe("baseline-deny@1.0.0");
    const ev = await eventsOf(w, r.tenantId);
    expect(ev[0]).toMatchObject({ seq: 1, action: "tenant.provision", decision: "ALLOW", enforcement_point: "admin" });
    expect((await w.store.listActiveAssignments(r.tenantId)).length).toBe(1);
  });

  it("refuses duplicate slugs without leaving partial state, bad input, unknown and foreign regions", async () => {
    const slug = `dup-${kind}`;
    await w.cp.provisioner.signup({ slug, name: "A", ownerEmail: "a@a.test", region: "us-east-1" });
    expect(await code(w.cp.provisioner.signup({ slug, name: "B", ownerEmail: "b@b.test", region: "us-east-1" }))).toBe("conflict");
    expect(await code(w.cp.provisioner.signup({ slug: "Bad Slug", name: "B", ownerEmail: "b@b.test", region: "us-east-1" }))).toBe("invalid");
    expect(await code(w.cp.provisioner.signup({ slug: "ok-slug", name: "", ownerEmail: "b@b.test", region: "us-east-1" }))).toBe("invalid");
    expect(await code(w.cp.provisioner.signup({ slug: "ok-slug", name: "B", ownerEmail: "nope", region: "us-east-1" }))).toBe("invalid");
    expect(await code(w.cp.provisioner.signup({ slug: "ok-slug", name: "B", ownerEmail: "b@b.test", region: "mars-1" }))).toBe("invalid");
    expect(await code(w.cp.provisioner.signup({ slug: "eu-slug", name: "B", ownerEmail: "b@b.test", region: "eu-west-1" }))).toBe("region_mismatch");
  });

  it("fails closed if the baseline pack is missing or the default packs do not validate", async () => {
    const audit = new AdminAudit(w.auditStore);
    const base = { store: w.store, audit, region: "us-east-1", regions: ["us-east-1"] };
    const nobase = new Provisioner({ ...base, defaultPacks: [{ apiVersion: "policy.axis.dev/v1", kind: "PolicyPack", metadata: { name: "other", version: "1.0.0" }, spec: { defaultDecision: "DENY", rules: [{ id: "r", enforcementPoints: ["tool_call"], decision: "DENY" }] } }], validator: cachedValidator });
    expect(await code(nobase.signup({ slug: `nb-${kind}`, name: "x", ownerEmail: "a@a.test", region: "us-east-1" }))).toBe("unavailable");
    const bad = new Provisioner({ ...base, defaultPacks: [{ broken: true }], validator: cachedValidator });
    expect(await code(bad.signup({ slug: `bd-${kind}`, name: "x", ownerEmail: "a@a.test", region: "us-east-1" }))).toBe("unavailable");
    expect(await code(new Provisioner({ ...base, validator: (d) => (d.length ? { ok: true, policyVersion: "x", rego: "" } : { ok: false, issues: [] }), defaultPacks: [] }).signup({ slug: `e-${kind}`, name: "x", ownerEmail: "a@a.test", region: "us-east-1" }))).toBe("unavailable");
  });
});
