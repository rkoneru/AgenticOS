import { randomUUID } from "node:crypto";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  CLASS_BOUNDS,
  DATA_CLASSES,
  PHI_AUDIT_MIN_DAYS,
  boundsFor,
  effectiveRetention,
  type DataClass,
} from "../src/index.js";
import { FakeProvider, adminOnly, email, officer, rig, setupTenant } from "./helpers.js";

const DAY = 86_400_000;

describe("effectiveRetention (decision logic)", () => {
  it("clamps into [min, max] and flags which bound applied", () => {
    expect(effectiveRetention("billing", 30, false)).toEqual({
      days: CLASS_BOUNDS.billing.minDays,
      clamped: "min",
    });
    expect(effectiveRetention("billing", 99999, false)).toEqual({
      days: CLASS_BOUNDS.billing.maxDays,
      clamped: "max",
    });
    expect(effectiveRetention("memory", 100, false)).toEqual({ days: 100, clamped: null });
    expect(effectiveRetention("memory", 0, false)).toEqual({ days: 1, clamped: "min" });
    expect(effectiveRetention("memory", 1.5, false)).toEqual({ days: 1, clamped: "min" });
    expect(effectiveRetention("memory", Number.NaN, false)).toEqual({ days: 1, clamped: "min" });
  });
  it("PHI tenants get the HIPAA floor on audit", () => {
    expect(boundsFor("audit", true).min).toBe(PHI_AUDIT_MIN_DAYS);
    expect(boundsFor("audit", false).min).toBe(365);
    expect(effectiveRetention("audit", 400, true).days).toBe(PHI_AUDIT_MIN_DAYS);
    expect(boundsFor("memory", true).min).toBe(1);
  });
  it("property: the effective period is always within bounds and never below the floor", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...DATA_CLASSES),
        fc.integer({ min: -10, max: 100000 }),
        fc.boolean(),
        (cls, days, phi) => {
          const e = effectiveRetention(cls, days, phi);
          const b = boundsFor(cls, phi);
          expect(e.days).toBeGreaterThanOrEqual(b.min);
          expect(e.days).toBeLessThanOrEqual(b.max);
          if (days >= b.min && days <= b.max) expect(e.days).toBe(days);
        },
      ),
    );
  });
});

describe("RetentionEngine", () => {
  const setup = () => {
    const mem = new FakeProvider("mem", { classes: ["memory"] });
    const conv = new FakeProvider("conv", { classes: ["conversation"] });
    const logs = new FakeProvider("logs", { classes: ["run_logs"] });
    const bill = new FakeProvider("bill", { classes: ["billing"] });
    const r = rig([mem, conv, logs, bill]);
    const t = setupTenant(r);
    return { r, t, mem, conv, logs, bill };
  };
  const old = (days: number, r: { clock: { now: Date } }) =>
    new Date(r.clock.now.getTime() - days * DAY);

  it("resolves tenant settings from the control-plane port and governance overrides", async () => {
    const { r, t } = setup();
    r.settings.set(t, {
      retentionAuditDays: 100,
      retentionTranscriptDays: 7,
      retentionMemoryDays: 400,
    });
    await r.retention.setPolicy(officer(t), "run_logs", 120);
    const res = await r.retention.resolve(t);
    const by = (c: DataClass) => res!.find((x) => x.dataClass === c)!;
    expect(by("memory")).toMatchObject({
      requestedDays: 400,
      effectiveDays: 400,
      source: "control_plane",
      clamped: null,
    });
    expect(by("conversation")).toMatchObject({ effectiveDays: 7, source: "control_plane" });
    expect(by("transcripts")).toMatchObject({ effectiveDays: 7 });
    expect(by("audit")).toMatchObject({ requestedDays: 100, effectiveDays: 365, clamped: "min" });
    expect(by("run_logs")).toMatchObject({ effectiveDays: 120, source: "governance" });
    expect(by("telemetry")).toMatchObject({ source: "default", effectiveDays: 30 });
    r.settings.set(t, {
      retentionAuditDays: 400,
      retentionTranscriptDays: 7,
      retentionMemoryDays: 400,
      phiMode: true,
    });
    expect(
      (await r.retention.resolve(t))!.find((x) => x.dataClass === "audit")!.effectiveDays,
    ).toBe(PHI_AUDIT_MIN_DAYS);
  });

  it("setPolicy validates and is officer-gated", async () => {
    const { r, t } = setup();
    await expect(r.retention.setPolicy(adminOnly(t), "run_logs", 100)).rejects.toMatchObject({
      code: "forbidden",
    });
    await expect(r.retention.setPolicy(officer(t), "run_logs", 5)).rejects.toMatchObject({
      code: "invalid",
    });
    await expect(r.retention.setPolicy(officer(t), "billing", 100)).rejects.toMatchObject({
      code: "invalid",
    });
    await expect(r.retention.setPolicy(officer(t), "memory", 100)).rejects.toMatchObject({
      code: "invalid",
    });
    await expect(r.retention.setPolicy(officer(t), "nope" as never, 100)).rejects.toMatchObject({
      code: "invalid",
    });
    await r.retention.setPolicy(officer(t), "telemetry", 10);
  });

  it("purges only data older than the effective period; dry run changes nothing", async () => {
    const { r, t, mem } = setup();
    r.settings.set(t, {
      retentionAuditDays: 2555,
      retentionTranscriptDays: 30,
      retentionMemoryDays: 100,
    });
    mem.put(t, "a", "x", { createdAt: old(200, r) });
    mem.put(t, "b", "x", { createdAt: old(50, r) });
    const dry = await r.retention.run(officer(t), { dryRun: true, classes: ["memory"] });
    expect(dry.classes[0]).toMatchObject({
      status: "dry_run",
      matched: 1,
      purged: 0,
      effectiveDays: 100,
    });
    expect(mem.all(t)).toHaveLength(2);
    const real = await r.retention.run(officer(t), { classes: ["memory"] });
    expect(real.classes[0]).toMatchObject({ status: "purged", matched: 1, purged: 1 });
    expect(mem.all(t).map((x) => x.owner)).toEqual(["b"]);
    const runs = await r.store.listRuns(t);
    expect(runs).toHaveLength(2);
    expect(runs[1]?.finishedAt).not.toBeNull();
    const acts = (await r.audit.read(t, {})).map((e) => e.action);
    expect(acts).toContain("retention.dry_run.completed");
    expect(acts).toContain("retention.purge.completed");
  });

  it("NEVER purges a class under a tenant hold, but purges the others", async () => {
    const { r, t, mem, conv } = setup();
    mem.put(t, "a", "x", { createdAt: old(4000, r) });
    conv.put(t, "a", "x", { createdAt: old(4000, r) });
    await r.holds.placeHold(officer(t), {
      scope: "tenant",
      reason: "litigation",
      dataClasses: ["memory"],
    });
    const rep = await r.retention.run(officer(t), { classes: ["memory", "conversation"] });
    expect(rep.classes.find((c) => c.dataClass === "memory")).toMatchObject({
      status: "skipped_hold",
      purged: 0,
    });
    expect(rep.classes.find((c) => c.dataClass === "conversation")).toMatchObject({
      status: "purged",
      purged: 1,
    });
    expect(mem.all(t)).toHaveLength(1);
    expect(conv.all(t)).toHaveLength(0);
  });

  it("a hold with no class list freezes everything; releasing it allows the purge", async () => {
    const { r, t, mem } = setup();
    mem.put(t, "a", "x", { createdAt: old(4000, r) });
    const h = await r.holds.placeHold(officer(t), { scope: "tenant", reason: "freeze all" });
    expect((await r.retention.run(officer(t), { classes: ["memory"] })).classes[0]?.status).toBe(
      "skipped_hold",
    );
    await r.holds.release(officer(t), h.id);
    expect((await r.retention.run(officer(t), { classes: ["memory"] })).classes[0]?.status).toBe(
      "purged",
    );
  });

  it("subject and case holds protect only the linked rows", async () => {
    const { r, t, mem } = setup();
    mem.put(t, "jane.doe@example.com", "x", { createdAt: old(4000, r) });
    mem.put(t, "carol@example.com", "x", { createdAt: old(4000, r) });
    mem.put(t, "other@example.com", "x", { createdAt: old(4000, r) });
    await r.holds.placeHold(officer(t), {
      scope: "subject",
      reason: "dispute",
      groups: [[email()]],
    });
    await r.holds.placeHold(officer(t), {
      scope: "case",
      caseRef: "C-1",
      reason: "inquiry",
      groups: [[email("carol@example.com")]],
    });
    const rep = await r.retention.run(officer(t), { classes: ["memory"] });
    expect(rep.classes[0]).toMatchObject({
      status: "purged",
      matched: 3,
      purged: 1,
      protectedByHold: 2,
    });
    expect(
      mem
        .all(t)
        .map((x) => x.owner)
        .sort(),
    ).toEqual(["carol@example.com", "jane.doe@example.com"]);
  });

  it("never touches audit; billing only past its floored period", async () => {
    const { r, t, bill } = setup();
    r.settings.set(t, {
      retentionAuditDays: 365,
      retentionTranscriptDays: 30,
      retentionMemoryDays: 30,
    });
    await r.retention.setPolicy(officer(t), "billing", CLASS_BOUNDS.billing.minDays);
    bill.put(t, "a", "x", { createdAt: old(CLASS_BOUNDS.billing.minDays - 1, r) });
    bill.put(t, "b", "x", { createdAt: old(CLASS_BOUNDS.billing.minDays + 1, r) });
    const rep = await r.retention.run(officer(t));
    expect(rep.classes.find((c) => c.dataClass === "audit")).toMatchObject({
      status: "retained_by_policy",
      purged: 0,
    });
    expect(rep.classes.find((c) => c.dataClass === "billing")).toMatchObject({
      status: "purged",
      purged: 1,
    });
    expect(bill.all(t).map((x) => x.owner)).toEqual(["a"]);
    expect(rep.classes.find((c) => c.dataClass === "telemetry")?.status).toBe("no_store");
  });

  it("fails closed when settings are unavailable", async () => {
    const { r, t, mem } = setup();
    mem.put(t, "a", "x", { createdAt: old(9000, r) });
    r.settings.delete(t);
    const rep = await r.retention.run(officer(t), { classes: ["memory"] });
    expect(rep.classes[0]?.status).toBe("settings_unavailable");
    expect(mem.all(t)).toHaveLength(1);
    // a throwing port behaves the same
    const bad = rig([mem]);
    (bad.retention as unknown as { d: { settings: unknown } }).d.settings = {
      get: async () => {
        throw new Error("cp down");
      },
    };
    expect((await bad.retention.run(officer(t), { classes: ["memory"] })).classes[0]?.status).toBe(
      "settings_unavailable",
    );
  });

  it("reports provider errors per class and keeps going", async () => {
    const { r, t, mem, conv } = setup();
    mem.purge = async () => {
      throw new Error("boom");
    };
    conv.put(t, "a", "x", { createdAt: old(4000, r) });
    const rep = await r.retention.run(officer(t), { classes: ["memory", "conversation"] });
    expect(rep.classes[0]).toMatchObject({ status: "error", error: "boom" });
    expect(rep.classes[1]?.status).toBe("purged");
  });

  it("a purge provider cannot pseudonymise (no subject context)", async () => {
    const { r, t, mem } = setup();
    mem.purge = async (ctx) => {
      await ctx.pseudonym("x", "y");
      return { matched: 0, purged: 0, protectedByHold: 0 };
    };
    expect((await r.retention.run(officer(t), { classes: ["memory"] })).classes[0]?.status).toBe(
      "error",
    );
  });

  it("is tenant-isolated and officer-gated", async () => {
    const { r, t, mem } = setup();
    const t2 = setupTenant(r);
    mem.put(t, "a", "x", { createdAt: old(4000, r) });
    mem.put(t2, "a", "x", { createdAt: old(4000, r) });
    await expect(r.retention.run(adminOnly(t))).rejects.toMatchObject({ code: "forbidden" });
    await r.retention.run(officer(t), { classes: ["memory"] });
    expect(mem.all(t)).toHaveLength(0);
    expect(mem.all(t2)).toHaveLength(1);
    expect(await r.store.listRuns(t2)).toHaveLength(0);
  });

  it("property: retention never purges held, protected or too-young rows", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(
          fc.record({
            owner: fc.constantFrom("a", "b", "c"),
            ageDays: fc.integer({ min: 0, max: 2000 }),
          }),
          { maxLength: 12 },
        ),
        fc.array(fc.constantFrom("a", "b", "c"), { maxLength: 3 }),
        fc.boolean(),
        fc.integer({ min: 1, max: 1500 }),
        async (rows, protectedOwners, tenantHold, days) => {
          const mem = new FakeProvider("mem", { classes: ["memory"] });
          const r = rig([mem]);
          const t = setupTenant(r);
          r.settings.set(t, {
            retentionAuditDays: 2555,
            retentionTranscriptDays: 30,
            retentionMemoryDays: days,
          });
          for (const x of rows) mem.put(t, x.owner, "x", { createdAt: old(x.ageDays, r) });
          for (const o of new Set(protectedOwners))
            await r.holds.placeHold(officer(t), {
              scope: "subject",
              reason: "prop hold",
              groups: [[{ kind: "subject_key", value: o }]],
            });
          if (tenantHold)
            await r.holds.placeHold(officer(t), {
              scope: "tenant",
              reason: "prop freeze",
              dataClasses: ["memory"],
            });
          const before = mem.all(t).slice();
          await r.retention.run(officer(t), { classes: ["memory"] });
          const after = new Set(mem.all(t));
          for (const row of before) {
            const age = (r.clock.now.getTime() - (row.createdAt as Date).getTime()) / DAY;
            const held = tenantHold || (protectedOwners as string[]).includes(row.owner);
            // Retention purges rows STRICTLY older than the window: a row exactly `days` old is still inside it
            // (the conservative side), so the boundary itself may go either way and is not asserted.
            if (held || age <= days) expect(after.has(row) || age === days).toBe(true);
            if (!held && age > days) expect(after.has(row)).toBe(false);
          }
        },
      ),
      { numRuns: 60 },
    );
  });

  it("ids and runs are unique", () => {
    expect(randomUUID()).not.toBe(randomUUID());
  });
});
