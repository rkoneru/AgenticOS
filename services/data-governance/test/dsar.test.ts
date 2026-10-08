import { randomUUID } from "node:crypto";
import { hashJson, verifyChain } from "@axis/contracts";
import { describe, expect, it } from "vitest";
import {
  DAY_MS,
  GovernanceError,
  MemoryGovernanceStore,
  ResidualDataError,
  slaState,
  verifyBundle,
} from "../src/index.js";
import {
  FakeProvider,
  OkVerifier,
  adminOnly,
  email,
  officer,
  rig,
  setupTenant,
  verifiedErase,
} from "./helpers.js";

const eventsOf = async (r: ReturnType<typeof rig>, t: string) => r.audit.read(t, {});

describe("DSAR lifecycle", () => {
  it("requires the privacy_officer role of the same tenant", async () => {
    const r = rig([new FakeProvider("a")]);
    const t = setupTenant(r);
    await expect(
      r.engine.open(adminOnly(t), { kind: "erase", identifiers: [email()] }),
    ).rejects.toMatchObject({ code: "forbidden" });
    await expect(
      r.engine.open({ tenantId: t, id: "x", roles: [] }, { kind: "erase", identifiers: [email()] }),
    ).rejects.toBeInstanceOf(GovernanceError);
    await expect(r.engine.list(adminOnly(t))).rejects.toMatchObject({ code: "forbidden" });
  });

  it("rejects empty and malformed identifiers", async () => {
    const r = rig([new FakeProvider("a")]);
    const t = setupTenant(r);
    await expect(
      r.engine.open(officer(t), { kind: "erase", identifiers: [] }),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(
      r.engine.open(officer(t), { kind: "erase", identifiers: [{ kind: "email", value: "  " }] }),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(
      r.engine.open(officer(t), {
        kind: "erase",
        identifiers: [{ kind: "nope" as never, value: "x" }],
      }),
    ).rejects.toMatchObject({ code: "invalid" });
  });

  it("sets a 30-day deadline and tracks SLA states", async () => {
    const r = rig([new FakeProvider("a")]);
    const t = setupTenant(r);
    const q = await r.engine.open(officer(t), { kind: "export", identifiers: [email()] });
    expect(q.dueAt.getTime() - q.receivedAt.getTime()).toBe(30 * DAY_MS);
    expect(slaState(q, new Date(q.receivedAt.getTime() + 10 * DAY_MS))).toBe("ok");
    expect(slaState(q, new Date(q.receivedAt.getTime() + 24 * DAY_MS))).toBe("at_risk");
    expect(slaState(q, new Date(q.receivedAt.getTime() + 31 * DAY_MS))).toBe("breached");
    expect(
      slaState({ ...q, status: "completed" }, new Date(q.receivedAt.getTime() + 99 * DAY_MS)),
    ).toBe("closed");
  });

  it("sweepSla emits at_risk then breached once each", async () => {
    const r = rig([new FakeProvider("a")]);
    const t = setupTenant(r);
    const q = await r.engine.open(officer(t), { kind: "export", identifiers: [email()] });
    r.clock.now = new Date(q.receivedAt.getTime() + 25 * DAY_MS);
    expect(await r.engine.sweepSla(officer(t))).toEqual([{ id: q.id, state: "at_risk" }]);
    await r.engine.sweepSla(officer(t));
    r.clock.now = new Date(q.receivedAt.getTime() + 31 * DAY_MS);
    await r.engine.sweepSla(officer(t));
    await r.engine.sweepSla(officer(t));
    const actions = (await eventsOf(r, t)).map((e) => e.action);
    expect(actions.filter((a) => a === "dsar.sla.at_risk")).toHaveLength(1);
    expect(actions.filter((a) => a === "dsar.sla.breached")).toHaveLength(1);
  });

  it("extends once, by 60 days, only inside the deadline", async () => {
    const r = rig([new FakeProvider("a")]);
    const t = setupTenant(r);
    const q = await r.engine.open(officer(t), { kind: "export", identifiers: [email()] });
    await expect(r.engine.extend(officer(t), q.id, "x")).rejects.toMatchObject({ code: "invalid" });
    const e = await r.engine.extend(officer(t), q.id, "complex request");
    expect(e.extendedUntil?.getTime()).toBe(q.dueAt.getTime() + 60 * DAY_MS);
    await expect(r.engine.extend(officer(t), q.id, "again please")).rejects.toMatchObject({
      code: "conflict",
    });
    r.clock.now = new Date(q.receivedAt.getTime() + 31 * DAY_MS);
    expect(slaState(e, r.clock.now)).toBe("ok");
    const q2 = await r.engine.open(officer(t), {
      kind: "export",
      identifiers: [email("b@example.org")],
    });
    r.clock.now = new Date(q2.receivedAt.getTime() + 40 * DAY_MS);
    await expect(r.engine.extend(officer(t), q2.id, "too late now")).rejects.toMatchObject({
      code: "invalid",
    });
  });

  it("reject closes the request; closed requests cannot be extended or rejected again", async () => {
    const r = rig([new FakeProvider("a")]);
    const t = setupTenant(r);
    const q = await r.engine.open(officer(t), { kind: "erase", identifiers: [email()] });
    await expect(r.engine.reject(officer(t), q.id, "bogus" as never)).rejects.toMatchObject({
      code: "invalid",
    });
    const x = await r.engine.reject(officer(t), q.id, "manifestly_unfounded");
    expect(x.status).toBe("rejected");
    expect(x.sealedIdentifiers).toBeNull();
    await expect(r.engine.reject(officer(t), q.id, "other")).rejects.toMatchObject({
      code: "invalid",
    });
    await expect(r.engine.extend(officer(t), q.id, "closed one")).rejects.toMatchObject({
      code: "invalid",
    });
  });

  it("a failed verification leaves the request unverified and audits a DENY", async () => {
    const r = rig([new FakeProvider("a")], { verifier: new OkVerifier(false) });
    const t = setupTenant(r);
    const q = await r.engine.open(officer(t), { kind: "erase", identifiers: [email()] });
    const v = await r.engine.verify(officer(t), q.id, {});
    expect(v.status).toBe("received");
    await expect(r.engine.erase(officer(t), q.id)).rejects.toMatchObject({ code: "not_verified" });
    await expect(r.engine.export(officer(t), q.id)).rejects.toMatchObject({ code: "not_verified" });
    expect(
      (await eventsOf(r, t)).find((e) => e.action === "dsar.verification.failed")?.decision,
    ).toBe("DENY");
  });

  it("verify is idempotent", async () => {
    const r = rig([new FakeProvider("a")]);
    const t = setupTenant(r);
    const q = await r.engine.open(officer(t), { kind: "erase", identifiers: [email()] });
    await r.engine.verify(officer(t), q.id, {});
    const again = await r.engine.verify(officer(t), q.id, {});
    expect(again.status).toBe("verified");
    expect(r.verifier.calls).toBe(1);
  });

  it("requests are invisible across tenants", async () => {
    const r = rig([new FakeProvider("a")]);
    const t1 = setupTenant(r);
    const t2 = setupTenant(r);
    const q = await r.engine.open(officer(t1), { kind: "erase", identifiers: [email()] });
    await expect(r.engine.get(officer(t2), q.id)).rejects.toMatchObject({ code: "not_found" });
    await expect(r.engine.erase(officer(t2), q.id)).rejects.toMatchObject({ code: "not_found" });
    expect(await r.engine.list(officer(t2))).toEqual([]);
  });

  it("an identifier shared by two subjects is refused", async () => {
    const r = rig([new FakeProvider("a")]);
    const t = setupTenant(r);
    await r.engine.open(officer(t), { kind: "export", identifiers: [email("a@x.org")] });
    await r.engine.open(officer(t), { kind: "export", identifiers: [email("b@x.org")] });
    await expect(
      r.engine.open(officer(t), {
        kind: "export",
        identifiers: [email("a@x.org"), email("b@x.org")],
      }),
    ).rejects.toMatchObject({ code: "conflict" });
  });

  it("restriction requests place a restriction that isRestricted reports", async () => {
    const r = rig([new FakeProvider("a")]);
    const t = setupTenant(r);
    const q = await r.engine.open(officer(t), { kind: "restrict", identifiers: [email()] });
    await expect(
      r.engine.applyRestriction(officer(t), q.id, "contested accuracy"),
    ).rejects.toMatchObject({ code: "not_verified" });
    await r.engine.verify(officer(t), q.id, {});
    const done = await r.engine.applyRestriction(officer(t), q.id, "contested accuracy");
    expect(done.status).toBe("completed");
    expect(await r.engine.applyRestriction(officer(t), q.id, "contested accuracy")).toMatchObject({
      status: "completed",
    });
    expect(await r.holds.isRestricted(t, [email("JANE.DOE@example.com")])).toBe(true);
    expect(await r.holds.isRestricted(t, [email("other@example.com")])).toBe(false);
    expect(await r.holds.isRestricted(randomUUID(), [email()])).toBe(false);
    const erase = await r.engine.open(officer(t), { kind: "erase", identifiers: [email()] });
    await expect(
      r.engine.applyRestriction(officer(t), erase.id, "no reason"),
    ).rejects.toMatchObject({ code: "invalid" });
  });
});

describe("export", () => {
  it("produces a signed bundle with per-store counts and hashes that verifies offline", async () => {
    const a = new FakeProvider("a");
    const b = new FakeProvider("b", { retainAfter: true });
    const r = rig([a, b]);
    const t = setupTenant(r);
    a.put(t, "jane.doe@example.com", "one");
    a.put(t, "jane.doe@example.com", "two");
    b.put(t, "jane.doe@example.com", "three");
    a.put(t, "someone-else@example.com", "other");
    const p = officer(t);
    const q = await r.engine.open(p, { kind: "export", identifiers: [email()] });
    await expect(r.engine.export(p, q.id)).rejects.toMatchObject({ code: "not_verified" });
    await r.engine.verify(p, q.id, {});
    const bundle = await r.engine.export(p, q.id);
    expect(bundle.manifest.total_records).toBe(3);
    expect(bundle.manifest.stores.map((s) => [s.provider, s.collections[0]?.count])).toEqual([
      ["a", 2],
      ["b", 1],
    ]);
    expect(bundle.manifest.stores[1]?.declaration.retains[0]?.legalBasis).toBe("test");
    expect(JSON.stringify(bundle)).not.toContain("other");
    expect(verifyBundle(bundle, r.signer.publicKey)).toEqual({ ok: true });
    // tampering is detected: record, count, manifest
    const rec = structuredClone(bundle);
    (rec.records["a"]?.["rows"]?.[0] as { payload: string }).payload = "edited";
    expect(verifyBundle(rec, r.signer.publicKey)).toMatchObject({ ok: false });
    const man = structuredClone(bundle);
    man.manifest.total_records = 99;
    expect(verifyBundle(man, r.signer.publicKey)).toEqual({ ok: false, reason: "signature" });
    const cnt = structuredClone(bundle);
    cnt.records["a"]?.["rows"]?.pop();
    expect(verifyBundle(cnt, r.signer.publicKey)).toMatchObject({ ok: false });
    const wrongKey = rig([]).signer.publicKey;
    expect(verifyBundle(bundle, wrongKey)).toMatchObject({ ok: false });
    expect((await r.engine.get(p, q.id)).status).toBe("completed");
    expect((await eventsOf(r, t)).some((e) => e.action === "dsar.export.completed")).toBe(true);
  });

  it("detects count/total/hash inconsistencies with a validly signed manifest", async () => {
    const a = new FakeProvider("a");
    const r = rig([a]);
    const t = setupTenant(r);
    a.put(t, "jane.doe@example.com");
    const p = officer(t);
    const q = await r.engine.open(p, { kind: "export", identifiers: [email()] });
    await r.engine.verify(p, q.id, {});
    const b = await r.engine.export(p, q.id);
    const resign = (m: typeof b.manifest) => ({ ...b, manifest: m, signature: r.signer.sign(m) });
    expect(verifyBundle(resign({ ...b.manifest, total_records: 5 }), r.signer.publicKey)).toEqual({
      ok: false,
      reason: "total",
    });
    const bad = structuredClone(b.manifest);
    (bad.stores[0] as { collections: { sha256: string }[] }).collections[0]!.sha256 = "0".repeat(
      64,
    );
    expect(verifyBundle(resign(bad), r.signer.publicKey)).toMatchObject({
      ok: false,
      reason: "hash:a.rows",
    });
    expect(
      verifyBundle(resign({ ...b.manifest, records_sha256: "f".repeat(64) }), r.signer.publicKey),
    ).toEqual({ ok: false, reason: "records_sha256" });
  });

  it("refuses a destination outside the tenant's regions and audits the denial", async () => {
    const r = rig([new FakeProvider("a")]);
    const t = setupTenant(r, randomUUID(), "eu-west-1");
    const p = officer(t);
    const q = await r.engine.open(p, {
      kind: "export",
      identifiers: [email()],
      destinationRegion: "us-east-1",
    });
    await r.engine.verify(p, q.id, {});
    await expect(r.engine.export(p, q.id)).rejects.toMatchObject({ code: "residency" });
    expect((await eventsOf(r, t)).find((e) => e.action === "dsar.export.refused")?.decision).toBe(
      "DENY",
    );
    const ok = await r.engine.open(p, {
      kind: "export",
      identifiers: [email("z@x.org")],
      destinationRegion: "eu-west-1",
    });
    await r.engine.verify(p, ok.id, {});
    await expect(r.engine.export(p, ok.id)).resolves.toBeTruthy();
    // no destination -> service region (eu-west-1) is used; unknown tenant -> refused
    const t2 = randomUUID();
    await expect(
      r.engine
        .open(officer(t2), { kind: "export", identifiers: [email()] })
        .then((x) =>
          r.engine.verify(officer(t2), x.id, {}).then(() => r.engine.export(officer(t2), x.id)),
        ),
    ).rejects.toMatchObject({ code: "residency" });
  });

  it("includes identifiers discovered by other stores (closure)", async () => {
    const a = new FakeProvider("a", { discover: [{ kind: "end_user_id", value: "eu-123" }] });
    const b = new FakeProvider("b");
    const r = rig([a, b]);
    const t = setupTenant(r);
    b.put(t, "eu-123", "linked-row");
    const p = officer(t);
    const q = await r.engine.open(p, { kind: "export", identifiers: [email()] });
    await r.engine.verify(p, q.id, {});
    const bundle = await r.engine.export(p, q.id);
    expect(bundle.manifest.total_records).toBe(1);
  });
});

describe("erase", () => {
  it("erases everywhere, verifies zero residual, shreds the subject and completes", async () => {
    const a = new FakeProvider("a");
    const b = new FakeProvider("b");
    const r = rig([a, b]);
    const t = setupTenant(r);
    a.put(t, "jane.doe@example.com");
    b.put(t, "jane.doe@example.com");
    b.put(t, "bob@example.com");
    const id = await verifiedErase(r, t, [email()]);
    const out = await r.engine.erase(officer(t), id);
    expect(out.status).toBe("completed");
    expect(a.all(t)).toHaveLength(0);
    expect(b.all(t).map((x) => x.owner)).toEqual(["bob@example.com"]);
    expect(out.request.sealedIdentifiers).toBeNull();
    expect(out.request.result["verification"]).toMatchObject({ ok: true });
    const req = await r.store.getRequest(t, id);
    const subj = await r.store.getSubject(t, req!.subjectId);
    expect(subj?.salt).toBeNull();
    expect(subj?.shreddedAt).not.toBeNull();
    // the identifier no longer resolves to the old subject: a new request gets a NEW subject
    const again = await r.engine.open(officer(t), { kind: "export", identifiers: [email()] });
    expect(again.subjectId).not.toBe(req!.subjectId);
    expect(again.subjectRef).not.toBe(req!.subjectRef);
  });

  it("is idempotent: a second erase returns the stored outcome without touching providers", async () => {
    const a = new FakeProvider("a");
    const r = rig([a]);
    const t = setupTenant(r);
    a.put(t, "jane.doe@example.com");
    const id = await verifiedErase(r, t, [email()]);
    const first = await r.engine.erase(officer(t), id);
    const calls = a.erasedCalls;
    const second = await r.engine.erase(officer(t), id);
    expect(second.status).toBe("completed");
    expect(second.request.result).toEqual(first.request.result);
    expect(a.erasedCalls).toBe(calls);
  });

  it("FAILS the verification pass when a store keeps data, and keeps the request open", async () => {
    const a = new FakeProvider("a");
    const r = rig([a]);
    const t = setupTenant(r);
    a.put(t, "jane.doe@example.com", "x", { sticky: true });
    const id = await verifiedErase(r, t, [email()]);
    await expect(r.engine.erase(officer(t), id)).rejects.toBeInstanceOf(ResidualDataError);
    const req = await r.store.getRequest(t, id);
    expect(req?.status).toBe("processing");
    expect(req?.sealedIdentifiers).not.toBeNull();
    expect((await r.store.getSubject(t, req!.subjectId))?.salt).not.toBeNull(); // NOT shredded
    expect(
      (await eventsOf(r, t)).some(
        (e) => e.action === "dsar.erase.verification_failed" && e.decision === "DENY",
      ),
    ).toBe(true);
    expect((await eventsOf(r, t)).some((e) => e.action === "dsar.erase.completed")).toBe(false);
    // the leak is fixed -> resume completes
    a.all(t)[0]!.sticky = false;
    expect((await r.engine.erase(officer(t), id)).status).toBe("completed");
  });

  it("counts retained rows without treating them as residual", async () => {
    const p = new FakeProvider("ledger", { retainAfter: true });
    p.count = async () => ({ residual: 0, retained: 3, pseudonymised: 3 });
    const r = rig([p]);
    const t = setupTenant(r);
    const id = await verifiedErase(r, t, [email()]);
    const out = await r.engine.erase(officer(t), id);
    expect(out.request.result["verification"]).toMatchObject({
      ok: true,
      providers: [{ provider: "ledger", retained: 3, residual: 0 }],
    });
  });

  it("only the named tenant is touched", async () => {
    const a = new FakeProvider("a");
    const r = rig([a]);
    const t1 = setupTenant(r);
    const t2 = setupTenant(r);
    a.put(t1, "jane.doe@example.com");
    a.put(t2, "jane.doe@example.com");
    const id = await verifiedErase(r, t1, [email()]);
    await r.engine.erase(officer(t1), id);
    expect(a.all(t1)).toHaveLength(0);
    expect(a.all(t2)).toHaveLength(1);
  });

  it("never writes raw identifiers into the audit chain, and the chain verifies", async () => {
    const a = new FakeProvider("a", {
      discover: [{ kind: "end_user_id", value: "enduser-secret-77" }],
    });
    const r = rig([a]);
    const t = setupTenant(r);
    a.put(t, "jane.doe@example.com");
    const p = officer(t);
    const q = await r.engine.open(p, {
      kind: "erase",
      identifiers: [email(), { kind: "phone", value: "+1 (555) 010-9999" }],
    });
    await r.engine.verify(p, q.id, {});
    await r.engine.erase(p, q.id);
    await r.holds.placeHold(p, { scope: "subject", reason: "litigation", groups: [[email()]] });
    const events = await eventsOf(r, t);
    expect(events.length).toBeGreaterThan(4);
    const dump = JSON.stringify(events).toLowerCase();
    for (const raw of ["jane", "example.com", "5550109999", "enduser-secret-77"])
      expect(dump).not.toContain(raw);
    expect(verifyChain(events)).toEqual({ ok: true, length: events.length });
    expect(events[0]?.inputs_hash).toBe(
      hashJson({ request_id: q.id, kind: "erase", subject_ref: q.subjectRef }),
    );
  });

  it("refuses to write an audit event that contains a raw identifier and fails closed", async () => {
    const r = rig([new FakeProvider("a")]);
    const t = setupTenant(r);
    const { GovernanceAudit } = await import("../src/index.js");
    const ga = new GovernanceAudit(r.audit);
    await expect(
      ga.emit({
        tenantId: t,
        action: "x.y",
        actorId: "o",
        reason: "for jane.doe@example.com",
        input: {},
        raw: ["jane.doe@example.com"],
      }),
    ).rejects.toMatchObject({ code: "invalid" });
    const broken = new GovernanceAudit({
      append: async () => {
        throw new Error("db down");
      },
    });
    await expect(
      broken.emit({ tenantId: t, action: "x.y", actorId: "o", input: {} }),
    ).rejects.toMatchObject({ code: "unavailable" });
  });

  it("does not mutate when the audit append fails", async () => {
    const a = new FakeProvider("a");
    const r = rig([a]);
    const t = setupTenant(r);
    a.put(t, "jane.doe@example.com");
    const id = await verifiedErase(r, t, [email()]);
    const orig = r.audit.append.bind(r.audit);
    r.audit.append = async () => {
      throw new Error("audit down");
    };
    await expect(r.engine.erase(officer(t), id)).rejects.toMatchObject({ code: "unavailable" });
    expect(a.all(t)).toHaveLength(1);
    r.audit.append = orig;
    expect((await r.engine.erase(officer(t), id)).status).toBe("completed");
  });

  it("a non-erase request cannot be erased; rejected requests cannot proceed", async () => {
    const r = rig([new FakeProvider("a")]);
    const t = setupTenant(r);
    const x = await r.engine.open(officer(t), { kind: "export", identifiers: [email()] });
    await r.engine.verify(officer(t), x.id, {});
    await expect(r.engine.erase(officer(t), x.id)).rejects.toMatchObject({ code: "invalid" });
    const e = await r.engine.open(officer(t), { kind: "erase", identifiers: [email("q@x.org")] });
    await r.engine.reject(officer(t), e.id, "other");
    await expect(r.engine.erase(officer(t), e.id)).rejects.toMatchObject({ code: "invalid" });
    await expect(r.engine.export(officer(t), e.id)).rejects.toMatchObject({ code: "invalid" });
  });

  it("newly discovered identifiers are attached to the subject and sealed for resume", async () => {
    const a = new FakeProvider("a", { discover: [{ kind: "end_user_id", value: "eu-9" }] });
    const b = new FakeProvider("b");
    const r = rig([a, b]);
    const t = setupTenant(r);
    b.put(t, "eu-9");
    const id = await verifiedErase(r, t, [email()]);
    await r.engine.erase(officer(t), id);
    expect(b.all(t)).toHaveLength(0);
  });
});

describe("legal hold interplay", () => {
  it("a tenant-wide hold on a class suspends erasure of providers in that class; releasing resumes", async () => {
    const mem = new FakeProvider("mem", { classes: ["memory"] });
    const conv = new FakeProvider("conv", { classes: ["conversation"] });
    const r = rig([mem, conv]);
    const t = setupTenant(r);
    mem.put(t, "jane.doe@example.com");
    conv.put(t, "jane.doe@example.com");
    const p = officer(t);
    const hold = await r.holds.placeHold(p, {
      scope: "tenant",
      reason: "litigation 42",
      dataClasses: ["memory"],
    });
    const id = await verifiedErase(r, t, [email()]);
    const out = await r.engine.erase(p, id);
    expect(out.status).toBe("held");
    expect(mem.all(t)).toHaveLength(1);
    expect(conv.all(t)).toHaveLength(0);
    expect(out.request.status).toBe("processing");
    expect((await r.store.getSubject(t, out.request.subjectId))?.salt).not.toBeNull();
    await r.holds.release(p, hold.id);
    const done = await r.engine.erase(p, id);
    expect(done.status).toBe("completed");
    expect(mem.all(t)).toHaveLength(0);
  });

  it("a subject hold blocks only that subject; a case hold names its subjects", async () => {
    const mem = new FakeProvider("mem", { classes: ["memory"] });
    const r = rig([mem]);
    const t = setupTenant(r);
    const p = officer(t);
    mem.put(t, "jane.doe@example.com");
    mem.put(t, "bob@example.com");
    await r.holds.placeHold(p, {
      scope: "subject",
      reason: "dispute",
      groups: [[email("bob@example.com")]],
    });
    const janeId = await verifiedErase(r, t, [email()]);
    expect((await r.engine.erase(p, janeId)).status).toBe("completed");
    const bobId = await verifiedErase(r, t, [email("bob@example.com")]);
    expect((await r.engine.erase(p, bobId)).status).toBe("held");
    expect(mem.all(t)).toHaveLength(1);
    // case hold with a group
    const carol = email("carol@example.com");
    mem.put(t, "carol@example.com");
    await r.holds.placeHold(p, {
      scope: "case",
      caseRef: "CASE-9",
      reason: "regulator inquiry",
      groups: [[carol]],
      dataClasses: ["memory"],
    });
    expect((await r.engine.erase(p, await verifiedErase(r, t, [carol]))).status).toBe("held");
    // a case hold with no groups is class-wide
    await r.holds.placeHold(p, {
      scope: "case",
      caseRef: "CASE-10",
      reason: "class freeze",
      dataClasses: ["memory"],
    });
    mem.put(t, "dave@example.com");
    expect(
      (await r.engine.erase(p, await verifiedErase(r, t, [email("dave@example.com")]))).status,
    ).toBe("held");
  });
});

describe("hold registry validation", () => {
  it("validates input and is officer-gated", async () => {
    const r = rig([new FakeProvider("a")]);
    const t = setupTenant(r);
    const p = officer(t);
    await expect(
      r.holds.placeHold(adminOnly(t), { scope: "tenant", reason: "valid reason" }),
    ).rejects.toMatchObject({ code: "forbidden" });
    await expect(r.holds.placeHold(p, { scope: "tenant", reason: "x" })).rejects.toMatchObject({
      code: "invalid",
    });
    await expect(
      r.holds.placeHold(p, {
        scope: "tenant",
        reason: "valid reason",
        dataClasses: ["nope" as never],
      }),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(
      r.holds.placeHold(p, { scope: "subject", reason: "valid reason" }),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(
      r.holds.placeHold(p, { scope: "tenant", reason: "valid reason", groups: [[email()]] }),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(
      r.holds.placeHold(p, { scope: "case", reason: "valid reason" }),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(
      r.holds.placeHold(p, { scope: "tenant", reason: "valid reason".repeat(80) }),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(r.holds.restrict(p, [email()], "ok reason")).resolves.toMatchObject({
      kind: "restriction",
    });
    await expect(r.holds.release(p, randomUUID())).rejects.toMatchObject({ code: "not_found" });
    const h = await r.holds.placeHold(p, { scope: "tenant", reason: "valid reason" });
    expect(await r.holds.list(p)).toHaveLength(2);
    const rel = await r.holds.release(p, h.id);
    expect(rel.releasedAt).not.toBeNull();
    expect((await r.holds.release(p, h.id)).releasedAt).toEqual(rel.releasedAt);
    expect(await r.holds.list(p)).toHaveLength(1);
    expect(await r.holds.list(p, false)).toHaveLength(2);
    await expect(r.holds.list(adminOnly(t))).rejects.toMatchObject({ code: "forbidden" });
  });
});

describe("memory store behaviour", () => {
  it("rejects duplicate request ids and stale revisions", async () => {
    const s = new MemoryGovernanceStore();
    const r = rig([new FakeProvider("a")], { store: s });
    const t = setupTenant(r);
    const q = await r.engine.open(officer(t), { kind: "export", identifiers: [email()] });
    await expect(s.insertRequest(q)).rejects.toMatchObject({ code: "conflict" });
    await s.updateRequest({ ...q, status: "verified" }, q.rev);
    await expect(s.updateRequest({ ...q, status: "verified" }, q.rev)).rejects.toMatchObject({
      code: "conflict",
    });
    await expect(s.updateRequest({ ...q, id: randomUUID() }, 1)).rejects.toMatchObject({
      code: "not_found",
    });
    await expect(s.addLookups(t, randomUUID(), [])).rejects.toMatchObject({ code: "not_found" });
    await expect(s.releaseHold(t, randomUUID(), "o", new Date())).rejects.toMatchObject({
      code: "not_found",
    });
  });
});
