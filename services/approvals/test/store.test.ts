import { describe, expect, it } from "vitest";
import {
  MemoryApprovalStore,
  signRecord,
  isApprovalValidFor,
  type ApprovalRequest,
} from "../src/index.js";
import { HASH, T1, T2, input, principal, setup } from "./helpers.js";

async function made(over = {}) {
  const s = setup();
  const r = await s.svc.create(input(over));
  return { ...s, r };
}

describe("MemoryApprovalStore tenant scoping", () => {
  it("get / list / idempotency lookup never cross tenants, even for the same id or key", async () => {
    const store = new MemoryApprovalStore();
    const s = setup({ store });
    const a = await s.svc.create(input({ idempotency_key: "k" }));
    const b = await s.svc.create(input({ tenant_id: T2, idempotency_key: "k" }));
    expect(await store.get(T2, a.id)).toBeUndefined();
    expect(await store.get(T1, b.id)).toBeUndefined();
    expect((await store.findByIdempotencyKey(T1, "k"))?.id).toBe(a.id);
    expect((await store.findByIdempotencyKey(T2, "k"))?.id).toBe(b.id);
    expect(await store.findByIdempotencyKey(T1, "other")).toBeUndefined();
    expect((await store.list(T1, { limit: 10 })).map((r) => r.id)).toEqual([a.id]);
    expect(await store.list("33333333-3333-4333-8333-333333333333", { limit: 10 })).toEqual([]);
  });

  it("compareAndSet is version-checked, tenant-scoped, and never inserts", async () => {
    const { store, r } = await made();
    const next: ApprovalRequest = { ...r, version: r.version + 1, status: "denied" };
    expect(await store.compareAndSet({ ...next, tenant_id: T2 }, r.version)).toBe(false);
    expect(await store.compareAndSet({ ...next, id: "nope" }, r.version)).toBe(false);
    expect(await store.compareAndSet(next, 99)).toBe(false);
    expect((await store.get(T1, r.id))?.status).toBe("pending");
    expect(await store.compareAndSet(next, r.version)).toBe(true);
    expect(await store.compareAndSet(next, r.version)).toBe(false); // stale writer
  });

  it("returns copies, rejects duplicate ids, orders and limits listings, and bounds listDue", async () => {
    const { store, r, svc, clock } = await made();
    const got = (await store.get(T1, r.id)) as ApprovalRequest;
    got.status = "approved";
    expect((await store.get(T1, r.id))?.status).toBe("pending");
    await expect(store.insert(r)).rejects.toThrow("duplicate");
    await svc.create(input());
    await svc.create(input());
    expect((await store.list(T1, { limit: 2 })).length).toBe(2);
    expect((await store.list(T1, { limit: 5, status: "approved" })).length).toBe(0);
    expect(await store.listDue(clock.now(), 10)).toEqual([]);
    clock.advance(1000);
    expect((await store.listDue(clock.now(), 10)).length).toBe(3);
    expect((await store.listDue(clock.now(), 2)).length).toBe(2);
  });
});

describe("escalation and verification edge cases", () => {
  it("escalation clears a claim so the higher level can act", async () => {
    const { svc, clock, r } = await made();
    await svc.claim(principal("alice", ["finance"]), r.id);
    clock.advance(100);
    const e = await svc.get(principal("carol", ["cfo"]), r.id);
    expect(e.claimed_by).toBeNull();
    expect((await svc.approve(principal("carol", ["cfo"]), r.id)).status).toBe("approved");
  });

  it("isApprovalValidFor requires outcome APPROVED and a valid signature, independently", async () => {
    const { svc, signer, r } = await made();
    const rec = await svc.decisionRecord(await svc.approve(principal("alice", ["finance"]), r.id));
    const exp = { tenant_id: T1, run_id: "run-1", tool: "payments.refund", args_hash: HASH };
    const { signature, ...u } = rec;
    void signature;
    // properly signed, decision ALLOW, but outcome says DENIED
    expect(
      await isApprovalValidFor(await signRecord({ ...u, outcome: "DENIED" }, signer), exp, signer),
    ).toBe(false);
    // right fields, forged signature
    expect(
      await isApprovalValidFor(
        { ...rec, signature: Buffer.alloc(32).toString("base64") },
        exp,
        signer,
      ),
    ).toBe(false);
    expect(await isApprovalValidFor(rec, exp, signer)).toBe(true);
  });
});
