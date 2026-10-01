import { describe, expect, it } from "vitest";
import {
  ApprovalError,
  ApprovalResolver,
  HmacSigner,
  isApprovalValidFor,
  verifyRecord,
  type DecisionRecord,
  type ResolverTimers,
} from "../src/index.js";
import { HASH, KEY, T1, T2, input, principal, setup } from "./helpers.js";

const fin = principal("alice", ["finance"]);

class ManualTimers implements ResolverTimers {
  fns = new Map<number, () => void>();
  n = 0;
  setTimeout(fn: () => void): unknown {
    this.fns.set(++this.n, fn);
    return this.n;
  }
  clearTimeout(h: unknown): void {
    this.fns.delete(h as number);
  }
  fireAll(): void {
    const all = [...this.fns.values()];
    this.fns.clear();
    all.forEach((f) => f());
  }
}

describe("ApprovalResolver", () => {
  it("returns immediately for an already-decided request", async () => {
    const { svc, signer } = setup();
    const r = await svc.create(input());
    await svc.approve(fin, r.id);
    const rec = await new ApprovalResolver(svc).resolve(T1, r.id);
    expect(rec.outcome).toBe("APPROVED");
    expect(await verifyRecord(rec, signer)).toBe(true);
  });

  it("waits for an approval, waking on the terminal event", async () => {
    const { svc } = setup();
    const timers = new ManualTimers();
    const r = await svc.create(input());
    const p = new ApprovalResolver(svc, timers).resolve(T1, r.id);
    await new Promise((x) => setTimeout(x, 5));
    await svc.deny(fin, r.id);
    const rec = await p;
    expect(rec.outcome).toBe("DENIED");
    expect(timers.fns.size).toBe(0);
  });

  it("resolves EXPIRED (DENY) by itself when the SLA elapses, without a sweeper", async () => {
    const { svc, clock } = setup();
    const timers = new ManualTimers();
    const r = await svc.create(
      input({ approval: { roles: ["f"], sla_seconds: 10, escalate_to: [], on_timeout: "DENY" } }),
    );
    const p = new ApprovalResolver(svc, timers).resolve(T1, r.id);
    await new Promise((x) => setTimeout(x, 5));
    timers.fireAll(); // timer fires early (clock unchanged): re-arms, still pending
    await new Promise((x) => setTimeout(x, 5));
    expect(timers.fns.size).toBe(1);
    clock.advance(10);
    timers.fireAll();
    const rec = await p;
    expect(rec.outcome).toBe("EXPIRED");
    expect(rec.decision).toBe("DENY");
  });

  it("rejects for unknown ids and other tenants (callers treat rejection as DENY)", async () => {
    const { svc } = setup();
    const r = await svc.create(input());
    const rs = new ApprovalResolver(svc);
    await expect(rs.resolve(T2, r.id)).rejects.toBeInstanceOf(ApprovalError);
    await expect(rs.resolve(T1, "missing")).rejects.toBeInstanceOf(ApprovalError);
  });

  it("honours abort signals, before and during the wait", async () => {
    const { svc } = setup();
    const r = await svc.create(input());
    const rs = new ApprovalResolver(svc, new ManualTimers());
    const pre = new AbortController();
    pre.abort(new Error("stop"));
    await expect(rs.resolve(T1, r.id, pre.signal)).rejects.toThrow("stop");
    const live = new AbortController();
    const p = rs.resolve(T1, r.id, live.signal);
    await new Promise((x) => setTimeout(x, 5));
    live.abort(new Error("cancelled"));
    await expect(p).rejects.toThrow("cancelled");
    // other tenants' / other requests' terminal events do not wake an unrelated waiter
    const q = await svc.create(input());
    const w = rs.resolve(T1, r.id);
    await new Promise((x) => setTimeout(x, 5));
    await svc.approve(fin, q.id);
    await new Promise((x) => setTimeout(x, 5));
    await svc.approve(fin, r.id);
    expect((await w).request_id).toBe(r.id);
  });
});

describe("signed records and isApprovalValidFor", () => {
  async function approved() {
    const { svc, signer } = setup();
    const r = await svc.create(input());
    const rec = await svc.decisionRecord(await svc.approve(fin, r.id));
    return { rec, signer, r };
  }
  const exp = { tenant_id: T1, run_id: "run-1", tool: "payments.refund", args_hash: HASH };

  it("accepts an approved record only for the exact action", async () => {
    const { rec, signer } = await approved();
    expect(await isApprovalValidFor(rec, exp, signer)).toBe(true);
    expect(await isApprovalValidFor(rec, { ...exp, args_hash: "c".repeat(64) }, signer)).toBe(
      false,
    );
    expect(await isApprovalValidFor(rec, { ...exp, tool: "x" }, signer)).toBe(false);
    expect(await isApprovalValidFor(rec, { ...exp, run_id: "r2" }, signer)).toBe(false);
    expect(await isApprovalValidFor(rec, { ...exp, tenant_id: T2 }, signer)).toBe(false);
  });

  it("rejects tampered, re-keyed and wrong-key records", async () => {
    const { rec, signer } = await approved();
    const forged: DecisionRecord = { ...rec, args_hash: "d".repeat(64) };
    expect(await verifyRecord(forged, signer)).toBe(false);
    expect(await verifyRecord({ ...rec, outcome: "DENIED" }, signer)).toBe(false);
    expect(await verifyRecord({ ...rec, key_id: "other" }, signer)).toBe(false);
    expect(await verifyRecord({ ...rec, signature: 5 as never }, signer)).toBe(false);
    expect(await verifyRecord({ ...rec, signature: "AAAA" }, signer)).toBe(false);
    const other = new HmacSigner(new Uint8Array(32).fill(9));
    expect(await verifyRecord(rec, other)).toBe(false);
    expect(
      await verifyRecord(rec, {
        keyId: rec.key_id,
        sign: async () => new Uint8Array(),
        verify: async () => {
          throw new Error("x");
        },
      }),
    ).toBe(false);
  });

  it("never validates a denied or expired record, even correctly signed", async () => {
    const { svc, signer } = setup();
    const r = await svc.create(input());
    const rec = await svc.decisionRecord(await svc.deny(fin, r.id));
    expect(await isApprovalValidFor(rec, exp, signer)).toBe(false);
    // a "signed" record claiming APPROVED but decision DENY is also refused
    const { signRecord } = await import("../src/index.js");
    const { signature, ...unsigned } = rec;
    void signature;
    const odd = await signRecord({ ...unsigned, outcome: "APPROVED" }, signer);
    expect(await isApprovalValidFor(odd, exp, signer)).toBe(false);
  });

  it("requires a 32-byte HMAC key", () => {
    expect(() => new HmacSigner(new Uint8Array(8))).toThrow();
    expect(new HmacSigner(KEY).keyId).toBe("hmac-1");
  });
});
