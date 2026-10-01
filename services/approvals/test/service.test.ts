import { describe, expect, it } from "vitest";
import { ApprovalError, MemoryApprovalStore, type ApprovalRequest } from "../src/index.js";
import { T1, T2, input, principal, setup, RecordingNotifier } from "./helpers.js";

const fin = principal("alice", ["finance"]);
const cfo = principal("carol", ["cfo"]);
const ceo = principal("dave", ["ceo"]);

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    if (e instanceof ApprovalError) return e.code;
    throw e;
  }
  return "OK";
}

describe("create", () => {
  it("opens a pending request and audits requested before it exists", async () => {
    const { svc, log, notifier } = setup();
    const r = await svc.create(input());
    expect(r.status).toBe("pending");
    expect(r.level).toBe(1);
    expect(r.chain.map((c) => c.roles)).toEqual([["finance"], ["cfo"], ["ceo"]]);
    const evs = await log.read(T1);
    expect(evs.map((e) => e.action)).toEqual(["approval.requested"]);
    expect(evs[0]?.decision).toBe("REQUIRE_APPROVAL");
    expect(evs[0]?.reason).toContain(r.args_hash);
    await svc.flush();
    expect(notifier.seen.map((n) => n.kind)).toEqual(["requested"]);
    expect(JSON.stringify(notifier.seen)).not.toContain("secret");
  });

  it("is idempotent per idempotency_key and rejects reuse for a different request", async () => {
    const { svc, log } = setup();
    const a = await svc.create(input({ idempotency_key: "k1" }));
    const b = await svc.create(input({ idempotency_key: "k1" }));
    expect(b.id).toBe(a.id);
    expect((await log.read(T1)).length).toBe(1);
    expect(await code(svc.create(input({ idempotency_key: "k1", tool: "other" })))).toBe(
      "CONFLICT",
    );
    // same key in another tenant is independent
    const c = await svc.create(input({ idempotency_key: "k1", tenant_id: T2 }));
    expect(c.id).not.toBe(a.id);
  });

  it("fails closed when the audit append fails: nothing is created", async () => {
    const { svc, audit, store } = setup();
    audit.fail = true;
    expect(await code(svc.create(input()))).toBe("AUDIT_FAILED");
    expect(await store.list(T1, { limit: 10 })).toEqual([]);
  });

  it.each([
    ["tenant", { tenant_id: "nope" }],
    ["run", { run_id: "" }],
    ["trace", { trace_id: "x" }],
    ["tool", { tool: "" }],
    ["hash", { args_hash: "zz" }],
    ["risk", { risk_level: "none" as never }],
    ["agent", { agent: { name: "", version: "1" } }],
    ["requester type", { requester: { type: "robot" as never, id: "x" } }],
    ["agent pid", { requester: { type: "agent" as const, id: "x" } }],
    ["conflicted", { conflicted: [1 as never] }],
    ["idem", { idempotency_key: "" }],
    ["policy", { policy_version: "" }],
    [
      "roles",
      { approval: { roles: [], sla_seconds: 1, escalate_to: [], on_timeout: "DENY" as const } },
    ],
    [
      "sla",
      { approval: { roles: ["a"], sla_seconds: 0, escalate_to: [], on_timeout: "DENY" as const } },
    ],
    [
      "sla float",
      {
        approval: { roles: ["a"], sla_seconds: 1.5, escalate_to: [], on_timeout: "DENY" as const },
      },
    ],
    [
      "on_timeout",
      { approval: { roles: ["a"], sla_seconds: 1, escalate_to: [], on_timeout: "ALLOW" as never } },
    ],
    [
      "escalate too long",
      {
        approval: {
          roles: ["a"],
          sla_seconds: 1,
          escalate_to: ["1", "2", "3", "4", "5", "6"],
          on_timeout: "DENY" as const,
        },
      },
    ],
    [
      "escalate bad",
      {
        approval: { roles: ["a"], sla_seconds: 1, escalate_to: [""], on_timeout: "DENY" as const },
      },
    ],
    ["spec null", { approval: null as never }],
  ])("rejects invalid %s", async (_n, over) => {
    const { svc } = setup();
    expect(await code(svc.create(input(over)))).toBe("INVALID");
  });

  it("rejects a non-object input", async () => {
    const { svc } = setup();
    expect(await code(svc.create(null as never))).toBe("INVALID");
  });
});

describe("approve / deny", () => {
  it("approves with an eligible role, audits ALLOW, and signs a record", async () => {
    const { svc, log, signer } = setup();
    const r = await svc.create(input());
    const done = await svc.approve(fin, r.id, "ok");
    expect(done.status).toBe("approved");
    const evs = await log.read(T1);
    expect(evs.map((e) => [e.action, e.decision])).toEqual([
      ["approval.requested", "REQUIRE_APPROVAL"],
      ["approval.approved", "ALLOW"],
    ]);
    expect(evs[1]?.actor).toEqual({ type: "human", id: "alice" });
    expect((await log.verify(T1)).ok).toBe(true);
    const rec = await svc.decisionRecord(done);
    expect(rec.outcome).toBe("APPROVED");
    expect(rec.audit_event_id).toBe(evs[1]?.id);
    expect(rec.audit_hash).toBe(evs[1]?.hash);
    const { verifyRecord } = await import("../src/index.js");
    expect(await verifyRecord(rec, signer)).toBe(true);
  });

  it("denies and records DENY", async () => {
    const { svc, log } = setup();
    const r = await svc.create(input());
    const done = await svc.deny(fin, r.id);
    expect(done.status).toBe("denied");
    expect((await log.read(T1)).at(-1)?.decision).toBe("DENY");
    expect((await svc.decisionRecord(done)).decision).toBe("DENY");
  });

  it("blocks self-approval and self-deny, even with a valid role", async () => {
    const { svc } = setup();
    const r = await svc.create(input({ requester: { type: "human", id: "alice" } }));
    expect(await code(svc.approve(fin, r.id))).toBe("SELF_APPROVAL");
    expect(await code(svc.deny(fin, r.id))).toBe("SELF_APPROVAL");
    expect(await code(svc.claim(fin, r.id))).toBe("SELF_APPROVAL");
    expect((await svc.get(fin, r.id)).status).toBe("pending");
  });

  it("enforces separation of duties for conflicted principals", async () => {
    const { svc } = setup();
    const r = await svc.create(input({ conflicted: ["alice"] }));
    expect(await code(svc.approve(fin, r.id))).toBe("CONFLICT_OF_INTEREST");
  });

  it("enforces approver roles; higher levels do not apply until escalation", async () => {
    const { svc } = setup();
    const r = await svc.create(input());
    expect(await code(svc.approve(principal("x", ["eng"]), r.id))).toBe("FORBIDDEN_ROLE");
    expect(await code(svc.approve(cfo, r.id))).toBe("FORBIDDEN_ROLE");
    expect(await code(svc.approve(principal("y", []), r.id))).toBe("FORBIDDEN_ROLE");
  });

  it("rejects malformed principals and over-long comments", async () => {
    const { svc } = setup();
    const r = await svc.create(input());
    for (const p of [
      null,
      { tenant_id: "", id: "a", roles: [] },
      { tenant_id: T1, id: "", roles: [] },
      { tenant_id: T1, id: "a", roles: "x" },
      { tenant_id: T1, id: "a", roles: [1] },
    ]) {
      expect(await code(svc.approve(p as never, r.id))).toBe("INVALID");
    }
    expect(await code(svc.approve(fin, r.id, "x".repeat(1001)))).toBe("INVALID");
    expect(await code(svc.approve(fin, r.id, 5 as never))).toBe("INVALID");
  });

  it("never flips a decision; replay by the same decider is idempotent without new audit events", async () => {
    const { svc, log } = setup();
    const r = await svc.create(input());
    const a = await svc.approve(fin, r.id);
    const n = (await log.read(T1)).length;
    expect((await svc.approve(fin, r.id)).version).toBe(a.version);
    expect((await log.read(T1)).length).toBe(n);
    expect(await code(svc.deny(fin, r.id))).toBe("ALREADY_DECIDED");
    expect(await code(svc.approve(principal("bob", ["finance"]), r.id))).toBe("ALREADY_DECIDED");
    expect(await code(svc.claim(fin, r.id))).toBe("ALREADY_DECIDED");
    expect((await svc.get(fin, r.id)).status).toBe("approved");
  });

  it("approve audit failure leaves the request pending (fail-closed)", async () => {
    const { svc, audit } = setup();
    const r = await svc.create(input());
    audit.fail = true;
    expect(await code(svc.approve(fin, r.id))).toBe("AUDIT_FAILED");
    audit.fail = false;
    expect((await svc.get(fin, r.id)).status).toBe("pending");
  });

  it("deny still applies when the audit log is down (safe direction), with an empty audit ref", async () => {
    const { svc, audit } = setup();
    const r = await svc.create(input());
    audit.fail = true;
    const d = await svc.deny(fin, r.id);
    expect(d.status).toBe("denied");
    expect((await svc.decisionRecord(d)).audit_event_id).toBe("");
  });

  it("concurrent decisions: exactly one wins", async () => {
    const { svc } = setup();
    const r = await svc.create(input());
    const bob = principal("bob", ["finance"]);
    const res = await Promise.allSettled([
      svc.approve(fin, r.id),
      svc.deny(bob, r.id),
      svc.approve(bob, r.id),
    ]);
    expect(res.filter((x) => x.status === "fulfilled").length).toBe(1);
  });

  it("surfaces a store write conflict instead of overwriting", async () => {
    const store = new MemoryApprovalStore();
    const { svc } = setup({ store });
    const r = await svc.create(input());
    store.compareAndSet = async () => false;
    expect(await code(svc.approve(fin, r.id))).toBe("CONFLICT");
  });
});

describe("claim / release", () => {
  it("claims, blocks others, allows the claimant, and releases", async () => {
    const { svc, log } = setup();
    const r = await svc.create(input());
    const bob = principal("bob", ["finance"]);
    const c = await svc.claim(fin, r.id);
    expect(c.claimed_by).toBe("alice");
    expect((await svc.claim(fin, r.id)).version).toBe(c.version); // idempotent, no new event
    expect(await code(svc.claim(bob, r.id))).toBe("CLAIMED_BY_OTHER");
    expect(await code(svc.approve(bob, r.id))).toBe("CLAIMED_BY_OTHER");
    expect(await code(svc.release(bob, r.id))).toBe("CLAIMED_BY_OTHER");
    await svc.release(fin, r.id);
    expect((await svc.approve(bob, r.id)).decided_by).toBe("bob");
    expect((await log.read(T1)).map((e) => e.action)).toEqual([
      "approval.requested",
      "approval.claimed",
      "approval.released",
      "approval.approved",
    ]);
  });

  it("claim and release need a durable audit event; release of a decided request fails", async () => {
    const { svc, audit } = setup();
    const r = await svc.create(input());
    audit.fail = true;
    expect(await code(svc.claim(fin, r.id))).toBe("AUDIT_FAILED");
    audit.fail = false;
    await svc.claim(fin, r.id);
    audit.fail = true;
    expect(await code(svc.release(fin, r.id))).toBe("AUDIT_FAILED");
    audit.fail = false;
    await svc.approve(fin, r.id);
    expect(await code(svc.release(fin, r.id))).toBe("ALREADY_DECIDED");
  });
});

describe("tenant isolation", () => {
  it("another tenant's principal cannot see, claim, approve or deny (NOT_FOUND)", async () => {
    const { svc } = setup();
    const r = await svc.create(input());
    const evil = principal("alice", ["finance"], T2);
    expect(await code(svc.get(evil, r.id))).toBe("NOT_FOUND");
    expect(await code(svc.claim(evil, r.id))).toBe("NOT_FOUND");
    expect(await code(svc.approve(evil, r.id))).toBe("NOT_FOUND");
    expect(await code(svc.deny(evil, r.id))).toBe("NOT_FOUND");
    expect(await code(svc.release(evil, r.id))).toBe("NOT_FOUND");
    expect(await svc.list(evil)).toEqual([]);
    expect((await svc.get(fin, r.id)).status).toBe("pending");
  });

  it("audit events land on the owning tenant's chain only", async () => {
    const { svc, log } = setup();
    await svc.create(input());
    await svc.create(input({ tenant_id: T2 }));
    expect((await log.read(T1)).length).toBe(1);
    expect((await log.read(T2)).length).toBe(1);
  });

  it("store defensively rejects a tenant mismatch", async () => {
    const store = new MemoryApprovalStore();
    const { svc } = setup({ store });
    const r = await svc.create(input());
    const real = store.get.bind(store);
    store.get = async (_t, id) => {
      const x = await real(T1, id);
      return x && ({ ...x, tenant_id: T2 } as ApprovalRequest);
    };
    expect(await code(svc.get(fin, r.id))).toBe("NOT_FOUND");
  });
});

describe("list", () => {
  it("returns requests the principal may act on or filed, filtered by status and limit", async () => {
    const { svc } = setup();
    const a = await svc.create(input());
    await svc.create(
      input({
        approval: { roles: ["legal"], sla_seconds: 100, escalate_to: [], on_timeout: "DENY" },
      }),
    );
    const own = await svc.create(input({ requester: { type: "human", id: "eve" } }));
    await svc.approve(fin, a.id);
    expect((await svc.list(fin)).map((r) => r.id)).toEqual([a.id, own.id]);
    expect((await svc.list(fin, { status: "pending" })).map((r) => r.id)).toEqual([own.id]);
    expect((await svc.list(fin, { limit: 1 })).length).toBe(1);
    expect((await svc.list(principal("eve", []))).map((r) => r.id)).toEqual([own.id]);
  });
});

describe("SLA, escalation and expiry", () => {
  it("escalates level by level, widening eligibility, then expires to DENY", async () => {
    const { svc, clock, log, notifier } = setup();
    const r = await svc.create(input());
    clock.advance(100);
    expect(await code(svc.approve(cfo, r.id))).toBe("OK"); // escalated lazily at the deadline: cfo now eligible
    const r2 = await svc.create(input());
    clock.advance(99);
    expect((await svc.get(fin, r2.id)).level).toBe(1);
    clock.advance(1);
    const e = await svc.get(fin, r2.id);
    expect(e.level).toBe(2);
    expect(e.claimed_by).toBeNull();
    expect(await code(svc.approve(ceo, r2.id))).toBe("FORBIDDEN_ROLE");
    clock.advance(100);
    expect((await svc.get(fin, r2.id)).level).toBe(3);
    expect(await code(svc.approve(fin, r2.id))).toBe("OK"); // lower roles stay eligible
    expect((await log.read(T1)).filter((x) => x.action === "approval.escalated").length).toBe(3);
    await svc.flush();
    expect(notifier.seen.some((n) => n.kind === "escalated" && n.level === 2)).toBe(true);
  });

  it("expiry after the final level is DENY, never approve, and audited", async () => {
    const { svc, clock, log, notifier } = setup();
    const r = await svc.create(input());
    clock.advance(1000);
    const x = await svc.get(fin, r.id);
    expect(x.status).toBe("expired");
    expect(x.decided_by).toBeNull();
    expect(x.decided_at_ms).toBe(r.created_at_ms + 300_000);
    expect(await code(svc.approve(fin, r.id))).toBe("ALREADY_DECIDED");
    const rec = await svc.decisionRecord(x);
    expect(rec.outcome).toBe("EXPIRED");
    expect(rec.decision).toBe("DENY");
    expect(rec.decided_by).toBe("approvals-sla");
    const evs = await log.read(T1);
    expect(evs.at(-1)?.action).toBe("approval.expired");
    expect(evs.at(-1)?.decision).toBe("DENY");
    expect(evs.at(-1)?.actor.type).toBe("system");
    expect(rec.audit_event_id).toBe(evs.at(-1)?.id);
    await svc.flush();
    expect(notifier.seen.at(-1)?.kind).toBe("expired");
    expect(notifier.seen.at(-1)?.outcome).toBe("EXPIRED");
  });

  it("a single-level chain expires at its deadline; approving at the exact deadline fails", async () => {
    const { svc, clock } = setup();
    const r = await svc.create(
      input({
        approval: { roles: ["finance"], sla_seconds: 10, escalate_to: [], on_timeout: "DENY" },
      }),
    );
    clock.advance(10);
    expect(await code(svc.approve(fin, r.id))).toBe("ALREADY_DECIDED");
    expect((await svc.get(fin, r.id)).status).toBe("expired");
  });

  it("expiry applies even if the audit log is down (DENY direction)", async () => {
    const { svc, clock, audit } = setup();
    const r = await svc.create(
      input({
        approval: { roles: ["finance"], sla_seconds: 10, escalate_to: [], on_timeout: "DENY" },
      }),
    );
    audit.fail = true;
    clock.advance(10);
    const x = await svc.get(fin, r.id);
    expect(x.status).toBe("expired");
    expect(x.decision_audit_id).toBe("");
  });

  it("escalation needs audit: while the log is down, no approval is possible", async () => {
    const { svc, clock, audit } = setup();
    const r = await svc.create(input());
    audit.fail = true;
    clock.advance(100);
    expect(await code(svc.approve(cfo, r.id))).toBe("AUDIT_FAILED");
    expect(await code(svc.approve(fin, r.id))).toBe("AUDIT_FAILED");
  });

  it("sweep applies due timers across tenants and reports failures without throwing", async () => {
    const { svc, clock, audit } = setup();
    const a = await svc.create(input());
    const b = await svc.create(input({ tenant_id: T2 }));
    expect(await svc.sweep()).toBe(0);
    clock.advance(400);
    expect(await svc.sweep()).toBe(2);
    expect((await svc.get(fin, a.id)).status).toBe("expired");
    expect((await svc.get(principal("x", [], T2), b.id)).status).toBe("expired");
    const c = await svc.create(input());
    clock.advance(100);
    audit.fail = true;
    expect(await svc.sweep()).toBe(0); // escalation fails; logged, not thrown
    audit.fail = false;
    expect((await svc.get(fin, c.id)).level).toBe(2);
  });

  it("sweeps do not overlap and the interval sweeper can be stopped", async () => {
    const { svc, clock } = setup();
    await svc.create(input());
    clock.advance(400);
    const [x, y] = await Promise.all([svc.sweep(), svc.sweep()]);
    expect(x + y).toBe(1);
    let tick: (() => void) | undefined;
    let cleared: unknown;
    const h = svc.startSweeper(5, {
      setInterval: (fn) => {
        tick = fn;
        return "h";
      },
      clearInterval: (x) => {
        cleared = x;
      },
    });
    tick?.();
    h.stop();
    expect(cleared).toBe("h");
    // default timers path
    const real = svc.startSweeper(1_000_000);
    real.stop();
  });

  it("sweeper survives a crashing sweep", async () => {
    const { svc, store } = setup();
    store.listDue = async () => {
      throw new Error("boom");
    };
    let tick: (() => void) | undefined;
    svc.startSweeper(5, { setInterval: (fn) => ((tick = fn), 1), clearInterval: () => {} });
    tick?.();
    await new Promise((r) => setTimeout(r, 5));
    await expect(svc.sweep()).rejects.toThrow("boom");
  });
});

describe("decisionRecord and hooks", () => {
  it("refuses a record for a pending request", async () => {
    const { svc } = setup();
    const r = await svc.create(input());
    expect(await code(svc.decisionRecord(r))).toBe("NOT_DECIDED");
  });

  it("wraps signer failures", async () => {
    const { svc } = setup();
    const r = await svc.create(input());
    const d = await svc.approve(fin, r.id);
    const bad = new (await import("../src/index.js")).ApprovalService({
      store: new MemoryApprovalStore(),
      audit: {
        append: async () => {
          throw new Error("x");
        },
      },
      signer: {
        keyId: "k",
        sign: async () => {
          throw new Error("hsm");
        },
        verify: async () => false,
      },
    });
    expect(await code(bad.decisionRecord(d))).toBe("SIGNING_FAILED");
  });

  it("a throwing terminal listener does not break the transition; unsubscribe works", async () => {
    const { svc } = setup();
    const r = await svc.create(input());
    let calls = 0;
    const off = svc.onTerminal(() => {
      calls++;
      throw new Error("listener");
    });
    await svc.approve(fin, r.id);
    expect(calls).toBe(1);
    off();
    const r2 = await svc.create(input());
    await svc.approve(fin, r2.id);
    expect(calls).toBe(1);
  });

  it("works without a dispatcher and with the default clock/id generator", async () => {
    const { MemoryAuditLog } = await import("@axis/audit");
    const { ApprovalService, HmacSigner } = await import("../src/index.js");
    const svc = new ApprovalService({
      store: new MemoryApprovalStore(),
      audit: new MemoryAuditLog(),
      signer: new HmacSigner(new Uint8Array(32).fill(1)),
    });
    const r = await svc.create(input());
    expect((await svc.approve(fin, r.id)).status).toBe("approved");
    expect(svc.now()).toBeGreaterThan(0);
    await svc.flush();
  });
});

describe("notifications never block or approve", () => {
  it("a hanging channel does not delay transitions", async () => {
    const n = new RecordingNotifier();
    n.hang = true;
    const { svc } = setup({ notifier: n });
    const r = await svc.create(input());
    expect((await svc.approve(fin, r.id)).status).toBe("approved");
  });

  it("a failing channel is retried and the request state is unaffected", async () => {
    const n = new RecordingNotifier();
    n.failTimes = 2;
    const { svc } = setup({ notifier: n });
    const r = await svc.create(input());
    await svc.flush();
    expect(n.seen.length).toBe(1);
    expect((await svc.get(fin, r.id)).status).toBe("pending");
  });
});
