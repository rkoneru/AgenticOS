import { describe, expect, it } from "vitest";
import { ApprovalError, type ApprovalRequest, type Principal } from "../src/index.js";
import { T1, T2, input, setup } from "./helpers.js";

/** mulberry32: deterministic PRNG so failures reproduce from the seed. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const ROLES = ["finance", "cfo", "ceo", "eng"];
const USERS = ["alice", "bob", "carol", "dave", "erin", "refunder"];

interface Run {
  decided: Map<string, string>; // id -> frozen JSON of the terminal request
  approvals: { id: string; by: string }[];
}

async function simulate(seed: number): Promise<Run & { s: ReturnType<typeof setup> }> {
  const r = rng(seed);
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)] as T;
  const s = setup();
  const reqs: { id: string; tenant: string }[] = [];
  const run: Run = { decided: new Map(), approvals: [] };

  for (let step = 0; step < 120; step++) {
    const op = r();
    try {
      if (op < 0.2 || reqs.length === 0) {
        const tenant = pick([T1, T2]);
        const levels = Math.floor(r() * 3);
        const created = await s.svc.create(
          input({
            tenant_id: tenant,
            requester: { type: "human", id: pick(USERS) },
            conflicted: r() < 0.3 ? [pick(USERS)] : [],
            approval: {
              roles: [pick(ROLES)],
              sla_seconds: 1 + Math.floor(r() * 50),
              escalate_to: ROLES.slice(0, levels),
              on_timeout: "DENY",
            },
          }),
        );
        reqs.push({ id: created.id, tenant });
      } else if (op < 0.7) {
        const target = pick(reqs);
        const asTenant = r() < 0.15 ? (target.tenant === T1 ? T2 : T1) : target.tenant;
        const p: Principal = {
          tenant_id: asTenant,
          id: pick(USERS),
          roles: [pick(ROLES), pick(ROLES)],
        };
        const verdict = r() < 0.5 ? "approve" : "deny";
        const out =
          verdict === "approve"
            ? await s.svc.approve(p, target.id)
            : await s.svc.deny(p, target.id);
        // tenant isolation: a success implies the right tenant
        expect(asTenant).toBe(target.tenant);
        if (out.status === "approved") run.approvals.push({ id: target.id, by: p.id });
      } else if (op < 0.8) {
        const target = pick(reqs);
        await s.svc.claim(
          { tenant_id: target.tenant, id: pick(USERS), roles: [pick(ROLES)] },
          target.id,
        );
      } else if (op < 0.95) {
        s.clock.advance(Math.floor(r() * 40));
        if (r() < 0.5) await s.svc.sweep();
      } else {
        await s.svc.sweep();
      }
    } catch (e) {
      if (!(e instanceof ApprovalError)) throw e;
    }

    // Invariant: once terminal, a request never changes again.
    for (const { id, tenant } of reqs) {
      const cur = (await s.store.get(tenant, id)) as ApprovalRequest;
      const frozen = run.decided.get(id);
      if (frozen !== undefined) expect(JSON.stringify(cur)).toBe(frozen);
      else if (cur.status !== "pending") run.decided.set(id, JSON.stringify(cur));
    }
  }
  return { ...run, s };
}

const SEEDS = Array.from({ length: 40 }, (_, i) => i + 1);

describe("property: random operation sequences (40 seeds)", () => {
  it("decided requests are immutable and never flip", async () => {
    for (const seed of SEEDS) await simulate(seed); // assertions run inside simulate
  });

  it("expiry never yields approve; approvals are always legitimate and audited", async () => {
    for (const seed of SEEDS) {
      const { s, approvals } = await simulate(seed);
      for (const tenant of [T1, T2]) {
        const evs = await s.log.read(tenant);
        expect((await s.log.verify(tenant)).ok).toBe(true);
        const expired = new Set<string>();
        const approved = new Set<string>();
        for (const e of evs) {
          const id = /request=([0-9a-f-]+)/.exec(e.reason ?? "")?.[1] as string;
          if (e.action === "approval.expired") {
            expect(e.decision).toBe("DENY");
            expired.add(id);
          }
          if (e.action === "approval.approved") {
            expect(e.decision).toBe("ALLOW");
            approved.add(id);
          }
        }
        for (const id of expired) expect(approved.has(id)).toBe(false);
        const reqs = await s.store.list(tenant, { limit: 1000 });
        for (const r of reqs) {
          if (r.status === "expired") {
            expect(r.decided_by).toBeNull();
            const rec = await s.svc.decisionRecord(r);
            expect(rec.decision).toBe("DENY");
          }
          if (r.status === "approved") {
            expect(r.decided_by).not.toBe(r.requester.id);
            expect(r.conflicted).not.toContain(r.decided_by);
            expect(approved.has(r.id) || approvals.some((a) => a.id === r.id)).toBe(true);
          }
        }
      }
    }
  });

  it("tenant isolation: every record, event and decision stays within its own tenant", async () => {
    for (const seed of SEEDS) {
      const { s } = await simulate(seed);
      for (const tenant of [T1, T2]) {
        for (const r of await s.store.list(tenant, { limit: 1000 }))
          expect(r.tenant_id).toBe(tenant);
        for (const e of await s.log.read(tenant)) expect(e.tenant_id).toBe(tenant);
      }
    }
  });
});

describe("property harness sanity", () => {
  it("the random walks actually reach approved, denied, expired and escalated states", async () => {
    const seen = { approved: 0, denied: 0, expired: 0, escalated: 0, crossTenantAttempts: 0 };
    for (const seed of SEEDS) {
      const { s } = await simulate(seed);
      for (const t of [T1, T2]) {
        for (const r of await s.store.list(t, { limit: 1000 })) {
          if (r.status === "approved") seen.approved++;
          if (r.status === "denied") seen.denied++;
          if (r.status === "expired") seen.expired++;
          if (r.level > 1) seen.escalated++;
        }
      }
    }
    expect(seen.approved).toBeGreaterThan(10);
    expect(seen.denied).toBeGreaterThan(10);
    expect(seen.expired).toBeGreaterThan(10);
    expect(seen.escalated).toBeGreaterThan(10);
  });
});
