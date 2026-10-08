import { describe, expect, it } from "vitest";
import { ApprovalsProvider, type ApprovalLike } from "../src/index.js";

const ctx = {
  tenantId: "t1",
  now: new Date(),
  pseudonym: async (_k: string, v: string) => `anon_${v.length}`,
};

function store(rows: ApprovalLike[]) {
  return {
    rows,
    list: async () => rows.map((r) => structuredClone(r)),
    compareAndSet: async (next: ApprovalLike, v: number) => {
      const i = rows.findIndex((r) => r.id === next.id);
      if (i < 0 || rows[i]!.version !== v) return false;
      rows[i] = next;
      return true;
    },
  };
}
const row = (id: string, who: string, over: Partial<ApprovalLike> = {}): ApprovalLike => ({
  id,
  version: 1,
  requester: { type: "human", id: who },
  conflicted: [who, "other"],
  claimed_by: who,
  decided_by: who,
  comment: `by ${who}`,
  reason: "r",
  ...over,
});

describe("ApprovalsProvider over the in-memory approvals store port", () => {
  it("finds, exports, pseudonymises and verifies; others are untouched", async () => {
    const s = store([row("a", "jane"), row("b", "bob"), row("c", "bob", { conflicted: ["jane"] })]);
    const p = new ApprovalsProvider({ store: s as never });
    const ids = [{ kind: "user_ref" as const, value: "jane" }];
    expect((await p.find(ctx, ids)).count).toBe(2);
    expect((await p.export(ctx, ids))[0]?.records).toHaveLength(2);
    expect((await p.count(ctx, ids)).residual).toBe(2);
    const r = await p.erase(ctx, ids);
    expect(r).toMatchObject({ pseudonymised: 2, erased: 0 });
    expect((await p.count(ctx, ids)).residual).toBe(0);
    expect(JSON.stringify(s.rows[0])).not.toContain("jane");
    expect(s.rows[0]?.comment).toBeNull();
    expect(s.rows[1]?.comment).toBe("by bob");
    expect(await p.erase(ctx, ids)).toMatchObject({ pseudonymised: 0 });
  });
  it("works with no store configured", async () => {
    const p = new ApprovalsProvider({});
    expect(await p.find(ctx, [{ kind: "user_ref", value: "x" }])).toEqual({ count: 0 });
    expect(await p.erase(ctx, [{ kind: "user_ref", value: "x" }])).toMatchObject({
      pseudonymised: 0,
    });
  });
});
