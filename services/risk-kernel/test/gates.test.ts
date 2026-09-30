import { describe, expect, it } from "vitest";
import {
  MemoryCounterStore,
  MemoryKillSwitchStore,
  budgetKey,
  evaluateGate,
  getPath,
  type GateEnv,
  type PolicyGate,
} from "../src/index.js";
import { T1, req } from "./helpers.js";

const NOW = Date.parse("2026-03-01T12:00:00.000Z");
const env = (context: Record<string, unknown> = {}, over: Partial<GateEnv> = {}): GateEnv => ({
  now: NOW,
  req: req({ context }),
  killSwitches: new MemoryKillSwitchStore(),
  counters: new MemoryCounterStore(),
  ...over,
});
const gate = (type: string, params: Record<string, unknown> = {}, scope?: string): PolicyGate => ({
  id: "g1",
  type,
  params,
  ...(scope ? { scope } : {}),
});

describe("getPath", () => {
  it("reads own properties only and never prototype members", () => {
    expect(getPath({ a: { b: 1 } }, "a.b")).toBe(1);
    expect(getPath({ a: 1 }, "a.b")).toBeUndefined();
    expect(getPath({}, "constructor")).toBeUndefined();
    expect(getPath({}, "__proto__")).toBeUndefined();
    expect(getPath(null, "a")).toBeUndefined();
  });
});

describe("kill_switch gate", () => {
  it.each(["global", "tenant", "agent", "tool"] as const)(
    "fails when %s is engaged",
    async (scope) => {
      const e = env({ tool: { name: "crm" } });
      await e.killSwitches.set(
        scope,
        { tenantId: T1, target: scope === "agent" ? "claims-triage" : "crm" },
        true,
      );
      expect((await evaluateGate(gate("kill_switch", {}, scope), e)).pass).toBe(false);
    },
  );
  it("passes when nothing is engaged, and rejects an invalid scope", async () => {
    expect((await evaluateGate(gate("kill_switch", {}, "tenant"), env())).pass).toBe(true);
    expect((await evaluateGate(gate("kill_switch", {}, "planet"), env())).pass).toBe(false);
    expect((await evaluateGate(gate("kill_switch"), env())).pass).toBe(false);
  });
});

describe("staleness gate", () => {
  const g = gate("staleness", { field: "args.ts", maxAgeSeconds: 5 });
  it("passes fresh ISO and epoch-ms timestamps", async () => {
    expect(
      (await evaluateGate(g, env({ args: { ts: new Date(NOW - 2000).toISOString() } }))).pass,
    ).toBe(true);
    expect((await evaluateGate(g, env({ args: { ts: NOW - 5000 } }))).pass).toBe(true);
  });
  it("fails stale, far-future, missing, malformed and mistyped values", async () => {
    for (const ts of [NOW - 5001, NOW + 6000, undefined, "yesterday", {}, null]) {
      expect((await evaluateGate(g, env({ args: { ts } }))).pass, String(ts)).toBe(false);
    }
  });
  it("tolerates small clock skew into the future", async () => {
    expect((await evaluateGate(g, env({ args: { ts: NOW + 3000 } }))).pass).toBe(true);
  });
  it("fails on invalid params", async () => {
    expect(
      (await evaluateGate(gate("staleness", { field: 5, maxAgeSeconds: 5 }), env())).pass,
    ).toBe(false);
    expect((await evaluateGate(gate("staleness", { field: "a" }), env())).pass).toBe(false);
  });
});

describe("amount_cap gate", () => {
  const g = gate("amount_cap", { field: "args.amount", max: 100 });
  it("boundary: equal passes, above fails", async () => {
    expect((await evaluateGate(g, env({ args: { amount: 100 } }))).pass).toBe(true);
    expect((await evaluateGate(g, env({ args: { amount: 100.01 } }))).pass).toBe(false);
  });
  it("fails on missing, string, NaN and Infinity amounts", async () => {
    for (const amount of [undefined, "5", NaN, Infinity, null]) {
      expect((await evaluateGate(g, env({ args: { amount } }))).pass, String(amount)).toBe(false);
    }
  });
  it("fails on invalid params", async () => {
    expect(
      (
        await evaluateGate(
          gate("amount_cap", { field: "args.amount" }),
          env({ args: { amount: 1 } }),
        )
      ).pass,
    ).toBe(false);
  });
  it("reasons never echo request values", async () => {
    const r = await evaluateGate(g, env({ args: { amount: 987654 } }));
    expect(r.reason).not.toContain("987654");
  });
});

describe("target_cap gate", () => {
  const g = gate("target_cap", { field: "args.amount", max: 100, perTarget: true });
  it("reserves atomically and blocks once the cap would be exceeded; rollback releases the reservation", async () => {
    const counters = new MemoryCounterStore();
    const run = (amount: number, target: string) =>
      evaluateGate(g, env({ args: { amount, target } }, { counters }));
    const a = await run(60, "venue-a");
    expect(a.pass).toBe(true);
    expect((await run(60, "venue-a")).pass).toBe(false); // the first reservation counts immediately: 60 + 60 > 100
    expect((await run(60, "venue-b")).pass).toBe(true); // separate target
    await a.rollback?.(); // e.g. a later gate failed: the capacity comes back
    expect((await run(60, "venue-a")).pass).toBe(true);
    expect((await run(40, "venue-a")).pass).toBe(true); // exactly at cap
    expect((await run(1, "venue-a")).pass).toBe(false);
  });
  it("parallel reservations can never jointly exceed the cap (no read-then-add race)", async () => {
    const counters = new MemoryCounterStore();
    const results = await Promise.all(
      Array.from({ length: 10 }, () =>
        evaluateGate(g, env({ args: { amount: 60, target: "v" } }, { counters })),
      ),
    );
    expect(results.filter((r) => r.pass)).toHaveLength(1);
  });
  it("perTarget=false shares one counter; target falls back to tool.name; fails with no target", async () => {
    const counters = new MemoryCounterStore();
    const shared = gate("target_cap", { field: "args.amount", max: 100, perTarget: false });
    expect(
      (await evaluateGate(shared, env({ args: { amount: 80, target: "x" } }, { counters }))).pass,
    ).toBe(true);
    expect(
      (await evaluateGate(shared, env({ args: { amount: 30, target: "y" } }, { counters }))).pass,
    ).toBe(false);
    expect(
      (await evaluateGate(g, env({ args: { amount: 1 }, tool: { name: "t" } }, { counters }))).pass,
    ).toBe(true);
    expect((await evaluateGate(g, env({ args: { amount: 1 } }, { counters }))).pass).toBe(false);
  });
  it("resets on the next UTC day", async () => {
    const counters = new MemoryCounterStore();
    await evaluateGate(g, env({ args: { amount: 100, target: "a" } }, { counters }));
    const tomorrow = env(
      { args: { amount: 100, target: "a" } },
      { counters, now: NOW + 86_400_000 },
    );
    expect((await evaluateGate(g, tomorrow)).pass).toBe(true);
  });
  it("fails on negative, missing or invalid inputs", async () => {
    expect((await evaluateGate(g, env({ args: { amount: -5, target: "a" } }))).pass).toBe(false);
    expect((await evaluateGate(g, env({ args: { target: "a" } }))).pass).toBe(false);
    expect((await evaluateGate(gate("target_cap", {}), env())).pass).toBe(false);
  });
  it("counter keys cannot collide through ':' in agent or target names", async () => {
    const counters = new MemoryCounterStore();
    const as = (agent: string, target: string) =>
      evaluateGate(g, {
        ...env({ args: { amount: 100, target } }, { counters }),
        req: req({
          blueprint: { name: agent, version: "1" },
          context: { args: { amount: 100, target } },
        }),
      });
    expect((await as("a", "b:g1:c")).pass).toBe(true);
    expect((await as("a:g1:b", "c")).pass).toBe(true); // a different (agent,target) pair; must not share a counter
    expect(budgetKey(T1, "a:b", "m", "day", NOW)).not.toBe(budgetKey(T1, "a", "b:m", "day", NOW));
  });
});

describe("budget gate", () => {
  const g = gate("budget", { metric: "cost_usd", window: "day", hard: 100, soft: 80 });
  const seed = (counters: MemoryCounterStore, window: string, spent: number, runId = "") =>
    counters.add(budgetKey(T1, "claims-triage", "cost_usd", window, NOW, runId), spent);
  it("passes under soft, warns at soft, fails at hard", async () => {
    const counters = new MemoryCounterStore();
    expect(await evaluateGate(g, env({}, { counters }))).toMatchObject({
      pass: true,
      reason: "gate g1: ok",
    });
    await seed(counters, "day", 85);
    expect(await evaluateGate(g, env({}, { counters }))).toMatchObject({ pass: true });
    expect((await evaluateGate(g, env({}, { counters }))).reason).toContain("soft");
    await seed(counters, "day", 15);
    expect((await evaluateGate(g, env({}, { counters }))).pass).toBe(false);
  });
  it.each(["run", "hour", "day", "month"])("window %s keys spend separately", async (window) => {
    const counters = new MemoryCounterStore();
    const gw = gate("budget", { metric: "cost_usd", window, hard: 10 });
    await seed(counters, window, 10, "run-1");
    const e = env({ run: { id: "run-1" } }, { counters });
    expect((await evaluateGate(gw, e)).pass).toBe(false);
    const other = env({ run: { id: "run-2" } }, { counters });
    expect((await evaluateGate(gw, other)).pass).toBe(window === "run");
  });
  it("run budgets need run.id; params must be valid", async () => {
    expect(
      (await evaluateGate(gate("budget", { metric: "tokens", window: "run", hard: 1 }), env()))
        .pass,
    ).toBe(false);
    expect(
      (await evaluateGate(gate("budget", { metric: "tokens", window: "day" }), env())).pass,
    ).toBe(false);
    expect((await evaluateGate(gate("budget", {}), env())).pass).toBe(false);
  });
  it("soft-only budgets never fail", async () => {
    const counters = new MemoryCounterStore();
    await seed(counters, "day", 1e9);
    expect(
      (
        await evaluateGate(
          gate("budget", { metric: "cost_usd", window: "day", soft: 1 }),
          env({}, { counters }),
        )
      ).pass,
    ).toBe(true);
  });
});

describe("rate_limit gate", () => {
  const g = gate("rate_limit", { max: 2, windowSeconds: 10, key: "agent" });
  it("allows max hits per window then fails, and recovers after the window", async () => {
    const counters = new MemoryCounterStore();
    const at = (now: number) => evaluateGate(g, env({}, { counters, now }));
    expect((await at(NOW)).pass).toBe(true);
    expect((await at(NOW + 1)).pass).toBe(true);
    expect((await at(NOW + 2)).pass).toBe(false);
    expect((await at(NOW + 10_001)).pass).toBe(true);
  });
  it.each(["tenant", "tool", "actor"])("supports key %s", async (key) => {
    const gk = gate("rate_limit", { max: 1, windowSeconds: 10, key });
    const counters = new MemoryCounterStore();
    const e = env({ tool: { name: "t" } }, { counters });
    expect((await evaluateGate(gk, e)).pass).toBe(true);
    expect((await evaluateGate(gk, e)).pass).toBe(false);
  });
  it("defaults to the agent key; fails when the key cannot be resolved or params are invalid", async () => {
    const d = gate("rate_limit", { max: 1, windowSeconds: 10 });
    const counters = new MemoryCounterStore();
    expect((await evaluateGate(d, env({}, { counters }))).pass).toBe(true);
    expect((await evaluateGate(d, env({}, { counters }))).pass).toBe(false);
    expect(
      (await evaluateGate(gate("rate_limit", { max: 1, windowSeconds: 10, key: "tool" }), env()))
        .pass,
    ).toBe(false);
    expect((await evaluateGate(gate("rate_limit", { max: 1 }), env())).pass).toBe(false);
  });
});

describe("fail-closed", () => {
  it("unknown gate types fail", async () => {
    expect((await evaluateGate(gate("telepathy"), env())).pass).toBe(false);
  });
  it("store errors fail the gate instead of throwing", async () => {
    const broken = new MemoryCounterStore();
    broken.get = () => Promise.reject(new Error("redis down"));
    broken.reserve = () => Promise.reject(new Error("redis down"));
    broken.hit = () => Promise.reject(new Error("redis down"));
    const ks = new MemoryKillSwitchStore();
    ks.isEngaged = () => Promise.reject(new Error("redis down"));
    const e = env({ args: { amount: 1, target: "a" } }, { counters: broken, killSwitches: ks });
    for (const g of [
      gate("target_cap", { field: "args.amount", max: 10 }),
      gate("budget", { metric: "tokens", window: "day", hard: 1 }),
      gate("rate_limit", { max: 5, windowSeconds: 5 }),
      gate("kill_switch", {}, "tenant"),
    ]) {
      const r = await evaluateGate(g, e);
      expect(r.pass, g.type).toBe(false);
      expect(r.reason).toContain("evaluation error");
    }
  });
});

describe("memory stores", () => {
  it("kill-switch keys do not collide across tenants/scopes and ignore unresolved targets", async () => {
    const ks = new MemoryKillSwitchStore();
    await ks.set("tool", { tenantId: T1, target: "crm" }, true);
    expect(await ks.isEngaged("tool", { tenantId: T1, agent: "a", tool: "crm" })).toBe(true);
    expect(await ks.isEngaged("tool", { tenantId: "other", agent: "a", tool: "crm" })).toBe(false);
    expect(await ks.isEngaged("tool", { tenantId: T1, agent: "a" })).toBe(false);
    expect(await ks.isEngaged("agent", { tenantId: T1, agent: "crm" })).toBe(false);
    expect(await ks.isEngaged("tenant", { tenantId: "", agent: "a" })).toBe(false);
    await ks.set("tool", { tenantId: T1, target: "crm" }, false);
    expect(await ks.isEngaged("tool", { tenantId: T1, agent: "a", tool: "crm" })).toBe(false);
  });
});
