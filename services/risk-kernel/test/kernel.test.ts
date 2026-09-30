import { verifyChain } from "@axis/contracts";
import { describe, expect, it } from "vitest";
import { RiskKernel, type PolicyEngine } from "../src/index.js";
import { PID, T1, T2, harness, req } from "./helpers.js";

const payments = (amount: unknown, extra: Record<string, unknown> = {}) =>
  req({
    context: {
      tool: { name: "payments", kind: "function", side_effects: "external" },
      args: { amount, ...extra },
    },
    action: "payments",
  });

const engineReturning = (value: unknown): PolicyEngine => ({
  evaluate: () => Promise.resolve(value),
});
const goodResult = (over: Record<string, unknown> = {}) => ({
  decision: "ALLOW",
  reason: "r",
  matched: ["x/y"],
  winners: ["x/y"],
  gates: [],
  redact: [],
  approval: null,
  policy_version: "x@1.0.0",
  ...over,
});

describe("decisions", () => {
  it("ALLOW: read tool, audited before the response, chain valid", async () => {
    const h = await harness();
    const r = await h.kernel.evaluate(req());
    expect(r).toMatchObject({
      decision: "ALLOW",
      policy_version: "baseline-deny@1.0.0,phi-redaction@1.1.0",
    });
    expect(r.matched_rule_ids).toEqual(["baseline-deny/allow-read-tools"]);
    const chain = h.audit.events.get(T1) ?? [];
    expect(chain).toHaveLength(1);
    expect(chain[0]).toMatchObject({
      id: r.audit_event_id,
      decision: "ALLOW",
      enforcement_point: "tool_call",
      action: "lookup",
    });
    expect(verifyChain(chain).ok).toBe(true);
  });

  it("default DENY when nothing matches", async () => {
    const h = await harness();
    const r = await h.kernel.evaluate(
      req({ context: { tool: { name: "crm", side_effects: "write" }, args: {} } }),
    );
    expect(r.decision).toBe("DENY");
    expect(r.reason).toContain("default deny");
    expect(h.audit.events.get(T1)?.[0]?.decision).toBe("DENY");
  });

  it("REQUIRE_APPROVAL returns the approval spec and audits it", async () => {
    const h = await harness();
    const r = await h.kernel.evaluate(payments(5000));
    expect(r.decision).toBe("REQUIRE_APPROVAL");
    expect(r.approval).toEqual({
      roles: ["finance-approver"],
      sla_seconds: 900,
      escalate_to: ["finance-director"],
      on_timeout: "DENY",
    });
    expect(r.approval_id).toBe(""); // assigned by the approvals service (Phase 3)
  });

  it("a failing gate turns REQUIRE_APPROVAL into DENY (amount above the cap)", async () => {
    const h = await harness();
    const r = await h.kernel.evaluate(payments(20000));
    expect(r.decision).toBe("DENY");
    expect(r.reason).toContain("amount-cap");
  });

  it("ALLOW_WITH_REDACTION returns the fields to redact", async () => {
    const h = await harness();
    const r = await h.kernel.evaluate(
      req({
        enforcement_point: "model_call",
        action: "complete",
        context: { data: { phi: true } },
      }),
    );
    expect(r).toMatchObject({
      decision: "ALLOW_WITH_REDACTION",
      redact_fields: ["phi.mrn", "phi.ssn", "pii.email"],
    });
  });

  it("redact fields and approval are only exposed for the matching decision", async () => {
    const h = await harness(
      {},
      engineReturning(
        goodResult({ redact: ["x"], approval: { roles: ["r"], sla_seconds: 5, escalate_to: [] } }),
      ),
    );
    const r = await h.kernel.evaluate(req());
    expect(r).toMatchObject({ decision: "ALLOW", redact_fields: [], approval: null });
  });
});

describe("fail-closed: every failure mode denies, and never throws", () => {
  const cases: [string, () => Promise<Parameters<typeof harness>>][] = [
    ["engine throws", async () => [{}, { evaluate: () => Promise.reject(new Error("boom")) }]],
    [
      "engine throws synchronously",
      async () => [
        {},
        {
          evaluate: () => {
            throw new Error("boom");
          },
        },
      ],
    ],
    ["engine returns undefined", async () => [{}, engineReturning(undefined)]],
    ["engine returns a string", async () => [{}, engineReturning("ALLOW")]],
    ["unknown decision", async () => [{}, engineReturning(goodResult({ decision: "PERMIT" }))]],
    [
      "missing decision",
      async () => [{}, engineReturning({ ...goodResult(), decision: undefined })],
    ],
    ["decision in lowercase", async () => [{}, engineReturning(goodResult({ decision: "allow" }))]],
    [
      "REQUIRE_APPROVAL without approval",
      async () => [{}, engineReturning(goodResult({ decision: "REQUIRE_APPROVAL" }))],
    ],
    [
      "REDACTION without fields",
      async () => [{}, engineReturning(goodResult({ decision: "ALLOW_WITH_REDACTION" }))],
    ],
    ["malformed gates", async () => [{}, engineReturning(goodResult({ gates: [{ id: 1 }] }))]],
    ["gates not an array", async () => [{}, engineReturning(goodResult({ gates: "none" }))]],
    [
      "malformed approval",
      async () => [
        {},
        engineReturning(goodResult({ decision: "REQUIRE_APPROVAL", approval: { roles: "x" } })),
      ],
    ],
    ["missing lists", async () => [{}, engineReturning(goodResult({ matched: "x" }))]],
    ["missing reason", async () => [{}, engineReturning(goodResult({ reason: 1 }))]],
    [
      "unknown gate type",
      async () => [
        {},
        engineReturning(goodResult({ gates: [{ id: "g", type: "mystery", params: {} }] })),
      ],
    ],
    [
      "gate with bad params",
      async () => [
        {},
        engineReturning(goodResult({ gates: [{ id: "g", type: "amount_cap", params: {} }] })),
      ],
    ],
  ];
  it.each(cases)("%s", async (_name, make) => {
    const [over, engine] = await make();
    const h = await harness(over, engine);
    const r = await h.kernel.evaluate(req());
    expect(r.decision).toBe("DENY");
  });

  it("policy timeout (async engine that hangs)", async () => {
    const h = await harness(
      { policyTimeoutMs: 20 },
      { evaluate: () => new Promise(() => undefined) },
    );
    const r = await h.kernel.evaluate(req());
    expect(r).toMatchObject({ decision: "DENY", reason: "policy evaluation timed out" });
  });

  it("policy over budget (slow synchronous engine) is denied even though it returned a value", async () => {
    const slow: PolicyEngine = {
      evaluate: () => {
        const end = performance.now() + 15;
        while (performance.now() < end) {
          /* burn CPU */
        }
        return Promise.resolve(goodResult());
      },
    };
    const h = await harness({ policyTimeoutMs: 5 }, slow);
    expect((await h.kernel.evaluate(req())).decision).toBe("DENY");
  });

  it("audit sink failure turns an ALLOW into DENY with no audit id", async () => {
    const h = await harness({ audit: { append: () => Promise.reject(new Error("db down")) } });
    const r = await h.kernel.evaluate(req());
    expect(r).toMatchObject({ decision: "DENY", reason: "audit unavailable", audit_event_id: "" });
    expect(h.logs).toContain("error:audit append failed; denying");
  });

  it("audit sink that throws synchronously also denies", async () => {
    const h = await harness({
      audit: {
        append: () => {
          throw new Error("sync");
        },
      },
    });
    expect((await h.kernel.evaluate(req())).decision).toBe("DENY");
  });

  it("kill-switch store failure denies", async () => {
    const h = await harness();
    h.kill.isEngaged = () => Promise.reject(new Error("redis down"));
    const r = await h.kernel.evaluate(req());
    expect(r).toMatchObject({ decision: "DENY", reason: "kill-switch state unavailable" });
  });

  it("gate commit failure denies", async () => {
    const gates = [
      {
        id: "cap",
        type: "target_cap",
        params: { field: "args.amount", max: 100, perTarget: true },
      },
    ];
    const h = await harness({}, engineReturning(goodResult({ gates })));
    h.counters.add = () => Promise.reject(new Error("redis down"));
    const r = await h.kernel.evaluate(
      req({ context: { tool: { name: "t" }, args: { amount: 5, target: "v" } } }),
    );
    expect(r).toMatchObject({ decision: "DENY", reason: "gate state unavailable" });
  });

  it("an unexpected internal exception still yields DENY", async () => {
    const h = await harness();
    const r = await h.kernel.evaluate({
      get tenant_id(): string {
        throw new Error("getter");
      },
    });
    expect(r).toMatchObject({ decision: "DENY", reason: "internal error" });
  });

  it("the context cannot contain values that break hashing (NaN) - request is denied, not crashed", async () => {
    const h = await harness();
    const r = await h.kernel.evaluate(
      req({ context: { tool: { name: "lookup", side_effects: "read" }, args: { n: NaN } } }),
    );
    expect(r.decision).toBe("DENY");
  });

  it("malformed policy output reveals nothing beyond a reason", async () => {
    const h = await harness({}, engineReturning({ decision: "ALLOW", leaked: "secret" }));
    const r = await h.kernel.evaluate(req());
    expect(JSON.stringify(r)).not.toContain("secret");
  });
});

describe("request validation", () => {
  const bad: [string, unknown][] = [
    ["null", null],
    ["array", []],
    ["tenant not uuid", { ...req(), tenant_id: "nope" }],
    ["uppercase tenant uuid", { ...req(), tenant_id: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" }],
    ["bad trace", { ...req(), trace_id: "xyz" }],
    ["actor missing", { ...req(), actor: undefined }],
    ["actor type unknown", { ...req(), actor: { type: "robot", id: "x" } }],
    ["agent without pid", { ...req(), actor: { type: "agent", id: "x" } }],
    ["agent bad pid", { ...req(), actor: { type: "agent", id: "x", pid: "pid_1" } }],
    ["human with bad pid", { ...req(), actor: { type: "human", id: "x", pid: 5 } }],
    ["blueprint missing", { ...req(), blueprint: undefined }],
    ["blueprint empty name", { ...req(), blueprint: { name: "", version: "1" } }],
    ["unknown enforcement point", { ...req(), enforcement_point: "telepathy" }],
    ["action empty", { ...req(), action: "" }],
    ["action too long", { ...req(), action: "x".repeat(300) }],
    ["context not object", { ...req(), context: "x" }],
    ["context array", { ...req(), context: [] }],
  ];
  it.each(bad)("%s is denied and not audited", async (_n, input) => {
    const h = await harness();
    const r = await h.kernel.evaluate(input);
    expect(r).toMatchObject({ decision: "DENY", audit_event_id: "" });
    expect(r.reason).toMatch(/invalid request|internal error/);
    expect(h.audit.events.size).toBe(0);
  });

  it("accepts human and system actors without a pid", async () => {
    const h = await harness();
    for (const actor of [
      { type: "human", id: "u1" },
      { type: "system", id: "scheduler" },
    ] as const) {
      expect((await h.kernel.evaluate(req({ actor }))).decision).toBe("ALLOW");
    }
  });
});

describe("kill-switches", () => {
  it.each([
    ["global", {}, "global"],
    ["tenant", { tenantId: T1 }, "tenant"],
    ["agent", { tenantId: T1, target: "claims-triage" }, "agent"],
    ["tool", { tenantId: T1, target: "lookup" }, "tool"],
  ] as const)(
    "%s kill-switch denies an otherwise allowed request, audited, then releases",
    async (scope, target, label) => {
      const h = await harness();
      expect((await h.kernel.evaluate(req())).decision).toBe("ALLOW");
      await h.kill.set(scope, target, true);
      const denied = await h.kernel.evaluate(req());
      expect(denied).toMatchObject({ decision: "DENY", reason: `kill-switch engaged (${label})` });
      expect(h.audit.events.get(T1)?.at(-1)).toMatchObject({
        decision: "DENY",
        id: denied.audit_event_id,
      });
      await h.kill.set(scope, target, false);
      expect((await h.kernel.evaluate(req())).decision).toBe("ALLOW");
    },
  );

  it("tenant kill-switches do not affect other tenants; global affects all", async () => {
    const h = await harness();
    await h.kill.set("tenant", { tenantId: T1 }, true);
    expect((await h.kernel.evaluate(req({ tenant_id: T2 }))).decision).toBe("ALLOW");
    await h.kill.set("global", {}, true);
    expect((await h.kernel.evaluate(req({ tenant_id: T2 }))).decision).toBe("DENY");
  });

  it("is effective on the very next decision (propagation well under 1 s)", async () => {
    const h = await harness();
    const t0 = performance.now();
    await h.kill.set("tenant", { tenantId: T1 }, true);
    const r = await h.kernel.evaluate(req());
    expect(r.decision).toBe("DENY");
    expect(performance.now() - t0).toBeLessThan(1000);
  });
});

describe("stateful gates through the kernel", () => {
  it("rate limit: the 31st call within a minute is denied, then recovers", async () => {
    const h = await harness();
    const decisions: string[] = [];
    for (let i = 0; i < 31; i++) decisions.push((await h.kernel.evaluate(req())).decision);
    expect(decisions.slice(0, 30).every((d) => d === "ALLOW")).toBe(true);
    expect(decisions[30]).toBe("DENY");
    h.clock.now += 61_000;
    expect((await h.kernel.evaluate(req())).decision).toBe("ALLOW");
  });

  it("target cap commits only for allowed requests", async () => {
    const h = await harness(
      {},
      engineReturning(
        goodResult({
          decision: "ALLOW",
          gates: [
            {
              id: "cap",
              type: "target_cap",
              params: { field: "args.amount", max: 100, perTarget: true },
            },
            { id: "amt", type: "amount_cap", params: { field: "args.amount", max: 60 } },
          ],
        }),
      ),
    );
    const call = (amount: number) =>
      h.kernel.evaluate(req({ context: { tool: { name: "t" }, args: { amount, target: "v" } } }));
    expect((await call(70)).decision).toBe("DENY"); // amount_cap fails: must not have been counted
    expect((await call(60)).decision).toBe("ALLOW");
    expect((await call(60)).decision).toBe("DENY"); // 60 + 60 > 100
    expect((await call(40)).decision).toBe("ALLOW");
  });
});

describe("audit content and confidentiality", () => {
  it("records hashes, never raw arguments, and reasons never echo request values", async () => {
    const h = await harness();
    const secret = "SSN-123-45-6789";
    const r = await h.kernel.evaluate(payments(99999, { note: secret }));
    const chain = JSON.stringify(h.audit.events.get(T1));
    expect(chain).not.toContain(secret);
    expect(JSON.stringify(r)).not.toContain(secret);
    const e = h.audit.events.get(T1)?.[0];
    expect(e?.inputs_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(e?.outputs_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(e?.actor.pid).toBe(PID);
  });

  it("the audit chain stays valid across many decisions for two tenants", async () => {
    const h = await harness();
    for (let i = 0; i < 10; i++) {
      await h.kernel.evaluate(req());
      await h.kernel.evaluate(
        req({ tenant_id: T2, context: { tool: { name: "x", side_effects: "write" } } }),
      );
    }
    expect(verifyChain(h.audit.events.get(T1) ?? [])).toEqual({ ok: true, length: 10 });
    expect(verifyChain(h.audit.events.get(T2) ?? [])).toEqual({ ok: true, length: 10 });
  });

  it("long reasons are truncated to the audit schema limit", async () => {
    const h = await harness(
      {},
      engineReturning(goodResult({ decision: "DENY", reason: "x".repeat(5000) })),
    );
    const r = await h.kernel.evaluate(req());
    expect(r.reason).toHaveLength(1000);
  });
});

describe("the caller cannot spoof kernel-owned policy inputs", () => {
  it("context.tenant / agent / actor / enforcement_point are overwritten", async () => {
    const seen: Record<string, unknown>[] = [];
    const h = await harness(
      {},
      { evaluate: (input) => (seen.push(input), Promise.resolve(goodResult())) },
    );
    await h.kernel.evaluate(
      req({
        context: {
          tenant: { id: "evil" },
          agent: { name: "admin" },
          actor: { id: "root" },
          enforcement_point: "x",
          tool: { name: "t" },
        },
      }),
    );
    expect(seen[0]).toMatchObject({
      tenant: { id: T1 },
      agent: { name: "claims-triage", version: "1.0.0" },
      actor: { type: "agent", id: "claims-triage" },
      enforcement_point: "tool_call",
      tool: { name: "t" },
    });
  });
});

describe("performance budget (NFR: gate adds < 25 ms p99; policy decision p99 < 10 ms)", () => {
  it("in-process p99 is far below the budget", async () => {
    const h = await harness({ policyTimeoutMs: 1000 });
    for (let i = 0; i < 200; i++)
      await h.kernel.evaluate(
        req({ tenant_id: T2, context: { tool: { name: "x", side_effects: "write" } } }),
      ); // warm up
    const times: number[] = [];
    for (let i = 0; i < 500; i++) {
      h.clock.now += 120_000; // keep the rate limiter out of the way
      const t = performance.now();
      await h.kernel.evaluate(req());
      times.push(performance.now() - t);
    }
    times.sort((a, b) => a - b);
    const p99 = times[Math.floor(times.length * 0.99)] as number;
    expect(p99).toBeLessThan(25);
  });
});

describe("constructor defaults", () => {
  it("works with only the required dependencies", async () => {
    const h = await harness();
    const k = new RiskKernel({
      engine: await import("./helpers.js").then((m) => m.defaultEngine()),
      audit: h.audit,
      killSwitches: h.kill,
      counters: h.counters,
    });
    expect((await k.evaluate(req())).decision).toBe("ALLOW");
    expect((await k.evaluate(null)).decision).toBe("DENY");
  });
});
