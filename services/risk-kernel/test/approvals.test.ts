import { hashJson } from "@axis/contracts";
import { describe, expect, it } from "vitest";
import {
  MemoryConsumedApprovals,
  type ApprovalRequestInput,
  type ApprovalRequester,
  type ApprovalVerifier,
  type ExpectedApproval,
  type PolicyEngine,
} from "../src/index.js";
import { PID, T1, T2, defaultEngine, harness, req } from "./helpers.js";

const RUN = "run_abc";
const ARGS = { amount: 5000, payee: "acme" };
const RECORD = { request_id: "ap-1", outcome: "APPROVED", signature: "sig" };

const payments = (over: { args?: Record<string, unknown>; run?: unknown; tenant?: string } = {}) =>
  req({
    tenant_id: over.tenant ?? T1,
    action: "payments",
    context: {
      tool: { name: "payments", kind: "function", side_effects: "external" },
      args: over.args ?? ARGS,
      ...(over.run === undefined
        ? { run: { id: RUN } }
        : over.run === null
          ? {}
          : { run: over.run }),
    },
  });

const withRecord = (r: ReturnType<typeof payments>, record: unknown = RECORD) => ({
  ...r,
  context: { ...r.context, approval: record },
});

class FakeRequester implements ApprovalRequester {
  inputs: ApprovalRequestInput[] = [];
  next: () => Promise<{ id: string }> = () => Promise.resolve({ id: `ap-${this.inputs.length}` });
  create(input: ApprovalRequestInput): Promise<{ id: string }> {
    this.inputs.push(input);
    return this.next();
  }
}

class FakeVerifier implements ApprovalVerifier {
  calls: { record: unknown; expected: ExpectedApproval }[] = [];
  answer: () => Promise<boolean> = () => Promise.resolve(true);
  verify(record: unknown, expected: ExpectedApproval): Promise<boolean> {
    this.calls.push({ record, expected });
    return this.answer();
  }
}

describe("approval request (REQUIRE_APPROVAL)", () => {
  it("opens a request bound to tenant/run/tool/args-hash and returns its id; the id is in the audited reason", async () => {
    const requester = new FakeRequester();
    const h = await harness({ approvalRequester: requester });
    const r = await h.kernel.evaluate(payments());
    expect(r.decision).toBe("REQUIRE_APPROVAL");
    expect(r.approval_id).toBe("ap-1");
    expect(requester.inputs).toHaveLength(1);
    expect(requester.inputs[0]).toMatchObject({
      tenant_id: T1,
      run_id: RUN,
      trace_id: "a".repeat(32),
      tool: "payments",
      args_hash: hashJson(ARGS),
      risk_level: "high",
      requester: { type: "agent", id: "claims-triage", pid: PID },
      agent: { name: "claims-triage", version: "1.0.0" },
      approval: { roles: ["finance-approver"], sla_seconds: 900, on_timeout: "DENY" },
      policy_version: "baseline-deny@1.0.0,phi-redaction@1.1.0",
    });
    const row = h.audit.events.get(T1)?.[0];
    expect(row).toMatchObject({ decision: "REQUIRE_APPROVAL", id: r.audit_event_id });
    expect(row?.reason).toContain("request=ap-1");
  });

  it("without a requester the outcome is unchanged: REQUIRE_APPROVAL with an empty id (clients deny)", async () => {
    const h = await harness();
    const r = await h.kernel.evaluate(payments());
    expect(r).toMatchObject({ decision: "REQUIRE_APPROVAL", approval_id: "" });
  });

  it.each([
    ["the service rejects", () => Promise.reject(new Error("approvals down"))],
    ["the service returns no id", () => Promise.resolve({ id: "" })],
    ["the service returns nothing", () => Promise.resolve(undefined as unknown as { id: string })],
  ])("DENY when %s", async (_n, next) => {
    const requester = new FakeRequester();
    requester.next = next;
    const h = await harness({ approvalRequester: requester });
    const r = await h.kernel.evaluate(payments());
    expect(r).toMatchObject({
      decision: "DENY",
      reason: "approval request could not be created",
      approval_id: "",
    });
    expect(h.audit.events.get(T1)?.[0]?.decision).toBe("DENY"); // the denial is audited
  });

  it("DENY when the request carries no run id (the approval could not be bound)", async () => {
    const requester = new FakeRequester();
    const h = await harness({ approvalRequester: requester });
    for (const run of [null, { id: "" }, { id: 7 }]) {
      const r = await h.kernel.evaluate(payments({ run }));
      expect(r).toMatchObject({ decision: "DENY", reason: "approval needs context.run.id" });
    }
    expect(requester.inputs).toEqual([]);
  });

  it("a failing gate denies BEFORE any request is opened", async () => {
    const requester = new FakeRequester();
    const h = await harness({ approvalRequester: requester });
    const r = await h.kernel.evaluate(payments({ args: { amount: 20000 } }));
    expect(r.decision).toBe("DENY");
    expect(r.reason).toContain("amount-cap");
    expect(requester.inputs).toEqual([]);
  });

  it("capacity reserved by gates is released for a pending approval (nothing executes)", async () => {
    const capped: PolicyEngine = {
      evaluate: () =>
        Promise.resolve({
          decision: "REQUIRE_APPROVAL",
          reason: "needs a human",
          matched: ["p/r"],
          winners: ["p/r"],
          gates: [
            {
              id: "cap",
              type: "target_cap",
              params: { field: "args.amount", max: 100, perTarget: true },
            },
          ],
          redact: [],
          approval: { roles: ["r"], sla_seconds: 60, escalate_to: [], on_timeout: "DENY" },
          policy_version: "p@1",
        }),
    };
    const h = await harness({ approvalRequester: new FakeRequester() }, capped);
    const call = payments({ args: { amount: 100, target: "v" } });
    for (let i = 0; i < 3; i++) {
      // were pending requests to keep their reservation, the second would trip the cap of 100
      expect((await h.kernel.evaluate(call)).decision).toBe("REQUIRE_APPROVAL");
    }
  });

  it("a DENY from the audit append after creating the request is still a DENY", async () => {
    const requester = new FakeRequester();
    const h = await harness({
      approvalRequester: requester,
      audit: { append: () => Promise.reject(new Error("down")) },
    });
    const r = await h.kernel.evaluate(payments());
    expect(r).toMatchObject({ decision: "DENY", reason: "audit unavailable", approval_id: "" });
  });
});

describe("re-gating an approved action", () => {
  const setup = async () => {
    const requester = new FakeRequester();
    const verifier = new FakeVerifier();
    const h = await harness({ approvalRequester: requester, approvalVerifier: verifier });
    return { h, requester, verifier };
  };

  it("ALLOWs when the record verifies for exactly this tenant/run/tool/args, and audits an ALLOW", async () => {
    const { h, verifier, requester } = await setup();
    const r = await h.kernel.evaluate(withRecord(payments()));
    expect(r.decision).toBe("ALLOW");
    expect(r.approval_id).toBe("ap-1");
    expect(r.reason).toContain("approved: request=ap-1");
    expect(verifier.calls).toEqual([
      {
        record: RECORD,
        expected: { tenant_id: T1, run_id: RUN, tool: "payments", args_hash: hashJson(ARGS) },
      },
    ]);
    expect(requester.inputs).toEqual([]); // no second request
    const row = h.audit.events.get(T1)?.[0];
    expect(row).toMatchObject({ decision: "ALLOW", action: "payments", id: r.audit_event_id });
  });

  it("is single-use: the same record cannot authorise a second execution", async () => {
    const { h } = await setup();
    expect((await h.kernel.evaluate(withRecord(payments()))).decision).toBe("ALLOW");
    const again = await h.kernel.evaluate(withRecord(payments()));
    expect(again).toMatchObject({ decision: "DENY", reason: "approval already used" });
  });

  it("single-use is per tenant: the same request id for another tenant is a different approval", async () => {
    const { h } = await setup();
    expect((await h.kernel.evaluate(withRecord(payments()))).decision).toBe("ALLOW");
    expect((await h.kernel.evaluate(withRecord(payments({ tenant: T2 })))).decision).toBe("ALLOW");
  });

  it.each([
    ["verifier says no", () => Promise.resolve(false)],
    ["verifier throws", () => Promise.reject(new Error("boom"))],
  ])("DENY when the %s", async (_n, answer) => {
    const { h, verifier } = await setup();
    verifier.answer = answer;
    const r = await h.kernel.evaluate(withRecord(payments()));
    expect(r.decision).toBe("DENY");
    expect(r.approval_id).toBe("");
    expect(h.audit.events.get(T1)?.[0]?.decision).toBe("DENY");
  });

  it.each([
    ["no request_id", {}],
    ["empty request_id", { request_id: "" }],
    ["numeric request_id", { request_id: 4 }],
  ])("DENY when the verified record has %s", async (_n, record) => {
    const { h } = await setup();
    const r = await h.kernel.evaluate(withRecord(payments(), record));
    expect(r).toMatchObject({
      decision: "DENY",
      reason: "approval record not valid for this action",
    });
  });

  it("DENY when the request has no run id", async () => {
    const { h, verifier } = await setup();
    const r = await h.kernel.evaluate(withRecord(payments({ run: null })));
    expect(r).toMatchObject({ decision: "DENY", reason: "approval needs context.run.id" });
    expect(verifier.calls).toEqual([]);
  });

  it("a call without args hashes as the empty document on both paths", async () => {
    const { h, verifier, requester } = await setup();
    const noArgs = req({
      action: "payments",
      context: { tool: { name: "payments", side_effects: "none" }, run: { id: RUN } },
    });
    expect((await h.kernel.evaluate(noArgs)).decision).toBe("ALLOW"); // read-class: no approval involved
    expect(verifier.calls).toEqual([]);
    expect(requester.inputs).toEqual([]);
  });

  it("never bypasses the gate: a failing cap gate still denies, and the approval is NOT consumed", async () => {
    const { h, verifier } = await setup();
    const big = withRecord(payments({ args: { amount: 20000 } }));
    const r = await h.kernel.evaluate(big);
    expect(r.decision).toBe("DENY");
    expect(r.reason).toContain("amount-cap");
    expect(verifier.calls).toEqual([]);
    expect((await h.kernel.evaluate(withRecord(payments()))).decision).toBe("ALLOW");
  });

  it("never bypasses a kill-switch", async () => {
    const { h, verifier } = await setup();
    await h.kill.set("tenant", { tenantId: T1, target: undefined }, true);
    const r = await h.kernel.evaluate(withRecord(payments()));
    expect(r).toMatchObject({ decision: "DENY", reason: "kill-switch engaged (tenant)" });
    expect(verifier.calls).toEqual([]);
  });

  it("never bypasses a DENY policy outcome", async () => {
    const verifier = new FakeVerifier();
    const deny: PolicyEngine = {
      evaluate: () =>
        Promise.resolve({
          decision: "DENY",
          reason: "explicit deny",
          matched: ["p/deny"],
          winners: ["p/deny"],
          gates: [],
          redact: [],
          approval: null,
          policy_version: "p@1",
        }),
    };
    const h = await harness({ approvalVerifier: verifier }, deny);
    const r = await h.kernel.evaluate(withRecord(payments()));
    expect(r).toMatchObject({ decision: "DENY", reason: "explicit deny" });
    expect(verifier.calls).toEqual([]);
  });

  it("a record cannot turn a non-approval outcome into anything else (ALLOW stays ALLOW, default DENY stays DENY)", async () => {
    const { h, verifier } = await setup();
    const unknownTool = req({
      action: "crm",
      context: {
        tool: { name: "crm", side_effects: "write" },
        args: {},
        run: { id: RUN },
        approval: RECORD,
      },
    });
    expect((await h.kernel.evaluate(unknownTool)).decision).toBe("DENY");
    expect((await h.kernel.evaluate(withRecord(req()))).decision).toBe("ALLOW");
    expect(verifier.calls).toEqual([]);
  });

  it("without a verifier a presented record is ignored: a NEW request is opened, nothing is allowed", async () => {
    const requester = new FakeRequester();
    const h = await harness({ approvalRequester: requester });
    const r = await h.kernel.evaluate(withRecord(payments()));
    expect(r).toMatchObject({ decision: "REQUIRE_APPROVAL", approval_id: "ap-1" });
  });

  it("the record is evidence for the kernel, not policy input", async () => {
    let seen: Record<string, unknown> = {};
    const real = await defaultEngine();
    const spy: PolicyEngine = {
      evaluate: (input) => {
        seen = input;
        return real.evaluate(input);
      },
    };
    const h = await harness({ approvalVerifier: new FakeVerifier() }, spy);
    await h.kernel.evaluate(withRecord(payments()));
    expect("approval" in seen).toBe(false);
    expect(seen["run"]).toEqual({ id: RUN });
  });

  it("an audit failure on the approved path does not burn the approval", async () => {
    let down = true;
    const verifier = new FakeVerifier();
    const h = await harness({
      approvalVerifier: verifier,
      audit: {
        append: (e) =>
          down
            ? Promise.reject(new Error("down"))
            : Promise.resolve({ ...e, seq: 1, prev_hash: "0".repeat(64), hash: "f".repeat(64) }),
      },
    });
    expect((await h.kernel.evaluate(withRecord(payments()))).reason).toBe("audit unavailable");
    down = false;
    expect((await h.kernel.evaluate(withRecord(payments()))).decision).toBe("ALLOW");
  });

  it("an injected consumed-approvals store is used", async () => {
    const consumed = new MemoryConsumedApprovals();
    await consumed.consume(T1, "ap-1");
    const h = await harness({ approvalVerifier: new FakeVerifier(), consumedApprovals: consumed });
    expect((await h.kernel.evaluate(withRecord(payments()))).reason).toBe("approval already used");
  });

  it("a consumed-approvals store that throws is DENY", async () => {
    const h = await harness({
      approvalVerifier: new FakeVerifier(),
      consumedApprovals: {
        consume: () => Promise.reject(new Error("redis down")),
        release: () => Promise.resolve(),
      },
    });
    expect((await h.kernel.evaluate(withRecord(payments()))).reason).toBe(
      "approval verification failed",
    );
  });

  it("concurrent re-submissions of one approval: exactly one wins", async () => {
    const { h } = await setup();
    const out = await Promise.all(
      Array.from({ length: 8 }, () => h.kernel.evaluate(withRecord(payments()))),
    );
    expect(out.filter((r) => r.decision === "ALLOW")).toHaveLength(1);
  });
});

describe("MemoryConsumedApprovals", () => {
  it("consume is once-only and release undoes it", async () => {
    const c = new MemoryConsumedApprovals();
    expect(await c.consume(T1, "a")).toBe(true);
    expect(await c.consume(T1, "a")).toBe(false);
    expect(await c.consume(T2, "a")).toBe(true);
    await c.release(T1, "a");
    expect(await c.consume(T1, "a")).toBe(true);
  });
});
