import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  Explainer,
  EXPLANATION_KEYS,
  describeGate,
  remediationFor,
  sanitizeText,
  withNarration,
  narratorInput,
  type PolicyMetadataSource,
} from "../src/index.js";
import { ev, hex32, world } from "./helpers.js";

describe("Explainer.explainEvent", () => {
  it("explains a policy-rule denial: what happened, which rule, which pack, what would allow it", async () => {
    const w = world();
    const trace = hex32();
    await w.log.append(ev(w.tenant, { trace_id: trace }));
    const denied = await w.log.append(
      ev(w.tenant, {
        trace_id: trace,
        action: "send-report",
        decision: "DENY",
        reason: "tenant-acme/deny-restricted",
      }),
    );
    const x = await new Explainer({ audit: w.reader }).explainEvent(w.tenant, denied.seq);
    expect(x).toBeDefined();
    expect(Object.keys(x!)).toEqual([...EXPLANATION_KEYS]);
    expect(x!.summary).toContain('"send-report" was denied');
    expect(x!.summary).toContain("tenant-acme/deny-restricted");
    expect(x!.decision_refs).toHaveLength(1);
    expect(x!.decision_refs[0]).toMatchObject({
      audit_event_id: denied.id,
      seq: denied.seq,
      decision: "DENY",
      gate: "policy_rule",
      rule_ids: ["tenant-acme/deny-restricted"],
      policy_packs: ["tenant-acme@1.0.0"],
    });
    expect(x!.steps.map((s) => s.n)).toEqual([1, 2, 3, 4]);
    expect(x!.steps[3]?.text).toContain("1 earlier event");
    expect(x!.remediation[0]).toMatchObject({
      kind: "review_policy_rule",
      hint: "tenant-acme/deny-restricted",
    });
  });

  it("explains a kill-switch denial and points at the release call", async () => {
    const w = world();
    const e = await w.log.append(
      ev(w.tenant, {
        decision: "DENY",
        reason: "kill-switch engaged (tenant)",
        policy_version: "none",
      }),
    );
    const x = (await new Explainer({ audit: w.reader }).explainEvent(w.tenant, e.seq))!;
    expect(x.decision_refs[0]).toMatchObject({
      gate: "kill_switch",
      kill_switch_scope: "tenant",
      policy_packs: [],
    });
    expect(x.steps[1]?.text).toContain("No policy version is recorded");
    expect(x.remediation[0]).toMatchObject({ kind: "release_kill_switch" });
  });

  it("explains caps, budgets, rate limits, staleness, default deny, audit and evaluation failures", async () => {
    const w = world();
    const reasons: [string, string][] = [
      ["gate base/cap: amount exceeds cap 500", "raise the cap"],
      ["gate base/day: cumulative cap 1000 would be exceeded", "resets at 00:00 UTC"],
      ["gate base/b: hard tokens budget reached", "Raise the tokens limit"],
      ["gate base/r: rate limit 5/60s exceeded", "Retry after"],
      ["gate base/s: args.ts older than 30s", "fresh args.ts"],
      ["no matching rule (default deny)", "allows"],
      ["audit unavailable", "fail-closed"],
      ["internal error", "fail-closed"],
      ["invalid request: bad", "Correct the request"],
      ["weird", "Inspect"],
    ];
    const ex = new Explainer({ audit: w.reader });
    for (const [reason, hint] of reasons) {
      const e = await w.log.append(ev(w.tenant, { decision: "DENY", reason }));
      const x = (await ex.explainEvent(w.tenant, e.seq))!;
      expect(x.remediation.map((r) => r.text).join("|"), reason).toContain(hint);
      expect(x.summary.length).toBeGreaterThan(20);
    }
  });

  it("explains an approval request with the call that decides it", async () => {
    const w = world();
    const id = randomUUID();
    const e = await w.log.append(
      ev(w.tenant, { decision: "REQUIRE_APPROVAL", reason: `tenant-acme/needs-ok; request=${id}` }),
    );
    const x = (await new Explainer({ audit: w.reader }).explainEvent(w.tenant, e.seq))!;
    expect(x.decision_refs[0]).toMatchObject({ gate: "approval", approval_id: id });
    expect(x.remediation.some((r) => r.hint === `POST /v1/approvals/${id}/decision`)).toBe(true);
  });

  it("an allowed event needs no remediation", async () => {
    const w = world();
    const e = await w.log.append(ev(w.tenant));
    const x = (await new Explainer({ audit: w.reader }).explainEvent(w.tenant, e.seq))!;
    expect(x.remediation).toEqual([]);
    expect(x.summary).toContain("was allowed");
  });

  it("uses tenant-owned rule metadata for phrasing, and survives a failing metadata source", async () => {
    const w = world();
    const e = await w.log.append(
      ev(w.tenant, { decision: "DENY", reason: "tenant-acme/deny-restricted" }),
    );
    const src: PolicyMetadataSource = {
      describeRules: async (t, ids) =>
        t === w.tenant
          ? ids.map((id) => ({ id, description: "No access to restricted claims" }))
          : [],
    };
    const x = (await new Explainer({ audit: w.reader, policies: src }).explainEvent(
      w.tenant,
      e.seq,
    ))!;
    expect(x.remediation[0]?.text).toContain("No access to restricted claims");
    const broken: PolicyMetadataSource = {
      describeRules: async () => Promise.reject(new Error("boom")),
    };
    const y = (await new Explainer({ audit: w.reader, policies: broken }).explainEvent(
      w.tenant,
      e.seq,
    ))!;
    expect(y.remediation[0]?.kind).toBe("review_policy_rule");
  });

  it("never explains another tenant's event, an unknown seq or a malformed seq", async () => {
    const w = world();
    const mine = await w.log.append(ev(w.tenant));
    const theirs = await w.log.append(
      ev(w.other, { decision: "DENY", reason: "tenant-beta/secret-rule" }),
    );
    const ex = new Explainer({ audit: w.reader });
    expect(await ex.explainEvent(w.tenant, mine.seq + 5)).toBeUndefined();
    expect(await ex.explainEvent(w.tenant, 0)).toBeUndefined();
    expect(await ex.explainEvent(w.tenant, 1.5)).toBeUndefined();
    expect(await ex.explainEvent(w.tenant, Number.NaN)).toBeUndefined();
    // seq 1 exists in both chains: each tenant sees only its own
    expect(theirs.seq).toBe(mine.seq);
    const x = (await ex.explainEvent(w.tenant, mine.seq))!;
    expect(JSON.stringify(x)).not.toContain("tenant-beta");
  });

  it("a reader that leaks another tenant's rows is ignored (defence in depth)", async () => {
    const w = world();
    const theirs = await w.log.append(
      ev(w.other, { decision: "DENY", reason: "tenant-beta/secret-rule" }),
    );
    const leaky = { listEvents: async () => [theirs] };
    const ex = new Explainer({ audit: leaky });
    expect(await ex.explainEvent(w.tenant, theirs.seq)).toBeUndefined();
    const run = await ex.explainRun(w.tenant, { traceId: theirs.trace_id });
    expect(JSON.stringify(run)).not.toContain("tenant-beta");
    expect(run.decision_refs).toEqual([]);
  });
});

describe("Explainer.explainRun", () => {
  it("summarises a run: counts, first denial, approvals, remediation without duplicates, and how it ended", async () => {
    const w = world();
    const trace = hex32();
    await w.log.append(
      ev(w.tenant, { trace_id: trace, action: "model.invoke", enforcement_point: "model_call" }),
    );
    await w.log.append(ev(w.tenant, { trace_id: trace, action: "lookup-claim" }));
    const d1 = await w.log.append(
      ev(w.tenant, {
        trace_id: trace,
        action: "lookup-restricted",
        decision: "DENY",
        reason: "tenant-acme/deny-restricted",
      }),
    );
    await w.log.append(
      ev(w.tenant, {
        trace_id: trace,
        action: "lookup-restricted",
        decision: "DENY",
        reason: "tenant-acme/deny-restricted",
      }),
    );
    await w.log.append(
      ev(w.tenant, {
        trace_id: trace,
        action: "send-report",
        decision: "REQUIRE_APPROVAL",
        reason: `tenant-acme/needs-ok; request=${randomUUID()}`,
      }),
    );
    await w.log.append(
      ev(w.tenant, { trace_id: hex32(), action: "other-trace", decision: "DENY", reason: "x/y" }),
    );
    const x = await new Explainer({ audit: w.reader }).explainRun(w.tenant, {
      traceId: trace,
      runEvents: [
        {
          sequence: 2,
          type: "process_transition",
          pid: "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV",
          at: "2026-10-01T00:00:00.000Z",
          data: { to: "terminated", exit_reason: "policy_denied" },
        },
        {
          sequence: 1,
          type: "budget_warning",
          pid: "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV",
          at: "2026-10-01T00:00:00.000Z",
          data: {},
        },
        {
          sequence: 3,
          type: "action_blocked",
          pid: "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV",
          at: "2026-10-01T00:00:00.000Z",
          data: {},
        },
      ],
    });
    expect(x.summary).toContain("5 gated actions: 2 allowed, 1 sent for approval, 2 denied.");
    expect(x.summary).toContain(`First denial: "lookup-restricted" at tool_call (#${d1.seq})`);
    expect(x.summary).toContain('exit reason "policy_denied"');
    expect(x.decision_refs.map((r) => r.decision)).toEqual(["DENY", "DENY", "REQUIRE_APPROVAL"]);
    const texts = x.remediation.map((r) => r.text);
    expect(new Set(texts).size).toBe(texts.length);
    expect(x.steps.at(-1)?.text).toContain("exit reason");
    expect(x.steps.every((s, i) => s.n === i + 1)).toBe(true);
  });

  it("explains an empty trace honestly and ignores malformed trace ids", async () => {
    const w = world();
    const ex = new Explainer({ audit: w.reader });
    const x = await ex.explainRun(w.tenant, { traceId: hex32() });
    expect(x.summary).toContain("nothing to explain yet");
    expect(x.decision_refs).toEqual([]);
    const bad = await ex.explainRun(w.tenant, { traceId: "../../etc" });
    expect(bad.decision_refs).toEqual([]);
  });

  it("reports an unfinished run and a clean one", async () => {
    const w = world();
    const trace = hex32();
    await w.log.append(ev(w.tenant, { trace_id: trace }));
    const ex = new Explainer({ audit: w.reader });
    const open = await ex.explainRun(w.tenant, {
      traceId: trace,
      runEvents: [
        {
          sequence: 1,
          type: "run_started",
          pid: "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV",
          at: "2026-10-01T00:00:00.000Z",
        },
      ],
    });
    expect(open.summary).toContain("had not finished");
    expect(open.summary).toContain("1 gated action: 1 allowed, 0 sent for approval, 0 denied.");
    expect(open.remediation).toEqual([]);
    const none = await ex.explainRun(w.tenant, { traceId: trace, runEvents: [] });
    expect(none.summary).not.toContain("finished");
  });

  it("caps the number of steps", async () => {
    const w = world();
    const trace = hex32();
    for (let i = 0; i < 90; i++)
      await w.log.append(
        ev(w.tenant, {
          trace_id: trace,
          decision: "DENY",
          reason: "gate p/g: hard tokens budget reached",
        }),
      );
    const x = await new Explainer({ audit: w.reader }).explainRun(w.tenant, { traceId: trace });
    expect(x.steps.length).toBe(60);
  });

  it("is deterministic: same audit rows, same explanation", async () => {
    const w = world();
    const trace = hex32();
    await w.log.append(
      ev(w.tenant, {
        trace_id: trace,
        decision: "DENY",
        reason: "no matching rule (default deny)",
      }),
    );
    const ex = new Explainer({ audit: w.reader });
    expect(await ex.explainRun(w.tenant, { traceId: trace })).toEqual(
      await ex.explainRun(w.tenant, { traceId: trace }),
    );
  });
});

describe("sanitizeText", () => {
  it("masks credential-shaped text, strips control characters and bounds length", () => {
    const s = sanitizeText(
      "bad sk-abcdefghijkl and Bearer abcdefghijk1234 and axk_0123456789abcdef_" +
        "A".repeat(43) +
        "\u0000\n password=hunter2",
    );
    expect(s).not.toMatch(/sk-abc|abcdefghijk1234|axk_0123|hunter2/);
    expect(s).toContain("[redacted]");
    expect(s).not.toMatch(/\p{Cc}/u);
    expect(sanitizeText("x".repeat(1000)).length).toBe(300);
  });
});

describe("narrator is off by default and only sees PHI-safe fields", () => {
  const base = {
    summary: "s",
    steps: [],
    remediation: [{ kind: "inspect" as const, text: "t" }],
    decision_refs: [
      {
        audit_event_id: randomUUID(),
        seq: 1,
        ts: "2026-10-01T00:00:00.000Z",
        decision: "DENY" as const,
        enforcement_point: "tool_call",
        action: "lookup-claim-for-jane-doe",
        policy_version: "p@1",
        policy_packs: ["p@1"],
        gate: "policy_rule" as const,
        rule_ids: ["p/r"],
        reason: "patient Jane Doe SSN 123-45-6789",
      },
    ],
  };
  it("returns the deterministic explanation untouched unless explicitly enabled", async () => {
    let called = false;
    const narrator = async () => ((called = true), "hello");
    expect(await withNarration(base, { narrator })).toBe(base);
    expect(await withNarration(base, { enabled: true })).toBe(base);
    expect(called).toBe(false);
  });
  it("when enabled, passes only enumerated fields (no reason text, action or ids) and attaches the narrative", async () => {
    let seen = "";
    const out = await withNarration(base, {
      enabled: true,
      narrator: async (i) => ((seen = JSON.stringify(i)), "A short story."),
    });
    expect(out.narrative).toBe("A short story.");
    expect(seen).not.toMatch(/Jane|SSN|123-45|lookup-claim|audit_event_id/);
    expect(narratorInput(base).decisions[0]).toEqual({
      gate: "policy_rule",
      decision: "DENY",
      enforcement_point: "tool_call",
      rule_ids: ["p/r"],
    });
  });
  it("a failing or empty narrator changes nothing", async () => {
    expect(
      await withNarration(base, {
        enabled: true,
        narrator: async () => Promise.reject(new Error("x")),
      }),
    ).toBe(base);
    expect(await withNarration(base, { enabled: true, narrator: async () => "" })).toBe(base);
  });
});

describe("describeGate and remediationFor cover sparse classifications", () => {
  const dec = (decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL" | "ALLOW_WITH_REDACTION") => ({
    decision,
    action: "a",
    enforcement_point: "tool_call",
  });
  it("phrases every gate kind without optional details", () => {
    const kinds = [
      "kill_switch",
      "amount_cap",
      "target_cap",
      "budget",
      "rate_limit",
      "staleness",
      "invalid_request",
      "evaluation_failure",
      "other",
      "admin",
      "approval",
      "policy_rule",
      "default_deny",
      "audit_unavailable",
    ] as const;
    for (const gate of kinds)
      for (const d of ["ALLOW", "DENY", "REQUIRE_APPROVAL", "ALLOW_WITH_REDACTION"] as const) {
        expect(describeGate({ gate, ruleIds: ["p/r"] }, dec(d)).length).toBeGreaterThan(5);
      }
    expect(
      describeGate(
        { gate: "staleness", ruleIds: [], detail: "args.ts is in the future" },
        dec("DENY"),
      ),
    ).toContain("in the future");
    expect(describeGate({ gate: "other", ruleIds: [], detail: "x" }, dec("DENY"))).toContain(
      "gate reported",
    );
  });
  it("gives hints for sparse classes, and none for allowed decisions", () => {
    const ref = (decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL" | "ALLOW_WITH_REDACTION") => ({
      audit_event_id: "i",
      seq: 1,
      ts: "t",
      decision,
      enforcement_point: "tool_call",
      action: "a",
      policy_version: "none",
      policy_packs: [],
      gate: "other" as const,
      rule_ids: [],
      reason: "",
    });
    const none = new Map();
    for (const gate of [
      "kill_switch",
      "amount_cap",
      "target_cap",
      "budget",
      "rate_limit",
      "staleness",
      "approval",
      "policy_rule",
    ] as const) {
      expect(
        remediationFor({ gate, ruleIds: ["p/r"] }, ref("DENY"), none).length,
        gate,
      ).toBeGreaterThan(0);
    }
    expect(
      remediationFor({ gate: "approval", ruleIds: [] }, ref("REQUIRE_APPROVAL"), none)[0]?.hint,
    ).toBe("POST /v1/approvals/{id}/decision");
    expect(
      remediationFor(
        { gate: "policy_rule", ruleIds: ["p/r"] },
        ref("REQUIRE_APPROVAL"),
        new Map([["p/r", { id: "p/r", approval: { roles: ["admin", "owner"] } }]]),
      )[0]?.text,
    ).toContain("admin or owner");
    expect(remediationFor({ gate: "policy_rule", ruleIds: ["p/r"] }, ref("ALLOW"), none)).toEqual(
      [],
    );
    expect(
      remediationFor({ gate: "policy_rule", ruleIds: ["p/r"] }, ref("ALLOW_WITH_REDACTION"), none),
    ).toEqual([]);
  });
});
