import { describe, expect, it } from "vitest";
import { classifyReason } from "../src/index.js";

const c = (reason: string | undefined, action = "send-report", ep = "tool_call") =>
  classifyReason(reason, action, ep);

describe("classifyReason: the formats the kernel, gates and approvals service actually write", () => {
  it.each([
    ["kill-switch engaged (tenant)", { gate: "kill_switch", killSwitchScope: "tenant" }],
    ["kill-switch engaged (global)", { gate: "kill_switch", killSwitchScope: "global" }],
    [
      "gate base/ks: kill-switch engaged (tool)",
      { gate: "kill_switch", killSwitchScope: "tool", gateId: "base/ks" },
    ],
    [
      "gate base/cap: amount exceeds cap 500",
      { gate: "amount_cap", field: "amount", limit: 500, gateId: "base/cap" },
    ],
    ["gate base/day: cumulative cap 1000 would be exceeded", { gate: "target_cap", limit: 1000 }],
    ["gate base/b: hard tokens budget reached", { gate: "budget", metric: "tokens" }],
    ["gate base/b: run.id missing for run-scoped budget", { gate: "budget" }],
    ["gate base/r: rate limit 5/60s exceeded", { gate: "rate_limit", limit: 5 }],
    ["gate base/s: args.ts older than 30s", { gate: "staleness", field: "args.ts", limit: 30 }],
    ["gate base/s: args.ts is in the future", { gate: "staleness" }],
    ["gate base/s: args.ts missing or not a timestamp", { gate: "staleness" }],
    ["gate base/x: invalid params", { gate: "other" }],
    ["no matching rule (default deny)", { gate: "default_deny" }],
    ["audit unavailable", { gate: "audit_unavailable" }],
    ["invalid request: action must be a string", { gate: "invalid_request" }],
    ["internal error", { gate: "evaluation_failure" }],
    ["policy evaluation timed out", { gate: "evaluation_failure" }],
    ["kill-switch state unavailable", { gate: "evaluation_failure" }],
    [
      "pack/deny-big, pack/other",
      { gate: "policy_rule", ruleIds: ["pack/deny-big", "pack/other"] },
    ],
    ["approval already used", { gate: "approval" }],
    ["approval record not valid for this action", { gate: "approval" }],
    ["something else entirely", { gate: "other" }],
  ])("%s", (reason, want) => {
    expect(c(reason)).toMatchObject(want);
  });

  it("recognises approval flows, with the request id and rules", () => {
    const id = "123e4567-e89b-42d3-a456-426614174000";
    expect(c(`pack/needs-ok; request=${id}`)).toMatchObject({
      gate: "approval",
      approvalId: id,
      ruleIds: ["pack/needs-ok"],
    });
    expect(c(`approved: request=${id}; pack/needs-ok`)).toMatchObject({
      gate: "approval",
      approvalId: id,
      ruleIds: ["pack/needs-ok"],
    });
    expect(c(undefined, "approval.approved", "admin")).toMatchObject({ gate: "approval" });
  });

  it("an unknown kill-switch scope is not trusted", () => {
    expect(c("kill-switch engaged (galaxy)").gate).toBe("other");
  });

  it("admin events are admin, never a gate", () => {
    expect(c("owner=x", "api.runs.start", "admin").gate).toBe("admin");
  });

  it("empty or missing reasons are other", () => {
    expect(c(undefined).gate).toBe("other");
    expect(c("").gate).toBe("other");
  });
});
