import { describe, expect, it } from "vitest";
import { validatePolicyResult, validateRequest } from "../src/index.js";
import { req } from "./helpers.js";

describe("validateRequest", () => {
  it("returns a normalised request and drops unknown top-level fields", () => {
    const v = validateRequest({ ...req(), extra: "x" });
    expect(v.ok).toBe(true);
    if (v.ok) expect("extra" in v.value).toBe(false);
  });
});

describe("validatePolicyResult", () => {
  const good = {
    decision: "DENY",
    reason: "r",
    matched: [],
    winners: [],
    gates: [{ id: "g", type: "kill_switch", scope: "tenant", params: {} }],
    redact: [],
    approval: null,
    policy_version: "v",
  };
  it("accepts a well-formed result and keeps gate scope", () => {
    const v = validatePolicyResult(good);
    expect(v.ok && v.value.gates[0]?.scope).toBe("tenant");
  });
  it("rejects when approval is not null or an object", () => {
    expect(validatePolicyResult({ ...good, approval: 5 }).ok).toBe(false);
  });
  it("rejects non-string scope silently by omitting it", () => {
    const v = validatePolicyResult({
      ...good,
      gates: [{ id: "g", type: "t", scope: 5, params: {} }],
    });
    expect(v.ok && v.value.gates[0]?.scope).toBeUndefined();
  });
});
