import { describe, expect, it } from "vitest";
import { coerceDecision, FAIL_CLOSED_DECISION, isDecision } from "../src/index.js";

describe("decision model", () => {
  it("fails closed to DENY", () => {
    expect(FAIL_CLOSED_DECISION).toBe("DENY");
  });
  it("accepts the four outcomes", () => {
    for (const d of ["ALLOW", "DENY", "REQUIRE_APPROVAL", "ALLOW_WITH_REDACTION"]) {
      expect(isDecision(d)).toBe(true);
      expect(coerceDecision(d)).toBe(d);
    }
  });
  it("coerces anything else to DENY", () => {
    for (const v of [undefined, null, "allow", 1, {}, ""]) {
      expect(isDecision(v)).toBe(false);
      expect(coerceDecision(v)).toBe("DENY");
    }
  });
});
