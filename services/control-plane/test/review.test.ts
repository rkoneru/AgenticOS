// Independent Phase 6 review: regression tests for defects found by the adversarial reviewer.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { CpError, type PackValidator } from "../src/index.js";
import { KINDS, cachedValidator, makeWorld, type World } from "./world.js";

const code = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "ok";
  } catch (e) {
    return e instanceof CpError ? e.code : `other:${String(e)}`;
  }
};

const pack = (name: string, nRules: number) => ({
  apiVersion: "policy.axis.dev/v1",
  kind: "PolicyPack",
  metadata: { name, version: "1.0.0" },
  spec: {
    defaultDecision: "DENY",
    rules: Array.from({ length: nRules }, (_, i) => ({
      id: `r${i}`,
      enforcementPoints: ["tool_call"],
      when: {
        all: [
          { field: "args.x", op: "eq", value: i },
          { field: "tool.name", op: "in", value: ["a", "b"] },
        ],
      },
      decision: "ALLOW",
    })),
  },
});

describe.each(KINDS)("review: policy publish resource limits (%s store)", (kind) => {
  let w: World;
  let calls = 0;
  const counting: PackValidator = (docs) => {
    calls++;
    return cachedValidator(docs);
  };
  beforeAll(async () => {
    w = await makeWorld(kind, { validator: counting });
  });
  afterAll(() => w.close());

  it("rejects an oversized pack before the synchronous opa check/build can stall the process", async () => {
    // 1400 rules fit in the 256 KiB body limit and take `opa` minutes (300 rules: ~4.5 s): it must never reach the validator.
    const t = await w.tenant();
    const before = calls;
    expect(await code(w.cp.admin.publishPolicy(t.owner, pack("huge", 1400)))).toBe("invalid");
    expect(await code(w.cp.admin.publishPolicy(t.owner, pack("deep", 101)))).toBe("invalid");
    expect(calls).toBe(before);
  });

  it("a pack within the limits still publishes and activates; a set above the total limit cannot be activated", async () => {
    const t = await w.tenant();
    const a = await w.cp.admin.publishPolicy(t.owner, pack("set-a", 60)); // 60*3+60 = 240 nodes
    const b = await w.cp.admin.publishPolicy(t.owner, pack("set-b", 60));
    const c = await w.cp.admin.publishPolicy(t.owner, pack("set-c", 60));
    await w.cp.admin.activatePolicy(t.owner, a.versionId);
    await w.cp.admin.activatePolicy(t.owner, b.versionId);
    expect(await code(w.cp.admin.activatePolicy(t.owner, c.versionId))).toBe("invalid");
  });
});
