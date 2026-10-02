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
    const longList = pack("longlist", 1);
    longList.spec.rules[0]!.when.all[1]!.value = Array.from({ length: 20_000 }, (_, i) => `v${i}`); // one rule, ~40 s in opa
    expect(await code(w.cp.admin.publishPolicy(t.owner, longList))).toBe("invalid");
    expect(calls).toBe(before);
  });

  it("a pack within the limits still publishes and activates; a set above the total limit cannot be activated", async () => {
    const t = await w.tenant();
    const a = await w.cp.admin.publishPolicy(t.owner, pack("set-a", 90));
    const b = await w.cp.admin.publishPolicy(t.owner, pack("set-b", 90));
    const c = await w.cp.admin.publishPolicy(t.owner, pack("set-c", 90));
    await w.cp.admin.activatePolicy(t.owner, a.versionId);
    await w.cp.admin.activatePolicy(t.owner, b.versionId);
    expect(await code(w.cp.admin.activatePolicy(t.owner, c.versionId))).toBe("invalid");
  });
});

describe.each(KINDS)(
  "review: BYO model keys honour 'builders touch only keys they own' (%s store)",
  (kind) => {
    let w: World;
    beforeAll(async () => {
      w = await makeWorld(kind);
    });
    afterAll(() => w.close());

    it("a builder can neither overwrite nor delete a key written by someone else, but manages its own", async () => {
      const t = await w.tenant();
      const b1 = await w.member(t.tenantId, "builder");
      const b2 = await w.member(t.tenantId, "builder");
      const adm = await w.member(t.tenantId, "admin");
      await w.cp.admin.putModelKey(adm.principal, "anthropic", "prod", "admin-secret");
      // another builder cannot replace the admin's production key with its own (traffic redirection) nor destroy it
      expect(await code(w.cp.admin.putModelKey(b1.principal, "anthropic", "prod", "evil"))).toBe(
        "forbidden",
      );
      expect(await code(w.cp.admin.deleteModelKey(b1.principal, "anthropic", "prod"))).toBe(
        "forbidden",
      );
      expect(await w.cp.modelKeys.revealForRuntime(t.tenantId, "anthropic", "prod")).toBe(
        "admin-secret",
      );
      // own key: create, rotate, delete are fine; a peer builder is refused
      await w.cp.admin.putModelKey(b1.principal, "openai", "dev", "one");
      await w.cp.admin.putModelKey(b1.principal, "openai", "dev", "two");
      expect(await code(w.cp.admin.putModelKey(b2.principal, "openai", "dev", "x"))).toBe(
        "forbidden",
      );
      expect(await code(w.cp.admin.deleteModelKey(b2.principal, "openai", "dev"))).toBe(
        "forbidden",
      );
      // an admin may manage anyone's key
      await w.cp.admin.putModelKey(adm.principal, "openai", "dev", "admin-took-over");
      expect(await code(w.cp.admin.deleteModelKey(b1.principal, "openai", "dev"))).toBe(
        "forbidden",
      );
      await w.cp.admin.deleteModelKey(adm.principal, "openai", "dev");
    });
  },
);
