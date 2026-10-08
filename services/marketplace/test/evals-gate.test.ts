import { describe, expect, it } from "vitest";
import type { EvalGateInput, EvalGatePort, EvalGateResult } from "@axis/registry";
import { Pub, ablDoc, makeEnv, reviewer } from "./helpers.js";

const rid = (t: string, ns: string, name: string, v: string): string => `${t}|${ns}/${name}@${v}`;

const SUITES = { evals: { suites: [{ ref: "smoke@1.0.0", threshold: 0.8 }] } };
const blocked: EvalGateResult = {
  allowed: false,
  reasons: [
    {
      code: "below_threshold",
      suite_ref: "smoke@1.0.0",
      message: "score 0.5 is below the required 0.8",
    },
  ],
};

function gate(
  result: () => EvalGateResult | Promise<EvalGateResult>,
): EvalGatePort & { calls: EvalGateInput[] } {
  const calls: EvalGateInput[] = [];
  return { calls, check: (i) => (calls.push(i), Promise.resolve().then(result)) };
}

describe("marketplace submit-for-review is gated by the Eval Hub", () => {
  it("refuses a submission that declares evals when the gate does not allow it: evals_gate_failed with reasons, no review created", async () => {
    const g = gate(() => blocked);
    const env = makeEnv({ evalGate: g });
    const pub = await Pub.create(env);
    await pub.publish(ablDoc("helper-agent", "1.0.0", SUITES));
    await expect(
      env.mp.reviews.submit(pub.b, {
        namespace: pub.namespace,
        name: "helper-agent",
        version: "1.0.0",
      }),
    ).rejects.toMatchObject({
      code: "evals_gate_failed",
      status: 409,
      reasons: blocked.reasons,
    });
    expect(g.calls).toHaveLength(1);
    expect(g.calls[0]).toMatchObject({
      purpose: "marketplace_submit",
      tenantId: pub.tenantId,
      suites: [{ ref: "smoke@1.0.0", threshold: 0.8 }],
    });
    expect(await env.mp.reviews.mine(pub.b)).toEqual([]);
    expect(await env.mp.reviews.queue(reviewer())).toEqual([]);
  });

  it("allows it when the gate allows, and then asks again at approval (release) time", async () => {
    let state: EvalGateResult = { allowed: true, reasons: [] };
    const g = gate(() => state);
    const env = makeEnv({ evalGate: g });
    const pub = await Pub.create(env);
    await pub.publish(ablDoc("helper-agent", "1.0.0", SUITES));
    const rv = await env.mp.reviews.submit(pub.b, {
      namespace: pub.namespace,
      name: "helper-agent",
      version: "1.0.0",
    });
    expect(rv.state).toBe("in_review");
    // between submission and approval the evals regress: the approval is refused and the review stays open
    state = blocked;
    const id = rid(pub.tenantId, pub.namespace, "helper-agent", "1.0.0");
    await expect(
      env.mp.reviews.decide(reviewer("rev-2"), id, {
        decision: "approve",
        note: "reviewed scan and blueprint",
      }),
    ).rejects.toMatchObject({ code: "evals_gate_failed" });
    expect((await env.mp.reviews.get(reviewer("rev-2"), id)).state).toBe("in_review");
    expect(
      await env.registry.listVersions({ tenantId: null }, pub.namespace, "helper-agent"),
    ).toEqual([]);
    state = { allowed: true, reasons: [] };
    const ok = await env.mp.reviews.decide(reviewer("rev-2"), id, {
      decision: "approve",
      note: "reviewed scan and blueprint",
    });
    expect(ok.state).toBe("approved");
    expect(
      await env.registry.listVersions({ tenantId: null }, pub.namespace, "helper-agent"),
    ).toHaveLength(1);
    expect(g.calls.map((c) => c.purpose)).toEqual([
      "marketplace_submit",
      "release",
      "release",
      "release",
    ]);
  });

  it("a blueprint without declared suites is asked about too when a gate is wired (tenant-required suites); with no gate wired it passes, and one that declares evals is refused", async () => {
    const g = gate(() => blocked);
    const env = makeEnv({ evalGate: g });
    const pub = await Pub.create(env);
    await pub.publish(ablDoc("plain-agent", "1.0.0"));
    await expect(
      env.mp.reviews.submit(pub.b, {
        namespace: pub.namespace,
        name: "plain-agent",
        version: "1.0.0",
      }),
    ).rejects.toMatchObject({ code: "evals_gate_failed" });
    expect(g.calls).toHaveLength(1);
    expect(g.calls[0]?.suites).toEqual([]);
    const open = makeEnv({ evalGate: gate(() => ({ allowed: true, reasons: [] })) });
    const pubOpen = await Pub.create(open);
    await pubOpen.publish(ablDoc("plain-agent", "1.0.0"));
    expect(
      (
        await open.mp.reviews.submit(pubOpen.b, {
          namespace: pubOpen.namespace,
          name: "plain-agent",
          version: "1.0.0",
        })
      ).state,
    ).toBe("in_review");
    const none = makeEnv({}); // no gate wired at all
    const pubNone = await Pub.create(none);
    await pubNone.publish(ablDoc("plain-agent", "1.0.0"));
    expect(
      (
        await none.mp.reviews.submit(pubNone.b, {
          namespace: pubNone.namespace,
          name: "plain-agent",
          version: "1.0.0",
        })
      ).state,
    ).toBe("in_review");

    const env2 = makeEnv(); // default: the registry's deny-all gate
    const pub2 = await Pub.create(env2);
    await pub2.publish(ablDoc("helper-agent", "1.0.0", SUITES));
    await expect(
      env2.mp.reviews.submit(pub2.b, {
        namespace: pub2.namespace,
        name: "helper-agent",
        version: "1.0.0",
      }),
    ).rejects.toMatchObject({
      code: "evals_gate_failed",
      reasons: [{ code: "gate_unavailable" }],
    });
  });

  it("a gate that throws refuses", async () => {
    const env = makeEnv({ evalGate: { check: () => Promise.reject(new Error("hub down")) } });
    const pub = await Pub.create(env);
    await pub.publish(ablDoc("helper-agent", "1.0.0", SUITES));
    await expect(
      env.mp.reviews.submit(pub.b, {
        namespace: pub.namespace,
        name: "helper-agent",
        version: "1.0.0",
      }),
    ).rejects.toMatchObject({ code: "evals_gate_failed" });
  });
});
