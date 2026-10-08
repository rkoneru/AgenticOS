import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  DENY_ALL_EVAL_GATE,
  RegistryError,
  generatePublisherKey,
  signEvalStatement,
  type EvalGateInput,
  type EvalGatePort,
  type EvalStatement,
  type PlatformPrincipal,
} from "../src/index.js";
import { MemoryAuditLog } from "@axis/audit";
import { MemoryRegistryStore, RegistryService, ServiceAudit } from "../src/index.js";
import { Clock, Publisher, ablDoc, rid, type Harness } from "./helpers.js";

const MARKET: PlatformPrincipal = {
  kind: "platform",
  subject: "marketplace",
  service: "marketplace",
};
const HUBP: PlatformPrincipal = { kind: "platform", subject: "eval-hub", service: "eval-hub" };

const withSuites = (name: string, version: string, suites: unknown[]) =>
  ablDoc(name, version, suites.length > 0 ? { evals: { suites } } : {});

async function setup(gate?: EvalGatePort, hubKey = generatePublisherKey()) {
  const clock = new Clock(new Date("2026-10-02T12:00:00Z"));
  const audit = new MemoryAuditLog({ now: clock.now });
  const store = new MemoryRegistryStore();
  const svc = new RegistryService({
    store,
    audit: new ServiceAudit(audit, "registry", clock.now),
    now: clock.now,
    ...(gate ? { evalGate: gate } : {}),
    evalHubKeys: [{ keyId: hubKey.keyId, publicKey: hubKey.publicKey }],
  });
  const h: Harness = { store, audit, clock, svc };
  const tenant = randomUUID();
  const pub = await Publisher.create(h, tenant, `ns-${rid()}`);
  return { h, svc, pub, tenant, hubKey };
}

const fail = async (p: Promise<unknown>): Promise<RegistryError> => {
  try {
    await p;
  } catch (e) {
    return e as RegistryError;
  }
  throw new Error("expected a refusal");
};

describe("the eval gate port", () => {
  it("is asked with the suites of the STORED blueprint; with a hub wired it is asked even when none are declared (tenant-required suites)", async () => {
    const seen: EvalGateInput[] = [];
    const gate: EvalGatePort = {
      check: (i) => (seen.push(i), Promise.resolve({ allowed: true, reasons: [] })),
    };
    const { svc, pub, tenant } = await setup(gate);
    await pub.publish(withSuites("agent-one", "1.0.0", [{ ref: "smoke@1.0.0", threshold: 0.8 }]));
    await pub.publish(withSuites("agent-two", "1.0.0", []));
    await svc.setVersionPublic(MARKET, pub.namespace, "agent-two", "1.0.0");
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ suites: [], blueprint: { name: "agent-two" } });
    seen.length = 0;
    await svc.setVersionPublic(MARKET, pub.namespace, "agent-one", "1.0.0");
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({
      tenantId: tenant,
      purpose: "release",
      actor: "marketplace",
      suites: [{ ref: "smoke@1.0.0", threshold: 0.8 }],
    });
    expect(seen[0]?.blueprint).toMatchObject({
      namespace: pub.namespace,
      name: "agent-one",
      version: "1.0.0",
    });
  });

  it("a wired hub that refuses blocks a blueprint that declares no suites (a tenant-required suite is missing a run)", async () => {
    const { svc, pub } = await setup({
      check: () =>
        Promise.resolve({
          allowed: false,
          reasons: [{ code: "missing_run", suite_ref: "house@1.0.0", message: "no run" }],
        }),
    });
    await pub.publish(withSuites("agent-two", "1.0.0", []));
    const e = await fail(svc.setVersionPublic(MARKET, pub.namespace, "agent-two", "1.0.0"));
    expect(e).toMatchObject({ code: "evals_gate_failed", checks: ["missing_run"] });
  });

  it("without a wired hub a blueprint that declares no suites is released (nothing could know of a requirement)", async () => {
    const { svc, pub } = await setup();
    await pub.publish(withSuites("agent-two", "1.0.0", []));
    await svc.setVersionPublic(MARKET, pub.namespace, "agent-two", "1.0.0");
    expect((await svc.listVersions({ tenantId: null }, pub.namespace, "agent-two")).length).toBe(1);
  });

  it("refuses with evals_gate_failed (409) and the reasons; the version stays private; the refusal is audited", async () => {
    const reasons = [
      {
        code: "below_threshold",
        suite_ref: "smoke@1.0.0",
        message: "score 0.5 is below the required 0.8",
      },
    ];
    const { h, svc, pub, tenant } = await setup({
      check: () => Promise.resolve({ allowed: false, reasons }),
    });
    await pub.publish(withSuites("agent-one", "1.0.0", [{ ref: "smoke@1.0.0", threshold: 0.8 }]));
    const e = await fail(svc.setVersionPublic(MARKET, pub.namespace, "agent-one", "1.0.0"));
    expect(e).toMatchObject({
      code: "evals_gate_failed",
      status: 409,
      checks: ["below_threshold"],
      reasons,
    });
    expect(await svc.listVersions({ tenantId: null }, pub.namespace, "agent-one")).toEqual([]);
    const ev = (await h.audit.read(tenant)).filter(
      (x) => x.action === "registry.evals_gate.release",
    );
    expect(ev).toHaveLength(1);
    expect(ev[0]).toMatchObject({ decision: "DENY" });
  });

  it("the default refuses; so does a port that throws, returns garbage, or an unreadable stored ABL", async () => {
    const d = await setup();
    await d.pub.publish(withSuites("agent-one", "1.0.0", [{ ref: "smoke@1.0.0", threshold: 0.8 }]));
    expect(
      (await fail(d.svc.setVersionPublic(MARKET, d.pub.namespace, "agent-one", "1.0.0"))).reasons[0]
        ?.code,
    ).toBe("gate_unavailable");
    expect((await DENY_ALL_EVAL_GATE.check({} as EvalGateInput)).allowed).toBe(false);
    for (const [check, code] of [
      [() => Promise.reject(new Error("boom")), "gate_unavailable"],
      [() => Promise.resolve({ allowed: false, reasons: [] }), "not_allowed"],
      [() => Promise.resolve(null as never), "not_allowed"],
      [() => Promise.resolve({ allowed: 1 as never, reasons: "x" as never }), "not_allowed"],
    ] as const) {
      const s = await setup({ check });
      await s.pub.publish(
        withSuites("agent-one", "1.0.0", [{ ref: "smoke@1.0.0", threshold: 0.8 }]),
      );
      expect(
        (await fail(s.svc.setVersionPublic(MARKET, s.pub.namespace, "agent-one", "1.0.0")))
          .reasons[0]?.code,
      ).toBe(code);
    }
  });

  it("calls `released` after a release, and a failing `released` does not undo it", async () => {
    let released = 0;
    const s = await setup({
      check: () => Promise.resolve({ allowed: true, reasons: [] }),
      released: () => (released++, Promise.reject(new Error("baseline store down"))),
    });
    await s.pub.publish(withSuites("agent-one", "1.0.0", [{ ref: "smoke@1.0.0", threshold: 0.8 }]));
    await s.svc.setVersionPublic(MARKET, s.pub.namespace, "agent-one", "1.0.0");
    expect(released).toBe(1);
    expect(await s.svc.listVersions({ tenantId: null }, s.pub.namespace, "agent-one")).toHaveLength(
      1,
    );
  });

  it("requireEvalGate: unknown versions are not found", async () => {
    const s = await setup({ check: () => Promise.resolve({ allowed: true, reasons: [] }) });
    const e = await fail(
      s.svc.requireEvalGate({
        tenantId: s.tenant,
        namespace: s.pub.namespace,
        name: "ghost",
        version: "1.0.0",
        purpose: "marketplace_submit",
        actor: "u",
      }),
    );
    expect(e.code).toBe("not_found");
  });
});

describe("eval attestations", () => {
  const statement = (ns: string, hash: string, runId = "run-1"): EvalStatement => ({
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: `${ns}/agent-one@1.0.0`, digest: { sha256: hash } }],
    predicateType: "https://axis.dev/eval-result/v1",
    predicate: {
      run_id: runId,
      suite_ref: "smoke@1.0.0",
      suite_hash: "s".repeat(64),
      dataset_hash: "d".repeat(64),
      mode: "ci",
      status: "passed",
      overall: 0.9,
      per_grader: { exact: 0.9 },
      pass_threshold: 0.8,
      sample_size: 4,
      runner_id: "r",
      finished_at: "2026-10-08T12:00:00.000Z",
      record_hash: "h".repeat(64),
    },
  });

  it("verified against the trusted hub keys, bound to the version's content hash, append-only per run", async () => {
    const { svc, pub, hubKey, h } = await setup();
    const rec = await pub.publish(withSuites("agent-one", "1.0.0", []));
    const ref = { namespace: pub.namespace, name: "agent-one", version: "1.0.0" };
    const env = signEvalStatement(statement(pub.namespace, rec.contentHash), hubKey);
    const a = await svc.attachEvalAttestation(HUBP, ref, env);
    expect(a).toMatchObject({
      runId: "run-1",
      suiteRef: "smoke@1.0.0",
      overall: 0.9,
      contentHash: rec.contentHash,
      attachedBy: "eval-hub",
    });
    expect((await fail(svc.attachEvalAttestation(HUBP, ref, env))).code).toBe("conflict");
    expect(
      await svc.evalAttestations({ tenantId: pub.p.tenantId }, pub.namespace, "agent-one", "1.0.0"),
    ).toHaveLength(1);
    expect(
      await svc.evalAttestations({ tenantId: null }, pub.namespace, "agent-one", "1.0.0"),
    ).toEqual([]);
    // as a reader sees it: re-verified on every read, with the decoded summary only when it verifies
    const seen = await svc.evalAttestationSummaries(
      { tenantId: pub.p.tenantId },
      pub.namespace,
      "agent-one",
      "1.0.0",
    );
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({
      verified: true,
      predicate: { run_id: "run-1", overall: 0.9, status: "passed", suite_ref: "smoke@1.0.0" },
    });
    expect(
      await svc.evalAttestationSummaries({ tenantId: null }, pub.namespace, "agent-one", "1.0.0"),
    ).toEqual([]);
    // the same stored envelope read by a registry that does not trust the hub key (or after it was altered) is NOT verified
    const untrusting = new RegistryService({
      store: (
        svc as unknown as { store: ConstructorParameters<typeof RegistryService>[0]["store"] }
      ).store,
      audit: new ServiceAudit(new MemoryAuditLog(), "registry"),
      evalHubKeys: [{ keyId: "other", publicKey: generatePublisherKey().publicKey }],
    });
    const distrust = await untrusting.evalAttestationSummaries(
      { tenantId: pub.p.tenantId },
      pub.namespace,
      "agent-one",
      "1.0.0",
    );
    expect(distrust).toHaveLength(1);
    expect(distrust[0]).toMatchObject({ verified: false, predicate: null });
    // wrong key, wrong hash, wrong name, wrong caller
    const other = generatePublisherKey();
    expect(
      (
        await fail(
          svc.attachEvalAttestation(
            HUBP,
            ref,
            signEvalStatement(statement(pub.namespace, rec.contentHash, "run-2"), other),
          ),
        )
      ).code,
    ).toBe("verification_failed");
    expect(
      (
        await fail(
          svc.attachEvalAttestation(
            HUBP,
            ref,
            signEvalStatement(statement(pub.namespace, "0".repeat(64), "run-3"), hubKey),
          ),
        )
      ).code,
    ).toBe("verification_failed");
    expect(
      (await fail(svc.attachEvalAttestation(HUBP, { ...ref, version: "2.0.0" }, env))).code,
    ).toBe("not_found");
    expect((await fail(svc.attachEvalAttestation(MARKET, ref, env))).code).toBe("forbidden");
    const bad = signEvalStatement(
      { ...statement(pub.namespace, rec.contentHash, "run-4"), predicateType: "other" },
      hubKey,
    );
    expect((await fail(svc.attachEvalAttestation(HUBP, ref, bad))).code).toBe(
      "verification_failed",
    );
    const audited = (await h.audit.read(pub.p.tenantId)).filter((x) =>
      x.action.startsWith("registry.eval_attestation.attach"),
    );
    expect(audited.length).toBeGreaterThanOrEqual(2);
  });
});
