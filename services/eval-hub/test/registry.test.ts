import { randomUUID } from "node:crypto";
import { MemoryAuditLog } from "@axis/audit";
import {
  DENY_ALL_EVAL_GATE,
  MemoryRegistryStore,
  RegistryError,
  RegistryService,
  ServiceAudit,
  ablContentHash,
  buildStatement,
  generatePublisherKey,
  signBlueprint,
  signEvalStatement,
  signStatement,
  verifyEvalAttestation,
  type DsseEnvelope,
  type EvalGatePort,
  type PlatformPrincipal,
  type PublisherKeyPair,
  type TenantPrincipal,
} from "@axis/registry";
import { describe, expect, it } from "vitest";
import {
  MemoryDocStore,
  buildEvalStatement,
  createEvalHub,
  type HubSigningKey,
  type PublisherLookup,
} from "../src/index.js";
import { Clock, bp, caseResults, payloadFor, seedSuite, world } from "./helpers.js";
import { randomBytes } from "node:crypto";
const rid = (n = 6): string => Array.from(randomBytes(n), (b) => "cdfghjkpquxyz"[b % 13]).join("");

const MARKET: PlatformPrincipal = {
  kind: "platform",
  subject: "marketplace",
  service: "marketplace",
};
const HUBP: PlatformPrincipal = { kind: "platform", subject: "eval-hub", service: "eval-hub" };

const abl = (name: string, version: string, suites: { ref: string; threshold: number }[]) => ({
  apiVersion: "abl.axis.dev/v1",
  kind: "Agent",
  metadata: { name, version },
  spec: {
    riskClassification: {
      level: "minimal",
      rationale: "Answers general product questions; no decisions about people.",
    },
    model: { primary: { provider: "anthropic", model: "claude-sonnet-5-5" } },
    instructions: { system: "You are a helpful assistant." },
    ...(suites.length > 0 ? { evals: { suites } } : {}),
  },
});

interface Stack {
  tenant: string;
  ns: string;
  clock: Clock;
  registry: RegistryService;
  hubKey: HubSigningKey & { publicKey: string };
  publish(doc: Record<string, unknown>): Promise<string>;
  w: ReturnType<typeof world>;
}

async function stack(o: { gate?: "hub" | EvalGatePort | "none" } = {}): Promise<Stack> {
  const clock = new Clock(new Date("2026-10-08T12:00:00Z"));
  const tenant = randomUUID();
  const ns = `ns-${rid()}`;
  const audit = new MemoryAuditLog({ now: clock.now });
  const hubKeyPair = generatePublisherKey();
  const hubKey = {
    keyId: hubKeyPair.keyId,
    privateKey: hubKeyPair.privateKey,
    publicKey: hubKeyPair.publicKey,
  };
  const docs = new MemoryDocStore();
  const store = new MemoryRegistryStore();
  const ref: { registry?: RegistryService } = {};
  const lookup: PublisherLookup = { publisherOf: () => Promise.resolve("publisher-1") };
  const hub = createEvalHub({
    docs,
    audit: new ServiceAudit(audit, "eval-hub", clock.now),
    now: clock.now,
    publishers: lookup,
    signing: hubKey,
    sink: {
      attach: async (_t, r, env) => {
        await (ref.registry as RegistryService).attachEvalAttestation(HUBP, r, env);
      },
    },
  });
  const gate =
    o.gate === "none"
      ? undefined
      : o.gate === undefined || o.gate === "hub"
        ? hub.gatePort
        : o.gate;
  const registry = new RegistryService({
    store,
    audit: new ServiceAudit(audit, "registry", clock.now),
    now: clock.now,
    ...(gate ? { evalGate: gate } : {}),
    evalHubKeys: [{ keyId: hubKey.keyId, publicKey: hubKey.publicKey }],
  });
  ref.registry = registry;
  const admin: TenantPrincipal = {
    kind: "tenant",
    tenantId: tenant,
    subject: "publisher-1",
    role: "admin",
  };
  await registry.claimNamespace(admin, ns);
  const key: PublisherKeyPair = generatePublisherKey();
  await registry.addKey(admin, ns, {
    publicKey: key.publicKey,
    validFrom: new Date(clock.t.getTime() - 1000),
  });
  const w = world({ docs, tenant, start: "2026-10-08T12:00:00Z" });
  // share the clock/audit/hub of the stack
  Object.assign(w, { hub, clock, audit });
  return {
    tenant,
    ns,
    clock,
    registry,
    hubKey,
    w,
    async publish(doc) {
      const meta = doc["metadata"] as { name: string; version: string };
      const hash = ablContentHash(doc);
      const sig = signBlueprint(
        {
          namespace: ns,
          name: meta.name,
          version: meta.version,
          riskLevel: "minimal",
          contentHash: hash,
        },
        key,
        clock.now(),
      );
      const prov = signStatement(
        buildStatement(
          {
            namespace: ns,
            name: meta.name,
            version: meta.version,
            abl: doc,
            builderId: "ci.example.com/builder",
            sourceRef: "git+https://example.com/r@refs/heads/main",
            now: clock.now(),
          },
          hash,
        ),
        key,
      );
      await registry.publish(admin, ns, { abl: doc, signature: sig, provenance: prov });
      return hash;
    },
  };
}

async function evalRun(
  s: Stack,
  hash: string,
  name: string,
  version: string,
  score: number,
  suite = "smoke@1.0.0",
) {
  const run = await s.w.hub.runs.startAsRunner(s.w.runner, {
    suite_ref: suite,
    blueprint: { ...bp(hash, name, version), namespace: s.ns },
  });
  const results = caseResults(["c1", "c2", "c3", "c4"], ["exact", "contains"], score);
  return s.w.hub.runs.submitResults(s.w.runner, run.id, await payloadFor(s.w, run, results));
}

const refusal = async (p: Promise<unknown>): Promise<RegistryError | undefined> => {
  try {
    await p;
    return undefined;
  } catch (e) {
    return e as RegistryError;
  }
};

describe("registry release is gated", () => {
  it("blocks a release without a passing eval run (evals_gate_failed carries the reasons), allows it with one, and attests the run", async () => {
    const s = await stack();
    await seedSuite(s.w);
    await s.w.hub.runs.registerRunner(s.w.admin, "runner-1");
    const hash = await s.publish(
      abl("support-agent", "1.0.0", [{ ref: "smoke@1.0.0", threshold: 0.8 }]),
    );
    const blocked = await refusal(
      s.registry.setVersionPublic(MARKET, s.ns, "support-agent", "1.0.0"),
    );
    expect(blocked).toBeInstanceOf(RegistryError);
    expect(blocked?.code).toBe("evals_gate_failed");
    expect(blocked?.status).toBe(409);
    expect(blocked?.reasons.map((r) => r.code)).toEqual(["missing_run"]);
    expect(blocked?.reasons[0]?.suite_ref).toBe("smoke@1.0.0");
    // nothing became public
    expect(await s.registry.listVersions({ tenantId: null }, s.ns, "support-agent")).toEqual([]);
    expect(
      (await s.registry.listVersions({ tenantId: randomUUID() }, s.ns, "support-agent")).length,
    ).toBe(0);

    const run = await evalRun(s, hash, "support-agent", "1.0.0", 0.9);
    expect(run.status).toBe("passed");
    await s.registry.setVersionPublic(MARKET, s.ns, "support-agent", "1.0.0");
    expect((await s.registry.listVersions({ tenantId: null }, s.ns, "support-agent")).length).toBe(
      1,
    );

    // the signed summary is attached to the version, verifies, and is about this very content
    const atts = await s.registry.evalAttestations(
      { tenantId: s.tenant },
      s.ns,
      "support-agent",
      "1.0.0",
    );
    expect(atts).toHaveLength(1);
    expect(atts[0]).toMatchObject({
      runId: run.id,
      suiteRef: "smoke@1.0.0",
      contentHash: hash,
      overall: 0.9,
    });
    const v = verifyEvalAttestation(atts[0]?.envelope as DsseEnvelope, [
      { keyId: s.hubKey.keyId, publicKey: s.hubKey.publicKey },
    ]);
    expect(v.ok).toBe(true);
    // released readers see it too
    expect(
      (await s.registry.evalAttestations({ tenantId: null }, s.ns, "support-agent", "1.0.0"))
        .length,
    ).toBe(1);
    // the release promoted the run to the baseline
    expect(
      (
        await s.w.hub.baselines.list(s.w.admin, {
          blueprint_name: "support-agent",
          suite_ref: "smoke@1.0.0",
        })
      ).map((b) => b.run_id),
    ).toEqual([run.id]);
    // the hub can also hand out the attestation
    const direct = (await s.w.hub.runs.attestation(s.w.admin, run.id)) as DsseEnvelope;
    expect(
      verifyEvalAttestation(direct, [{ keyId: s.hubKey.keyId, publicKey: s.hubKey.publicKey }]).ok,
    ).toBe(true);
  });

  it("a regressing v2 is blocked, with the regression among the reasons", async () => {
    const s = await stack();
    await seedSuite(s.w, { tolerance: 0.02, pass_threshold: 0.5 });
    await s.w.hub.runs.registerRunner(s.w.admin, "runner-1");
    const h1 = await s.publish(
      abl("support-agent", "1.0.0", [{ ref: "smoke@1.0.0", threshold: 0.5 }]),
    );
    await evalRun(s, h1, "support-agent", "1.0.0", 0.95);
    await s.registry.setVersionPublic(MARKET, s.ns, "support-agent", "1.0.0");
    s.clock.advance(1000);
    const h2 = await s.publish(
      abl("support-agent", "1.1.0", [{ ref: "smoke@1.0.0", threshold: 0.5 }]),
    );
    await evalRun(s, h2, "support-agent", "1.1.0", 0.7);
    const e = await refusal(s.registry.setVersionPublic(MARKET, s.ns, "support-agent", "1.1.0"));
    expect(e?.code).toBe("evals_gate_failed");
    expect(e?.reasons.map((r) => r.code)).toEqual(["regression"]);
    expect(e?.checks).toEqual(["regression"]);
    expect(
      (await s.registry.listVersions({ tenantId: null }, s.ns, "support-agent")).map(
        (r) => r.record.version,
      ),
    ).toEqual(["1.0.0"]);
    // the failure is audited as a denial in the tenant's chain
    const denied = (await s.w.audit.read(s.tenant)).filter(
      (x) => x.action === "registry.evals_gate.release",
    );
    expect(denied).toHaveLength(1);
    expect(denied[0]).toMatchObject({ decision: "DENY" });
    expect(denied[0]?.reason).toContain("regression");
    // a better run for the same content passes it
    s.clock.advance(1000);
    await evalRun(s, h2, "support-agent", "1.1.0", 0.96);
    await s.registry.setVersionPublic(MARKET, s.ns, "support-agent", "1.1.0");
    expect((await s.registry.listVersions({ tenantId: null }, s.ns, "support-agent")).length).toBe(
      2,
    );
  });

  it("a blueprint that declares no suites is still asked about (tenant-required suites); with no hub wired it is released", async () => {
    const asked: string[] = [];
    const s = await stack({
      gate: {
        check: (i) => (
          asked.push(i.blueprint.name),
          Promise.resolve({ allowed: true, reasons: [] })
        ),
      },
    });
    await s.publish(abl("plain-agent", "1.0.0", []));
    await s.registry.setVersionPublic(MARKET, s.ns, "plain-agent", "1.0.0");
    expect(asked).toEqual(["plain-agent"]);
    const s2 = await stack({ gate: "none" });
    await s2.publish(abl("plain-agent", "1.0.0", []));
    await s2.registry.setVersionPublic(MARKET, s2.ns, "plain-agent", "1.0.0");
  });

  it("the real hub blocks a blueprint that declares NO suites while the tenant requires one (ADR 0058), and allows it once a run passes", async () => {
    const s = await stack();
    await seedSuite(s.w, { suite: { applies_to: ["plain-agent"], required_for_release: true } });
    await s.w.hub.runs.registerRunner(s.w.admin, "runner-1");
    const hash = await s.publish(abl("plain-agent", "1.0.0", []));
    const e = await refusal(s.registry.setVersionPublic(MARKET, s.ns, "plain-agent", "1.0.0"));
    expect(e?.code).toBe("evals_gate_failed");
    expect(e?.reasons.map((r) => r.code)).toEqual(["missing_run"]);
    await evalRun(s, hash, "plain-agent", "1.0.0", 0.95);
    await s.registry.setVersionPublic(MARKET, s.ns, "plain-agent", "1.0.0");
  });

  it("the default gate refuses: a registry without a wired gate cannot release a blueprint that declares evals", async () => {
    const s = await stack({ gate: "none" });
    await s.publish(abl("support-agent", "1.0.0", [{ ref: "smoke@1.0.0", threshold: 0.8 }]));
    const e = await refusal(s.registry.setVersionPublic(MARKET, s.ns, "support-agent", "1.0.0"));
    expect(e?.code).toBe("evals_gate_failed");
    expect(e?.reasons[0]?.code).toBe("gate_unavailable");
    const e2 = await refusal(
      s.registry.requireEvalGate({
        tenantId: s.tenant,
        namespace: s.ns,
        name: "support-agent",
        version: "1.0.0",
        purpose: "marketplace_submit",
        actor: "x",
      }),
    );
    expect(e2?.code).toBe("evals_gate_failed");
    expect((await DENY_ALL_EVAL_GATE.check({} as never)).allowed).toBe(false);
  });

  it("a gate that throws, hangs up or says nothing is a refusal; `allowed: true` is the only way through", async () => {
    const mk = (check: EvalGatePort["check"]) => stack({ gate: { check } });
    for (const [check, code] of [
      [() => Promise.reject(new Error("boom")), "gate_unavailable"],
      [() => Promise.resolve({ allowed: false, reasons: [] }), "not_allowed"],
      [() => Promise.resolve(undefined as never), "not_allowed"],
      [() => Promise.resolve({ allowed: "true" as never, reasons: [] }), "not_allowed"],
    ] as const) {
      const s = await mk(check);
      await s.publish(abl("support-agent", "1.0.0", [{ ref: "smoke@1.0.0", threshold: 0.8 }]));
      const e = await refusal(s.registry.setVersionPublic(MARKET, s.ns, "support-agent", "1.0.0"));
      expect(e?.code).toBe("evals_gate_failed");
      expect(e?.reasons[0]?.code).toBe(code);
    }
    const ok = await stack({
      gate: { check: () => Promise.resolve({ allowed: true, reasons: [] }) },
    });
    await ok.publish(abl("support-agent", "1.0.0", [{ ref: "smoke@1.0.0", threshold: 0.8 }]));
    await ok.registry.setVersionPublic(MARKET, ok.ns, "support-agent", "1.0.0");
  });

  it("only the registry's own stored suites decide: the gate is handed the declared refs and thresholds", async () => {
    let seen: unknown;
    const s = await stack({
      gate: { check: (i) => ((seen = i), Promise.resolve({ allowed: true, reasons: [] })) },
    });
    const hash = await s.publish(
      abl("support-agent", "1.0.0", [
        { ref: "a-suite@^1.0.0", threshold: 0.7 },
        { ref: "b-suite@2.0.0", threshold: 0.9 },
      ]),
    );
    await s.registry.setVersionPublic(MARKET, s.ns, "support-agent", "1.0.0");
    expect(seen).toMatchObject({
      tenantId: s.tenant,
      blueprint: { namespace: s.ns, name: "support-agent", version: "1.0.0", contentHash: hash },
      suites: [
        { ref: "a-suite@^1.0.0", threshold: 0.7 },
        { ref: "b-suite@2.0.0", threshold: 0.9 },
      ],
      purpose: "release",
    });
  });
});

describe("eval attestations on the registry", () => {
  async function withRun() {
    const s = await stack();
    await seedSuite(s.w);
    await s.w.hub.runs.registerRunner(s.w.admin, "runner-1");
    const hash = await s.publish(
      abl("support-agent", "1.0.0", [{ ref: "smoke@1.0.0", threshold: 0.8 }]),
    );
    const run = await evalRun(s, hash, "support-agent", "1.0.0", 0.9);
    const suite = await s.w.hub.suites.get(s.w.admin, "smoke@1.0.0");
    return { s, hash, run, suite };
  }
  const ref = (s: Stack) => ({ namespace: s.ns, name: "support-agent", version: "1.0.0" });

  it("rejects an envelope signed by an untrusted key, a tampered payload, another version and a duplicate", async () => {
    const { s, run, suite } = await withRun();
    const stranger = generatePublisherKey();
    const forged = signEvalStatement(buildEvalStatement(run, suite), stranger);
    expect((await refusal(s.registry.attachEvalAttestation(HUBP, ref(s), forged)))?.code).toBe(
      "verification_failed",
    );
    const good = (await s.w.hub.runs.attestation(s.w.admin, run.id)) as DsseEnvelope;
    const tampered = {
      ...good,
      payload: Buffer.from(
        Buffer.from(good.payload, "base64").toString().replace('"overall":0.9', '"overall":1'),
      ).toString("base64"),
    };
    expect((await refusal(s.registry.attachEvalAttestation(HUBP, ref(s), tampered)))?.code).toBe(
      "verification_failed",
    );
    // a genuine summary of v1 cannot be attached to another version / hash
    await s.publish(abl("support-agent", "1.1.0", [{ ref: "smoke@1.0.0", threshold: 0.8 }]));
    expect(
      (await refusal(s.registry.attachEvalAttestation(HUBP, { ...ref(s), version: "1.1.0" }, good)))
        ?.code,
    ).toBe("verification_failed");
    // attached automatically at finalization; a second attach of the same run is a conflict
    expect((await refusal(s.registry.attachEvalAttestation(HUBP, ref(s), good)))?.code).toBe(
      "conflict",
    );
    expect(
      (await refusal(s.registry.attachEvalAttestation(HUBP, ref(s), { payloadType: "x" } as never)))
        ?.code,
    ).toBe("invalid");
    expect(
      (await refusal(s.registry.attachEvalAttestation(HUBP, { ...ref(s), name: "ghost" }, good)))
        ?.code,
    ).toBe("not_found");
    expect(
      (
        await refusal(
          s.registry.attachEvalAttestation(HUBP, { ...ref(s), namespace: "nope-ns" }, good),
        )
      )?.code,
    ).toBe("not_found");
  });

  it("only the Eval Hub may attach, and a different platform service may not", async () => {
    const { s, run } = await withRun();
    const good = (await s.w.hub.runs.attestation(s.w.admin, run.id)) as DsseEnvelope;
    expect((await refusal(s.registry.attachEvalAttestation(MARKET, ref(s), good)))?.code).toBe(
      "forbidden",
    );
    expect(
      (
        await refusal(
          s.registry.attachEvalAttestation(
            { kind: "tenant", tenantId: s.tenant, subject: "u", role: "owner" } as never,
            ref(s),
            good,
          ),
        )
      )?.code,
    ).toBe("forbidden");
    // the marketplace principal cannot be used for the hub's calls, and the hub cannot release
    expect(
      (await refusal(s.registry.setVersionPublic(HUBP, s.ns, "support-agent", "1.0.0")))?.code,
    ).toBe("forbidden");
  });

  it("verifyEvalAttestation never throws on malformed input", () => {
    const k = [{ keyId: "k", publicKey: "A".repeat(43) }];
    expect(
      verifyEvalAttestation({ payloadType: "x", payload: "!", signatures: [] } as never, k).ok,
    ).toBe(false);
    expect(
      verifyEvalAttestation(
        { payloadType: "application/vnd.in-toto+json", payload: "e30=", signatures: [] },
        k,
      ).ok,
    ).toBe(false);
    expect(verifyEvalAttestation(undefined as never, k).ok).toBe(false);
  });

  it("the hub does not attach (and records why) when the registry refuses; the run is still final", async () => {
    const s = await stack();
    // a registry that does not trust the hub key
    const lone = new RegistryService({
      store: new MemoryRegistryStore(),
      audit: new ServiceAudit(new MemoryAuditLog(), "registry"),
    });
    const hub = createEvalHub({
      docs: new MemoryDocStore(),
      audit: new ServiceAudit(s.w.audit, "eval-hub", s.clock.now),
      now: s.clock.now,
      signing: s.hubKey,
      sink: { attach: async (_t, r, e) => void (await lone.attachEvalAttestation(HUBP, r, e)) },
    });
    const w2 = world({ tenant: s.tenant });
    Object.assign(w2, { hub, audit: s.w.audit, clock: s.clock });
    await seedSuite(w2);
    await w2.hub.runs.registerRunner(w2.admin, "runner-1");
    const run = await w2.hub.runs.startAsRunner(w2.runner, {
      suite_ref: "smoke@1.0.0",
      blueprint: { ...bp(), namespace: "nope-ns" },
    });
    const done = await w2.hub.runs.submitResults(
      w2.runner,
      run.id,
      await payloadFor(w2, run, caseResults(["c1", "c2", "c3", "c4"], ["exact", "contains"], 1)),
    );
    expect(done.status).toBe("passed");
    const failed = (await s.w.audit.read(s.tenant)).filter(
      (x) => x.action === "evals.attestation.failed",
    );
    expect(failed).toHaveLength(1);
  });
});
