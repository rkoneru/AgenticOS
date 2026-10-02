import { afterAll, describe, expect, it } from "vitest";
import { MemoryDocStore } from "../src/index.js";
import {
  type Env,
  Pub,
  ablDoc,
  adminClient,
  makeEnv,
  moderator,
  newPool,
  pgEnv,
  reviewer,
  tenantP,
} from "./helpers.js";

const pool = newPool();
afterAll(() => pool.end());

const envs: [string, () => Promise<Env>][] = [
  ["memory", () => Promise.resolve(makeEnv({ docs: new MemoryDocStore() }))],
  ["postgres", async () => pgEnv(pool, await adminClient())],
];

const actions = async (e: Env, tenantId: string): Promise<string[]> =>
  (await e.audit.read(tenantId)).map((x) => `${x.action}:${x.decision}`);
const rid = (t: string, ns: string, name: string, v: string): string => `${t}|${ns}/${name}@${v}`;

describe.each(envs)("publisher verification (%s)", (_n, mk) => {
  it("unverified -> pending -> evidence -> verified, audited; reviewer actions in the publisher's chain", async () => {
    const env = await mk();
    const t = await env.tenant();
    const p = tenantP(t, "admin", "alice");
    expect(await env.mp.publishers.get(p)).toBeUndefined();
    const rec = await env.mp.publishers.start(p, {
      legalName: "Acme Corp",
      domain: "acme.example.com",
      contactEmail: "ops@acme.example.com",
    });
    expect(rec.state).toBe("pending");
    expect(rec.challenge).toMatch(/^[0-9a-f]{32}$/);
    // no evidence yet: the reviewer cannot verify
    await expect(
      env.mp.publishers.decide(reviewer(), t, { decision: "approve", reason: "looks fine" }),
    ).rejects.toMatchObject({ code: "conflict", checks: ["evidence_missing"] });
    // evidence fails (DNS record missing)
    const failed = await env.mp.publishers.submitEvidence(p);
    expect(failed.map((e) => `${e.kind}:${e.result}`)).toEqual([
      "domain_dns_txt:failed",
      "identity:passed",
    ]);
    await expect(
      env.mp.publishers.decide(reviewer(), t, { decision: "approve", reason: "looks fine" }),
    ).rejects.toMatchObject({ code: "conflict" });
    env.domain.records.set("acme.example.com", [`axis-verify=${rec.challenge}`]);
    await env.mp.publishers.submitEvidence(p);
    expect((await env.mp.publishers.evidence(p)).length).toBe(4);
    expect((await env.mp.publishers.queue(reviewer())).some((q) => q.tenantId === t)).toBe(true);
    expect((await env.mp.publishers.evidenceFor(reviewer(), t)).length).toBe(4);
    const done = await env.mp.publishers.decide(reviewer("rev-9"), t, {
      decision: "approve",
      reason: "domain + identity ok",
    });
    expect(done).toMatchObject({ state: "verified", decidedBy: "rev-9" });
    expect(await env.mp.publishers.isVerified(t)).toBe(true);
    expect(await actions(env, t)).toEqual(
      expect.arrayContaining([
        "marketplace.publisher.start:ALLOW",
        "marketplace.publisher.evidence:ALLOW",
        "marketplace.publisher.decide:ALLOW",
        "marketplace.publisher.decide.failed:DENY",
      ]),
    );
    // verified cannot restart or be re-decided
    await expect(
      env.mp.publishers.start(p, {
        legalName: "Acme Corp",
        domain: "acme.example.com",
        contactEmail: "ops@acme.example.com",
      }),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(
      env.mp.publishers.decide(reviewer("rev-9"), t, {
        decision: "approve",
        reason: "again again",
      }),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(env.mp.publishers.submitEvidence(p)).rejects.toMatchObject({ code: "conflict" });
  });

  it("reject, then resubmit; suspension of a verified publisher", async () => {
    const env = await mk();
    const t = await env.tenant();
    const p = tenantP(t, "owner", "olga");
    await env.mp.publishers.start(p, {
      legalName: "Shady Ltd",
      domain: "shady.example.com",
      contactEmail: "x@shady.example.com",
    });
    expect(
      (
        await env.mp.publishers.decide(reviewer(), t, {
          decision: "reject",
          reason: "cannot confirm identity",
        })
      ).state,
    ).toBe("rejected");
    const again = await env.mp.publishers.start(p, {
      legalName: "Shady Ltd",
      domain: "shady.example.com",
      contactEmail: "x@shady.example.com",
    });
    expect(again.state).toBe("pending");
    env.domain.records.set("shady.example.com", [`axis-verify=${again.challenge}`]);
    env.identity.reject.add("Shady Ltd");
    await env.mp.publishers.submitEvidence(p);
    await expect(
      env.mp.publishers.decide(reviewer(), t, { decision: "approve", reason: "trust me bro" }),
    ).rejects.toMatchObject({ checks: ["evidence_missing"] });
    env.identity.reject.clear();
    await env.mp.publishers.submitEvidence(p);
    await env.mp.publishers.decide(reviewer(), t, {
      decision: "approve",
      reason: "now it checks out",
    });
    await expect(
      env.mp.publishers.suspend(reviewer() as never, t, "abuse reports"),
    ).rejects.toMatchObject({ code: "forbidden" });
    await env.mp.publishers.suspend(moderator(), t, "abuse reports received");
    expect(await env.mp.publishers.isVerified(t)).toBe(false);
    await expect(
      env.mp.publishers.suspend(moderator(), t, "abuse reports received"),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(
      env.mp.publishers.suspend(moderator(), await env.tenant(), "abuse reports received"),
    ).rejects.toMatchObject({ code: "not_found" });
    await expect(env.mp.publishers.suspend(moderator(), t, "no")).rejects.toMatchObject({
      code: "invalid",
    });
  });

  it("authorization: roles, reviewer independence, input validation, isolation", async () => {
    const env = await mk();
    const t = await env.tenant();
    const t2 = await env.tenant();
    const good = {
      legalName: "Acme Corp",
      domain: "acme.example.com",
      contactEmail: "ops@acme.example.com",
    };
    for (const role of ["builder", "viewer", "auditor"] as const)
      await expect(env.mp.publishers.start(tenantP(t, role), good)).rejects.toMatchObject({
        code: "forbidden",
      });
    expect(await actions(env, t)).toContain("marketplace.publisher.start:DENY");
    for (const bad of [
      { ...good, legalName: "A" },
      { ...good, domain: "not a domain" },
      { ...good, domain: "localhost" },
      { ...good, contactEmail: "nope" },
    ])
      await expect(env.mp.publishers.start(tenantP(t), bad)).rejects.toMatchObject({
        code: "invalid",
      });
    const a = tenantP(t, "admin", "alice");
    await env.mp.publishers.start(a, good);
    // tenant staff cannot act as reviewers, and reviewers cannot use tenant APIs
    await expect(
      env.mp.publishers.decide(moderator() as never, t, {
        decision: "approve",
        reason: "fine fine",
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
    await expect(env.mp.publishers.queue(a as never)).rejects.toMatchObject({ code: "forbidden" });
    await expect(env.mp.publishers.get(reviewer() as never)).rejects.toMatchObject({
      code: "forbidden",
    });
    // the reviewer may not be the submitter, nor belong to the tenant
    await expect(
      env.mp.publishers.decide(reviewer("alice"), t, {
        decision: "approve",
        reason: "self approval",
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
    await expect(
      env.mp.publishers.decide(reviewer("someone", t), t, {
        decision: "approve",
        reason: "own org",
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
    expect(await actions(env, t)).toContain("marketplace.publisher.decide:DENY");
    await expect(
      env.mp.publishers.decide(reviewer(), t, { decision: "maybe" as never, reason: "whatever" }),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(
      env.mp.publishers.decide(reviewer(), t, { decision: "reject", reason: "no" }),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(
      env.mp.publishers.decide(reviewer(), t2, { decision: "reject", reason: "does not exist" }),
    ).rejects.toMatchObject({ code: "not_found" });
    // tenant 2 sees nothing of tenant 1
    expect(await env.mp.publishers.get(tenantP(t2))).toBeUndefined();
    expect(await env.mp.publishers.evidence(tenantP(t2))).toEqual([]);
  });
});

describe.each(envs)("security review workflow (%s)", (_n, mk) => {
  it("submit -> scan -> in_review -> approved; version becomes listed and pinned by hash; republish needs re-review", async () => {
    const env = await mk();
    const pub = await Pub.create(env);
    await pub.publish(ablDoc("helper-agent", "1.0.0"));
    const rv = await env.mp.reviews.submit(pub.b, {
      namespace: pub.namespace,
      name: "helper-agent",
      version: "1.0.0",
    });
    expect(rv.state).toBe("in_review");
    expect(rv.contentHash).toMatch(/^[0-9a-f]{64}$/);
    expect((await env.mp.reviews.queue(reviewer())).map((q) => q.review.name)).toContain(
      "helper-agent",
    );
    const id = rid(pub.tenantId, pub.namespace, "helper-agent", "1.0.0");
    expect((await env.mp.reviews.get(reviewer(), id)).state).toBe("in_review");
    // listing before approval: draft, not in the public catalog, not installable
    await env.mp.listings.create(pub.b, {
      namespace: pub.namespace,
      name: "helper-agent",
      title: "Helper",
      summary: "Helps with things",
    });
    expect(
      (await env.mp.listings.catalog()).some(
        (e) => e.namespace === pub.namespace && e.name === "helper-agent",
      ),
    ).toBe(false);
    const approved = await env.mp.reviews.decide(reviewer("rev-2"), id, {
      decision: "approve",
      note: "reviewed scan and blueprint",
    });
    expect(approved).toMatchObject({
      state: "approved",
      decidedBy: "rev-2",
      approvedHash: rv.contentHash,
    });
    const e = (await env.mp.listings.catalog()).find(
      (x) => x.namespace === pub.namespace && x.name === "helper-agent",
    );
    expect(e?.latest?.version).toBe("1.0.0");
    expect(e?.latest?.contentHash).toBe(rv.contentHash);
    // the namespace is now public in the registry: another tenant can resolve it
    const other = await env.tenant();
    expect(
      (await env.registry.resolve({ tenantId: other }, `${pub.namespace}/helper-agent@^1.0.0`))
        .version,
    ).toBe("1.0.0");
    // republish a new version: NOT installable until it is reviewed again
    await pub.publish(ablDoc("helper-agent", "1.1.0"));
    expect(
      (await env.mp.listings.catalog()).find(
        (x) => x.namespace === pub.namespace && x.name === "helper-agent",
      )?.versions,
    ).toEqual(["1.0.0"]);
    await expect(
      env.mp.listings.installable(pub.namespace, "helper-agent", "^1.0.0").then((r) => r.version),
    ).resolves.toBe("1.0.0");
    await expect(
      env.mp.listings.installable(pub.namespace, "helper-agent", "1.1.0"),
    ).rejects.toMatchObject({ code: "not_found" });
    // audit trail
    expect(await actions(env, pub.tenantId)).toEqual(
      expect.arrayContaining([
        "marketplace.review.submit:ALLOW",
        "marketplace.review.decide.done:ALLOW",
      ]),
    );
    // cannot decide twice; submitting twice conflicts
    await expect(
      env.mp.reviews.decide(reviewer("rev-3"), id, { decision: "reject", note: "changed my mind" }),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(
      env.mp.reviews.submit(pub.b, {
        namespace: pub.namespace,
        name: "helper-agent",
        version: "1.0.0",
      }),
    ).rejects.toMatchObject({ code: "conflict" });
    expect((await env.mp.reviews.mine(pub.b)).length).toBe(1);
  });

  it("reviewer != publisher: submitter, tenant members and anyone who acted for the publisher are refused", async () => {
    const env = await mk();
    const pub = await Pub.create(env);
    await pub.publish(ablDoc("helper-agent", "1.0.0"));
    await env.mp.reviews.submit(pub.b, {
      namespace: pub.namespace,
      name: "helper-agent",
      version: "1.0.0",
    });
    const id = rid(pub.tenantId, pub.namespace, "helper-agent", "1.0.0");
    const note = "approving my own work";
    await expect(
      env.mp.reviews.decide(reviewer(pub.b.subject), id, { decision: "approve", note }),
    ).rejects.toMatchObject({ code: "forbidden" });
    await expect(
      env.mp.reviews.decide(reviewer(pub.p.subject), id, { decision: "approve", note }),
    ).rejects.toMatchObject({ code: "forbidden" }); // acted for the publisher (verification)
    await expect(
      env.mp.reviews.decide(reviewer("outsider", pub.tenantId), id, { decision: "approve", note }),
    ).rejects.toMatchObject({ code: "forbidden" });
    expect(await actions(env, pub.tenantId)).toContain("marketplace.review.decide:DENY");
    // tenant principals and moderators are not reviewers
    await expect(
      env.mp.reviews.decide(pub.p as never, id, { decision: "approve", note }),
    ).rejects.toMatchObject({ code: "forbidden" });
    await expect(
      env.mp.reviews.decide(moderator() as never, id, { decision: "approve", note }),
    ).rejects.toMatchObject({ code: "forbidden" });
    expect((await env.mp.reviews.get(reviewer(), id)).state).toBe("in_review");
  });

  it("high findings need each one acknowledged by a human; critical findings can never be approved (and are auto-rejected)", async () => {
    const env = await mk();
    const pub = await Pub.create(env);
    const risky = {
      tools: [
        { name: "pay-out", kind: "function", sideEffects: "external" },
        { name: "web", kind: "browser", sideEffects: "read" },
      ],
    };
    await pub.publish(ablDoc("risky-agent", "1.0.0", risky));
    const rv = await env.mp.reviews.submit(pub.b, {
      namespace: pub.namespace,
      name: "risky-agent",
      version: "1.0.0",
    });
    expect(rv.state).toBe("in_review");
    expect(rv.maxSeverity).toBe("high");
    const id = rid(pub.tenantId, pub.namespace, "risky-agent", "1.0.0");
    const high = rv.findings.filter((f) => f.severity === "high").map((f) => f.id);
    expect(high.length).toBeGreaterThanOrEqual(2);
    await expect(
      env.mp.reviews.decide(reviewer(), id, { decision: "approve", note: "quick look only" }),
    ).rejects.toMatchObject({ checks: ["unacknowledged_findings"] });
    await expect(
      env.mp.reviews.decide(reviewer(), id, {
        decision: "approve",
        note: "quick look only",
        acknowledged: [high[0] as string],
      }),
    ).rejects.toMatchObject({ checks: ["unacknowledged_findings"] });
    expect(
      (
        await env.mp.reviews.decide(reviewer(), id, {
          decision: "approve",
          note: "acknowledged every high finding",
          acknowledged: high,
        })
      ).acknowledged,
    ).toEqual([...new Set(high)]);
    // critical: a leaked credential in the prompt is rejected by the scan itself
    await pub.publish(
      ablDoc("leaky-agent", "1.0.0", { instructions: { system: "use key AKIAABCDEFGHIJKLMNOP" } }),
    );
    const leaky = await env.mp.reviews.submit(pub.b, {
      namespace: pub.namespace,
      name: "leaky-agent",
      version: "1.0.0",
    });
    expect(leaky).toMatchObject({
      state: "rejected",
      maxSeverity: "critical",
      decidedBy: "system:scan",
    });
    await expect(
      env.mp.reviews.decide(reviewer(), rid(pub.tenantId, pub.namespace, "leaky-agent", "1.0.0"), {
        decision: "approve",
        note: "override attempt",
      }),
    ).rejects.toMatchObject({ code: "conflict" });
  });

  it("request_changes and reject are terminal; a fixed version needs a NEW review", async () => {
    const env = await mk();
    const pub = await Pub.create(env);
    await pub.publish(ablDoc("helper-agent", "1.0.0"));
    await env.mp.reviews.submit(pub.b, {
      namespace: pub.namespace,
      name: "helper-agent",
      version: "1.0.0",
    });
    const id = rid(pub.tenantId, pub.namespace, "helper-agent", "1.0.0");
    expect(
      (
        await env.mp.reviews.decide(reviewer(), id, {
          decision: "request_changes",
          note: "please add a budget",
        })
      ).state,
    ).toBe("changes_requested");
    await expect(
      env.mp.reviews.decide(reviewer(), id, { decision: "approve", note: "now it is fine" }),
    ).rejects.toMatchObject({ code: "conflict" });
    await pub.publish(ablDoc("helper-agent", "1.0.1"));
    await env.mp.reviews.submit(pub.b, {
      namespace: pub.namespace,
      name: "helper-agent",
      version: "1.0.1",
    });
    const id2 = rid(pub.tenantId, pub.namespace, "helper-agent", "1.0.1");
    expect(
      (
        await env.mp.reviews.decide(reviewer(), id2, {
          decision: "reject",
          note: "still not acceptable",
        })
      ).state,
    ).toBe("rejected");
    expect((await env.mp.reviews.queue(reviewer(), "rejected")).length).toBeGreaterThan(0);
  });

  it("submission rules: verified publisher, own namespace, existing version; decision input validation", async () => {
    const env = await mk();
    const unverified = await Pub.create(env, { verified: false });
    await unverified.publish(ablDoc("helper-agent", "1.0.0"));
    await expect(
      env.mp.reviews.submit(unverified.b, {
        namespace: unverified.namespace,
        name: "helper-agent",
        version: "1.0.0",
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
    const pub = await Pub.create(env);
    await pub.publish(ablDoc("helper-agent", "1.0.0"));
    await expect(
      env.mp.reviews.submit(tenantP(pub.tenantId, "viewer"), {
        namespace: pub.namespace,
        name: "helper-agent",
        version: "1.0.0",
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
    await expect(
      env.mp.reviews.submit(pub.b, {
        namespace: pub.namespace,
        name: "helper-agent",
        version: "9.9.9",
      }),
    ).rejects.toMatchObject({ code: "not_found" });
    const other = await Pub.create(env);
    await expect(
      env.mp.reviews.submit(other.b, {
        namespace: pub.namespace,
        name: "helper-agent",
        version: "1.0.0",
      }),
    ).rejects.toMatchObject({ code: expect.stringMatching(/forbidden|not_found/) });
    await env.mp.reviews.submit(pub.b, {
      namespace: pub.namespace,
      name: "helper-agent",
      version: "1.0.0",
    });
    const id = rid(pub.tenantId, pub.namespace, "helper-agent", "1.0.0");
    await expect(
      env.mp.reviews.decide(reviewer(), id, { decision: "approve", note: "short" }),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(
      env.mp.reviews.decide(reviewer(), id, {
        decision: "nope" as never,
        note: "long enough note",
      }),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(
      env.mp.reviews.decide(reviewer(), "garbage", {
        decision: "approve",
        note: "long enough note",
      }),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(
      env.mp.reviews.decide(reviewer(), rid(pub.tenantId, pub.namespace, "nope-agent", "1.0.0"), {
        decision: "approve",
        note: "long enough note",
      }),
    ).rejects.toMatchObject({ code: "not_found" });
    await expect(
      env.mp.reviews.get(reviewer(), rid(pub.tenantId, pub.namespace, "nope-agent", "1.0.0")),
    ).rejects.toMatchObject({ code: "not_found" });
  });

  it("TOCTOU: a version yanked after the scan cannot be approved; a suspended publisher cannot be approved for", async () => {
    const env = await mk();
    const pub = await Pub.create(env);
    await pub.publish(ablDoc("helper-agent", "1.0.0"));
    await env.mp.reviews.submit(pub.b, {
      namespace: pub.namespace,
      name: "helper-agent",
      version: "1.0.0",
    });
    await env.registry.yank(pub.p, pub.namespace, "helper-agent", "1.0.0", "found a bug");
    const id = rid(pub.tenantId, pub.namespace, "helper-agent", "1.0.0");
    await expect(
      env.mp.reviews.decide(reviewer(), id, {
        decision: "approve",
        note: "approving a yanked one",
      }),
    ).rejects.toMatchObject({ code: "not_found" });
    await pub.publish(ablDoc("helper-agent", "1.0.1"));
    await env.mp.reviews.submit(pub.b, {
      namespace: pub.namespace,
      name: "helper-agent",
      version: "1.0.1",
    });
    await env.mp.publishers.suspend(moderator(), pub.tenantId, "policy violation seen");
    await expect(
      env.mp.reviews.decide(reviewer(), rid(pub.tenantId, pub.namespace, "helper-agent", "1.0.1"), {
        decision: "approve",
        note: "approve anyway",
      }),
    ).rejects.toMatchObject({ checks: ["publisher_not_verified"] });
  });

  it("automated approval is OFF by default and only applies at or below the configured severity", async () => {
    const env = makeEnv({ review: { autoApproveAtOrBelow: "low" } });
    const pub = await Pub.create(env);
    await pub.publish(ablDoc("quiet-agent", "1.0.0"));
    const quiet = await env.mp.reviews.submit(pub.b, {
      namespace: pub.namespace,
      name: "quiet-agent",
      version: "1.0.0",
    });
    expect(quiet).toMatchObject({
      state: "approved",
      decidedBy: "system:scan",
      approvedHash: quiet.contentHash,
    });
    await pub.publish(
      ablDoc("loud-agent", "1.0.0", {
        tools: [{ name: "wr", kind: "function", sideEffects: "write" }],
      }),
    );
    expect(
      (
        await env.mp.reviews.submit(pub.b, {
          namespace: pub.namespace,
          name: "loud-agent",
          version: "1.0.0",
        })
      ).state,
    ).toBe("in_review");
  });
});

describe.each(envs)("installs (%s)", (_n, mk) => {
  async function released(env: Env, spec: Record<string, unknown> = {}) {
    const pub = await Pub.create(env);
    await pub.release("helper-agent", "1.0.0", spec);
    const buyer = await env.tenant();
    return { pub, buyer, admin: tenantP(buyer, "admin", "bella") };
  }

  it("preview shows the diff vs the tenant baseline; install needs the matching consent; creates pin + deny-by-default pack; meters the publisher", async () => {
    const env = await mk();
    const { pub, buyer, admin } = await released(env, {
      tools: [
        {
          name: "crm",
          kind: "mcp",
          mcpServer: "https://mcp.example.com/crm",
          sideEffects: "write",
        },
      ],
    });
    const pv = await env.mp.installs.preview(admin, pub.namespace, "helper-agent", "^1.0.0");
    expect(pv.version).toBe("1.0.0");
    expect(pv.diff.widening).toBe(true);
    expect(pv.diff.added.map((a) => a.key)).toEqual(
      expect.arrayContaining([
        "tool:mcp:crm",
        "mcp:https://mcp.example.com/crm",
        "model:anthropic",
      ]),
    );
    expect(pv.diff.added.map((a) => a.key)).not.toContain("memory:run"); // already in the default baseline
    // consent is mandatory and exact
    const base = {
      namespace: pub.namespace,
      name: "helper-agent",
      version: "1.0.0",
      contentHash: pv.contentHash,
    };
    await expect(
      env.mp.installs.install(admin, { ...base, consentDigest: "0".repeat(64) }),
    ).rejects.toMatchObject({ checks: ["consent_required"] });
    await expect(
      env.mp.installs.install(admin, {
        ...base,
        contentHash: "0".repeat(64),
        consentDigest: pv.consentDigest,
      }),
    ).rejects.toMatchObject({ checks: ["content_hash_mismatch"] });
    await expect(
      env.mp.installs.install(tenantP(buyer, "builder"), {
        ...base,
        consentDigest: pv.consentDigest,
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
    await expect(
      env.mp.installs.install(admin, {
        ...base,
        version: "^1.0.0",
        consentDigest: pv.consentDigest,
      }),
    ).rejects.toMatchObject({ code: "invalid" });
    const inst = await env.mp.installs.install(admin, { ...base, consentDigest: pv.consentDigest });
    expect(inst).toMatchObject({
      state: "active",
      version: "1.0.0",
      contentHash: pv.contentHash,
      consentedBy: "bella",
      publisherTenantId: pub.tenantId,
    });
    expect(inst.granted.map((g) => g.key)).toContain("tool:mcp:crm");
    const pack = inst.policyPack as { spec: { defaultDecision: string; rules: { id: string }[] } };
    expect(pack.spec.defaultDecision).toBe("DENY");
    expect(pack.spec.rules.map((r) => r.id)).toContain("allow-mcp-crm");
    expect(await actions(env, buyer)).toEqual(
      expect.arrayContaining([
        "marketplace.install:ALLOW",
        "marketplace.install.done:ALLOW",
        "marketplace.install:ALLOW",
      ]),
    );
    await expect(
      env.mp.installs.install(admin, { ...base, consentDigest: pv.consentDigest }),
    ).rejects.toMatchObject({ code: "conflict" });
    // metering: one marketplace_installs record for the PUBLISHER, idempotent, with no installer tenant id in clear
    const rows = await env.ledger.entries(pub.tenantId);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      meter: "marketplace_installs",
      quantity: 1n,
      source: "marketplace",
    });
    expect(rows[0]?.dimensions["listing"]).toBe(`${pub.namespace}/helper-agent`);
    expect(JSON.stringify(rows[0]?.dimensions)).not.toContain(buyer);
    expect(inst.meteredAt).not.toBeNull();
    expect(await env.mp.installs.flushMetering(admin)).toBe(0);
    expect((await env.mp.installs.list(admin)).length).toBe(1);
    expect((await env.mp.installs.get(admin, pub.namespace, "helper-agent")).version).toBe("1.0.0");
  });

  it("consent goes stale when the tenant baseline changes between preview and install (TOCTOU)", async () => {
    const env = await mk();
    const { pub, admin } = await released(env);
    const pv = await env.mp.installs.preview(admin, pub.namespace, "helper-agent", "1.0.0");
    await env.mp.installs.setBaseline(admin, [
      ...(await env.mp.installs.baseline(admin)).granted,
      { key: "model:anthropic", level: 1 },
    ]);
    await expect(
      env.mp.installs.install(admin, {
        namespace: pub.namespace,
        name: "helper-agent",
        version: "1.0.0",
        contentHash: pv.contentHash,
        consentDigest: pv.consentDigest,
      }),
    ).rejects.toMatchObject({ checks: ["consent_required"] });
    const fresh = await env.mp.installs.preview(admin, pub.namespace, "helper-agent", "1.0.0");
    expect(fresh.diff.added.map((a) => a.key)).not.toContain("model:anthropic");
    await env.mp.installs.install(admin, {
      namespace: pub.namespace,
      name: "helper-agent",
      version: "1.0.0",
      contentHash: fresh.contentHash,
      consentDigest: fresh.consentDigest,
    });
  });

  it("baseline validation and roles", async () => {
    const env = await mk();
    const t = await env.tenant();
    await expect(env.mp.installs.setBaseline(tenantP(t, "builder"), [])).rejects.toMatchObject({
      code: "forbidden",
    });
    await expect(
      env.mp.installs.setBaseline(tenantP(t), [{ key: 1 } as never]),
    ).rejects.toMatchObject({ code: "invalid" });
    expect((await env.mp.installs.baseline(tenantP(t, "viewer"))).granted).toEqual([
      { key: "memory:run", level: 1 },
    ]);
    await env.mp.installs.setBaseline(tenantP(t), [{ key: "a", level: 1 }]);
    await env.mp.installs.setBaseline(tenantP(t), [{ key: "b", level: 2 }]);
    expect((await env.mp.installs.baseline(tenantP(t))).granted).toEqual([{ key: "b", level: 2 }]);
  });

  it("only approved, unyanked, listed versions install; unreviewed and yanked ones do not", async () => {
    const env = await mk();
    const { pub, admin } = await released(env);
    await pub.publish(ablDoc("helper-agent", "1.1.0")); // published but never reviewed
    await expect(
      env.mp.installs.preview(admin, pub.namespace, "helper-agent", "1.1.0"),
    ).rejects.toMatchObject({ code: "not_found" });
    expect(
      (await env.mp.installs.preview(admin, pub.namespace, "helper-agent", "^1.0.0")).version,
    ).toBe("1.0.0");
    await env.registry.yank(pub.p, pub.namespace, "helper-agent", "1.0.0", "security fix pending");
    await expect(
      env.mp.installs.preview(admin, pub.namespace, "helper-agent", "^1.0.0"),
    ).rejects.toMatchObject({ code: "not_found" });
    await expect(
      env.mp.installs.preview(admin, pub.namespace, "ghost-agent", "^1.0.0"),
    ).rejects.toMatchObject({ code: "not_found" });
  });

  it("registry content that no longer matches the approved hash is refused at install", async () => {
    const env = await mk();
    const { pub, admin } = await released(env);
    const rows = await env.docs.find({ kind: "platform" }, "listings", {
      namespace: pub.namespace,
    });
    const l = rows[0]!;
    const data = l.data as { approved: { contentHash: string }[] };
    await env.docs.update({ kind: "platform" }, l.tenantId, "listings", l.key, l.rev, {
      ...l.data,
      approved: [{ ...data.approved[0], contentHash: "f".repeat(64) }],
    });
    await expect(
      env.mp.installs.preview(admin, pub.namespace, "helper-agent", "1.0.0"),
    ).rejects.toMatchObject({ checks: ["approval_hash_mismatch"] });
  });

  it("updates: widening needs re-consent, narrowing does not, downgrade refused, uninstall and reinstall", async () => {
    const env = await mk();
    const { pub, admin } = await released(env);
    const p1 = await env.mp.installs.preview(admin, pub.namespace, "helper-agent", "1.0.0");
    await env.mp.installs.install(admin, {
      namespace: pub.namespace,
      name: "helper-agent",
      version: "1.0.0",
      contentHash: p1.contentHash,
      consentDigest: p1.consentDigest,
    });
    // 1.1.0 widens (adds an external tool)
    await pub.release("helper-agent", "1.1.0", {
      tools: [{ name: "pay-out", kind: "function", sideEffects: "external" }],
    });
    const p2 = await env.mp.installs.preview(admin, pub.namespace, "helper-agent", "1.1.0");
    expect(p2.diff.widening).toBe(true); // preview is against the BASELINE
    await expect(
      env.mp.installs.update(admin, pub.namespace, "helper-agent", { version: "1.1.0" }),
    ).rejects.toMatchObject({ checks: ["consent_required"] });
    const inst = (await env.mp.installs.list(admin))[0]!;
    expect(inst.version).toBe("1.0.0");
    // the consent digest for an update is computed against the grant: obtain it from the refusal path by recomputing via preview helper
    const widen = await env.mp.installs.updatePreview(
      admin,
      pub.namespace,
      "helper-agent",
      "1.1.0",
    );
    expect(widen.diff.added.map((a) => a.key)).toContain("tool:function:pay-out");
    await expect(
      env.mp.installs.update(admin, pub.namespace, "helper-agent", {
        version: "1.1.0",
        consentDigest: "0".repeat(64),
      }),
    ).rejects.toMatchObject({ checks: ["consent_required"] });
    const up = await env.mp.installs.update(admin, pub.namespace, "helper-agent", {
      version: "1.1.0",
      consentDigest: widen.consentDigest,
    });
    expect(up.version).toBe("1.1.0");
    expect(up.granted.map((g) => g.key)).toContain("tool:function:pay-out");
    // 1.2.0 narrows (drops the tool): no consent needed, grant shrinks
    await pub.release("helper-agent", "1.2.0");
    const narrowed = await env.mp.installs.update(admin, pub.namespace, "helper-agent", {
      version: "1.2.0",
    });
    expect(narrowed.granted.map((g) => g.key)).not.toContain("tool:function:pay-out");
    // rollback defence
    await expect(
      env.mp.installs.update(admin, pub.namespace, "helper-agent", { version: "1.0.0" }),
    ).rejects.toMatchObject({ checks: ["rollback"] });
    expect(
      (
        await env.mp.installs.update(admin, pub.namespace, "helper-agent", {
          version: "1.0.0",
          allowDowngrade: true,
        })
      ).version,
    ).toBe("1.0.0");
    // uninstall / reinstall
    await env.mp.installs.uninstall(admin, pub.namespace, "helper-agent");
    expect((await env.mp.installs.list(admin))[0]).toMatchObject({
      state: "uninstalled",
      policyPack: null,
    });
    await expect(
      env.mp.installs.uninstall(admin, pub.namespace, "helper-agent"),
    ).rejects.toMatchObject({ code: "not_found" });
    await expect(
      env.mp.installs.update(admin, pub.namespace, "helper-agent", { version: "1.2.0" }),
    ).rejects.toMatchObject({ code: "not_found" });
    const p3 = await env.mp.installs.preview(admin, pub.namespace, "helper-agent", "1.2.0");
    const again = await env.mp.installs.install(admin, {
      namespace: pub.namespace,
      name: "helper-agent",
      version: "1.2.0",
      contentHash: p3.contentHash,
      consentDigest: p3.consentDigest,
    });
    expect(again.installCount).toBe(2);
    expect(await env.ledger.entries(pub.tenantId)).toHaveLength(2);
    await expect(env.mp.installs.get(admin, pub.namespace, "ghost-agent")).rejects.toMatchObject({
      code: "not_found",
    });
    expect(await actions(env, admin.tenantId)).toEqual(
      expect.arrayContaining(["marketplace.install.update:ALLOW", "marketplace.uninstall:ALLOW"]),
    );
  });

  it("metering hook failure never fails the install; flush retries idempotently", async () => {
    const env = await mk();
    const { pub, admin } = await released(env);
    env.meterFail.on = true;
    const pv = await env.mp.installs.preview(admin, pub.namespace, "helper-agent", "1.0.0");
    const inst = await env.mp.installs.install(admin, {
      namespace: pub.namespace,
      name: "helper-agent",
      version: "1.0.0",
      contentHash: pv.contentHash,
      consentDigest: pv.consentDigest,
    });
    expect(inst.meteredAt).toBeNull();
    expect(await env.ledger.entries(pub.tenantId)).toHaveLength(0);
    expect(await env.mp.installs.flushMetering(admin)).toBe(0);
    env.meterFail.on = false;
    expect(await env.mp.installs.flushMetering(admin)).toBe(1);
    expect(await env.mp.installs.flushMetering(admin)).toBe(0);
    expect(await env.ledger.entries(pub.tenantId)).toHaveLength(1);
    expect(
      (await env.mp.installs.get(admin, pub.namespace, "helper-agent")).meteredAt,
    ).not.toBeNull();
  });

  it("tenant isolation: installs, baselines and previews of one tenant are invisible and untouchable by another (IDOR)", async () => {
    const env = await mk();
    const { pub, admin } = await released(env);
    const pv = await env.mp.installs.preview(admin, pub.namespace, "helper-agent", "1.0.0");
    await env.mp.installs.install(admin, {
      namespace: pub.namespace,
      name: "helper-agent",
      version: "1.0.0",
      contentHash: pv.contentHash,
      consentDigest: pv.consentDigest,
    });
    const other = tenantP(await env.tenant(), "owner", "mallory");
    expect(await env.mp.installs.list(other)).toEqual([]);
    await expect(env.mp.installs.get(other, pub.namespace, "helper-agent")).rejects.toMatchObject({
      code: "not_found",
    });
    await expect(
      env.mp.installs.uninstall(other, pub.namespace, "helper-agent"),
    ).rejects.toMatchObject({ code: "not_found" });
    await expect(
      env.mp.installs.update(other, pub.namespace, "helper-agent", { version: "1.0.0" }),
    ).rejects.toMatchObject({ code: "not_found" });
    expect((await env.mp.installs.baseline(other)).granted).toEqual([
      { key: "memory:run", level: 1 },
    ]);
    // the other tenant's consent digest is bound to the same blueprint but its install is its own record
    await env.mp.installs.install(other, {
      namespace: pub.namespace,
      name: "helper-agent",
      version: "1.0.0",
      contentHash: pv.contentHash,
      consentDigest: pv.consentDigest,
    });
    expect((await env.mp.installs.list(admin)).length).toBe(1);
    expect((await env.mp.installs.list(other)).length).toBe(1);
    // publisher cannot read installers' records either
    expect(await env.mp.installs.list(pub.p)).toEqual([]);
  });

  it("takedown: immediate delist + block, registry yank, existing installs flagged; version-level takedown", async () => {
    const env = await mk();
    const { pub, admin } = await released(env);
    await pub.release("helper-agent", "1.1.0");
    const p1 = await env.mp.installs.preview(admin, pub.namespace, "helper-agent", "1.0.0");
    await env.mp.installs.install(admin, {
      namespace: pub.namespace,
      name: "helper-agent",
      version: "1.0.0",
      contentHash: p1.contentHash,
      consentDigest: p1.consentDigest,
    });
    // version-level takedown of 1.1.0: 1.0.0 untouched
    await expect(
      env.mp.listings.takedown(reviewer() as never, {
        namespace: pub.namespace,
        name: "helper-agent",
        reason: "not a moderator at all",
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
    await expect(
      env.mp.listings.takedown(moderator(), {
        namespace: pub.namespace,
        name: "helper-agent",
        reason: "short",
      }),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(
      env.mp.listings.takedown(moderator(), {
        namespace: pub.namespace,
        name: "ghost-agent",
        reason: "does not exist at all",
      }),
    ).rejects.toMatchObject({ code: "not_found" });
    await expect(
      env.mp.listings.takedown(moderator(), {
        namespace: pub.namespace,
        name: "helper-agent",
        version: "7.0.0",
        reason: "no such version listed",
      }),
    ).rejects.toMatchObject({ code: "not_found" });
    expect(
      await env.mp.listings.takedown(moderator(), {
        namespace: pub.namespace,
        name: "helper-agent",
        version: "1.1.0",
        reason: "malicious behaviour in 1.1.0",
      }),
    ).toEqual({ flagged: 0 });
    expect(
      (await env.mp.listings.catalog()).find(
        (e) => e.namespace === pub.namespace && e.name === "helper-agent",
      )?.versions,
    ).toEqual(["1.0.0"]);
    await expect(
      env.mp.installs.preview(admin, pub.namespace, "helper-agent", "1.1.0"),
    ).rejects.toMatchObject({ code: "not_found" });
    expect((await env.mp.installs.list(admin))[0]?.state).toBe("active");
    // whole listing
    const res = await env.mp.listings.takedown(moderator("mod-2"), {
      namespace: pub.namespace,
      name: "helper-agent",
      reason: "publisher compromised, delisting everything",
    });
    expect(res).toEqual({ flagged: 1 });
    expect(
      (await env.mp.listings.catalog()).some(
        (e) => e.namespace === pub.namespace && e.name === "helper-agent",
      ),
    ).toBe(false);
    await expect(env.mp.listings.entry(pub.namespace, "helper-agent")).rejects.toMatchObject({
      code: "not_found",
    });
    const other = tenantP(await env.tenant(), "admin", "newbie");
    await expect(
      env.mp.installs.preview(other, pub.namespace, "helper-agent", "1.0.0"),
    ).rejects.toMatchObject({ code: "not_found" });
    const flagged = (await env.mp.installs.list(admin))[0]!;
    expect(flagged).toMatchObject({
      state: "flagged",
      flagReason: "publisher compromised, delisting everything",
    });
    await expect(
      env.mp.installs.update(admin, pub.namespace, "helper-agent", { version: "1.0.0" }),
    ).rejects.toMatchObject({ code: "not_found" });
    // registry versions are yanked by the platform
    await expect(
      env.registry.resolve({ tenantId: other.tenantId }, `${pub.namespace}/helper-agent@^1.0.0`),
    ).rejects.toMatchObject({ code: "not_found" });
    // everything audited in the right chains
    expect(await actions(env, admin.tenantId)).toContain("marketplace.install.flagged:ALLOW");
    expect(await actions(env, pub.tenantId)).toContain("marketplace.moderation.takedown:ALLOW");
    // uninstall of a flagged install is still allowed
    await env.mp.installs.uninstall(admin, pub.namespace, "helper-agent");
  });
});

describe.each(envs)("listings (%s)", (_n, mk) => {
  it("creation rules, catalog search without any credential, categories", async () => {
    const env = await mk();
    const pub = await Pub.create(env);
    await pub.release("helper-agent", "1.0.0");
    await pub.release("search-agent", "1.0.0", {}, { listing: false });
    const l = {
      namespace: pub.namespace,
      name: "search-agent",
      title: "Search",
      summary: "Finds documents",
      categories: ["search"],
    };
    await expect(env.mp.listings.create(tenantP(pub.tenantId, "viewer"), l)).rejects.toMatchObject({
      code: "forbidden",
    });
    const unverified = await Pub.create(env, { verified: false });
    await expect(
      env.mp.listings.create(unverified.b, { ...l, namespace: unverified.namespace }),
    ).rejects.toMatchObject({ code: "forbidden" });
    await expect(env.mp.listings.create(pub.b, { ...l, title: "x" })).rejects.toMatchObject({
      code: "invalid",
    });
    await expect(
      env.mp.listings.create(pub.b, { ...l, categories: ["Bad Cat"] }),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(
      env.mp.listings.create(pub.b, { ...l, namespace: "someone-elses" }),
    ).rejects.toMatchObject({ code: "forbidden" });
    await expect(
      env.mp.listings.create(pub.b, { ...l, name: "ghost-agent" }),
    ).rejects.toMatchObject({ code: "not_found" });
    const created = await env.mp.listings.create(pub.b, l);
    expect(created.status).toBe("listed"); // an approved version already exists
    await expect(env.mp.listings.create(pub.b, l)).rejects.toMatchObject({ code: "conflict" });
    const all = (await env.mp.listings.catalog()).filter((e) => e.namespace === pub.namespace);
    expect(all.map((e) => e.name).sort()).toEqual(["helper-agent", "search-agent"]);
    expect(
      (await env.mp.listings.catalog({ text: "documents" }))
        .filter((e) => e.namespace === pub.namespace)
        .map((e) => e.name),
    ).toEqual(["search-agent"]);
    expect(
      (await env.mp.listings.catalog({ category: "search" })).filter(
        (e) => e.namespace === pub.namespace,
      ),
    ).toHaveLength(1);
    expect((await env.mp.listings.entry(pub.namespace, "search-agent")).latest?.version).toBe(
      "1.0.0",
    );
    // a draft listing (nothing approved) is invisible
    await pub.publish(ablDoc("draft-agent", "1.0.0"));
    const draft = await env.mp.listings.create(pub.b, {
      namespace: pub.namespace,
      name: "draft-agent",
      title: "Draft",
      summary: "Not yet reviewed",
    });
    expect(draft.status).toBe("draft");
    expect(
      (await env.mp.listings.catalog()).some(
        (e) => e.namespace === pub.namespace && e.name === "draft-agent",
      ),
    ).toBe(false);
  });
});
