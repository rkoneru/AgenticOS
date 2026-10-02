import { randomUUID } from "node:crypto";
import { afterAll, describe, expect, it } from "vitest";
import {
  MemoryRegistryStore,
  generatePublisherKey,
  parseRef,
  type PlatformPrincipal,
  type RegistryStore,
} from "../src/index.js";
import {
  Publisher,
  ablDoc,
  adminClient,
  harness,
  newPool,
  newTenant,
  pgStore,
  principal,
  rid,
} from "./helpers.js";

const pool = newPool();
afterAll(() => pool.end());

const platform: PlatformPrincipal = {
  kind: "platform",
  subject: "svc:marketplace",
  service: "marketplace",
};

type Make = () => Promise<{ store: RegistryStore; tenant: () => Promise<string> }>;
const makes: [string, Make][] = [
  [
    "memory",
    () =>
      Promise.resolve({
        store: new MemoryRegistryStore(),
        tenant: () => Promise.resolve(randomUUID()),
      }),
  ],
  [
    "postgres",
    async () => {
      const admin = await adminClient();
      return { store: pgStore(pool), tenant: () => newTenant(admin) };
    },
  ],
];

describe.each(makes)("registry service (%s store)", (_n, make) => {
  async function setup() {
    const { store, tenant } = await make();
    const h = harness(store);
    const sfx = rid(6);
    const a = await Publisher.create(h, await tenant(), `acme-${sfx}`);
    const bTenant = await tenant();
    return { h, a, bTenant, sfx, tenant };
  }
  const auditActions = async (h: ReturnType<typeof harness>, tenantId: string) =>
    (await h.audit.read(tenantId)).map((e) => `${e.action}:${e.decision}`);

  it("publishes, resolves exact/caret/tilde, and audits the mutation", async () => {
    const { h, a } = await setup();
    for (const v of ["1.0.0", "1.2.0", "1.2.5", "2.0.0", "2.1.0-beta.1"])
      await a.publish(ablDoc("helper-agent", v));
    const view = { tenantId: a.p.tenantId };
    const r = (ref: string) => h.svc.resolve(view, `${a.namespace}/${ref}`).then((x) => x.version);
    expect(await r("helper-agent@^1.0.0")).toBe("1.2.5");
    expect(await r("helper-agent@~1.2.0")).toBe("1.2.5");
    expect(await r("helper-agent@1.0.0")).toBe("1.0.0");
    expect(await r("helper-agent@*")).toBe("2.0.0"); // pre-releases are not picked by *
    expect(await r("helper-agent@>=2.1.0-alpha")).toBe("2.1.0-beta.1");
    await expect(r("helper-agent@^3.0.0")).rejects.toMatchObject({ code: "not_found" });
    const actions = await auditActions(h, a.p.tenantId);
    expect(actions.filter((x) => x === "registry.publish:ALLOW")).toHaveLength(5);
    expect(actions.filter((x) => x === "registry.publish.done:ALLOW")).toHaveLength(5);
  });

  it("versions are immutable: republish (same or different content) is a conflict; the original is untouched", async () => {
    const { h, a } = await setup();
    const first = await a.publish(ablDoc("helper-agent", "1.0.0"));
    await expect(a.publish(ablDoc("helper-agent", "1.0.0"))).rejects.toMatchObject({
      code: "conflict",
    });
    await expect(
      a.publish(ablDoc("helper-agent", "1.0.0", { instructions: { system: "evil" } })),
    ).rejects.toMatchObject({ code: "conflict" });
    const got = await h.svc.getVersion(
      { tenantId: a.p.tenantId },
      a.namespace,
      "helper-agent",
      "1.0.0",
    );
    expect(got.contentHash).toBe(first.contentHash);
    expect(await auditActions(h, a.p.tenantId)).toContain("registry.publish.failed:DENY");
  });

  it("rejects bad semver, build metadata, schema and lint failures, oversize", async () => {
    const { a } = await setup();
    await expect(a.publish(ablDoc("helper-agent", "1.0.0+build5"))).rejects.toMatchObject({
      code: "invalid",
      message: expect.stringContaining("build metadata"),
    });
    await expect(a.publish(ablDoc("helper-agent", "1.0"))).rejects.toMatchObject({
      code: "invalid",
    });
    await expect(
      a.h.svc.publish(a.p, a.namespace, {
        abl: { nope: true },
        signature: a.submission(ablDoc("helper-agent", "1.0.0")).signature,
        provenance: a.submission(ablDoc("helper-agent", "1.0.0")).provenance,
      }),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(
      a.publish(
        ablDoc("helper-agent", "1.0.0", {
          tools: [
            { name: "xx", kind: "function" },
            { name: "xx", kind: "function" },
          ],
        }),
      ),
    ).rejects.toMatchObject({ code: "invalid", message: expect.stringContaining("ABL001") });
    await expect(
      a.h.svc.publish(a.p, a.namespace, {
        abl: "str",
        signature: a.key as never,
        provenance: {} as never,
      }),
    ).rejects.toMatchObject({ code: "invalid" });
    const sub = a.submission(ablDoc("helper-agent", "1.0.0"));
    await expect(
      a.h.svc.publish(a.p, a.namespace, { ...sub, provenance: "x" as never }),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(
      a.h.svc.publish(a.p, a.namespace, { ...sub, signature: null as never }),
    ).rejects.toMatchObject({ code: "invalid" });
    const big = ablDoc("big-agent", "1.0.0");
    (big["spec"] as { instructions: { system: string } }).instructions.system = "x".repeat(
      1_100_000,
    );
    await expect(a.publish(big)).rejects.toMatchObject({ code: "invalid" });
  });

  it("refuses a bad signature, a foreign key, an unregistered key and a stale attestation (nothing is stored)", async () => {
    const { h, a } = await setup();
    const doc = ablDoc("helper-agent", "1.0.0");
    const sub = a.submission(doc);
    const bad = {
      ...sub,
      signature: {
        ...sub.signature,
        sig: sub.signature.sig.slice(0, -2) + (sub.signature.sig.endsWith("AA") ? "BB" : "AA"),
      },
    };
    await expect(h.svc.publish(a.p, a.namespace, bad)).rejects.toMatchObject({
      code: "verification_failed",
      checks: expect.arrayContaining(["signature_invalid"]),
    });
    const rogue = generatePublisherKey();
    await expect(a.publish(doc, { key: rogue })).rejects.toMatchObject({
      code: "verification_failed",
      checks: expect.arrayContaining(["signing_key_unknown"]),
    });
    const other = await Publisher.create(
      h,
      await setup().then((s) => s.bTenant),
      `other-${rid(6)}`,
    );
    await expect(a.publish(doc, { key: other.key })).rejects.toMatchObject({
      code: "verification_failed",
    });
    await expect(
      h.svc.getVersion({ tenantId: a.p.tenantId }, a.namespace, "helper-agent", "1.0.0"),
    ).rejects.toMatchObject({ code: "not_found" });
    // signed in the far future (clock claim) is refused
    await expect(
      a.publish(doc, { signedAt: new Date(h.clock.t.getTime() + 3_600_000) }),
    ).rejects.toMatchObject({ checks: expect.arrayContaining(["signed_after_publish"]) });
  });

  it("key lifecycle: rotate, revoke retired/compromised, effective timestamps", async () => {
    const { h, a } = await setup();
    await a.publish(ablDoc("helper-agent", "1.0.0"));
    const view = { tenantId: a.p.tenantId };
    const k2 = generatePublisherKey();
    h.clock.advance(60_000);
    const { oldKey, newKey } = await h.svc.rotateKey(a.p, a.namespace, a.key.keyId, {
      newPublicKey: k2.publicKey,
    });
    expect(oldKey.validUntil).toEqual(newKey.validFrom);
    // old key can no longer publish; the new key can; v1 (signed before rotation) still verifies
    await expect(a.publish(ablDoc("helper-agent", "1.0.1"))).rejects.toMatchObject({
      code: "verification_failed",
    });
    await a.publish(ablDoc("helper-agent", "1.0.2"), { key: k2 });
    expect((await h.svc.resolve(view, `${a.namespace}/helper-agent@1.0.0`)).version).toBe("1.0.0");
    // revoke as compromised: everything signed with the old key stops verifying (resolution FAILS, no silent fallback)
    await h.svc.revokeKey(a.p, a.namespace, a.key.keyId, { reason: "compromised" });
    await expect(h.svc.resolve(view, `${a.namespace}/helper-agent@1.0.0`)).rejects.toMatchObject({
      code: "verification_failed",
      checks: expect.arrayContaining(["signing_key_not_trusted"]),
    });
    expect((await h.svc.resolve(view, `${a.namespace}/helper-agent@1.0.2`)).version).toBe("1.0.2");
    await expect(
      h.svc.revokeKey(a.p, a.namespace, a.key.keyId, { reason: "retired" }),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(
      h.svc.revokeKey(a.p, a.namespace, "k1-" + "0".repeat(32), { reason: "retired" }),
    ).rejects.toMatchObject({ code: "not_found" });
    await expect(
      h.svc.revokeKey(a.p, a.namespace, k2.keyId, { reason: "bogus" as never }),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(
      h.svc.rotateKey(a.p, a.namespace, a.key.keyId, { newPublicKey: k2.publicKey }),
    ).rejects.toBeDefined();
    await expect(
      h.svc.rotateKey(a.p, a.namespace, "k1-" + "0".repeat(32), {
        newPublicKey: generatePublisherKey().publicKey,
      }),
    ).rejects.toMatchObject({ code: "not_found" });
    await expect(
      h.svc.rotateKey(a.p, a.namespace, k2.keyId, { newPublicKey: k2.publicKey }),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(h.svc.addKey(a.p, a.namespace, { publicKey: "short" })).rejects.toMatchObject({
      code: "invalid",
    });
    await expect(h.svc.addKey(a.p, a.namespace, { publicKey: k2.publicKey })).rejects.toMatchObject(
      { code: "conflict" },
    );
    await expect(
      h.svc.addKey(a.p, a.namespace, {
        publicKey: generatePublisherKey().publicKey,
        validFrom: new Date(h.clock.t.getTime() + 400 * 86_400_000),
      }),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(
      h.svc.revokeKey(a.p, a.namespace, k2.keyId, {
        reason: "retired",
        effectiveAt: new Date("junk"),
      }),
    ).rejects.toMatchObject({ code: "invalid" });
    expect((await h.svc.listKeys(a.p, a.namespace)).length).toBe(2);
  });

  it("retired key: versions published BEFORE the effective time keep verifying, later ones are refused", async () => {
    const { h, a } = await setup();
    await a.publish(ablDoc("helper-agent", "1.0.0"));
    h.clock.advance(3_600_000);
    await h.svc.revokeKey(a.p, a.namespace, a.key.keyId, { reason: "retired" });
    expect(
      (await h.svc.resolve({ tenantId: a.p.tenantId }, `${a.namespace}/helper-agent@1.0.0`))
        .version,
    ).toBe("1.0.0");
    h.clock.advance(1000);
    await expect(a.publish(ablDoc("helper-agent", "1.0.1"))).rejects.toMatchObject({
      code: "verification_failed",
    });
  });

  it("yank and deprecate: yanked versions are not resolved; deprecated are flagged; never deleted; reasons required", async () => {
    const { h, a } = await setup();
    const view = { tenantId: a.p.tenantId };
    for (const v of ["1.0.0", "1.1.0", "1.2.0"]) await a.publish(ablDoc("helper-agent", v));
    await h.svc.yank(a.p, a.namespace, "helper-agent", "1.2.0", "critical bug");
    expect((await h.svc.resolve(view, `${a.namespace}/helper-agent@^1.0.0`)).version).toBe("1.1.0");
    await h.svc.deprecate(a.p, a.namespace, "helper-agent", "1.1.0", "use 1.3");
    const r = await h.svc.resolve(view, `${a.namespace}/helper-agent@^1.0.0`);
    expect(r).toMatchObject({ version: "1.1.0", state: "deprecated", statusReason: "use 1.3" });
    await expect(h.svc.resolve(view, `${a.namespace}/helper-agent@1.2.0`)).rejects.toMatchObject({
      code: "not_found",
    });
    await expect(
      h.svc.getVersion(view, a.namespace, "helper-agent", "1.2.0"),
    ).rejects.toMatchObject({ code: "not_found" });
    expect(
      (await h.svc.getVersion(view, a.namespace, "helper-agent", "1.2.0", { allowYanked: true }))
        .state,
    ).toBe("yanked");
    expect(
      (await h.svc.resolve(view, `${a.namespace}/helper-agent@1.2.0`, { allowYanked: true }))
        .version,
    ).toBe("1.2.0");
    const rows = await h.svc.listVersions(view, a.namespace, "helper-agent");
    expect(rows.map((x) => `${x.record.version}:${x.status.state}`)).toEqual([
      "1.0.0:active",
      "1.1.0:deprecated",
      "1.2.0:yanked",
    ]);
    await expect(
      h.svc.yank(a.p, a.namespace, "helper-agent", "1.2.0", "again"),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(h.svc.yank(a.p, a.namespace, "helper-agent", "1.0.0", "x")).rejects.toMatchObject({
      code: "invalid",
    });
    await expect(
      h.svc.yank(a.p, a.namespace, "helper-agent", "9.9.9", "no such"),
    ).rejects.toMatchObject({ code: "not_found" });
    expect(
      (await h.audit.read(a.p.tenantId)).some(
        (e) => e.action === "registry.yank" && e.reason === "authorized",
      ),
    ).toBe(true);
  });

  it("verify-on-resolve fails closed when stored data is tampered with, and does NOT fall back to an older version", async () => {
    class Tampering extends MemoryRegistryStore {
      tamper: ((abl: string) => string) | undefined;
      override async listVersions(...args: Parameters<MemoryRegistryStore["listVersions"]>) {
        const rows = await super.listVersions(...args);
        const t = this.tamper;
        return t
          ? rows.map((r) =>
              r.record.version === "1.1.0"
                ? { ...r, record: { ...r.record, abl: t(r.record.abl) } }
                : r,
            )
          : rows;
      }
    }
    const store = new Tampering();
    const h = harness(store);
    const a = await Publisher.create(h, randomUUID(), "acme");
    await a.publish(ablDoc("helper-agent", "1.0.0"));
    await a.publish(ablDoc("helper-agent", "1.1.0"));
    store.tamper = (abl) => abl.replace("helpful", "harmful"); // a malicious/buggy storage layer
    await expect(
      h.svc.resolve({ tenantId: a.p.tenantId }, "acme/helper-agent@^1.0.0"),
    ).rejects.toMatchObject({
      code: "verification_failed",
      checks: expect.arrayContaining(["content_hash_mismatch"]),
    });
    expect(await auditActions(h, a.p.tenantId)).toContain("registry.verify:DENY");
    expect(
      (await h.svc.resolve({ tenantId: a.p.tenantId }, "acme/helper-agent@1.0.0")).version,
    ).toBe("1.0.0"); // pinned exact still fine
  });

  it("rollback guard: refuses to resolve below a pinned lock", async () => {
    const { h, a } = await setup();
    await a.publish(ablDoc("helper-agent", "1.0.0"));
    await a.publish(ablDoc("helper-agent", "1.1.0"));
    await h.svc.yank(a.p, a.namespace, "helper-agent", "1.1.0", "bad release");
    const view = { tenantId: a.p.tenantId };
    expect((await h.svc.resolve(view, `${a.namespace}/helper-agent@^1.0.0`)).version).toBe("1.0.0");
    await expect(
      h.svc.resolve(view, `${a.namespace}/helper-agent@^1.0.0`, { notBelow: "1.1.0" }),
    ).rejects.toMatchObject({ code: "verification_failed", checks: ["rollback"] });
    expect(
      (await h.svc.resolve(view, `${a.namespace}/helper-agent@^1.0.0`, { notBelow: "1.0.0" }))
        .version,
    ).toBe("1.0.0");
  });

  describe("authorization and isolation", () => {
    it("viewer/auditor cannot publish, builder cannot manage keys or yank, admin can; denials are audited", async () => {
      const { h, a } = await setup();
      const sub = a.submission(ablDoc("helper-agent", "1.0.0"));
      for (const role of ["viewer", "auditor", "billing"] as const)
        await expect(h.svc.publish({ ...a.p, role }, a.namespace, sub)).rejects.toMatchObject({
          code: "forbidden",
        });
      const builder = { ...a.p, role: "builder" as const };
      await h.svc.publish(builder, a.namespace, sub);
      await expect(
        h.svc.yank(builder, a.namespace, "helper-agent", "1.0.0", "reason"),
      ).rejects.toMatchObject({ code: "forbidden" });
      await expect(
        h.svc.addKey(builder, a.namespace, { publicKey: generatePublisherKey().publicKey }),
      ).rejects.toMatchObject({ code: "forbidden" });
      await expect(h.svc.claimNamespace(builder, "another-ns")).rejects.toMatchObject({
        code: "forbidden",
      });
      await expect(
        h.svc.publish({ ...a.p, role: "nonsense" as never }, a.namespace, sub),
      ).rejects.toMatchObject({ code: "forbidden" });
      await expect(h.svc.publish(platform as never, a.namespace, sub)).rejects.toMatchObject({
        code: "forbidden",
      });
      expect(await auditActions(h, a.p.tenantId)).toContain("registry.publish:DENY");
    });

    it("tenant B cannot read, resolve, publish into, yank in, or manage keys of tenant A's private namespace (IDOR)", async () => {
      const { h, a, bTenant } = await setup();
      await a.publish(ablDoc("helper-agent", "1.0.0"));
      const b = principal(bTenant, "owner");
      const vb = { tenantId: bTenant };
      await expect(h.svc.resolve(vb, `${a.namespace}/helper-agent@^1.0.0`)).rejects.toMatchObject({
        code: "not_found",
      });
      await expect(
        h.svc.getVersion(vb, a.namespace, "helper-agent", "1.0.0"),
      ).rejects.toMatchObject({ code: "not_found" });
      expect(await h.svc.listVersions(vb, a.namespace, "helper-agent")).toEqual([]);
      const mine = generatePublisherKey();
      await expect(
        h.svc.publish(b, a.namespace, a.submission(ablDoc("helper-agent", "9.9.9"))),
      ).rejects.toMatchObject({ code: "forbidden" });
      await expect(
        h.svc.addKey(b, a.namespace, { publicKey: mine.publicKey }),
      ).rejects.toMatchObject({ code: "forbidden" });
      await expect(
        h.svc.revokeKey(b, a.namespace, a.key.keyId, { reason: "compromised" }),
      ).rejects.toMatchObject({ code: "forbidden" });
      await expect(
        h.svc.rotateKey(b, a.namespace, a.key.keyId, { newPublicKey: mine.publicKey }),
      ).rejects.toMatchObject({ code: "forbidden" });
      await expect(
        h.svc.yank(b, a.namespace, "helper-agent", "1.0.0", "takedown"),
      ).rejects.toMatchObject({ code: "forbidden" });
      await expect(h.svc.listKeys(b, a.namespace)).resolves.toEqual([]);
      expect((await h.svc.listNamespaces(b)).map((n) => n.namespace)).not.toContain(a.namespace);
      expect(await auditActions(h, bTenant)).toContain("registry.publish:DENY");
      // anonymous readers see nothing either
      await expect(
        h.svc.resolve({ tenantId: null }, `${a.namespace}/helper-agent@^1.0.0`),
      ).rejects.toMatchObject({ code: "not_found" });
    });

    it("platform operations are for the marketplace only: public namespaces become readable by everyone", async () => {
      const { h, a, bTenant } = await setup();
      await a.publish(ablDoc("helper-agent", "1.0.0"));
      await expect(
        h.svc.setNamespacePublic({ ...platform, service: "other" } as never, a.namespace),
      ).rejects.toMatchObject({ code: "forbidden" });
      await expect(h.svc.setNamespacePublic(a.p as never, a.namespace)).rejects.toMatchObject({
        code: "forbidden",
      });
      await expect(h.svc.setNamespacePublic(platform, "no-such-ns")).rejects.toMatchObject({
        code: "not_found",
      });
      await h.svc.setNamespacePublic(platform, a.namespace);
      expect(
        (await h.svc.resolve({ tenantId: bTenant }, `${a.namespace}/helper-agent@^1.0.0`)).version,
      ).toBe("1.0.0");
      expect(
        (await h.svc.resolve({ tenantId: null }, `${a.namespace}/helper-agent@^1.0.0`)).version,
      ).toBe("1.0.0");
      // but B still cannot write
      await expect(
        h.svc.publish(
          principal(bTenant, "owner"),
          a.namespace,
          a.submission(ablDoc("helper-agent", "2.0.0")),
        ),
      ).rejects.toMatchObject({ code: "forbidden" });
      // moderation: the platform yanks; the owner's chain records it
      await h.svc.platformYank(platform, a.namespace, "helper-agent", "1.0.0", "takedown: malware");
      await h.svc.platformYank(platform, a.namespace, "helper-agent", "1.0.0", "idempotent");
      await expect(
        h.svc.resolve({ tenantId: bTenant }, `${a.namespace}/helper-agent@^1.0.0`),
      ).rejects.toMatchObject({ code: "not_found" });
      await expect(
        h.svc.platformYank(platform, a.namespace, "helper-agent", "7.0.0", "none"),
      ).rejects.toMatchObject({ code: "not_found" });
      await expect(
        h.svc.platformYank(platform, "no-such-ns", "x", "1.0.0", "none"),
      ).rejects.toMatchObject({ code: "not_found" });
      await expect(
        h.svc.platformYank(a.p as never, a.namespace, "helper-agent", "1.0.0", "none"),
      ).rejects.toMatchObject({ code: "forbidden" });
      expect(await auditActions(h, a.p.tenantId)).toContain("registry.platform_yank:ALLOW");
    });
  });

  describe("namespaces and names", () => {
    it("claims validated, reserved and confusable namespaces are refused; names are typosquat-guarded", async () => {
      const { h, a, bTenant } = await setup();
      const b = principal(bTenant, "owner");
      for (const bad of ["A", "a", "1abc", "ab--cd", "abc-", "x".repeat(64), "has_underscore", ""])
        await expect(h.svc.claimNamespace(b, bad)).rejects.toMatchObject({ code: "invalid" });
      for (const r of ["axis", "official", "marketplace", "off1cial", "adm1n"])
        await expect(h.svc.claimNamespace(b, r)).rejects.toMatchObject({ code: "forbidden" });
      await expect(h.svc.claimNamespace(b, a.namespace)).rejects.toMatchObject({
        code: "conflict",
      });
      await expect(
        h.svc.claimNamespace(b, a.namespace.replace("acme", "acrne")),
      ).rejects.toMatchObject({ code: "conflict" }); // rn ~ m
      await expect(
        h.svc.claimNamespace(b, a.namespace.replace("acme", "acm3")),
      ).rejects.toMatchObject({ code: "conflict" }); // 3 ~ e
      await a.publish(ablDoc("payroll-agent", "1.0.0"));
      await expect(a.publish(ablDoc("payro1l-agent", "1.0.0"))).rejects.toMatchObject({
        code: "conflict",
        message: expect.stringContaining("confusable"),
      });
      await expect(a.publish(ablDoc("payrollagent", "1.0.0"))).rejects.toMatchObject({
        code: "conflict",
      });
      await a.publish(ablDoc("payroll-agent", "1.1.0")); // the real name keeps working
    });
  });

  describe("reference checks", () => {
    const dep = (ref: string) =>
      ablDoc("consumer-agent", "1.0.0", {
        tools: [{ name: "helper", kind: "agent", ref }],
        budgets: { costUsd: { hard: 1 } },
      });
    it("agent refs must be qualified, resolvable and verified; other refs only need valid syntax", async () => {
      const { a } = await setup();
      await a.publish(ablDoc("helper-agent", "1.0.0"));
      await a.publish(dep(`${a.namespace}/helper-agent@^1.0.0`));
      await expect(
        a.publish({
          ...dep("helper-agent@^1.0.0"),
          metadata: { name: "consumer-b", version: "1.0.0" },
        }),
      ).rejects.toMatchObject({ code: "invalid", message: expect.stringContaining("qualified") });
      await expect(
        a.publish({
          ...dep(`${a.namespace}/missing-agent@^1.0.0`),
          metadata: { name: "consumer-c", version: "1.0.0" },
        }),
      ).rejects.toMatchObject({
        code: "invalid",
        message: expect.stringContaining("cannot be resolved"),
      });
      await expect(
        a.publish({
          ...dep(`${a.namespace}/helper-agent@^1.x`),
          metadata: { name: "consumer-d", version: "1.0.0" },
        }),
      ).rejects.toBeDefined();
      await expect(
        a.publish({
          ...dep(`${a.namespace}/consumer-agent@^1.0.0`),
          metadata: { name: "consumer-agent", version: "1.1.0" },
        }),
      ).rejects.toMatchObject({ code: "invalid", message: expect.stringContaining("itself") });
      const fn = ablDoc("fn-agent", "1.0.0", {
        tools: [
          { name: "fn-tool", kind: "function", ref: "policy-db@^1.0.0", sideEffects: "read" },
        ],
        policy: { packs: ["baseline-deny@^1.0.0"] },
      });
      await a.publish(fn);
      const badFn = ablDoc("fn-bad", "1.0.0", {
        tools: [
          { name: "fn-tool", kind: "function", ref: "policy-db@^1.0.0.0", sideEffects: "read" },
        ],
      });
      await expect(a.publish(badFn)).rejects.toBeDefined();
      const badPack = ablDoc("pack-bad", "1.0.0", { policy: { packs: ["not a ref"] } });
      await expect(a.publish(badPack)).rejects.toMatchObject({ code: "invalid" });
      const badRange = ablDoc("pack-bad2", "1.0.0", { policy: { packs: ["good-pack@^zzz"] } });
      await expect(a.publish(badRange)).rejects.toMatchObject({ code: "invalid" });
    });
    it("detects cycles and a dependency whose own signature no longer verifies", async () => {
      const { h, a } = await setup();
      await a.publish(ablDoc("leaf-agent", "1.0.0"));
      await a.publish({
        ...dep(`${a.namespace}/leaf-agent@^1.0.0`),
        metadata: { name: "mid-agent", version: "1.0.0" },
      });
      // mid@2.0.0 -> leaf; leaf@1.1.0 -> mid@^1 (cycle through names): refused
      await expect(
        a.publish({
          ...dep(`${a.namespace}/mid-agent@^1.0.0`),
          metadata: { name: "leaf-agent", version: "1.1.0" },
        }),
      ).rejects.toMatchObject({ code: "invalid", message: expect.stringContaining("cycle") });
      await h.svc.revokeKey(a.p, a.namespace, a.key.keyId, { reason: "compromised" });
      const k2 = generatePublisherKey();
      await h.svc.addKey(a.p, a.namespace, { publicKey: k2.publicKey });
      await expect(
        a.publish(dep(`${a.namespace}/leaf-agent@^1.0.0`), { key: k2 }),
      ).rejects.toMatchObject({
        code: "invalid",
        message: expect.stringContaining("verification_failed"),
      });
    });
    it("a public namespace may only depend on public namespaces; unqualified resolution is refused", async () => {
      const { h, a, tenant } = await setup();
      const other = await Publisher.create(h, await tenant(), `priv-${rid(6)}`);
      await other.publish(ablDoc("secret-agent", "1.0.0"));
      await a.publish(ablDoc("helper-agent", "1.0.0"));
      await h.svc.setNamespacePublic(platform, a.namespace);
      await expect(a.publish(dep(`${other.namespace}/secret-agent@^1.0.0`))).rejects.toMatchObject({
        code: "invalid",
      }); // not visible to A
      await h.svc.setNamespacePublic(platform, other.namespace);
      await h.svc.setNamespacePublic(platform, a.namespace);
      await a.publish(dep(`${other.namespace}/secret-agent@^1.0.0`)); // other is public now: fine
      await expect(
        h.svc.resolve({ tenantId: a.p.tenantId }, "helper-agent@^1.0.0"),
      ).rejects.toMatchObject({ code: "invalid" });
      // visible to the publisher but NOT public: a public namespace must not depend on it
      const priv = `own-${rid(6)}`;
      await h.svc.claimNamespace(a.p, priv);
      const privKey = generatePublisherKey();
      await h.svc.addKey(a.p, priv, {
        publicKey: privKey.publicKey,
        validFrom: new Date(h.clock.t.getTime() - 1000),
      });
      const pp = new Publisher(h, a.p, priv);
      pp.key = privKey;
      await pp.publish(ablDoc("inner-agent", "1.0.0"));
      await expect(
        a.publish({
          ...dep(`${priv}/inner-agent@^1.0.0`),
          metadata: { name: "consumer-z", version: "1.0.0" },
        }),
      ).rejects.toMatchObject({ message: expect.stringContaining("public namespace") });
      expect(() => parseRef("ab/cd@^1.0.0")).not.toThrow();
      expect(() => parseRef("Bad/ns@^1.0.0")).toThrow();
      expect(() => parseRef("ns/name@junk")).toThrow();
      expect(() => parseRef(undefined as never)).toThrow();
    });
  });

  it("audit failure means the mutation is not performed (fail-closed)", async () => {
    const { store, tenant } = await make();
    const h = harness(store);
    const a = await Publisher.create(h, await tenant(), `fc-${rid(6)}`);
    const failing = new (await import("../src/index.js")).RegistryService({
      store,
      audit: new (await import("../src/index.js")).ServiceAudit(
        { append: () => Promise.reject(new Error("down")) },
        "registry",
      ),
      now: h.clock.now,
    });
    await expect(
      failing.publish(a.p, a.namespace, a.submission(ablDoc("helper-agent", "1.0.0"))),
    ).rejects.toMatchObject({ code: "unavailable" });
    await expect(
      h.svc.getVersion({ tenantId: a.p.tenantId }, a.namespace, "helper-agent", "1.0.0"),
    ).rejects.toMatchObject({ code: "not_found" });
    await expect(failing.claimNamespace(a.p, "never-claimed")).rejects.toMatchObject({
      code: "unavailable",
    });
  });
});
