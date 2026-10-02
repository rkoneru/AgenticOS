import { randomBytes, randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it, inject } from "vitest";
import {
  LastOwnerError,
  StoreConflict,
  type ApiKeyRecord,
  type ProvisionSpec,
} from "../src/index.js";
import { KINDS, ROLE, makeWorld, type World } from "./world.js";

const spec = (slug: string): ProvisionSpec => {
  const tenantId = randomUUID();
  const ownerId = randomUUID();
  return {
    tenantId,
    slug,
    name: slug,
    region: "us-east-1",
    phiMode: false,
    owner: { id: ownerId, userRef: `u:${ownerId}`, email: `${slug}@x.test` },
    packs: [
      {
        packId: randomUUID(),
        versionId: randomUUID(),
        name: "baseline-deny",
        version: "1.0.0",
        source: { a: 1 },
        rego: "package x",
        contentHash: "a".repeat(64),
      },
    ],
    budgets: [{ scope: "tenant", target: "", metric: "tokens", period: "day", hard: 5 }],
    settings: { retentionAuditDays: 365, retentionTranscriptDays: 1, retentionMemoryDays: 1 },
    placement: { isolationTier: "shared_rls" },
  };
};

describe.each(KINDS)("store contract (%s)", (kind) => {
  let w: World;
  beforeAll(async () => {
    w = await makeWorld(kind);
  });
  afterAll(() => w.close());

  it("provisioning is atomic: a slug conflict leaves nothing behind", async () => {
    const s1 = spec(`atomic-${kind}`);
    await w.store.provisionTenant(s1);
    const s2 = { ...spec(`atomic-${kind}`) };
    await expect(w.store.provisionTenant(s2)).rejects.toBeInstanceOf(StoreConflict);
    expect(await w.store.getTenant(s2.tenantId)).toBeUndefined();
    expect(await w.store.getMember(s2.tenantId, s2.owner.id)).toBeUndefined();
    expect(await w.store.listBudgets(s2.tenantId)).toEqual([]);
  });

  it("every read and write is scoped by tenant: another tenant's ids are invisible", async () => {
    const a = spec(`sa-${kind}`);
    const b = spec(`sb-${kind}`);
    await w.store.provisionTenant(a);
    await w.store.provisionTenant(b);
    expect(await w.store.getMember(b.tenantId, a.owner.id)).toBeUndefined();
    expect(
      await w.store.updateMember(b.tenantId, a.owner.id, { role: "viewer" }, new Date()),
    ).toBeUndefined();
    expect((await w.store.getMember(a.tenantId, a.owner.id))?.role).toBe("owner");
    expect(await w.store.getTenant(b.tenantId)).toMatchObject({ slug: `sb-${kind}` });
    expect(await w.store.findMemberByEmail(b.tenantId, a.owner.email)).toBeUndefined();
    expect(await w.store.findMemberByUserRef(b.tenantId, a.owner.userRef)).toBeUndefined();
    expect((await w.store.listBudgets(a.tenantId)).length).toBe(1);
    expect(
      await w.store.deleteBudget(b.tenantId, (await w.store.listBudgets(a.tenantId))[0]!.id),
    ).toBe(false);
    expect(await w.store.getSettings(b.tenantId)).toMatchObject({ tenantId: b.tenantId });
    await w.store.putSettings({
      tenantId: a.tenantId,
      retentionAuditDays: 400,
      retentionTranscriptDays: 2,
      retentionMemoryDays: 3,
    });
    expect((await w.store.getSettings(b.tenantId))?.retentionAuditDays).toBe(365);
  });

  it("members: uniqueness, last-owner guard, status changes, lookups", async () => {
    const s = spec(`m-${kind}`);
    await w.store.provisionTenant(s);
    const t = s.tenantId;
    const m = await w.store.insertMember({
      tenantId: t,
      id: randomUUID(),
      userRef: "r1",
      email: "A@x.test",
      role: "viewer",
      status: "active",
      directoryId: undefined as never,
      externalId: undefined as never,
    });
    expect(m.email).toBe("A@x.test");
    await expect(
      w.store.insertMember({
        tenantId: t,
        id: randomUUID(),
        userRef: "r2",
        email: "a@X.test",
        role: "viewer",
        status: "active",
      }),
    ).rejects.toBeInstanceOf(StoreConflict);
    await expect(
      w.store.insertMember({
        tenantId: t,
        id: randomUUID(),
        userRef: "r1",
        email: "b@x.test",
        role: "viewer",
        status: "active",
      }),
    ).rejects.toBeInstanceOf(StoreConflict);
    expect((await w.store.findMemberByEmail(t, "a@x.TEST"))?.id).toBe(m.id);
    await expect(
      w.store.updateMember(t, s.owner.id, { role: "admin" }, new Date()),
    ).rejects.toBeInstanceOf(LastOwnerError);
    await expect(
      w.store.updateMember(t, s.owner.id, { status: "deprovisioned" }, new Date()),
    ).rejects.toBeInstanceOf(LastOwnerError);
    await expect(
      w.store.updateMember(t, m.id, { email: s.owner.email }, new Date()),
    ).rejects.toBeInstanceOf(StoreConflict);
    const d = await w.store.updateMember(
      t,
      m.id,
      { status: "deprovisioned", displayName: "X" },
      new Date(),
    );
    expect(d).toMatchObject({ status: "deprovisioned", displayName: "X" });
    expect(d?.deprovisionedAt).toBeDefined();
    const e = await w.store.insertMember({
      tenantId: t,
      id: randomUUID(),
      userRef: "r3",
      email: "e@x.test",
      role: "viewer",
      status: "active",
      directoryId: undefined as never,
    });
    expect(e.directoryId).toBeUndefined();
  });

  it("pre-tenant lookups need the exact prefix AND hash", async () => {
    const s = spec(`l-${kind}`);
    await w.store.provisionTenant(s);
    const hash = randomBytes(32);
    const key: ApiKeyRecord = {
      tenantId: s.tenantId,
      id: randomUUID(),
      name: "k",
      prefix: randomBytes(8).toString("hex"),
      keyHash: hash,
      scopes: ["*"],
      environment: "dev",
      ownerMemberId: s.owner.id,
      createdBy: s.owner.id,
      createdAt: new Date(),
    };
    await w.store.insertApiKey(key);
    expect((await w.store.findApiKeyByLookup(key.prefix, hash))?.id).toBe(key.id);
    expect(await w.store.findApiKeyByLookup(key.prefix, randomBytes(32))).toBeUndefined();
    expect(await w.store.findApiKeyByLookup(randomBytes(8).toString("hex"), hash)).toBeUndefined();
    await expect(w.store.insertApiKey({ ...key, id: randomUUID() })).rejects.toBeInstanceOf(
      StoreConflict,
    );
    const org = `org-${randomUUID()}`;
    await w.store.upsertConnection({
      tenantId: s.tenantId,
      id: randomUUID(),
      idpOrgId: org,
      connectionType: "saml",
      jitEnabled: false,
      jitDefaultRole: "viewer",
    });
    expect((await w.store.findConnectionByOrg(org))?.tenantId).toBe(s.tenantId);
    expect(await w.store.findConnectionByOrg(`${org}x`)).toBeUndefined();
    const other = spec(`l2-${kind}`);
    await w.store.provisionTenant(other);
    await expect(
      w.store.upsertConnection({
        tenantId: other.tenantId,
        id: randomUUID(),
        idpOrgId: org,
        connectionType: "saml",
        jitEnabled: false,
        jitDefaultRole: "viewer",
      }),
    ).rejects.toBeInstanceOf(StoreConflict);
  });

  it("refresh rotation is compare-and-set: concurrent rotations with the same token produce exactly one winner", async () => {
    const s = spec(`r-${kind}`);
    await w.store.provisionTenant(s);
    const id = randomUUID();
    const h0 = randomBytes(32);
    const now = new Date();
    await w.store.insertSession({
      tenantId: s.tenantId,
      id,
      memberId: s.owner.id,
      refreshHash: h0,
      counter: 0,
      authMethod: "dev",
      createdAt: now,
      expiresAt: new Date(now.getTime() + 1e6),
      refreshedAt: now,
    });
    const results = await Promise.all(
      Array.from({ length: 8 }, () =>
        w.store.rotateRefresh(s.tenantId, id, h0, randomBytes(32), now),
      ),
    );
    expect(results.filter(Boolean)).toHaveLength(1);
    const cur = (await w.store.getSession(s.tenantId, id))!;
    expect(cur.counter).toBe(1);
    expect(cur.prevRefreshHash?.equals(h0)).toBe(true);
    await w.store.revokeSession(s.tenantId, id, now, "x");
    expect(await w.store.rotateRefresh(s.tenantId, id, cur.refreshHash, randomBytes(32), now)).toBe(
      false,
    );
  });

  it("groups, mappings, domains, packs, budgets and credentials behave as the services need", async () => {
    const s = spec(`g-${kind}`);
    await w.store.provisionTenant(s);
    const t = s.tenantId;
    const dir = {
      tenantId: t,
      id: randomUUID(),
      name: "d",
      tokenPrefix: randomBytes(8).toString("hex"),
      tokenHash: randomBytes(32),
      defaultRole: "viewer" as const,
      status: "active" as const,
      createdAt: new Date(),
    };
    await w.store.insertDirectory(dir);
    await w.store.updateDirectory(t, dir.id, { lastUsedAt: new Date() });
    expect((await w.store.getDirectory(t, dir.id))?.lastUsedAt).toBeDefined();
    await w.store.setRoleMapping(t, dir.id, "G", "builder");
    await w.store.setRoleMapping(t, dir.id, "G", "admin");
    expect(await w.store.listRoleMappings(t, dir.id)).toEqual({ G: "admin" });
    await w.store.setRoleMapping(t, dir.id, "G", undefined);
    expect(await w.store.listRoleMappings(t, dir.id)).toEqual({});
    const g = await w.store.insertGroup({
      tenantId: t,
      id: randomUUID(),
      directoryId: dir.id,
      displayName: "G",
    });
    await expect(
      w.store.insertGroup({ tenantId: t, id: randomUUID(), directoryId: dir.id, displayName: "G" }),
    ).rejects.toBeInstanceOf(StoreConflict);
    const foreign = spec(`g2-${kind}`);
    await w.store.provisionTenant(foreign);
    await w.store.setGroupMembers(t, g.id, [s.owner.id, foreign.owner.id, randomUUID()]);
    expect(await w.store.groupMembers(t, g.id)).toEqual([s.owner.id]); // other tenants' and unknown ids are dropped
    expect((await w.store.groupsOfMember(t, dir.id, s.owner.id)).map((x) => x.id)).toEqual([g.id]);
    expect(
      await w.store.updateGroup(t, dir.id, g.id, { displayName: "H", externalId: "e" }),
    ).toMatchObject({ displayName: "H", externalId: "e" });
    expect(await w.store.updateGroup(t, randomUUID(), g.id, { displayName: "Z" })).toBeUndefined();
    expect(await w.store.deleteGroup(t, randomUUID(), g.id)).toBe(false);
    expect(await w.store.deleteGroup(t, dir.id, g.id)).toBe(true);
    expect(await w.store.groupMembers(t, g.id)).toEqual([]);
    // domains
    await w.store.upsertDomain({
      tenantId: t,
      domain: "d1.test",
      status: "pending",
      challengeHash: randomBytes(32),
    });
    await w.store.upsertDomain({
      tenantId: t,
      domain: "d1.test",
      status: "verified",
      verifiedAt: new Date(),
    });
    expect((await w.store.getDomain(t, "d1.test"))?.status).toBe("verified");
    await w.store.upsertDomain({
      tenantId: foreign.tenantId,
      domain: "d1.test",
      status: "pending",
    });
    await expect(
      w.store.upsertDomain({
        tenantId: foreign.tenantId,
        domain: "d1.test",
        status: "verified",
        verifiedAt: new Date(),
      }),
    ).rejects.toBeInstanceOf(StoreConflict);
    // tenant keys and credentials
    await w.store.insertTenantKey({
      tenantId: t,
      version: 1,
      kmsKeyId: "k",
      wrappedDek: randomBytes(60),
    });
    await expect(
      w.store.insertTenantKey({
        tenantId: t,
        version: 1,
        kmsKeyId: "k",
        wrappedDek: randomBytes(60),
      }),
    ).rejects.toBeInstanceOf(StoreConflict);
    expect(await w.store.getTenantKey(t, 2)).toBeUndefined();
    expect((await w.store.getActiveTenantKey(t))?.version).toBe(1);
    // budgets upsert keeps one row per (scope,target,metric,period)
    const b1 = await w.store.upsertBudget({
      tenantId: t,
      id: randomUUID(),
      scope: "tenant",
      target: "",
      metric: "tokens",
      period: "day",
      hard: 10,
    });
    const b2 = await w.store.upsertBudget({
      tenantId: t,
      id: randomUUID(),
      scope: "tenant",
      target: "",
      metric: "tokens",
      period: "day",
      hard: 20,
    });
    expect(b2.id).toBe(b1.id);
    expect(b2.hard).toBe(20);
    expect(
      (await w.store.listBudgets(t)).filter((b) => b.metric === "tokens" && b.period === "day"),
    ).toHaveLength(1);
    // packs: immutable versions, activation switches the active one
    const pv = (version: string) => ({
      tenantId: t,
      packId: randomUUID(),
      packName: "pack-x",
      versionId: randomUUID(),
      version,
      source: { v: version },
      rego: "r",
      contentHash: "b".repeat(64),
    });
    const v1 = await w.store.insertPackVersion(pv("1.0.0"));
    const v2 = await w.store.insertPackVersion(pv("2.0.0"));
    expect(v2.packId).toBe(v1.packId);
    await expect(w.store.insertPackVersion(pv("1.0.0"))).rejects.toBeInstanceOf(StoreConflict);
    await w.store.activatePackVersion(t, v1.versionId, s.owner.id, new Date());
    await w.store.activatePackVersion(t, v2.versionId, s.owner.id, new Date());
    const act = (await w.store.listActiveAssignments(t)).filter((a) => a.packId === v1.packId);
    expect(act.map((a) => a.versionId)).toEqual([v2.versionId]);
    await expect(
      w.store.activatePackVersion(t, randomUUID(), s.owner.id, new Date()),
    ).rejects.toBeInstanceOf(StoreConflict);
    expect(await w.store.deactivatePack(t, v1.packId, new Date())).toBe(true);
    expect(await w.store.deactivatePack(t, v1.packId, new Date())).toBe(false);
    expect((await w.store.getPackVersion(t, v1.versionId))?.packName).toBe("pack-x");
    expect((await w.store.listPackVersions(t)).length).toBeGreaterThanOrEqual(3);
  });
});

describe("Postgres row-level security of the 0008 tables, as the app role", () => {
  let c: pg.Client;
  beforeAll(async () => {
    c = new pg.Client({ connectionString: inject("dbUrl") });
    await c.connect();
  });
  afterAll(() => c.end());

  it("with no tenant set, every new table is empty and unwritable", async () => {
    const tables = [
      "sessions",
      "directories",
      "scim_groups",
      "scim_group_members",
      "directory_role_mappings",
      "identity_connections",
      "verified_domains",
      "tenant_keys",
      "policy_assignments",
      "tenant_settings",
      "tenant_placements",
      "members",
      "api_keys",
      "model_credentials",
    ];
    await c.query("BEGIN");
    await c.query(`SET LOCAL ROLE ${ROLE}`);
    for (const t of tables) expect((await c.query(`SELECT 1 FROM ${t}`)).rowCount, t).toBe(0);
    await c.query("ROLLBACK");
  });

  it("each of these tables has FORCED row level security", async () => {
    const r = await c.query(
      `SELECT relname FROM pg_class WHERE relname = ANY($1) AND NOT (relrowsecurity AND relforcerowsecurity)`,
      [
        [
          "sessions",
          "directories",
          "scim_groups",
          "scim_group_members",
          "directory_role_mappings",
          "identity_connections",
          "verified_domains",
          "tenant_keys",
          "policy_assignments",
          "tenant_settings",
          "tenant_placements",
        ],
      ],
    );
    expect(r.rows).toEqual([]);
  });

  it("the app role cannot create a tenant except through provision_tenant, nor edit one", async () => {
    await c.query("BEGIN");
    await c.query(`SET LOCAL ROLE ${ROLE}`);
    await expect(
      c.query(
        "INSERT INTO tenants (id, slug, name, region) VALUES (gen_random_uuid(), 'sneaky', 's', 'x')",
      ),
    ).rejects.toThrow(/permission denied/);
    await c.query("ROLLBACK");
  });
});
