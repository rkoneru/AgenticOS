import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CpError, type AdminService, type Role } from "../src/index.js";
import { KINDS, eventsOf, makeWorld, type World } from "./world.js";

const code = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "ok";
  } catch (e) {
    return e instanceof CpError ? e.code : `other:${String(e)}`;
  }
};

describe.each(KINDS)("tenant admin (%s store)", (kind) => {
  let w: World;
  let admin: AdminService;
  beforeAll(async () => {
    w = await makeWorld(kind);
    admin = w.cp.admin;
  });
  afterAll(() => w.close());

  describe("privilege escalation", () => {
    it("a member cannot grant a role above their own (invite)", async () => {
      const t = await w.tenant();
      const adm = await w.member(t.tenantId, "admin");
      expect(
        await code(admin.inviteMember(adm.principal, { email: "x@y.test", role: "owner" })),
      ).toBe("forbidden");
      expect(
        await code(admin.inviteMember(adm.principal, { email: "x@y.test", role: "admin" })),
      ).toBe("ok");
      const bld = await w.member(t.tenantId, "builder");
      expect(
        await code(admin.inviteMember(bld.principal, { email: "b@y.test", role: "viewer" })),
      ).toBe("forbidden"); // builders cannot invite at all
    });

    it("a member cannot raise another member (or themselves) above their own role", async () => {
      const t = await w.tenant();
      const adm = await w.member(t.tenantId, "admin");
      const bld = await w.member(t.tenantId, "builder");
      expect(await code(admin.updateMemberRole(adm.principal, bld.memberId, "owner"))).toBe(
        "forbidden",
      );
      expect(await code(admin.updateMemberRole(adm.principal, adm.memberId, "owner"))).toBe(
        "forbidden",
      );
      expect((await admin.updateMemberRole(adm.principal, bld.memberId, "operator")).role).toBe(
        "operator",
      );
      expect((await w.store.getMember(t.tenantId, adm.memberId))?.role).toBe("admin");
    });

    it("an admin cannot modify or remove an owner", async () => {
      const t = await w.tenant();
      const adm = await w.member(t.tenantId, "admin");
      expect(await code(admin.updateMemberRole(adm.principal, t.ownerId, "viewer"))).toBe(
        "forbidden",
      );
      expect(await code(admin.removeMember(adm.principal, t.ownerId))).toBe("forbidden");
      expect((await w.store.getMember(t.tenantId, t.ownerId))?.status).toBe("active");
    });

    it("roles without members.* rights cannot touch members", async () => {
      const t = await w.tenant();
      const v = await w.member(t.tenantId, "viewer");
      const o = await w.member(t.tenantId, "operator");
      for (const who of [v, o]) {
        expect(await code(admin.updateMemberRole(who.principal, t.ownerId, "viewer"))).toBe(
          "forbidden",
        );
        expect(await code(admin.removeMember(who.principal, t.ownerId))).toBe("forbidden");
        expect(
          await code(admin.inviteMember(who.principal, { email: "z@z.test", role: "viewer" })),
        ).toBe("forbidden");
      }
    });

    it("the last owner cannot be demoted or removed, but can once a second owner exists", async () => {
      const t = await w.tenant();
      expect(await code(admin.updateMemberRole(t.owner, t.ownerId, "admin"))).toBe("conflict");
      expect(await code(admin.removeMember(t.owner, t.ownerId))).toBe("conflict");
      const second = await w.member(t.tenantId, "owner");
      expect((await admin.updateMemberRole(t.owner, t.ownerId, "admin")).role).toBe("admin");
      // now `second` is the last owner
      expect(await code(admin.removeMember(second.principal, second.memberId))).toBe("conflict");
      expect(await code(admin.updateMemberRole(second.principal, second.memberId, "viewer"))).toBe(
        "conflict",
      );
    });

    it("two owners removing each other concurrently cannot leave the tenant without an owner", async () => {
      const t = await w.tenant();
      const second = await w.member(t.tenantId, "owner");
      const [a, b] = await Promise.all([
        code(admin.removeMember(t.owner, second.memberId)),
        code(admin.removeMember(second.principal, t.ownerId)),
      ]);
      const owners = (await w.store.listMembers(t.tenantId, 50)).items.filter(
        (m) => m.role === "owner" && m.status === "active",
      );
      expect(owners.length).toBeGreaterThanOrEqual(1);
      expect([a, b]).toContain("ok");
    });

    it("removing a member revokes their sessions and API keys immediately", async () => {
      const t = await w.tenant();
      const bld = await w.member(t.tenantId, "builder");
      const key = await admin.createApiKey(bld.principal, { name: "ci", scopes: ["apikeys:read"] });
      expect(await w.cp.apiKeys.verify(key.secret)).toBeDefined();
      const sessBefore = await w.cp.sessions.issue(
        (await w.store.getMember(t.tenantId, bld.memberId))!,
        "sso",
      );
      await admin.removeMember(t.owner, bld.memberId);
      // the rows themselves are revoked (not merely unusable because the member is inactive): re-activation must not revive them
      expect((await w.store.getSession(t.tenantId, sessBefore.sessionId))?.revokedAt).toBeDefined();
      expect((await w.store.getApiKey(t.tenantId, key.key.id))?.revokedAt).toBeDefined();
      await w.store.updateMember(t.tenantId, bld.memberId, { status: "active" }, w.clock.now());
      expect(await w.cp.apiKeys.verify(key.secret)).toBeUndefined();
      expect(await w.cp.sessions.authenticate(sessBefore.accessToken)).toBeUndefined();
      await w.store.updateMember(
        t.tenantId,
        bld.memberId,
        { status: "deprovisioned" },
        w.clock.now(),
      );
      expect(
        await w.cp.sessions.authenticate(
          (await w.cp.sessions.issue((await w.store.getMember(t.tenantId, t.ownerId))!, "dev"))
            .accessToken,
        ),
      ).toBeDefined();
      expect(await w.cp.apiKeys.verify(key.secret)).toBeUndefined();
      expect(
        await w.cp.sessions.authenticate(
          (
            await w.cp.sessions
              .issue((await w.store.getMember(t.tenantId, bld.memberId))!, "dev")
              .catch(() => ({ accessToken: "" }))
          ).accessToken,
        ),
      ).toBeUndefined();
    });
  });

  describe("tenant isolation", () => {
    it("tenant comes from the principal only; resources of another tenant look nonexistent for every id-based operation", async () => {
      const a = await w.tenant();
      const b = await w.tenant();
      const bMember = await w.member(b.tenantId, "viewer");
      const bKey = await admin.createApiKey(b.owner, { name: "bk", scopes: ["*"] });
      const bBudget = await admin.putBudget(b.owner, {
        scope: "agent",
        target: "agent-one",
        metric: "tokens",
        period: "day",
        hard: 10,
      });
      const bPolicies = await admin.listPolicies(b.owner);
      const dir = await admin.createDirectory(b.owner, "okta", "viewer");
      const checks = {
        member: await code(admin.getMember(a.owner, bMember.memberId)),
        role: await code(admin.updateMemberRole(a.owner, bMember.memberId, "builder")),
        remove: await code(admin.removeMember(a.owner, bMember.memberId)),
        revokeSessions: await code(admin.revokeMemberSessions(a.owner, bMember.memberId)),
        rotate: await code(admin.rotateApiKey(a.owner, bKey.key.id)),
        revoke: await code(admin.revokeApiKey(a.owner, bKey.key.id)),
        budget: await code(admin.deleteBudget(a.owner, bBudget.id)),
        activate: await code(admin.activatePolicy(a.owner, bPolicies[0]!.versionId)),
        dirRotate: await code(admin.rotateDirectoryToken(a.owner, dir.id)),
        dirRevoke: await code(admin.revokeDirectory(a.owner, dir.id)),
        dirMap: await code(admin.setGroupRole(a.owner, dir.id, "g", "viewer")),
      };
      for (const [k, v] of Object.entries(checks)) expect(v, k).toBe("not_found");
      // ...and nothing changed
      expect((await w.store.getMember(b.tenantId, bMember.memberId))?.role).toBe("viewer");
      expect((await w.store.getApiKey(b.tenantId, bKey.key.id))?.revokedAt).toBeUndefined();
      expect(await w.store.listBudgets(b.tenantId)).toHaveLength(5);
      // the same ids are indistinguishable from random ones
      expect(await code(admin.getMember(a.owner, randomUUID()))).toBe("not_found");
      expect(await code(admin.getMember(a.owner, "../../etc/passwd"))).toBe("not_found");
      expect(await code(admin.getMember(a.owner, "1 OR 1=1"))).toBe("not_found");
    });

    it("a lower role probing an id gets forbidden before not-found (no existence oracle)", async () => {
      const t = await w.tenant();
      const v = await w.member(t.tenantId, "viewer");
      expect(await code(admin.rotateApiKey(v.principal, randomUUID()))).toBe("forbidden");
      expect(await code(admin.updateMemberRole(v.principal, randomUUID(), "viewer"))).toBe(
        "forbidden",
      );
    });

    it("a principal forged for tenant A with a member of tenant B has no rights (store scopes by principal tenant)", async () => {
      const a = await w.tenant();
      const b = await w.tenant();
      const forged = { ...b.owner, tenantId: a.tenantId };
      // member b.owner does not exist in tenant A: mutations that need the member are refused, reads show only A's data
      const list = await admin.listMembers(forged);
      expect(list.items.every((m) => m.id !== b.ownerId)).toBe(true);
    });
  });

  describe("audit", () => {
    it("every mutation writes its decision and result into the tenant's chain; denies too; no secrets", async () => {
      const t = await w.tenant();
      const v = await w.member(t.tenantId, "viewer");
      await admin.createApiKey(t.owner, { name: "audited", scopes: ["audit:read"] });
      await admin.putModelKey(t.owner, "anthropic", "default", "sk-ant-SECRET-VALUE-123");
      await code(admin.inviteMember(v.principal, { email: "q@q.test", role: "viewer" }));
      const ev = await eventsOf(w, t.tenantId);
      const actions = ev.map((e) => `${e.action}:${e.decision}`);
      expect(actions).toContain("tenant.provision:ALLOW");
      expect(actions).toContain("admin.apikeys.create:ALLOW");
      expect(actions).toContain("admin.apikeys.create.result:ALLOW");
      expect(actions).toContain("admin.modelkeys.write:ALLOW");
      expect(actions).toContain("admin.members.invite:DENY");
      expect(JSON.stringify(ev)).not.toContain("SECRET-VALUE");
      expect(
        ev.every(
          (e) =>
            e.tenant_id === t.tenantId &&
            (e.enforcement_point === "admin" || e.action === "tenant.provision"),
        ),
      ).toBe(true);
      const verdict = await w.auditStore.verify(t.tenantId);
      expect(verdict.ok).toBe(true);
    });

    it("a mutation whose decision cannot be audited is not performed", async () => {
      const t = await w.tenant();
      const failing = (await import("../src/index.js")).wireControlPlane({
        store: w.store,
        auditSink: { append: () => Promise.reject(new Error("audit down")) },
        authorizer: await (await import("./world.js")).sharedAuthorizer(),
        idp: w.idp,
        kms: w.kms,
        dns: w.dns,
        region: w.region,
        regions: ["us-east-1"],
        secrets: (await import("./world.js")).secrets(),
        redirectUri: "https://x.test/cb",
        allowedReturnOrigins: [],
        now: w.clock.now,
      });
      const before = (await w.store.listMembers(t.tenantId, 50)).items.length;
      expect(
        await code(failing.admin.inviteMember(t.owner, { email: "n@n.test", role: "viewer" })),
      ).toBe("unavailable");
      expect((await w.store.listMembers(t.tenantId, 50)).items.length).toBe(before);
    });
  });

  describe("fail-closed authorization", () => {
    it("a missing policy denies every action", async () => {
      const t = await w.tenant();
      const { Authorizer, wireControlPlane } = await import("../src/index.js");
      const w2 = wireControlPlane({
        store: w.store,
        auditSink: w.auditStore,
        authorizer: Authorizer.missing(),
        idp: w.idp,
        kms: w.kms,
        dns: w.dns,
        region: w.region,
        regions: ["us-east-1"],
        secrets: (await import("./world.js")).secrets(),
        redirectUri: "https://x.test/cb",
        allowedReturnOrigins: [],
        now: w.clock.now,
      });
      expect(await code(w2.admin.tenant(t.owner))).toBe("forbidden");
      expect(await code(w2.admin.listMembers(t.owner))).toBe("forbidden");
    });
  });

  describe("region pinning", () => {
    it("rejects writes for a tenant homed in another region and still allows reads", async () => {
      const t = await w.tenant();
      const { wireControlPlane } = await import("../src/index.js");
      const eu = wireControlPlane({
        store: w.store,
        auditSink: w.auditStore,
        authorizer: await (await import("./world.js")).sharedAuthorizer(),
        idp: w.idp,
        kms: w.kms,
        dns: w.dns,
        region: "eu-west-1",
        regions: ["eu-west-1"],
        secrets: (await import("./world.js")).secrets(),
        redirectUri: "https://x.test/cb",
        allowedReturnOrigins: [],
        now: w.clock.now,
      });
      expect(
        await code(eu.admin.inviteMember(t.owner, { email: "e@e.test", role: "viewer" })),
      ).toBe("region_mismatch");
      expect(await code(eu.admin.createApiKey(t.owner, { name: "k", scopes: ["*"] }))).toBe(
        "region_mismatch",
      );
      expect(await code(eu.admin.tenant(t.owner))).toBe("ok");
    });
  });

  describe("operations", () => {
    it("API keys: scoped, own-key rule for builders, prod restrictions", async () => {
      const t = await w.tenant();
      const bld = await w.member(t.tenantId, "builder");
      const other = await w.member(t.tenantId, "builder");
      const mine = await admin.createApiKey(bld.principal, {
        name: "mine",
        scopes: ["apikeys:read"],
      });
      const theirs = await admin.createApiKey(other.principal, {
        name: "theirs",
        scopes: ["apikeys:read"],
      });
      expect(await code(admin.rotateApiKey(bld.principal, theirs.key.id))).toBe("forbidden");
      expect(await code(admin.revokeApiKey(bld.principal, theirs.key.id))).toBe("forbidden");
      expect(await code(admin.revokeApiKey(t.owner, theirs.key.id))).toBe("ok");
      expect(
        await code(
          admin.createApiKey(bld.principal, { name: "prod", scopes: ["*"], environment: "prod" }),
        ),
      ).toBe("forbidden");
      expect(
        await code(
          admin.createApiKey(t.owner, { name: "prod", scopes: ["*"], environment: "prod" }),
        ),
      ).toBe("ok");
      const rotated = await admin.rotateApiKey(bld.principal, mine.key.id);
      expect(rotated.key.rotatedFrom).toBe(mine.key.id);
      expect(await w.cp.apiKeys.verify(mine.secret)).toBeUndefined();
      expect(await w.cp.apiKeys.verify(rotated.secret)).toBeDefined();
    });

    it("API-key credentials cannot perform session-only actions and are limited by scope", async () => {
      const t = await w.tenant();
      const k = await admin.createApiKey(t.owner, {
        name: "svc",
        scopes: ["budgets:read", "policies:read"],
      });
      const p = (await w.cp.apiKeys.verify(k.secret))!;
      expect(await code(admin.listBudgets(p))).toBe("ok");
      expect(await code(admin.listPolicies(p))).toBe("ok");
      expect(await code(admin.listMembers(p))).toBe("forbidden"); // scope
      expect(
        await code(
          admin.putBudget(p, { scope: "tenant", metric: "tokens", period: "day", hard: 1 }),
        ),
      ).toBe("forbidden"); // scope
      const wide = await admin.createApiKey(t.owner, { name: "wide", scopes: ["*"] });
      const pw = (await w.cp.apiKeys.verify(wide.secret))!;
      expect(await code(admin.inviteMember(pw, { email: "k@k.test", role: "viewer" }))).toBe(
        "forbidden",
      ); // session-only
      expect(await code(admin.createApiKey(pw, { name: "x", scopes: ["*"] }))).toBe("forbidden");
    });

    it("budgets validate and feed the runtime config", async () => {
      const t = await w.tenant();
      expect(
        await code(
          admin.putBudget(t.owner, {
            scope: "tenant",
            metric: "tokens",
            period: "day",
            soft: 10,
            hard: 5,
          }),
        ),
      ).toBe("invalid");
      expect(
        await code(
          admin.putBudget(t.owner, {
            scope: "tenant",
            target: "x",
            metric: "tokens",
            period: "day",
            hard: 5,
          }),
        ),
      ).toBe("invalid");
      expect(
        await code(
          admin.putBudget(t.owner, { scope: "agent", metric: "tokens", period: "day", hard: 5 }),
        ),
      ).toBe("invalid");
      expect(
        await code(
          admin.putBudget(t.owner, {
            scope: "agent",
            target: "agent-x",
            metric: "tokens",
            period: "day",
            hard: -1,
          }),
        ),
      ).toBe("invalid");
      expect(
        await code(
          admin.putBudget(t.owner, {
            scope: "agent",
            target: "agent-x",
            metric: "tokens",
            period: "day",
            hard: Number.NaN,
          }),
        ),
      ).toBe("invalid");
      await admin.putBudget(t.owner, {
        scope: "agent",
        target: "agent-x",
        metric: "cost_usd",
        period: "day",
        soft: 1,
        hard: 2,
      });
      const cfg = await admin.budgetConfig(t.tenantId);
      expect(cfg.agents["agent-x"]).toEqual([
        { metric: "cost_usd", period: "day", soft: 1, hard: 2 },
      ]);
      expect(cfg.tenant.length).toBe(2);
      expect(cfg.run.length).toBe(2);
      const b = (await admin.listBudgets(t.owner)).find((x) => x.target === "agent-x")!;
      await admin.deleteBudget(t.owner, b.id);
      expect(await code(admin.deleteBudget(t.owner, b.id))).toBe("not_found");
    });

    it("retention: bounds, and audit retention can only grow", async () => {
      const t = await w.tenant();
      expect(await code(admin.updateRetention(t.owner, { auditDays: 30 }))).toBe("invalid");
      expect(await code(admin.updateRetention(t.owner, { auditDays: 4000 }))).toBe("invalid");
      expect(await code(admin.updateRetention(t.owner, { transcriptDays: 0 }))).toBe("invalid");
      expect(await code(admin.updateRetention(t.owner, { auditDays: 400 }))).toBe("conflict"); // default is 2555: shortening refused
      const s = await admin.updateRetention(t.owner, {
        auditDays: 3000,
        transcriptDays: 7,
        memoryDays: 90,
      });
      expect([s.retentionAuditDays, s.retentionTranscriptDays, s.retentionMemoryDays]).toEqual([
        3000, 7, 90,
      ]);
      expect((await admin.getSettings(t.owner)).retentionTranscriptDays).toBe(7);
    });

    it("tenant read shows region and tier; read roles see what they should", async () => {
      const t = await w.tenant();
      const info = await admin.tenant(t.owner);
      expect(info.region).toBe("us-east-1");
      expect(info.isolationTier).toBe("shared_rls");
      const aud = await w.member(t.tenantId, "auditor");
      expect((await admin.listAudit(aud.principal, { limit: 5 })).length).toBeGreaterThan(0);
      const bld = await w.member(t.tenantId, "builder");
      expect(await code(admin.listAudit(bld.principal, {}))).toBe("forbidden");
      const bill = await w.member(t.tenantId, "billing");
      expect(await code(admin.listMembers(bill.principal))).toBe("forbidden");
      expect(
        await code(
          admin.putBudget(bill.principal, {
            scope: "tenant",
            metric: "tokens",
            period: "month",
            hard: 100,
          }),
        ),
      ).toBe("ok");
    });

    it("members: list pages, duplicate e-mail conflicts, role vocabulary", async () => {
      const t = await w.tenant();
      for (let i = 0; i < 3; i++)
        await admin.inviteMember(t.owner, { email: `m${i}@x.test`, role: "viewer" });
      expect(await code(admin.inviteMember(t.owner, { email: "M0@x.test", role: "viewer" }))).toBe(
        "conflict",
      );
      expect(
        await code(admin.inviteMember(t.owner, { email: "not-an-email", role: "viewer" })),
      ).toBe("invalid");
      expect(
        await code(admin.inviteMember(t.owner, { email: "r@x.test", role: "god" as Role })),
      ).toBe("invalid");
      const p1 = await admin.listMembers(t.owner, 2);
      expect(p1.items).toHaveLength(2);
      const p2 = await admin.listMembers(t.owner, 2, p1.nextCursor);
      expect(p2.items.length).toBe(2);
      expect(p2.items.some((m) => p1.items.some((x) => x.id === m.id))).toBe(false);
      expect(await code(admin.listMembers(t.owner, 2, "not-a-uuid"))).toBe("not_found");
    });
  });
});
