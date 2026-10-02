import fc from "fast-check";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CpError, ROLES, ROLE_RANK, ScimHandler, type Principal, type Role } from "../src/index.js";
import { makeWorld, type World } from "./world.js";

const role = fc.constantFrom<Role>(...ROLES);
const attempt = async (p: Promise<unknown>): Promise<boolean> => {
  try {
    await p;
    return true;
  } catch (e) {
    if (e instanceof CpError) return false;
    throw e;
  }
};

describe("properties (memory store, real OPA policy)", () => {
  let w: World;
  beforeAll(async () => {
    w = await makeWorld("memory");
  });
  afterAll(() => w.close());

  it("role escalation is impossible: no sequence of admin operations ever gives anyone a role above the acting member's, and an owner always remains", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.record({ actor: fc.nat(5), target: fc.nat(5), newRole: role, kind: fc.constantFrom("invite", "update", "remove") }), { minLength: 1, maxLength: 12 }),
        fc.array(role, { minLength: 6, maxLength: 6 }),
        async (ops, roles) => {
          const t = await w.tenant();
          const ids: { id: string; p: Principal }[] = [{ id: t.ownerId, p: t.owner }];
          for (const r of roles.slice(0, 5)) {
            const m = await w.member(t.tenantId, r);
            ids.push({ id: m.memberId, p: m.principal });
          }
          for (const op of ops) {
            const actor = ids[op.actor % ids.length]!;
            const target = ids[op.target % ids.length]!;
            const actorRole = (await w.store.getMember(t.tenantId, actor.id))!.role;
            const before = new Map((await w.store.listMembers(t.tenantId, 200)).items.map((m) => [m.id, m.role] as const));
            // principals carry the role from login time; refresh it so the property is about CURRENT roles
            const live = await w.login(t.tenantId, actor.id).catch(() => undefined);
            if (!live) continue;
            if (op.kind === "invite") {
              const ok = await attempt(w.cp.admin.inviteMember(live, { email: `p${Math.random().toString(36).slice(2)}@x.test`, role: op.newRole }));
              if (ok) expect(ROLE_RANK[op.newRole]).toBeLessThanOrEqual(ROLE_RANK[actorRole]);
              continue;
            }
            const ok = await attempt(op.kind === "update" ? w.cp.admin.updateMemberRole(live, target.id, op.newRole) : w.cp.admin.removeMember(live, target.id));
            if (ok && op.kind === "update") {
              expect(ROLE_RANK[op.newRole], "granted role").toBeLessThanOrEqual(ROLE_RANK[actorRole]);
              expect(ROLE_RANK[before.get(target.id)!], "modified a more privileged member").toBeLessThanOrEqual(ROLE_RANK[actorRole]);
            }
            if (ok && op.kind === "remove") expect(ROLE_RANK[before.get(target.id)!], "removed a more privileged member").toBeLessThanOrEqual(ROLE_RANK[actorRole]);
            const after = (await w.store.listMembers(t.tenantId, 200)).items;
            expect(after.some((m) => m.role === "owner" && m.status === "active"), "an owner remains").toBe(true);
            for (const m of after) {
              const was = before.get(m.id);
              if (was !== undefined && m.role !== was) expect(ROLE_RANK[m.role]).toBeLessThanOrEqual(ROLE_RANK[actorRole]);
            }
          }
        },
      ),
      { numRuns: 60 },
    );
  });

  it("the tenant is derived from the session only: no operation, with any foreign id, reads or changes another tenant", async () => {
    const a = await w.tenant();
    const b = await w.tenant();
    const bm = await w.member(b.tenantId, "viewer");
    const bk = await w.cp.admin.createApiKey(b.owner, { name: "b", scopes: ["*"] });
    const bd = await w.cp.admin.putBudget(b.owner, { scope: "tenant", metric: "runtime_seconds", period: "day", hard: 9 });
    const dir = await w.cp.admin.createDirectory(b.owner, "d", "viewer");
    const pol = (await w.cp.admin.listPolicies(b.owner))[0]!;
    const snapshot = async () =>
      JSON.stringify({
        members: (await w.store.listMembers(b.tenantId, 200)).items.map((m) => [m.id, m.role, m.status]),
        keys: (await w.store.listApiKeys(b.tenantId, 200)).items.map((k) => [k.id, k.revokedAt]),
        budgets: await w.store.listBudgets(b.tenantId),
        dirs: (await w.store.listDirectories(b.tenantId)).map((d) => [d.id, d.status]),
        active: (await w.store.listActiveAssignments(b.tenantId)).map((x) => x.versionId),
        settings: await w.store.getSettings(b.tenantId),
        creds: (await w.store.listModelCredentials(b.tenantId)).length,
      });
    const before = await snapshot();
    const foreign = [bm.memberId, bk.key.id, bd.id, dir.id, pol.versionId, b.ownerId];
    const callers: Principal[] = [a.owner, ...(await Promise.all(ROLES.filter((r) => r !== "owner").map(async (r) => (await w.member(a.tenantId, r)).principal)))];
    const ops: ((p: Principal, id: string) => Promise<unknown>)[] = [
      (p, id) => w.cp.admin.getMember(p, id),
      (p, id) => w.cp.admin.updateMemberRole(p, id, "viewer"),
      (p, id) => w.cp.admin.removeMember(p, id),
      (p, id) => w.cp.admin.revokeMemberSessions(p, id),
      (p, id) => w.cp.admin.rotateApiKey(p, id),
      (p, id) => w.cp.admin.revokeApiKey(p, id),
      (p, id) => w.cp.admin.deleteBudget(p, id),
      (p, id) => w.cp.admin.activatePolicy(p, id),
      (p, id) => w.cp.admin.rotateDirectoryToken(p, id),
      (p, id) => w.cp.admin.revokeDirectory(p, id),
      (p, id) => w.cp.admin.setGroupRole(p, id, "g", "viewer"),
    ];
    await fc.assert(
      fc.asyncProperty(fc.constantFrom(...callers), fc.constantFrom(...ops), fc.constantFrom(...foreign), async (p, op, id) => {
        await attempt(op(p, id));
        expect(await snapshot()).toBe(before);
      }),
      { numRuns: 120 },
    );
    // and the lists a caller sees never contain foreign rows
    for (const p of callers.slice(0, 1)) {
      const members = await w.cp.admin.listMembers(p);
      expect(members.items.some((m) => m.id === bm.memberId || m.id === b.ownerId)).toBe(false);
      expect((await w.cp.admin.listApiKeys(p)).items.some((k) => k.id === bk.key.id)).toBe(false);
    }
  });

  it("SCIM deprovisioning always revokes every session and API key of the user, whatever their number", async () => {
    const t = await w.tenant();
    const dir = await w.cp.admin.createDirectory(t.owner, "okta", "builder");
    const ctx = (await w.cp.directories.authenticate(`Bearer ${dir.token}`))!;
    const scim = new ScimHandler(w.cp.directories);
    await fc.assert(
      fc.asyncProperty(fc.nat(4), fc.nat(4), fc.constantFrom("active-false", "okta", "put", "delete", "event"), async (nSessions, nKeys, style) => {
        const email = `u${Math.random().toString(36).slice(2)}@corp.test`;
        const u = await w.cp.directories.createUser(ctx, { userName: email, email, externalId: email, active: true });
        const member = (await w.store.getMember(t.tenantId, u.id))!;
        const sessions = await Promise.all(Array.from({ length: nSessions }, () => w.cp.sessions.issue(member, "sso")));
        const principal = await w.login(t.tenantId, u.id);
        const keys = await Promise.all(Array.from({ length: nKeys }, (_, i) => w.cp.apiKeys.create(principal, { name: `k${i}`, scopes: ["*"] })));
        const call = (method: string, body?: unknown) => scim.handle(ctx, { method, path: `/Users/${u.id}`, query: new URLSearchParams(), body });
        if (style === "active-false") await call("PATCH", { Operations: [{ op: "replace", path: "active", value: false }] });
        else if (style === "okta") await call("PATCH", { Operations: [{ op: "replace", value: { active: false } }] });
        else if (style === "put") await call("PUT", { userName: email, emails: [{ value: email }], active: false });
        else if (style === "delete") await call("DELETE");
        else await w.cp.directories.applyEvent(ctx, { type: "user.deleted", directoryId: "d", externalId: email });
        for (const s of sessions) expect(await w.cp.sessions.authenticate(s.accessToken)).toBeUndefined();
        for (const s of sessions) await expect(w.cp.sessions.refresh(s.refreshToken)).rejects.toBeInstanceOf(CpError);
        for (const k of keys) expect(await w.cp.apiKeys.verify(k.secret)).toBeUndefined();
        expect((await w.store.getMember(t.tenantId, u.id))?.status).toBe("deprovisioned");
      }),
      { numRuns: 40 },
    );
  });

  it("a role can never be derived from a token: an access token minted for a member always reflects the stored role", async () => {
    const t = await w.tenant();
    await fc.assert(
      fc.asyncProperty(role, role, async (r1, r2) => {
        const m = await w.member(t.tenantId, r1);
        const s = await w.cp.sessions.issue((await w.store.getMember(t.tenantId, m.memberId))!);
        if (r1 !== r2 && !(r1 === "owner")) await w.store.updateMember(t.tenantId, m.memberId, { role: r2 }, w.clock.now());
        const p = await w.cp.sessions.authenticate(s.accessToken);
        expect(p?.role).toBe((await w.store.getMember(t.tenantId, m.memberId))?.role);
      }),
      { numRuns: 40 },
    );
  });
});
