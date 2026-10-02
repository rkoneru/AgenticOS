import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  ScimHandler,
  parseFilter,
  type DirectoryContext,
  type ScimResponse,
} from "../src/index.js";
import { eventsOf, KINDS, makeWorld, type World } from "./world.js";

interface Ctx {
  t: Awaited<ReturnType<World["tenant"]>>;
  dir: { id: string; token: string };
  ctx: DirectoryContext;
  call: (
    method: string,
    path: string,
    body?: unknown,
    q?: Record<string, string>,
  ) => Promise<ScimResponse>;
}

describe("SCIM filter parser", () => {
  it("parses the supported subset", () => {
    expect(parseFilter('userName eq "a@b.test"')).toEqual([
      { attr: "username", op: "eq", value: "a@b.test" },
    ]);
    expect(parseFilter('userName eq "x" and active eq true')).toEqual([
      { attr: "username", op: "eq", value: "x" },
      { attr: "active", op: "eq", value: true },
    ]);
    expect(parseFilter("externalId pr")).toEqual([{ attr: "externalid", op: "pr" }]);
    expect(parseFilter('displayName co "a and b"')).toEqual([
      { attr: "displayname", op: "co", value: "a and b" },
    ]);
    expect(parseFilter('emails.value sw "a"')[0]).toMatchObject({ op: "sw" });
  });
  it("rejects everything else with invalidFilter", () => {
    for (const bad of [
      'userName eq "a" or userName eq "b"',
      '(userName eq "a")',
      'not (userName eq "a")',
      'password eq "x"',
      'userName gt "a"',
      "userName eq",
      "userName eq a",
      "x".repeat(600),
      "active pr true",
      'userName eq "a" and',
    ]) {
      expect(() => parseFilter(bad), bad).toThrow();
    }
  });
});

describe.each(KINDS)("SCIM 2.0 (%s store)", (kind) => {
  let w: World;
  let scim: ScimHandler;
  beforeAll(async () => {
    w = await makeWorld(kind);
    scim = new ScimHandler(w.cp.directories);
  });
  afterAll(() => w.close());

  async function setup(defaultRole: "viewer" | "builder" = "viewer"): Promise<Ctx> {
    const t = await w.tenant();
    const dir = await w.cp.admin.createDirectory(t.owner, "okta", defaultRole);
    const ctx = (await w.cp.directories.authenticate(`Bearer ${dir.token}`))!;
    const call: Ctx["call"] = (method, path, body, q = {}) =>
      scim.handle(ctx, { method, path, query: new URLSearchParams(q), body });
    return { t, dir, ctx, call };
  }
  const user = (email: string, extra: Record<string, unknown> = {}) => ({
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    userName: email,
    externalId: `ext-${email}`,
    name: { formatted: "Full Name" },
    emails: [{ value: email, primary: true }],
    active: true,
    ...extra,
  });
  /* eslint-disable @typescript-eslint/no-explicit-any */
  const body = (r: ScimResponse): Record<string, any> => r.body as Record<string, any>;
  /* eslint-enable @typescript-eslint/no-explicit-any */

  it("a directory can never default to owner", async () => {
    const t = await w.tenant();
    await expect(w.cp.admin.createDirectory(t.owner, "bad", "owner")).rejects.toThrow(
      /external role/,
    );
  });

  it("authenticates by per-directory bearer token only", async () => {
    const { dir, t } = await setup();
    expect(await w.cp.directories.authenticate(`Bearer ${dir.token}`)).toMatchObject({
      tenantId: t.tenantId,
    });
    for (const bad of [
      undefined,
      "",
      "Bearer",
      `Bearer ${dir.token}x`,
      `bearer ${dir.token}`,
      `Basic ${dir.token}`,
      `Bearer ${dir.token} extra`,
      "Bearer axs_0000000000000000_" + "A".repeat(43),
      "Bearer axk_" + dir.token.slice(4),
    ])
      expect(await w.cp.directories.authenticate(bad as string), String(bad)).toBeUndefined();
    // rotation invalidates the old token; revocation kills the directory
    const nt = await w.cp.admin.rotateDirectoryToken(t.owner, dir.id);
    expect(await w.cp.directories.authenticate(`Bearer ${dir.token}`)).toBeUndefined();
    expect(await w.cp.directories.authenticate(`Bearer ${nt.token}`)).toBeDefined();
    await w.cp.admin.revokeDirectory(t.owner, dir.id);
    expect(await w.cp.directories.authenticate(`Bearer ${nt.token}`)).toBeUndefined();
  });

  it("creates, reads, lists, filters, replaces and patches users with SCIM shapes", async () => {
    const { call, t } = await setup();
    const c = await call("POST", "/Users", user("ann@corp.test"));
    expect(c.status).toBe(201);
    expect(body(c)).toMatchObject({
      userName: "ann@corp.test",
      active: true,
      externalId: "ext-ann@corp.test",
      displayName: "Full Name",
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    });
    const id = body(c)["id"] as string;
    expect(await w.store.getMember(t.tenantId, id)).toMatchObject({
      role: "viewer",
      status: "active",
      directoryId: expect.any(String),
    });
    expect(body(await call("GET", `/Users/${id}`))["userName"]).toBe("ann@corp.test");
    await call("POST", "/Users", user("bob@corp.test"));
    const list = body(await call("GET", "/Users"));
    expect(list).toMatchObject({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
      totalResults: 2,
      startIndex: 1,
    });
    const f = body(
      await call("GET", "/Users", undefined, { filter: 'userName eq "BOB@corp.test"' }),
    );
    expect(f["totalResults"]).toBe(1);
    expect(
      body(await call("GET", "/Users", undefined, { filter: 'userName co "corp"' }))[
        "totalResults"
      ],
    ).toBe(2);
    expect(
      body(
        await call("GET", "/Users", undefined, { filter: 'userName sw "ann" and active eq true' }),
      )["totalResults"],
    ).toBe(1);
    expect(
      body(await call("GET", "/Users", undefined, { filter: 'userName ne "ann@corp.test"' }))[
        "totalResults"
      ],
    ).toBe(1);
    expect(
      body(await call("GET", "/Users", undefined, { filter: "externalId pr" }))["totalResults"],
    ).toBe(2);
    expect(
      body(await call("GET", "/Users", undefined, { filter: 'id eq "' + id + '"' }))[
        "totalResults"
      ],
    ).toBe(1);
    expect(
      body(await call("GET", "/Users", undefined, { count: "1", startIndex: "2" }))["Resources"],
    ).toHaveLength(1);
    const put = await call(
      "PUT",
      `/Users/${id}`,
      user("ann2@corp.test", { displayName: "Ann Two" }),
    );
    expect(body(put)).toMatchObject({ userName: "ann2@corp.test", displayName: "Ann Two" });
    const patch = await call("PATCH", `/Users/${id}`, {
      schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [
        { op: "replace", path: "displayName", value: "Ann Three" },
        { op: "Replace", value: { userName: "ann3@corp.test" } },
      ],
    });
    expect(body(patch)).toMatchObject({ displayName: "Ann Three", userName: "ann3@corp.test" });
  });

  it("returns RFC 7644 errors: 404, 409 uniqueness, 400 invalidValue/invalidFilter/invalidPath/invalidSyntax, 405", async () => {
    const { call } = await setup();
    const err = (r: ScimResponse, status: number, type?: string) => {
      expect(r.status).toBe(status);
      expect(body(r)).toMatchObject({
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        status: String(status),
        detail: expect.any(String),
      });
      if (type) expect(body(r)["scimType"]).toBe(type);
    };
    err(await call("GET", "/Users/00000000-0000-4000-8000-000000000999"), 404);
    err(await call("GET", "/Users/not-a-uuid"), 404);
    err(await call("GET", "/Nope"), 404);
    err(await call("GET", "/Users/a/b"), 404);
    await call("POST", "/Users", user("dup@corp.test"));
    err(await call("POST", "/Users", user("dup@corp.test")), 409, "uniqueness");
    err(
      await call("POST", "/Users", user("other@corp.test", { externalId: "ext-dup@corp.test" })),
      409,
      "uniqueness",
    );
    err(await call("POST", "/Users", { userName: "" }), 400, "invalidValue");
    err(await call("POST", "/Users", { userName: "not-an-email" }), 400, "invalidValue");
    err(await call("POST", "/Users", "string"), 400, "invalidSyntax");
    err(
      await call("GET", "/Users", undefined, { filter: 'userName eq "a" or userName eq "b"' }),
      400,
      "invalidFilter",
    );
    err(
      await call("PATCH", "/Users/00000000-0000-4000-8000-000000000999", {
        Operations: [{ op: "replace", path: "bogus", value: 1 }],
      }),
      400,
      "invalidPath",
    );
    err(await call("PATCH", "/Users/x", {}), 400, "invalidSyntax");
    err(await call("PATCH", "/Users/x", { Operations: [{ op: "frob" }] }), 400, "invalidSyntax");
    err(await call("DELETE", "/Users"), 405);
    err(await call("PUT", "/Users"), 405);
    err(await call("DELETE", "/Users/00000000-0000-4000-8000-000000000999"), 404);
    err(await call("POST", "/Groups", {}), 400, "invalidValue");
    err(await call("GET", "/Groups/00000000-0000-4000-8000-000000000999"), 404);
    err(
      await call(
        "PATCH",
        "/Users/" + body(await call("POST", "/Users", user("p@corp.test")))["id"],
        { Operations: [{ op: "replace", path: "active", value: "maybe" }] },
      ),
      400,
      "invalidValue",
    );
    expect((await call("GET", "/ServiceProviderConfig")).status).toBe(200);
  });

  it("deprovisioning (PATCH active=false in both IdP styles, PUT, DELETE) revokes sessions and API keys immediately", async () => {
    const { call, t } = await setup();
    const styles: [string, (id: string) => Promise<ScimResponse>][] = [
      [
        "azure",
        (id) =>
          call("PATCH", `/Users/${id}`, {
            Operations: [{ op: "Replace", path: "active", value: "False" }],
          }),
      ],
      [
        "okta",
        (id) =>
          call("PATCH", `/Users/${id}`, {
            Operations: [{ op: "replace", value: { active: false } }],
          }),
      ],
      ["put", (id) => call("PUT", `/Users/${id}`, user(`put@corp.test`, { active: false }))],
      ["delete", (id) => call("DELETE", `/Users/${id}`)],
    ];
    for (const [name, deprovision] of styles) {
      const email = name === "put" ? "put@corp.test" : `${name}@corp.test`;
      const created = body(await call("POST", "/Users", user(email)));
      const id = created["id"] as string;
      // the user is a builder with a live session and a live API key
      await w.store.updateMember(t.tenantId, id, { role: "builder" }, w.clock.now()); // manual role; irrelevant to revocation
      const sess = await w.cp.sessions.issue((await w.store.getMember(t.tenantId, id))!, "sso");
      const asUser = await w.cp.sessions.authenticate(sess.accessToken);
      expect(asUser).toBeDefined();
      const key = await w.cp.apiKeys.create(asUser!, { name: "k", scopes: ["*"] });
      expect(await w.cp.apiKeys.verify(key.secret)).toBeDefined();
      const r = await deprovision(id);
      expect([200, 204], name).toContain(r.status);
      expect(await w.cp.sessions.authenticate(sess.accessToken), `${name} session`).toBeUndefined();
      expect(
        await w.cp.sessions.authenticate(
          (await w.cp.sessions.refresh(sess.refreshToken).catch(() => ({ accessToken: "" })))
            .accessToken,
        ),
      ).toBeUndefined();
      expect(await w.cp.apiKeys.verify(key.secret), `${name} key`).toBeUndefined();
      // revoked rows, not just an inactive member: re-activating the member must not bring them back
      expect(
        (await w.store.getSession(t.tenantId, sess.sessionId))?.revokedAt,
        `${name} session row`,
      ).toBeDefined();
      expect(
        (await w.store.getApiKey(t.tenantId, key.key.id))?.revokedAt,
        `${name} key row`,
      ).toBeDefined();
      expect((await w.store.getMember(t.tenantId, id))?.status).toBe("deprovisioned");
    }
    const ev = (await eventsOf(w, t.tenantId)).map((e) => e.action);
    expect(ev.filter((a) => a === "scim.user.deprovision").length).toBe(3);
    expect(ev).toContain("scim.user.delete");
  });

  it("reactivation restores the member but not their revoked keys or sessions", async () => {
    const { call, t } = await setup();
    const id = body(await call("POST", "/Users", user("back@corp.test")))["id"] as string;
    const sess = await w.cp.sessions.issue((await w.store.getMember(t.tenantId, id))!);
    await call("PATCH", `/Users/${id}`, {
      Operations: [{ op: "replace", path: "active", value: false }],
    });
    await call("PATCH", `/Users/${id}`, {
      Operations: [{ op: "replace", path: "active", value: true }],
    });
    expect((await w.store.getMember(t.tenantId, id))?.status).toBe("active");
    expect(await w.cp.sessions.authenticate(sess.accessToken)).toBeUndefined();
    const inactive = body(
      await call("POST", "/Users", user("inactive@corp.test", { active: false })),
    );
    expect(inactive["active"]).toBe(false);
  });

  it("maps groups to roles from tenant-configured mappings, capped below owner, and recomputes on membership change", async () => {
    const { call, t, dir } = await setup("viewer");
    await w.cp.admin.setGroupRole(t.owner, dir.id, "Admins", "admin");
    await w.cp.admin.setGroupRole(t.owner, dir.id, "Builders", "builder");
    expect(
      await w.cp.admin
        .setGroupRole(t.owner, dir.id, "Owners", "owner")
        .catch((e: Error) => e.message),
    ).toMatch(/owner/);
    const id = body(await call("POST", "/Users", user("g@corp.test")))["id"] as string;
    const gOwners = body(
      await call("POST", "/Groups", { displayName: "Owners", members: [{ value: id }] }),
    );
    expect((await w.store.getMember(t.tenantId, id))?.role).toBe("viewer"); // "Owners" has no mapping: SCIM cannot mint roles
    const gb = body(
      await call("POST", "/Groups", { displayName: "Builders", members: [{ value: id }] }),
    );
    expect((await w.store.getMember(t.tenantId, id))?.role).toBe("builder");
    const ga = body(await call("POST", "/Groups", { displayName: "Admins" }));
    await call("PATCH", `/Groups/${ga["id"]}`, {
      Operations: [{ op: "add", path: "members", value: [{ value: id }] }],
    });
    expect((await w.store.getMember(t.tenantId, id))?.role).toBe("admin");
    await call("PATCH", `/Groups/${ga["id"]}`, {
      Operations: [{ op: "remove", path: `members[value eq "${id}"]` }],
    });
    expect((await w.store.getMember(t.tenantId, id))?.role).toBe("builder");
    await call("DELETE", `/Groups/${gb["id"]}`);
    expect((await w.store.getMember(t.tenantId, id))?.role).toBe("viewer");
    const got = body(await call("GET", `/Groups/${gOwners["id"]}`));
    expect(got["members"]).toEqual([{ value: id }]);
    // renaming a group re-evaluates its members
    await call("PATCH", `/Groups/${gOwners["id"]}`, {
      Operations: [{ op: "replace", path: "displayName", value: "Builders" }],
    });
    expect((await w.store.getMember(t.tenantId, id))?.role).toBe("builder");
    // replace members / PUT group
    await call("PATCH", `/Groups/${gOwners["id"]}`, {
      Operations: [{ op: "replace", path: "members", value: [] }],
    });
    expect((await w.store.getMember(t.tenantId, id))?.role).toBe("viewer");
    await call("PUT", `/Groups/${gOwners["id"]}`, {
      displayName: "Admins2",
      members: [{ value: id }],
    });
    expect(
      body(await call("GET", "/Groups", undefined, { filter: 'displayName eq "Admins2"' }))[
        "totalResults"
      ],
    ).toBe(1);
    expect((await call("POST", "/Groups", { displayName: "Admins2" })).status).toBe(409);
  });

  it("never lets SCIM touch owners: no role change; deprovisioning the last owner is refused but cuts access", async () => {
    const { t, dir } = await setup();
    // an owner provisioned by this directory (e.g. an owner appointed in-product who also exists in the IdP)
    const ctx = (await w.cp.directories.authenticate(`Bearer ${dir.token}`))!;
    const u = await w.cp.directories.createUser(ctx, {
      userName: "boss@corp.test",
      email: "boss@corp.test",
      externalId: "boss",
      active: true,
    });
    await w.store.updateMember(t.tenantId, u.id, { role: "owner" }, w.clock.now());
    await w.cp.directories.setRoleMapping(t.tenantId, dir.id, "G", "viewer");
    const g = await w.cp.directories.createGroup(ctx, { displayName: "G", memberIds: [u.id] });
    expect(g.displayName).toBe("G");
    expect((await w.store.getMember(t.tenantId, u.id))?.role).toBe("owner"); // not demoted by the mapping
    // another owner exists (the signup owner): deprovisioning works
    const sess = await w.cp.sessions.issue((await w.store.getMember(t.tenantId, u.id))!);
    await w.cp.directories.updateUser(ctx, u.id, { active: false });
    expect(await w.cp.sessions.authenticate(sess.accessToken)).toBeUndefined();
    // make it the last owner and try again
    await w.store.updateMember(t.tenantId, u.id, { status: "active" }, w.clock.now());
    await w.store.updateMember(t.tenantId, t.ownerId, { role: "admin" }, w.clock.now());
    const sess2 = await w.cp.sessions.issue((await w.store.getMember(t.tenantId, u.id))!);
    await expect(w.cp.directories.updateUser(ctx, u.id, { active: false })).rejects.toThrow(
      /last owner/,
    );
    expect(await w.cp.sessions.authenticate(sess2.accessToken)).toBeUndefined();
    expect(
      (await eventsOf(w, t.tenantId)).some((e) => e.action.endsWith("last_owner_locked_out")),
    ).toBe(true);
  });

  it("isolates directories: a token sees only the users it provisioned, and cannot touch other directories' or tenants' users", async () => {
    const a = await setup();
    const b = await setup();
    const aUser = body(await a.call("POST", "/Users", user("a@corp.test")))["id"] as string;
    const bUser = body(await b.call("POST", "/Users", user("b@corp.test")))["id"] as string;
    // same tenant, second directory
    const dir2 = await w.cp.admin.createDirectory(a.t.owner, "azure", "viewer");
    const ctx2 = (await w.cp.directories.authenticate(`Bearer ${dir2.token}`))!;
    const call2: Ctx["call"] = (m, p, bd, q = {}) =>
      scim.handle(ctx2, { method: m, path: p, query: new URLSearchParams(q), body: bd });
    for (const [call, id] of [
      [b.call, aUser],
      [call2, aUser],
      [a.call, bUser],
    ] as const) {
      expect((await call("GET", `/Users/${id}`)).status).toBe(404);
      expect(
        (
          await call("PATCH", `/Users/${id}`, {
            Operations: [{ op: "replace", path: "active", value: false }],
          })
        ).status,
      ).toBe(404);
      expect((await call("DELETE", `/Users/${id}`)).status).toBe(404);
    }
    expect((await w.store.getMember(a.t.tenantId, aUser))?.status).toBe("active");
    expect((await w.store.getMember(b.t.tenantId, bUser))?.status).toBe("active");
    expect(body(await call2("GET", "/Users"))["totalResults"]).toBe(0);
    // cannot add a foreign user to my group, nor reference unknown ids
    const g = body(await call2("POST", "/Groups", { displayName: "X" }));
    expect(
      (
        await call2("PATCH", `/Groups/${g["id"]}`, {
          Operations: [{ op: "add", path: "members", value: [{ value: aUser }] }],
        })
      ).status,
    ).toBe(400);
    expect((await b.call("PATCH", `/Groups/${g["id"]}`, { Operations: [] })).status).toBe(404);
    expect((await b.call("GET", `/Groups/${g["id"]}`)).status).toBe(404);
    // email of an existing (non-directory) member cannot be claimed by SCIM
    expect((await a.call("POST", "/Users", user(`owner@${a.t.slug}.test`))).status).toBe(409);
  });

  it("applies IdP directory events with the same rules (signature, create, update, deactivate, groups, delete)", async () => {
    const { t, dir } = await setup();
    const ctx = (await w.cp.directories.authenticate(`Bearer ${dir.token}`))!;
    const parse = (ev: object) =>
      w.idp.parseDirectoryEvent(JSON.stringify(ev), w.idp.signWebhook(JSON.stringify(ev)));
    const did = "idp-dir";
    await w.cp.admin.setGroupRole(t.owner, dir.id, "Eng", "builder");
    await w.cp.directories.applyEvent(
      ctx,
      parse({
        type: "user.created",
        directoryId: did,
        user: { externalId: "u1", userName: "u1@corp.test", email: "u1@corp.test", active: true },
      }),
    );
    const m = (await w.store.findMemberByExternalId(t.tenantId, dir.id, "u1"))!;
    expect(m.status).toBe("active");
    await w.cp.directories.applyEvent(
      ctx,
      parse({
        type: "user.updated",
        directoryId: did,
        user: {
          externalId: "u1",
          userName: "u1@corp.test",
          email: "u1@corp.test",
          active: true,
          displayName: "U One",
        },
      }),
    );
    expect((await w.store.getMember(t.tenantId, m.id))?.displayName).toBe("U One");
    await w.cp.directories.applyEvent(
      ctx,
      parse({
        type: "group.created",
        directoryId: did,
        group: { externalId: "g1", name: "Eng", memberExternalIds: ["u1", "unknown"] },
      }),
    );
    expect((await w.store.getMember(t.tenantId, m.id))?.role).toBe("builder");
    await w.cp.directories.applyEvent(
      ctx,
      parse({
        type: "group.updated",
        directoryId: did,
        group: { externalId: "g1", name: "Eng", memberExternalIds: [] },
      }),
    );
    expect((await w.store.getMember(t.tenantId, m.id))?.role).toBe("viewer");
    await w.cp.directories.applyEvent(
      ctx,
      parse({ type: "group.deleted", directoryId: did, externalId: "g1" }),
    );
    await w.cp.directories.applyEvent(
      ctx,
      parse({ type: "group.deleted", directoryId: did, externalId: "nope" }),
    );
    const sess = await w.cp.sessions.issue((await w.store.getMember(t.tenantId, m.id))!);
    await w.cp.directories.applyEvent(
      ctx,
      parse({
        type: "user.updated",
        directoryId: did,
        user: { externalId: "u1", userName: "u1@corp.test", email: "u1@corp.test", active: false },
      }),
    );
    expect(await w.cp.sessions.authenticate(sess.accessToken)).toBeUndefined();
    await w.cp.directories.applyEvent(
      ctx,
      parse({ type: "user.deleted", directoryId: did, externalId: "u1" }),
    );
    await w.cp.directories.applyEvent(
      ctx,
      parse({ type: "user.deleted", directoryId: did, externalId: "zzz" }),
    );
    expect(() => w.idp.parseDirectoryEvent("{}", "bad")).toThrow(/signature/);
    expect(() => w.idp.parseDirectoryEvent("{}", undefined)).toThrow(/signature/);
  });
});
