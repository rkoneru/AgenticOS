import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CpError, safeReturnTo, type IdpProfile } from "../src/index.js";
import { eventsOf, KINDS, makeWorld, type World } from "./world.js";

const code = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "ok";
  } catch (e) {
    return e instanceof CpError ? e.code : `other:${String(e)}`;
  }
};

describe("safeReturnTo", () => {
  const allowed = ["https://console.example.test"];
  it("keeps same-site paths and allow-listed origins, rejects everything else", () => {
    expect(safeReturnTo("/dashboard?x=1#h", allowed)).toBe("/dashboard?x=1#h");
    expect(safeReturnTo("https://console.example.test/a", allowed)).toBe(
      "https://console.example.test/a",
    );
    for (const bad of [
      "//evil.test",
      "/\\evil.test",
      "\\\\evil.test",
      "https://evil.test",
      "http://console.example.test/a",
      "javascript:alert(1)",
      "data:text/html,x",
      "https://console.example.test@evil.test/",
      "https://user:pw@console.example.test/",
      "evil.test",
      "///evil.test",
      "/a\nb",
      "/a\u0000b",
      "",
      "x".repeat(3000),
      "https://console.example.test.evil.test/",
    ])
      expect(safeReturnTo(bad, allowed), bad).toBe("/");
    expect(safeReturnTo(undefined, allowed)).toBe("/");
    expect(safeReturnTo("%2f%2fevil.test", allowed)).toBe("/");
  });
});

describe.each(KINDS)("SSO (%s store)", (kind) => {
  let w: World;
  let tenantId: string;
  const ORG = "org_acme";
  const profile = (over: Partial<Omit<IdpProfile, "nonce">> = {}): Omit<IdpProfile, "nonce"> => ({
    id: "idp-user-1",
    email: "alice@acme-corp.test",
    emailVerified: true,
    organizationId: ORG,
    connectionType: "oidc",
    firstName: "Alice",
    lastName: "A",
    ...over,
  });

  beforeAll(async () => {
    w = await makeWorld(kind);
    const t = await w.tenant();
    tenantId = t.tenantId;
    await w.cp.admin.setSsoConnection(t.owner, {
      idpOrgId: ORG,
      connectionType: "oidc",
      jitEnabled: true,
      jitDefaultRole: "viewer",
    });
    w.dns.records.set("_axis-challenge.acme-corp.test", []);
    const d = await w.cp.admin.beginDomain(t.owner, "acme-corp.test");
    w.dns.records.set(`_axis-challenge.acme-corp.test`, [d.recordValue]);
    await w.cp.admin.verifyDomain(t.owner, "acme-corp.test");
  });
  afterAll(() => w.close());

  /** Drives the browser steps: start, IdP login, return. */
  async function start(returnTo?: string) {
    const st = await w.cp.sso.begin(ORG, returnTo);
    const state = new URL(st.redirectUrl).searchParams.get("state")!;
    return { st, state, cookie: st.cookie };
  }

  it("completes a login: PKCE, state, nonce validated; session issued; audited; JIT member created as viewer", async () => {
    const { state, cookie, st } = await start("/console/agents");
    const u = new URL(st.redirectUrl);
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
    expect(u.searchParams.get("redirect_uri")).toBe("https://cp.example.test/auth/sso/callback");
    expect(st.cookieMaxAgeSec).toBe(600);
    const code = w.idp.complete(state, profile());
    const r = await w.cp.sso.callback({ code, state }, cookie);
    expect(r.tenantId).toBe(tenantId);
    expect(r.returnTo).toBe("/console/agents");
    const p = await w.cp.sessions.authenticate(r.session.accessToken);
    expect(p).toMatchObject({ tenantId, role: "viewer", credential: "session" });
    const ev = await eventsOf(w, tenantId);
    expect(ev.some((e) => e.action === "members.jit_provision")).toBe(true);
    expect(ev.some((e) => e.action === "auth.sso_login" && e.decision === "ALLOW")).toBe(true);
    // second login finds the same member (no duplicate)
    const s2 = await start();
    const r2 = await w.cp.sso.callback(
      { code: w.idp.complete(s2.state, profile()), state: s2.state },
      s2.cookie,
    );
    expect(r2.memberId).toBe(r.memberId);
  });

  it("rejects: missing/garbled/foreign cookie, wrong state, expired attempt, replayed attempt", async () => {
    const a = await start();
    const code = w.idp.complete(a.state, profile());
    expect(await code2(w.cp.sso.callback({ code, state: a.state }, undefined))).toBe(
      "unauthenticated",
    );
    expect(await code2(w.cp.sso.callback({ code, state: a.state }, "garbage"))).toBe(
      "unauthenticated",
    );
    const other = await start();
    expect(await code2(w.cp.sso.callback({ code, state: a.state }, other.cookie))).toBe(
      "unauthenticated",
    ); // cookie from a different attempt
    expect(await code2(w.cp.sso.callback({ code, state: "forged-state" }, a.cookie))).toBe(
      "unauthenticated",
    );
    expect(await code2(w.cp.sso.callback({ state: a.state }, a.cookie))).toBe("unauthenticated");
    expect(
      await code2(w.cp.sso.callback({ code, state: a.state, error: "access_denied" }, a.cookie)),
    ).toBe("unauthenticated");
    // tampered cookie (flip one char)
    // (the replacement must differ from the character it replaces, or the "tampered" cookie is the original: a 1-in-64 flake)
    const at = a.cookie.length - 2;
    const flipped =
      a.cookie.slice(0, at) + (a.cookie[at] === "A" ? "B" : "A") + a.cookie.slice(at + 1);
    expect(await code2(w.cp.sso.callback({ code, state: a.state }, flipped))).toBe(
      "unauthenticated",
    );
    // success once, then replay of the same attempt is refused
    const ok = await w.cp.sso.callback({ code, state: a.state }, a.cookie);
    expect(ok.memberId).toBeDefined();
    const code3 = w.idp.complete(a.state, profile());
    expect(await code2(w.cp.sso.callback({ code: code3, state: a.state }, a.cookie))).toBe(
      "unauthenticated",
    );
    // expiry
    const b = await start();
    const c2 = w.idp.complete(b.state, profile());
    w.clock.advance(601);
    expect(await code2(w.cp.sso.callback({ code: c2, state: b.state }, b.cookie))).toBe(
      "unauthenticated",
    );
  });
  const code2 = code;

  it("rejects a cookie sealed by someone else (unsigned state)", async () => {
    const { SsoService, FakeIdentityProvider } = await import("../src/index.js");
    const { randomBytes } = await import("node:crypto");
    const attacker = new SsoService({
      store: w.store,
      idp: new FakeIdentityProvider(),
      sessions: w.cp.sessions,
      audit: new (await import("../src/index.js")).AdminAudit(w.auditStore),
      cookieKey: randomBytes(32),
      redirectUri: "https://cp.example.test/auth/sso/callback",
      allowedReturnOrigins: [],
      now: w.clock.now,
    });
    const st = await attacker.begin(ORG).catch(() => undefined);
    // the attacker cannot even start without the org; with the same store they can, and their cookie is useless against the victim service
    if (st) {
      const state = new URL(st.redirectUrl).searchParams.get("state")!;
      expect(await code(w.cp.sso.callback({ code: "x", state }, st.cookie))).toBe(
        "unauthenticated",
      );
    }
  });

  it("rejects a forged login cookie (plain or sealed with another key) even when its contents are self-consistent", async () => {
    const { b64u, seal } = await import("../src/index.js");
    const { randomBytes } = await import("node:crypto");
    const verifier = "attacker-verifier-attacker-verifier-attacker-verifier";
    const payload = {
      s: "forged-state",
      n: "forged-nonce",
      v: verifier,
      o: ORG,
      r: "/",
      exp: Math.floor(w.clock.now().getTime() / 1000) + 600,
    };
    const code = w.idp.issueRogue(
      { ...profile({ id: "forger", email: "forger@acme-corp.test" }), nonce: "forged-nonce" },
      "https://cp.example.test/auth/sso/callback",
      verifier,
    );
    const plain = b64u(Buffer.from(JSON.stringify(payload)));
    const wrongKey = b64u(
      seal(randomBytes(32), Buffer.from(JSON.stringify(payload)), "axis-login.v1"),
    );
    for (const cookie of [plain, wrongKey])
      expect(await code2(w.cp.sso.callback({ code, state: "forged-state" }, cookie))).toBe(
        "unauthenticated",
      );
    expect(await w.store.findMemberByEmail(tenantId, "forger@acme-corp.test")).toBeUndefined();
  });

  it("rejects IdP-side failures: bad code, wrong PKCE verifier binding, reused code, wrong org", async () => {
    const a = await start();
    expect(await code(w.cp.sso.callback({ code: "not-a-code", state: a.state }, a.cookie))).toBe(
      "unauthenticated",
    );
    const b = await start();
    const rogue = w.idp.issueRogue(
      { ...profile(), nonce: "n" },
      "https://cp.example.test/auth/sso/callback",
      "attacker-verifier",
    );
    expect(await code(w.cp.sso.callback({ code: rogue, state: b.state }, b.cookie))).toBe(
      "unauthenticated",
    ); // PKCE challenge does not match our verifier
    const c = await start();
    const other = w.idp.complete(c.state, profile({ organizationId: "org_other" }));
    expect(await code(w.cp.sso.callback({ code: other, state: c.state }, c.cookie))).toBe(
      "unauthenticated",
    );
    // the IdP asserts an organization that EXISTS but belongs to another tenant: never a login into that tenant
    const other2 = await w.tenant();
    await w.cp.admin.setSsoConnection(other2.owner, {
      idpOrgId: "org_victim",
      connectionType: "oidc",
      jitEnabled: true,
    });
    await w.cp.admin.inviteMember(other2.owner, { email: "victim@x2.test", role: "admin" });
    const x = await start();
    const crossOrg = w.idp.complete(
      x.state,
      profile({ organizationId: "org_victim", email: "victim@x2.test" }),
    );
    expect(await code(w.cp.sso.callback({ code: crossOrg, state: x.state }, x.cookie))).toBe(
      "unauthenticated",
    );
    expect((await eventsOf(w, other2.tenantId)).some((e) => e.action === "auth.sso_login")).toBe(
      false,
    );
    const d = await start();
    const good = w.idp.complete(d.state, profile());
    await w.cp.sso.callback({ code: good, state: d.state }, d.cookie);
    const e = await start();
    expect(await code(w.cp.sso.callback({ code: good, state: e.state }, e.cookie))).toBe(
      "unauthenticated",
    ); // code reuse
  });

  it("enforces the nonce: wrong or missing nonce on an OIDC connection is refused and audited", async () => {
    const a = await start();
    expect(
      await code(
        w.cp.sso.callback(
          { code: w.idp.complete(a.state, profile(), { wrongNonce: true }), state: a.state },
          a.cookie,
        ),
      ),
    ).toBe("unauthenticated");
    const b = await start();
    expect(
      await code(
        w.cp.sso.callback(
          { code: w.idp.complete(b.state, profile(), { omitNonce: true }), state: b.state },
          b.cookie,
        ),
      ),
    ).toBe("unauthenticated");
    const ev = await eventsOf(w, tenantId);
    const reasons = ev
      .filter((e) => e.action === "auth.sso_login" && e.decision === "DENY")
      .map((e) => e.reason);
    expect(reasons).toContain("why=nonce_mismatch");
    expect(reasons).toContain("why=nonce_missing");
  });

  it("connection type mismatch is refused", async () => {
    const a = await start();
    expect(
      await code(
        w.cp.sso.callback(
          {
            code: w.idp.complete(a.state, profile({ connectionType: "saml" }), { omitNonce: true }),
            state: a.state,
          },
          a.cookie,
        ),
      ),
    ).toBe("unauthenticated");
  });

  it("JIT is limited to verified domains, verified e-mails and the tenant's configured non-owner role", async () => {
    const attempt = async (p: Omit<IdpProfile, "nonce">) => {
      const a = await start();
      return code(
        w.cp.sso.callback({ code: w.idp.complete(a.state, p), state: a.state }, a.cookie),
      );
    };
    expect(await attempt(profile({ id: "u2", email: "bob@evil.test" }))).toBe("unauthenticated"); // domain not verified
    expect(
      await attempt(profile({ id: "u3", email: "carol@acme-corp.test", emailVerified: false })),
    ).toBe("unauthenticated");
    expect(await attempt(profile({ id: "u4", email: "dave@sub.acme-corp.test" }))).toBe(
      "unauthenticated",
    ); // sub-domain is not the verified domain
    expect(await attempt(profile({ id: "u5", email: "erin@ACME-CORP.test" }))).toBe("ok");
    expect(await w.store.findMemberByEmail(tenantId, "erin@acme-corp.test")).toMatchObject({
      role: "viewer",
      status: "active",
    });
    const reasons = (await eventsOf(w, tenantId))
      .filter((e) => e.decision === "DENY")
      .map((e) => e.reason);
    expect(reasons).toContain("why=domain_not_verified");
    expect(reasons).toContain("why=email_unverified");
  });

  it("JIT disabled: unknown users are refused; known (invited) users still sign in", async () => {
    const t = await w.tenant();
    await w.cp.admin.setSsoConnection(t.owner, {
      idpOrgId: "org_nojit",
      connectionType: "saml",
      jitEnabled: false,
    });
    const dom = await w.cp.admin.beginDomain(t.owner, "nojit.test");
    w.dns.records.set(dom.recordName, [dom.recordValue]);
    await w.cp.admin.verifyDomain(t.owner, "nojit.test"); // domain verified and e-mail verified: ONLY the JIT flag stands in the way
    await w.cp.admin.inviteMember(t.owner, { email: "inv@nojit.test", role: "builder" });
    const run = async (email: string) => {
      const st = await w.cp.sso.begin("org_nojit");
      const state = new URL(st.redirectUrl).searchParams.get("state")!;
      return code(
        w.cp.sso.callback(
          {
            code: w.idp.complete(
              state,
              {
                id: email,
                email,
                emailVerified: true,
                organizationId: "org_nojit",
                connectionType: "saml",
              },
              { omitNonce: true },
            ),
            state,
          },
          st.cookie,
        ),
      );
    };
    expect(await run("stranger@nojit.test")).toBe("unauthenticated");
    expect((await eventsOf(w, t.tenantId)).some((e) => e.reason === "why=jit_disabled")).toBe(true);
    expect(await run("inv@nojit.test")).toBe("ok");
    // an unverified e-mail does not claim an existing member
    const st = await w.cp.sso.begin("org_nojit");
    const state = new URL(st.redirectUrl).searchParams.get("state")!;
    expect(
      await code(
        w.cp.sso.callback(
          {
            code: w.idp.complete(
              state,
              {
                id: "x",
                email: "inv@nojit.test",
                emailVerified: false,
                organizationId: "org_nojit",
                connectionType: "saml",
              },
              { omitNonce: true },
            ),
            state,
          },
          st.cookie,
        ),
      ),
    ).toBe("unauthenticated");
  });

  it("a deprovisioned member cannot sign in", async () => {
    const a = await start();
    const r = await w.cp.sso.callback(
      {
        code: w.idp.complete(a.state, profile({ id: "u9", email: "gone@acme-corp.test" })),
        state: a.state,
      },
      a.cookie,
    );
    await w.store.updateMember(tenantId, r.memberId, { status: "deprovisioned" }, w.clock.now());
    const b = await start();
    expect(
      await code(
        w.cp.sso.callback(
          {
            code: w.idp.complete(b.state, profile({ id: "u9", email: "gone@acme-corp.test" })),
            state: b.state,
          },
          b.cookie,
        ),
      ),
    ).toBe("unauthenticated");
    expect((await eventsOf(w, tenantId)).some((e) => e.reason === "why=member_deprovisioned")).toBe(
      true,
    );
  });

  it("begin: unknown organization and malformed ids are refused; an org can belong to one tenant only", async () => {
    expect(await code(w.cp.sso.begin("org_nope"))).toBe("invalid");
    expect(await code(w.cp.sso.begin("bad org!"))).toBe("invalid");
    const t2 = await w.tenant();
    expect(
      await code(w.cp.admin.setSsoConnection(t2.owner, { idpOrgId: ORG, connectionType: "oidc" })),
    ).toBe("conflict");
    expect(
      await code(
        w.cp.admin.setSsoConnection(t2.owner, {
          idpOrgId: "org_x",
          connectionType: "oidc",
          jitEnabled: true,
          jitDefaultRole: "owner",
        }),
      ),
    ).toBe("invalid");
    expect(
      await code(
        w.cp.admin.setSsoConnection(t2.owner, { idpOrgId: "bad id", connectionType: "oidc" }),
      ),
    ).toBe("invalid");
  });

  it("admin portal link needs a linked organization", async () => {
    const t = await w.tenant();
    expect(
      await code(w.cp.admin.adminPortalLink(t.owner, "sso", "https://console.example.test/")),
    ).toBe("conflict");
    await w.cp.admin.setSsoConnection(t.owner, {
      idpOrgId: `org_${t.slug}`,
      connectionType: "saml",
    });
    const l = await w.cp.admin.adminPortalLink(t.owner, "dsync", "https://console.example.test/");
    expect(l.url).toContain(`org_${t.slug}`);
    expect(w.idp.lastPortal?.intent).toBe("dsync");
  });

  it("domain verification: needs the TXT proof, is exclusive across tenants, refuses public mail domains", async () => {
    const t = await w.tenant();
    expect(await code(w.cp.admin.beginDomain(t.owner, "gmail.com"))).toBe("invalid");
    expect(await code(w.cp.admin.beginDomain(t.owner, "not a domain"))).toBe("invalid");
    expect(await code(w.cp.admin.verifyDomain(t.owner, "unstarted.test"))).toBe("not_found");
    const d = await w.cp.admin.beginDomain(t.owner, "newco.test");
    expect(await code(w.cp.admin.verifyDomain(t.owner, "newco.test"))).toBe("invalid"); // no record yet
    w.dns.records.set(d.recordName, ["axis-verify=wrong"]);
    expect(await code(w.cp.admin.verifyDomain(t.owner, "newco.test"))).toBe("invalid");
    w.dns.records.set(d.recordName, [d.recordValue]);
    expect((await w.cp.admin.verifyDomain(t.owner, "newco.test")).status).toBe("verified");
    expect(await code(w.cp.admin.beginDomain(t.owner, "newco.test"))).toBe("conflict");
    // another tenant that publishes the same proof (it cannot know it) or tries to claim: conflict at verification
    const t2 = await w.tenant();
    const d2 = await w.cp.admin.beginDomain(t2.owner, "newco.test");
    w.dns.records.set(d2.recordName, [d2.recordValue]);
    expect(await code(w.cp.admin.verifyDomain(t2.owner, "newco.test"))).toBe("conflict");
    expect((await w.cp.admin.listDomains(t.owner)).map((x) => x.domain)).toContain("newco.test");
  });
});
