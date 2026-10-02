import type http from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createControlPlaneServer, listenLoopback, runtimeAuthFromTokens } from "../src/index.js";
import { makeWorld, type World } from "./world.js";

describe("HTTP surface (Postgres store)", () => {
  let w: World;
  let server: http.Server;
  let base: string;
  const PLATFORM = "platform-secret-token";
  const DEV = "dev-secret-token";

  beforeAll(async () => {
    w = await makeWorld("pg", { platformToken: PLATFORM, devToken: DEV });
    const tenantForRuntime = (await w.tenant()).tenantId;
    w.cp.deps.runtimeAuth = runtimeAuthFromTokens({ [tenantForRuntime]: "rt-token" });
    (w as unknown as { rtTenant: string }).rtTenant = tenantForRuntime;
    server = createControlPlaneServer(w.cp.deps);
    base = `http://127.0.0.1:${await listenLoopback(server)}`;
  });
  afterAll(async () => {
    await new Promise((r) => server.close(r));
    await w.close();
  });

  const req = async (
    method: string,
    path: string,
    opts: { token?: string; body?: unknown; headers?: Record<string, string>; raw?: string } = {},
  ) => {
    const r = await fetch(base + path, {
      method,
      redirect: "manual",
      headers: {
        ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
        ...(opts.body !== undefined ? { "content-type": "application/json" } : {}),
        ...opts.headers,
      },
      ...(opts.raw !== undefined
        ? { body: opts.raw }
        : opts.body !== undefined
          ? { body: JSON.stringify(opts.body) }
          : {}),
    });
    const text = await r.text();
    let json: any; // eslint-disable-line @typescript-eslint/no-explicit-any
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
    return {
      status: r.status,
      json,
      text,
      headers: r.headers,
      setCookies: r.headers.getSetCookie(),
    };
  };

  async function provisioned() {
    const s = `http-${Math.random().toString(36).slice(2, 10)}`;
    const r = await req("POST", "/platform/v1/tenants", {
      token: PLATFORM,
      body: { slug: s, name: "H", owner_email: `o@${s}.test`, region: "us-east-1" },
    });
    expect(r.status).toBe(201);
    const sess = await req("POST", "/dev/session", {
      token: DEV,
      body: { tenant_id: r.json.tenant_id, member_id: r.json.owner_member_id },
    });
    expect(sess.status).toBe(201);
    return {
      tenantId: r.json.tenant_id as string,
      ownerId: r.json.owner_member_id as string,
      token: sess.json.access_token as string,
      refresh: sess.json.refresh_token as string,
      slug: s,
    };
  }

  it("provisioning needs the platform credential; dev sessions need the dev credential", async () => {
    expect((await req("POST", "/platform/v1/tenants", { body: {} })).status).toBe(401);
    expect((await req("POST", "/platform/v1/tenants", { token: "wrong", body: {} })).status).toBe(
      401,
    );
    expect(
      (await req("POST", "/platform/v1/tenants", { token: PLATFORM, body: { slug: "x" } })).status,
    ).toBe(422);
    expect(
      (await req("POST", "/platform/v1/tenants", { token: PLATFORM, body: { tenant_id: "x" } }))
        .status,
    ).toBe(422);
    expect((await req("POST", "/dev/session", { token: "wrong", body: {} })).status).toBe(401);
    expect(
      (await req("POST", "/dev/session", { token: DEV, body: { tenant_id: "x", member_id: "y" } }))
        .status,
    ).toBe(404);
  });

  it("admin routes authenticate with a session token or an API key and answer problem+json", async () => {
    const t = await provisioned();
    const ok = await req("GET", "/admin/v1/tenant", { token: t.token });
    expect(ok.status).toBe(200);
    expect(ok.json).toMatchObject({
      id: t.tenantId,
      region: "us-east-1",
      isolationTier: "shared_rls",
    });
    expect(ok.headers.get("cache-control")).toBe("no-store");
    const none = await req("GET", "/admin/v1/tenant");
    expect(none.status).toBe(401);
    expect(none.headers.get("content-type")).toBe("application/problem+json");
    expect(none.json).toMatchObject({ status: 401, code: "unauthenticated" });
    expect((await req("GET", "/admin/v1/tenant", { token: "junk" })).status).toBe(401);
    const key = await req("POST", "/admin/v1/api-keys", {
      token: t.token,
      body: { name: "svc", scopes: ["budgets:read"] },
    });
    expect(key.status).toBe(201);
    expect(key.json.secret).toMatch(/^axk_/);
    const viaKey = await req("GET", "/admin/v1/budgets", { token: key.json.secret });
    expect(viaKey.status).toBe(200);
    expect(viaKey.json.items.length).toBe(4);
    expect((await req("GET", "/admin/v1/members", { token: key.json.secret })).status).toBe(403); // scope
    expect(
      (
        await req("POST", "/admin/v1/members", {
          token: key.json.secret,
          body: { email: "a@b.test", role: "viewer" },
        })
      ).status,
    ).toBe(403);
    expect(
      (await req("DELETE", `/admin/v1/api-keys/${key.json.id}`, { token: t.token })).status,
    ).toBe(200);
    expect((await req("GET", "/admin/v1/budgets", { token: key.json.secret })).status).toBe(401);
  });

  it("the tenant comes from the credential: tenant ids in bodies are refused, in paths are routes that do not exist", async () => {
    const a = await provisioned();
    const b = await provisioned();
    const inBody = await req("POST", "/admin/v1/members", {
      token: a.token,
      body: { email: "x@y.test", role: "viewer", tenant_id: b.tenantId },
    });
    expect(inBody.status).toBe(422);
    expect(inBody.json.detail).toMatch(/tenant_id is not accepted/);
    expect(
      (
        await req("POST", "/admin/v1/members", {
          token: a.token,
          body: { email: "x@y.test", role: "viewer", tenantId: b.tenantId },
        })
      ).status,
    ).toBe(422);
    expect(
      (await req("GET", `/admin/v1/tenants/${b.tenantId}/members`, { token: a.token })).status,
    ).toBe(404);
    expect((await req("GET", `/admin/v1/members/${b.ownerId}`, { token: a.token })).status).toBe(
      404,
    ); // IDOR: another tenant's id
    expect((await req("DELETE", `/admin/v1/members/${b.ownerId}`, { token: a.token })).status).toBe(
      404,
    );
    expect(
      (
        await req("PATCH", `/admin/v1/members/${b.ownerId}`, {
          token: a.token,
          body: { role: "viewer" },
        })
      ).status,
    ).toBe(404);
    const mine = await req("GET", "/admin/v1/members", { token: a.token });
    expect(mine.json.items.map((m: { id: string }) => m.id)).toEqual([a.ownerId]);
    expect((await w.store.getMember(b.tenantId, b.ownerId))?.role).toBe("owner");
  });

  it("covers the admin resource routes end to end", async () => {
    const t = await provisioned();
    const tok = t.token;
    const inv = await req("POST", "/admin/v1/members", {
      token: tok,
      body: { email: "new@x.test", role: "builder" },
    });
    expect(inv.status).toBe(201);
    expect(
      (
        await req("PATCH", `/admin/v1/members/${inv.json.id}`, {
          token: tok,
          body: { role: "operator" },
        })
      ).json.role,
    ).toBe("operator");
    expect(
      (
        await req("PATCH", `/admin/v1/members/${inv.json.id}`, {
          token: tok,
          body: { role: "god" },
        })
      ).status,
    ).toBe(422);
    expect(
      (await req("POST", `/admin/v1/members/${inv.json.id}/revoke-sessions`, { token: tok })).json,
    ).toEqual({ revoked: 0 });
    expect((await req("GET", `/admin/v1/members/${inv.json.id}`, { token: tok })).status).toBe(200);
    expect((await req("DELETE", `/admin/v1/members/${inv.json.id}`, { token: tok })).status).toBe(
      204,
    );
    const k = await req("POST", "/admin/v1/api-keys", {
      token: tok,
      body: { name: "k", scopes: ["*"], environment: "staging", expires_in_days: 5 },
    });
    const rot = await req("POST", `/admin/v1/api-keys/${k.json.id}/rotate`, { token: tok });
    expect(rot.json.rotatedFrom).toBe(k.json.id);
    expect(
      (await req("GET", "/admin/v1/api-keys?limit=1", { token: tok })).json.items,
    ).toHaveLength(1);
    expect(
      (
        await req("PUT", "/admin/v1/model-keys/anthropic/default", {
          token: tok,
          body: { value: "sk-xyz-SECRET" },
        })
      ).status,
    ).toBe(200);
    const mk = await req("GET", "/admin/v1/model-keys", { token: tok });
    expect(mk.text).not.toContain("SECRET");
    expect(mk.json.items).toHaveLength(1);
    expect(
      (await req("DELETE", "/admin/v1/model-keys/anthropic/default", { token: tok })).status,
    ).toBe(204);
    const pol = await req("GET", "/admin/v1/policies", { token: tok });
    expect(pol.json.items[0]).toMatchObject({ pack: "baseline-deny", active: true });
    const pub = await req("POST", "/admin/v1/policies", {
      token: tok,
      body: {
        policy: {
          apiVersion: "policy.axis.dev/v1",
          kind: "PolicyPack",
          metadata: { name: "http-pack", version: "1.0.0" },
          spec: {
            defaultDecision: "DENY",
            rules: [{ id: "deny-all", enforcementPoints: ["tool_call"], decision: "DENY" }],
          },
        },
      },
    });
    expect(pub.status).toBe(201);
    expect(
      (await req("POST", `/admin/v1/policies/${pub.json.versionId}/activate`, { token: tok })).json
        .policyVersion,
    ).toBe("baseline-deny@1.0.0,http-pack@1.0.0");
    expect((await req("DELETE", "/admin/v1/policies/http-pack", { token: tok })).status).toBe(204);
    expect((await req("DELETE", "/admin/v1/policies/baseline-deny", { token: tok })).status).toBe(
      409,
    );
    expect(
      (await req("POST", "/admin/v1/policies", { token: tok, body: { policy: { nope: 1 } } }))
        .status,
    ).toBe(422);
    const bud = await req("PUT", "/admin/v1/budgets", {
      token: tok,
      body: {
        scope: "agent",
        target: "my-agent",
        metric: "tokens",
        period: "day",
        soft: 1,
        hard: 2,
      },
    });
    expect(bud.status).toBe(200);
    expect((await req("DELETE", `/admin/v1/budgets/${bud.json.id}`, { token: tok })).status).toBe(
      204,
    );
    expect(
      (
        await req("PATCH", "/admin/v1/settings", {
          token: tok,
          body: {
            retention_transcript_days: 9,
            retention_memory_days: 10,
            retention_audit_days: 3000,
          },
        })
      ).json,
    ).toMatchObject({ retentionTranscriptDays: 9, retentionAuditDays: 3000 });
    expect((await req("GET", "/admin/v1/settings", { token: tok })).status).toBe(200);
    const dir = await req("POST", "/admin/v1/directories", {
      token: tok,
      body: { name: "okta", default_role: "viewer" },
    });
    expect(dir.status).toBe(201);
    expect((await req("GET", "/admin/v1/directories", { token: tok })).text).not.toContain(
      dir.json.token,
    );
    expect(
      (
        await req("PUT", `/admin/v1/directories/${dir.json.id}/role-mappings`, {
          token: tok,
          body: { group: "Eng", role: "builder" },
        })
      ).status,
    ).toBe(204);
    expect(
      (
        await req("PUT", `/admin/v1/directories/${dir.json.id}/role-mappings`, {
          token: tok,
          body: { group: "Eng", role: null },
        })
      ).status,
    ).toBe(204);
    expect(
      (await req("POST", `/admin/v1/directories/${dir.json.id}/rotate-token`, { token: tok })).json
        .token,
    ).toMatch(/^axs_/);
    expect(
      (await req("DELETE", `/admin/v1/directories/${dir.json.id}`, { token: tok })).status,
    ).toBe(204);
    expect(
      (
        await req("PUT", "/admin/v1/sso/connection", {
          token: tok,
          body: {
            idp_org_id: `org_${t.slug}`,
            connection_type: "oidc",
            jit_enabled: true,
            jit_default_role: "viewer",
          },
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await req("POST", "/admin/v1/sso/portal-link", {
          token: tok,
          body: { intent: "sso", return_url: "https://console.example.test/" },
        })
      ).json.url,
    ).toContain("portal");
    expect(
      (await req("POST", "/admin/v1/domains", { token: tok, body: { domain: "http-co.test" } }))
        .status,
    ).toBe(201);
    expect((await req("GET", "/admin/v1/domains", { token: tok })).json.items).toHaveLength(1);
    expect(
      (await req("POST", "/admin/v1/domains/http-co.test/verify", { token: tok })).status,
    ).toBe(422);
    expect(
      (await req("GET", "/admin/v1/audit/events?limit=5", { token: tok })).json.items.length,
    ).toBeGreaterThan(0);
    for (const p of ["/admin/v1/nope", "/admin/v1/members/a/b/c", "/admin/v1/tenant/x", "/nowhere"])
      expect((await req("GET", p, { token: tok })).status).toBe(404);
    expect((await req("DELETE", "/admin/v1/tenant", { token: tok })).status).toBe(404);
  });

  it("rejects malformed bodies, oversized bodies, and never leaks internals on 500", async () => {
    const t = await provisioned();
    expect(
      (
        await req("POST", "/admin/v1/members", {
          token: t.token,
          raw: "{not json",
          headers: { "content-type": "application/json" },
        })
      ).status,
    ).toBe(400);
    expect((await req("POST", "/admin/v1/members", { token: t.token, body: [1, 2] })).status).toBe(
      422,
    );
    const big = await req("POST", "/admin/v1/members", {
      token: t.token,
      raw: JSON.stringify({ email: "x".repeat(300_000) }),
      headers: { "content-type": "application/json" },
    });
    expect(big.status).toBe(413);
    const orig = w.cp.deps.admin.tenant.bind(w.cp.deps.admin);
    w.cp.deps.admin.tenant = () =>
      Promise.reject(new Error("db password is hunter2 at /srv/secret"));
    const boom = await req("GET", "/admin/v1/tenant", { token: t.token });
    w.cp.deps.admin.tenant = orig;
    expect(boom.status).toBe(500);
    expect(boom.text).not.toContain("hunter2");
    expect(boom.json).toMatchObject({ code: "internal", detail: "internal error" });
  });

  it("SSO over HTTP: cookie flags, callback, cookie-authenticated admin with CSRF, rotation, logout", async () => {
    const t = await provisioned();
    const org = `org_http_${t.slug}`;
    await req("PUT", "/admin/v1/sso/connection", {
      token: t.token,
      body: { idp_org_id: org, connection_type: "oidc", jit_enabled: true },
    });
    await w.cp.admin.setSsoConnection(await w.login(t.tenantId, t.ownerId), {
      idpOrgId: org,
      connectionType: "oidc",
      jitEnabled: false,
    });
    const start = await req(
      "GET",
      `/auth/sso/start?org=${org}&return_to=${encodeURIComponent("//evil.test")}`,
    );
    expect(start.status).toBe(302);
    const loginCookie = start.setCookies.find((c) => c.startsWith("__Host-axis_login="))!;
    for (const f of ["HttpOnly", "Secure", "SameSite=Lax", "Path=/", "Max-Age=600"])
      expect(loginCookie).toContain(f);
    expect(loginCookie).not.toContain("Domain");
    const state = new URL(start.headers.get("location")!).searchParams.get("state")!;
    await w.cp.admin.inviteMember(await w.login(t.tenantId, t.ownerId), {
      email: "sso-user@x.test",
      role: "admin",
    });
    const code = w.idp.complete(state, {
      id: "idp-1",
      email: "sso-user@x.test",
      emailVerified: true,
      organizationId: org,
      connectionType: "oidc",
    });
    const cookieHeader = loginCookie.split(";")[0]!;
    const cb = await req("GET", `/auth/sso/callback?code=${code}&state=${state}`, {
      headers: { cookie: cookieHeader },
    });
    expect(cb.status).toBe(302);
    expect(cb.headers.get("location")).toBe("/"); // the open-redirect attempt fell back to "/"
    const at = cb.setCookies.find((c) => c.startsWith("__Host-axis_at="))!;
    const rt = cb.setCookies.find((c) => c.startsWith("__Host-axis_rt="))!;
    const csrf = cb.setCookies.find((c) => c.startsWith("__Host-axis_csrf="))!;
    for (const c of [at, rt])
      for (const f of ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"]) expect(c).toContain(f);
    expect(csrf).not.toContain("HttpOnly");
    expect(
      cb.setCookies.find((c) => c.startsWith("__Host-axis_login=") && c.includes("Max-Age=0")),
    ).toBeDefined();
    const jar = [at, rt, csrf].map((c) => c.split(";")[0]).join("; ");
    const csrfVal = csrf.split(";")[0]!.split("=")[1]!;
    expect((await req("GET", "/admin/v1/tenant", { headers: { cookie: jar } })).status).toBe(200);
    expect(
      (
        await req("POST", "/admin/v1/members", {
          headers: { cookie: jar },
          body: { email: "c@x.test", role: "viewer" },
        })
      ).status,
    ).toBe(403); // CSRF header missing
    expect(
      (
        await req("POST", "/admin/v1/members", {
          headers: { cookie: jar, "x-axis-csrf": "wrong" },
          body: { email: "c@x.test", role: "viewer" },
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await req("POST", "/admin/v1/members", {
          headers: { cookie: jar, "x-axis-csrf": csrfVal },
          body: { email: "c@x.test", role: "viewer" },
        })
      ).status,
    ).toBe(201);
    // login CSRF / forged callback
    expect(
      (
        await req("GET", `/auth/sso/callback?code=x&state=${state}`, {
          headers: { cookie: cookieHeader },
        })
      ).status,
    ).toBe(401);
    expect((await req("GET", `/auth/sso/callback?code=x&state=${state}`)).status).toBe(401);
    // refresh: needs CSRF when cookie based; rotates; old refresh token is dead
    expect((await req("POST", "/auth/refresh", { headers: { cookie: jar } })).status).toBe(403);
    const ref = await req("POST", "/auth/refresh", {
      headers: { cookie: jar, "x-axis-csrf": csrfVal },
    });
    expect(ref.status).toBe(200);
    expect(ref.json.refresh_token).toMatch(/^axr\./);
    expect(ref.setCookies.length).toBe(3);
    const oldRefresh = rt.split(";")[0]!.split("=")[1]!;
    expect(
      (await req("POST", "/auth/refresh", { body: { refresh_token: oldRefresh } })).status,
    ).toBe(401); // reuse revokes everything
    expect((await req("GET", "/admin/v1/tenant", { token: ref.json.access_token })).status).toBe(
      401,
    );
    // logout
    const t2 = await provisioned();
    expect((await req("POST", "/auth/logout", { token: t2.token })).status).toBe(204);
    expect((await req("GET", "/admin/v1/tenant", { token: t2.token })).status).toBe(401);
    expect(
      (await req("POST", "/auth/refresh", { body: { refresh_token: t2.refresh } })).status,
    ).toBe(401);
    expect((await req("POST", "/auth/refresh", { body: {} })).status).toBe(403);
    expect((await req("GET", "/auth/sso/start?org=nope")).status).toBe(422);
  });

  it("SCIM over HTTP: bearer auth, content type, deprovision revokes a live session", async () => {
    const t = await provisioned();
    const dir = await req("POST", "/admin/v1/directories", {
      token: t.token,
      body: { name: "okta" },
    });
    const scim = (method: string, path: string, body?: unknown) =>
      req(method, `/scim/v2${path}`, { token: dir.json.token, ...(body ? { body } : {}) });
    expect((await req("GET", "/scim/v2/Users")).status).toBe(401);
    expect((await req("GET", "/scim/v2/Users", { token: t.token })).status).toBe(401); // a session token is not a directory token
    const created = await scim("POST", "/Users", {
      userName: "hp@x.test",
      emails: [{ value: "hp@x.test", primary: true }],
      externalId: "e1",
    });
    expect(created.status).toBe(201);
    expect(created.headers.get("content-type")).toBe("application/scim+json");
    expect(
      (await scim("POST", "/Users", { userName: "hp@x.test", emails: [{ value: "hp@x.test" }] }))
        .json,
    ).toMatchObject({ status: "409", scimType: "uniqueness" });
    const sess = await w.cp.sessions.issue(
      (await w.store.getMember(t.tenantId, created.json.id))!,
      "sso",
    );
    expect((await req("GET", "/admin/v1/tenant", { token: sess.accessToken })).status).toBe(200);
    expect(
      (
        await scim("PATCH", `/Users/${created.json.id}`, {
          Operations: [{ op: "replace", path: "active", value: false }],
        })
      ).status,
    ).toBe(200);
    expect((await req("GET", "/admin/v1/tenant", { token: sess.accessToken })).status).toBe(401);
    const bad = await req("POST", "/scim/v2/Users", {
      token: dir.json.token,
      raw: "{oops",
      headers: { "content-type": "application/json" },
    });
    expect(bad.status).toBe(400);
    expect(bad.json.scimType).toBe("invalidSyntax");
    // IdP directory events: signature required
    const ev = JSON.stringify({
      type: "user.created",
      directoryId: "d",
      user: { externalId: "e2", userName: "ev@x.test", email: "ev@x.test", active: true },
    });
    expect(
      (
        await req("POST", "/hooks/idp", {
          token: dir.json.token,
          raw: ev,
          headers: { "x-idp-signature": "bad" },
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await req("POST", "/hooks/idp", {
          raw: ev,
          headers: { "x-idp-signature": w.idp.signWebhook(ev) },
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await req("POST", "/hooks/idp", {
          token: dir.json.token,
          raw: ev,
          headers: { "x-idp-signature": w.idp.signWebhook(ev) },
        })
      ).status,
    ).toBe(204);
    expect((await scim("GET", "/Users")).json.totalResults).toBe(2);
  });

  it("budget config bridge: the tenant's own budgets for the runtime, tenant from the bearer only", async () => {
    const rtTenant = (w as unknown as { rtTenant: string }).rtTenant;
    const owner = await w.login(rtTenant, (await w.store.listMembers(rtTenant, 5)).items[0]!.id);
    await w.cp.admin.putBudget(owner, {
      scope: "tenant",
      metric: "tokens",
      period: "day",
      hard: 1234,
    });
    const ok = await req("GET", "/internal/v1/budget-config", { token: "rt-token" });
    expect(ok.status).toBe(200);
    expect(ok.json.tenant).toEqual(
      expect.arrayContaining([expect.objectContaining({ metric: "tokens", hard: 1234 })]),
    );
    expect(ok.json.run.length).toBeGreaterThan(0);
    expect((await req("GET", "/internal/v1/budget-config")).status).toBe(401);
    expect((await req("GET", "/internal/v1/budget-config", { token: "nope" })).status).toBe(401);
    // a runtime token for tenant X never returns Y's budgets: Y's token reads Y's
    const other = await provisioned();
    w.cp.deps.runtimeAuth = runtimeAuthFromTokens({
      [rtTenant]: "rt-token",
      [other.tenantId]: "rt-other",
    });
    const o = await req("GET", "/internal/v1/budget-config", { token: "rt-other" });
    expect(JSON.stringify(o.json)).not.toContain("1234");
  });

  it("runtime bridge: per-tenant bearer, tenant from the credential only", async () => {
    const rtTenant = (w as unknown as { rtTenant: string }).rtTenant;
    const other = await provisioned();
    const owner = await w.login(rtTenant, (await w.store.listMembers(rtTenant, 5)).items[0]!.id);
    await w.cp.admin.putModelKey(owner, "anthropic", "default", "sk-live-RUNTIME");
    await w.cp.admin.putModelKey(
      await w.login(other.tenantId, other.ownerId),
      "anthropic",
      "default",
      "sk-live-OTHER",
    );
    const ok = await req("POST", "/internal/v1/model-keys/reveal", {
      token: "rt-token",
      body: { provider: "anthropic" },
    });
    expect(ok.json).toEqual({ value: "sk-live-RUNTIME" });
    expect(
      (
        await req("POST", "/internal/v1/model-keys/reveal", {
          token: "rt-token",
          body: { provider: "anthropic", tenant_id: other.tenantId },
        })
      ).status,
    ).toBe(422);
    expect(
      (
        await req("POST", "/internal/v1/model-keys/reveal", {
          token: "rt-token",
          body: { provider: "openai" },
        })
      ).status,
    ).toBe(404);
    expect(
      (
        await req("POST", "/internal/v1/model-keys/reveal", {
          token: "nope",
          body: { provider: "anthropic" },
        })
      ).status,
    ).toBe(401);
    expect(
      (await req("POST", "/internal/v1/model-keys/reveal", { body: { provider: "anthropic" } }))
        .status,
    ).toBe(401);
  });
});
