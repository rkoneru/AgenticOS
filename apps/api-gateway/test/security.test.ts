import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ABL, call, hex32, makeWorld, seed, type Cred, type Seed, type World } from "./world.js";

let w: World;
let a: Seed;
let b: Seed;
const open = { rate: { burst: 1e6, perSecond: 1e6 }, unauthRate: { burst: 1e6, perSecond: 1e6 } };

beforeAll(async () => {
  w = await makeWorld(open);
  a = await seed(w);
  b = await seed(w);
});
afterAll(() => w.close());

describe("authentication", () => {
  it("accepts a session bearer, an API key bearer and X-Axis-Api-Key, and nothing else", async () => {
    const key = await w.apiKey(a.owner, ["*"]);
    expect((await call(w, "GET", "/runs", { token: a.owner.token })).status).toBe(200);
    expect((await call(w, "GET", "/runs", { token: key })).status).toBe(200);
    expect((await call(w, "GET", "/runs", { key })).status).toBe(200);
    expect(
      (await call(w, "GET", "/runs", { headers: { cookie: `__Host-axis_at=${a.owner.token}` } }))
        .status,
    ).toBe(401);
    expect((await call(w, "GET", `/runs?access_token=${a.owner.token}`)).status).toBe(401);
  });

  it("two credentials at once are refused, not 'first wins'", async () => {
    const key = await w.apiKey(a.owner, ["*"]);
    const r = await call(w, "GET", "/runs", { token: a.owner.token, key });
    expect(r.status).toBe(400);
  });

  it.each([
    ["no scheme", "abc"],
    ["wrong scheme", "Basic dXNlcjpwYXNz"],
    ["empty bearer", "Bearer "],
    ["bearer with a space", "Bearer a b"],
    ["garbage token", "Bearer not.a.token"],
    ["forged axk key", "Bearer axk_0123456789abcdef_" + "A".repeat(43)],
    ["very long token", "Bearer " + "x".repeat(5000)],
  ])("rejects %s with 401 and no detail about why", async (_n, header) => {
    const r = await call(w, "GET", "/runs", { headers: { authorization: header } });
    expect(r.status).toBe(401);
    expect(r.headers.get("www-authenticate")).toContain("Bearer");
    expect(r.text).not.toMatch(/stack|at .*\(.*:\d+/);
  });

  it("a revoked API key and a revoked session stop working at once", async () => {
    const p = (await w.cp.sessions.authenticate(a.owner.token))!;
    const created = await w.cp.apiKeys.create(p, { name: "short", scopes: ["*"] });
    expect((await call(w, "GET", "/runs", { token: created.secret })).status).toBe(200);
    await w.cp.apiKeys.revoke(p, created.key.id);
    expect((await call(w, "GET", "/runs", { token: created.secret })).status).toBe(401);
    const m = await w.member(a.owner.tenantId, "viewer");
    expect((await call(w, "GET", "/runs", { token: m.token })).status).toBe(200);
  });

  it("a dependency outage while authenticating is a 503, never a 401 or an allow", async () => {
    const down = await makeWorld(
      { ...open },
      { auth: { authenticate: async () => Promise.reject(new Error("db down")) } },
    );
    const r = await call(down, "GET", "/runs", { token: "x" });
    expect(r.status).toBe(503);
    expect(r.text).not.toContain("db down");
    await down.close();
  });

  it("key scopes bound an API key: a read-only key cannot start a run even for an owner", async () => {
    const ro = await w.apiKey(a.owner, ["runs:read"]);
    expect((await call(w, "GET", "/runs", { token: ro })).status).toBe(200);
    const r = await call(w, "POST", "/runs", { token: ro, body: { blueprint: a.blueprint } });
    expect(r.status).toBe(403);
    expect((await call(w, "GET", "/approvals", { token: ro })).status).toBe(403);
  });
});

describe("the tenant comes from the credential and nowhere else", () => {
  it.each(["x-tenant-id", "X-Axis-Tenant", "x-axis-tenant-id", "X-Tenant"])(
    "header %s is refused",
    async (h) => {
      const r = await call(w, "GET", "/runs", {
        token: a.owner.token,
        headers: { [h]: b.owner.tenantId },
      });
      expect(r.status).toBe(400);
      expect(r.body.type).toContain("tenant_override");
    },
  );

  it.each(["tenant_id", "tenantId", "tenant-id", "TENANT_ID"])(
    "body key %s is refused on every body-taking operation",
    async (k) => {
      for (const [path, body] of [
        ["/runs", { blueprint: a.blueprint }],
        ["/blueprints", { abl: ABL("x1", "1.0.0") }],
        ["/audit/verify", {}],
        [
          "/policies:test",
          { policy: {}, request: { enforcement_point: "tool_call", context: {} } },
        ],
      ] as const) {
        const r = await call(w, "POST", path, {
          token: a.owner.token,
          body: { ...body, [k]: b.owner.tenantId },
        });
        expect(r.status, `${path} ${r.text}`).toBe(422);
      }
      const ks = await call(w, "PUT", "/kill-switches", {
        token: a.owner.token,
        body: { scope: "tenant", engaged: true, [k]: b.owner.tenantId },
      });
      expect(ks.status).toBe(422);
      expect(w.kernel.calls.every((c) => c.tenantId === a.owner.tenantId)).toBe(true);
    },
  );

  it.each(["tenant_id", "tenant", "tenantId"])("query parameter %s is refused", async (k) => {
    const r = await call(w, "GET", `/runs?${k}=${b.owner.tenantId}`, { token: a.owner.token });
    expect(r.status).toBe(422);
  });

  it("a run started with a spoofed tenant everywhere is still the credential's tenant's run", async () => {
    const r = await call(w, "POST", "/runs", {
      token: a.owner.token,
      body: { blueprint: a.blueprint, input: { tenant_id: b.owner.tenantId } },
      headers: { "x-forwarded-for": "10.0.0.1" },
    });
    expect(r.status).toBe(202);
    expect(w.runs.starts.at(-1)?.tenantId).toBe(a.owner.tenantId);
  });

  it("the tenant is the credential's even when the same member id exists elsewhere (no path from a token to another tenant)", async () => {
    const mine = await call(w, "GET", "/runs", { token: a.owner.token });
    const theirs = await call(w, "GET", "/runs", { token: b.owner.token });
    expect(mine.body.items.map((r: { id: string }) => r.id)).toContain(a.runId);
    expect(mine.body.items.map((r: { id: string }) => r.id)).not.toContain(b.runId);
    expect(theirs.body.items.map((r: { id: string }) => r.id)).not.toContain(a.runId);
  });
});

describe("IDOR: another tenant's id is indistinguishable from a missing one, on every path parameter", () => {
  const strip = (b: { trace_id?: string }): unknown => ({ ...b, trace_id: undefined });
  const cases: [string, (t: Seed) => { m: string; p: string; body?: unknown }][] = [
    ["GET run", (t) => ({ m: "GET", p: `/runs/${t.runId}` })],
    [
      "POST signal",
      (t) => ({ m: "POST", p: `/runs/${t.runId}/signals`, body: { signal: "KILL" } }),
    ],
    ["GET events", (t) => ({ m: "GET", p: `/runs/${t.runId}/events` })],
    ["GET events (SSE)", (t) => ({ m: "GET", p: `/runs/${t.runId}/events` })],
    ["GET explanation", (t) => ({ m: "GET", p: `/runs/${t.runId}/explanation` })],
    [
      "POST approval decision",
      (t) => ({
        m: "POST",
        p: `/approvals/${t.approvalId}/decision`,
        body: { decision: "approve" },
      }),
    ],
    [
      "GET blueprint version",
      (t) => ({ m: "GET", p: `/blueprints/${t.blueprint.name}/versions/9.9.9` }),
    ],
  ];
  it.each(cases)("%s", async (name, mk) => {
    const foreign = mk(b);
    const missing = {
      ...foreign,
      p: foreign.p
        .replace(b.runId, "11111111-1111-4111-8111-111111111111")
        .replace(b.approvalId, "11111111-1111-4111-8111-111111111111"),
    };
    const headers: Record<string, string> = name.includes("SSE")
      ? { accept: "text/event-stream" }
      : {};
    const r1 = await call(w, foreign.m, foreign.p, {
      token: a.owner.token,
      headers,
      ...(foreign.body ? { body: foreign.body } : {}),
    });
    const r2 = await call(w, missing.m, missing.p, {
      token: a.owner.token,
      headers,
      ...(missing.body ? { body: missing.body } : {}),
    });
    expect(r1.status).toBe(404);
    expect(strip(r1.body)).toEqual(strip(r2.body));
    // and the foreign resource was untouched
    expect((await w.runs.get(b.owner.tenantId, b.runId))?.state).toBe("running");
    expect((await w.approvals.peek(b.owner.tenantId, b.approvalId)).status).toBe("pending");
  });

  it("audit explanation by seq only ever reads the caller's own chain", async () => {
    // both tenants have a denial at the same seq; each tenant sees its own rule text only
    const ra = await call(w, "GET", `/audit/events/${a.denySeq}/explanation`, {
      token: a.owner.token,
    });
    expect(ra.status).toBe(200);
    expect(ra.body.decision_refs[0].audit_event_id).toBeTruthy();
    const head = await w.audit.head(b.owner.tenantId);
    const beyond = await call(w, "GET", `/audit/events/${(head?.seq ?? 0) + 100}/explanation`, {
      token: b.owner.token,
    });
    expect(beyond.status).toBe(404);
  });

  it("audit list and trace filter never return another tenant's rows", async () => {
    const list = await call(w, "GET", `/audit/events?trace_id=${b.traceId}&limit=100`, {
      token: a.owner.token,
    });
    expect(list.status).toBe(200);
    expect(list.body.items).toEqual([]);
    const all = await call(w, "GET", "/audit/events?limit=200", { token: a.owner.token });
    expect(
      all.body.items.every((e: { tenant_id: string }) => e.tenant_id === a.owner.tenantId),
    ).toBe(true);
  });

  it("a cursor is bound to its tenant and resource", async () => {
    for (let i = 0; i < 3; i++)
      await call(w, "POST", "/runs", { token: a.owner.token, body: { blueprint: a.blueprint } });
    const page = await call(w, "GET", "/runs?limit=1", { token: a.owner.token });
    expect(page.body.next_cursor).toBeTruthy();
    const cur = encodeURIComponent(page.body.next_cursor);
    expect(
      (await call(w, "GET", `/runs?limit=1&cursor=${cur}`, { token: a.owner.token })).status,
    ).toBe(200);
    expect(
      (await call(w, "GET", `/runs?limit=1&cursor=${cur}`, { token: b.owner.token })).status,
    ).toBe(422); // another tenant
    expect(
      (await call(w, "GET", `/approvals?cursor=${cur}`, { token: a.owner.token })).status,
    ).toBe(422); // another resource
    expect((await call(w, "GET", `/runs?cursor=${cur}x`, { token: a.owner.token })).status).toBe(
      422,
    ); // tampered
    expect((await call(w, "GET", "/runs?cursor=AAAA.BBBB", { token: a.owner.token })).status).toBe(
      422,
    ); // forged
    expect((await call(w, "GET", "/runs?cursor=a.b.c", { token: a.owner.token })).status).toBe(422);
  });

  it("a run service that answers with another tenant's run is not relayed", async () => {
    const evil = await makeWorld(open, {
      runs: {
        ...(new (await import("./fakes.js")).FakeRuns() as object),
        get: async () =>
          ({
            id: "11111111-1111-4111-8111-111111111111",
            tenant_id: "somebody-else",
            blueprint: { name: "x", version: "1" },
            state: "running",
            created_at: new Date().toISOString(),
          }) as never,
      } as never,
    });
    const o = await evil.tenant();
    const r = await call(evil, "GET", "/runs/11111111-1111-4111-8111-111111111111", {
      token: o.token,
    });
    expect(r.status).toBe(404);
    expect(evil.logs.some((l) => l.msg.includes("another tenant"))).toBe(true);
    await evil.close();
  });
});

describe("RBAC by role over the API", () => {
  const MATRIX: Record<string, string[]> = {
    viewer: ["GET /blueprints", "GET /runs", "GET /policies"],
    billing: ["GET /usage"],
    auditor: [
      "GET /blueprints",
      "GET /policies",
      "GET /usage",
      "GET /audit/events",
      "POST /audit/verify",
      "GET /approvals",
      "GET /kill-switches",
      "GET /runs",
    ],
    operator: [
      "GET /blueprints",
      "GET /runs",
      "GET /policies",
      "GET /approvals",
      "GET /kill-switches",
      "PUT /kill-switches",
      "POST /runs",
      "GET /usage",
    ],
    builder: [
      "GET /blueprints",
      "GET /policies",
      "POST /blueprints",
      "POST /policies",
      "POST /runs",
      "GET /runs",
      "GET /usage",
    ],
  };
  const reqFor = (route: string, sd: Seed): [string, string, unknown] => {
    const [m, p] = route.split(" ") as [string, string];
    const bodies: Record<string, unknown> = {
      "POST /blueprints": { abl: ABL(`rbac-${hex32().slice(0, 6)}`, "1.0.0") },
      "POST /policies": {
        policy: {
          apiVersion: "policy.axis.dev/v1",
          kind: "PolicyPack",
          metadata: { name: `p-${hex32().slice(0, 8)}`, version: "1.0.0" },
          spec: {
            defaultDecision: "DENY",
            rules: [{ id: "r1", enforcementPoints: ["tool_call"], decision: "DENY" }],
          },
        },
      },
      "POST /runs": { blueprint: sd.blueprint },
      "PUT /kill-switches": { scope: "tool", target: "send-report", engaged: false },
      "POST /audit/verify": {},
    };
    const path =
      p === "/usage"
        ? `/usage?from=${new Date(Date.now() - 1e8).toISOString()}&to=${new Date(Date.now() + 1e8).toISOString()}`
        : p;
    return [m, path, bodies[route]];
  };
  const ALL = [
    "GET /blueprints",
    "POST /blueprints",
    "GET /runs",
    "POST /runs",
    "GET /approvals",
    "GET /policies",
    "POST /policies",
    "GET /audit/events",
    "POST /audit/verify",
    "GET /kill-switches",
    "PUT /kill-switches",
    "GET /usage",
  ];
  for (const [role, allowed] of Object.entries(MATRIX))
    it(`${role}: exactly the ${allowed.length} allowed of ${ALL.length} routes`, async () => {
      const m: Cred = await w.member(a.owner.tenantId, role as never);
      for (const route of ALL) {
        const [method, path, body] = reqFor(route, a);
        const r = await call(w, method, path, {
          token: m.token,
          ...(body !== undefined ? { body } : {}),
        });
        const want = allowed.includes(route);
        expect(r.status === 403, `${role} ${route} -> ${r.status} ${r.text}`).toBe(!want);
        if (!want) expect(r.body.code).toBe("forbidden");
      }
    });

  it("a denied mutation is audited as DENY in the tenant's chain with the request's trace id", async () => {
    const v = await w.member(a.owner.tenantId, "viewer");
    const trace = hex32();
    const r = await call(w, "POST", "/runs", {
      token: v.token,
      body: { blueprint: a.blueprint },
      headers: { traceparent: `00-${trace}-0123456789abcdef-01` },
    });
    expect(r.status).toBe(403);
    expect(r.body.trace_id).toBe(trace);
    const events = await w.audit.listEvents(a.owner.tenantId, { traceId: trace, limit: 10 });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      action: "api.startRun",
      decision: "DENY",
      enforcement_point: "admin",
      actor: { type: "human", id: v.memberId },
    });
  });

  it("a mutation is audited as ALLOW BEFORE it runs; if the audit log is down the mutation does not run", async () => {
    const trace = hex32();
    const r = await call(w, "POST", "/runs", {
      token: a.owner.token,
      body: { blueprint: a.blueprint },
      headers: { traceparent: `00-${trace}-0123456789abcdef-01` },
    });
    expect(r.status).toBe(202);
    expect(r.body.trace_id).toBe(trace); // the run's trace is the request's trace: kernel decisions will share it
    expect(
      (await w.audit.listEvents(a.owner.tenantId, { traceId: trace, limit: 10 }))[0],
    ).toMatchObject({ action: "api.startRun", decision: "ALLOW" });
    const before = w.runs.starts.length;
    const deadAudit = await makeWorld(open, {
      audit: { record: async () => Promise.reject(new Error("chain down")) },
    });
    const o = await deadAudit.tenant();
    await call(deadAudit, "POST", "/blueprints", {
      token: o.token,
      body: { abl: ABL("claims") },
    }).then((x) => expect(x.status).toBe(503));
    const x = await call(deadAudit, "POST", "/runs", {
      token: o.token,
      body: { blueprint: { name: "claims", version: "1.0.0" } },
    });
    expect(x.status).toBe(503);
    expect(deadAudit.runs.starts).toHaveLength(0);
    expect(w.runs.starts.length).toBe(before);
    await deadAudit.close();
  });

  it("an authorizer failure (error, no policy) is DENY with code policy_denied", async () => {
    const broken = await makeWorld(open, {
      authz: { decide: async () => Promise.reject(new Error("opa crashed")) },
    });
    const o = await broken.tenant();
    const r = await call(broken, "GET", "/runs", { token: o.token });
    expect(r.status).toBe(403);
    expect(r.body.code).toBe("policy_denied");
    const none = await makeWorld(open, {
      authz: {
        decide: async () => ({ allowed: false, reason: "no policy loaded", policyVersion: "none" }),
      },
    });
    const o2 = await none.tenant();
    expect((await call(none, "GET", "/runs", { token: o2.token })).body.code).toBe("policy_denied");
    await broken.close();
    await none.close();
  });
});
