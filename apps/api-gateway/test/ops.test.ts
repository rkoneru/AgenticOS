import http from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createGateServer, MemoryKillSwitchStore, MemoryCounterStore } from "@axis/risk-kernel";
import { MemoryAuditLog } from "@axis/audit";
import * as grpc from "@grpc/grpc-js";
import {
  GrpcKernelKillApplier,
  HttpRunsPort,
  KillSwitchService,
  MemoryKillSwitchRecords,
  OpaCliPolicyTester,
  PortConflict,
  PortInvalid,
  PortNotFound,
  PortUnavailable,
  apiStatus,
} from "../src/index.js";
import { ABL, POLICY, call, hex32, makeWorld, seed, type Seed, type World } from "./world.js";

const open = { rate: { burst: 1e6, perSecond: 1e6 }, unauthRate: { burst: 1e6, perSecond: 1e6 } };
let w: World;
let a: Seed;
beforeAll(async () => {
  w = await makeWorld(open);
  a = await seed(w);
});
afterAll(() => w.close());
const T = () => a.owner.token;

describe("blueprints", () => {
  it("publish validates ABL and lint, is immutable, lists with a cursor", async () => {
    const bad = await call(w, "POST", "/blueprints", {
      token: T(),
      body: {
        abl: {
          ...ABL("bad1"),
          spec: { riskClassification: { level: "high", rationale: "x".repeat(20) } },
        },
      },
    });
    expect(bad.status).toBe(422);
    expect(bad.body.errors.length).toBeGreaterThan(0);
    const dup = await call(w, "POST", "/blueprints", { token: T(), body: { abl: ABL("claims") } });
    expect(dup.status).toBe(409);
    for (const v of ["1.1.0", "1.2.0", "1.10.0"])
      await call(w, "POST", "/blueprints", { token: T(), body: { abl: ABL("claims", v) } });
    const p1 = await call(w, "GET", "/blueprints?limit=2", { token: T() });
    expect(p1.body.items).toHaveLength(2);
    const p2 = await call(
      w,
      "GET",
      `/blueprints?limit=2&cursor=${encodeURIComponent(p1.body.next_cursor)}`,
      { token: T() },
    );
    expect(p2.body.items.map((x: { version: string }) => x.version)).toEqual(["1.2.0", "1.10.0"]);
    expect(
      (await call(w, "GET", "/blueprints/claims/versions/1.1.0", { token: T() })).body.content_hash,
    ).toMatch(/^[0-9a-f]{64}$/);
    expect((await call(w, "GET", "/blueprints/Claims/versions/1.1.0", { token: T() })).status).toBe(
      404,
    );
    expect(
      (await call(w, "GET", "/blueprints/claims/versions/not-semver", { token: T() })).status,
    ).toBe(404);
  });
});

describe("runs", () => {
  it("start passes the compiled manifest, the request trace id and the caller (never a tenant from the body)", async () => {
    const trace = hex32();
    const r = await call(w, "POST", "/runs", {
      token: T(),
      body: { blueprint: a.blueprint, input: { prompt: "p" } },
      headers: { traceparent: `00-${trace}-0123456789abcdef-01` },
    });
    expect(r.status).toBe(202);
    expect(r.headers.get("location")).toBe(`/v1/runs/${r.body.id}`);
    const s = w.runs.starts.at(-1)!;
    expect(s).toMatchObject({
      tenantId: a.owner.tenantId,
      traceId: trace,
      principal: { memberId: a.owner.memberId, role: "owner" },
    });
    expect((s.manifest as { manifest_version: number }).manifest_version).toBe(1);
    expect(
      (
        await call(w, "POST", "/runs", {
          token: T(),
          body: { blueprint: { name: "claims", version: "9.9.9" } },
        })
      ).status,
    ).toBe(404);
  });
  it("signals: state change, 409 on a terminated process, 404 for an unknown pid", async () => {
    const r = await call(w, "POST", "/runs", { token: T(), body: { blueprint: a.blueprint } });
    const id = r.body.id;
    const p = await call(w, "POST", `/runs/${id}/signals`, {
      token: T(),
      body: { signal: "PAUSE" },
    });
    expect(p.body.state).toBe("suspended");
    expect(
      (
        await call(w, "POST", `/runs/${id}/signals`, {
          token: T(),
          body: { signal: "KILL", pid: "axp_00000000000000000000000000" },
        })
      ).status,
    ).toBe(404);
    expect(
      (await call(w, "POST", `/runs/${id}/signals`, { token: T(), body: { signal: "KILL" } })).body
        .state,
    ).toBe("terminated");
    expect(
      (await call(w, "POST", `/runs/${id}/signals`, { token: T(), body: { signal: "RESUME" } }))
        .status,
    ).toBe(409);
    expect(
      (await call(w, "POST", `/runs/${id}/signals`, { token: T(), body: { signal: "HUP" } }))
        .status,
    ).toBe(422);
  });
  it("list filters and events pagination", async () => {
    expect((await call(w, "GET", "/runs?state=nonsense", { token: T() })).status).toBe(422);
    expect((await call(w, "GET", "/runs?blueprint=other", { token: T() })).body.items).toEqual([]);
    expect((await call(w, "GET", "/runs?limit=0", { token: T() })).status).toBe(422);
    expect((await call(w, "GET", "/runs?limit=201", { token: T() })).status).toBe(422);
    const ev = await call(w, "GET", `/runs/${a.runId}/events?limit=1`, { token: T() });
    expect(ev.body.items).toHaveLength(1);
    expect(ev.body.next_cursor).toBe("1");
    const ev2 = await call(
      w,
      "GET",
      `/runs/${a.runId}/events?after_sequence=${ev.body.next_cursor}&limit=50`,
      { token: T() },
    );
    expect(ev2.body.items[0].sequence).toBe(2);
    expect(ev2.body.next_cursor).toBeNull();
  });
  it("a down run service is 503", async () => {
    w.runs.failStart = true;
    expect(
      (await call(w, "POST", "/runs", { token: T(), body: { blueprint: a.blueprint } })).status,
    ).toBe(503);
    w.runs.failStart = false;
  });
});

describe("SSE", () => {
  const sse = (path: string, token: string, headers: Record<string, string> = {}) =>
    fetch(w.base + path, {
      headers: { accept: "text/event-stream", authorization: `Bearer ${token}`, ...headers },
    });
  it("streams events with ids, resumes from Last-Event-ID, ends when the run does", async () => {
    const run = await call(w, "POST", "/runs", { token: T(), body: { blueprint: a.blueprint } });
    const id = run.body.id as string;
    const res = await sse(`/runs/${id}/events`, T());
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/event-stream");
    setTimeout(() => {
      w.runs.append(id, { type: "model_call", data: { n: 1 } });
      w.runs.finish(id);
    }, 50);
    const text = await res.text();
    expect(text).toContain("id: 1\nevent: run_event");
    expect(text).toContain('"type":"model_call"');
    expect(text).toMatch(/event: end\ndata: \{"reason":"completed"\}/);
    const resumed = await (await sse(`/runs/${id}/events`, T(), { "last-event-id": "2" })).text();
    expect(resumed).not.toContain("id: 1\n");
    expect(resumed).not.toContain("id: 2\n");
    expect(resumed).toContain("id: 3\n");
  });
  it("requires a credential, a role with events.read, and a run of the caller's tenant", async () => {
    expect(
      (
        await fetch(w.base + `/runs/${a.runId}/events`, {
          headers: { accept: "text/event-stream" },
        })
      ).status,
    ).toBe(401);
    const billing = await w.member(a.owner.tenantId, "billing");
    expect((await sse(`/runs/${a.runId}/events`, billing.token)).status).toBe(403);
    const other = await w.tenant();
    expect((await sse(`/runs/${a.runId}/events`, other.token)).status).toBe(404);
  });
  it("a revoked credential ends the stream; the per-tenant stream cap is enforced", async () => {
    const q = await makeWorld({
      ...open,
      sseRecheckMs: 30,
      sseHeartbeatMs: 20,
      maxSseStreamsPerTenant: 2,
    });
    const s = await seed(q);
    const p = (await q.cp.sessions.authenticate(s.owner.token))!;
    const created = await q.cp.apiKeys.create(p, { name: "k", scopes: ["*"] });
    const get = (tok: string) =>
      fetch(q.base + `/runs/${s.runId}/events`, {
        headers: { accept: "text/event-stream", authorization: `Bearer ${tok}` },
      });
    const r1 = await get(created.secret);
    const r2 = await get(s.owner.token);
    expect((await get(s.owner.token)).status).toBe(429);
    await q.cp.apiKeys.revoke(p, created.key.id);
    const body = await r1.text(); // the stream closes by itself within a recheck interval
    expect(body).toContain("event: end");
    expect(body).toContain(": keep-alive");
    await r2.body?.cancel();
    await q.close();
  });
  it("a client that disconnects releases its stream slot", async () => {
    const q = await makeWorld({ ...open, maxSseStreamsPerTenant: 1 });
    const s = await seed(q);
    const ac = new AbortController();
    const r = await fetch(q.base + `/runs/${s.runId}/events`, {
      headers: { accept: "text/event-stream", authorization: `Bearer ${s.owner.token}` },
      signal: ac.signal,
    });
    await r.body?.getReader().read();
    ac.abort();
    await new Promise((x) => setTimeout(x, 100));
    const again = await fetch(q.base + `/runs/${s.runId}/events`, {
      headers: { accept: "text/event-stream", authorization: `Bearer ${s.owner.token}` },
    });
    expect(again.status).toBe(200);
    await again.body?.cancel();
    await q.close();
  });
});

describe("approvals", () => {
  it("lists, decides, is idempotent for the decider, refuses a second verdict, maps statuses", async () => {
    const list = await call(w, "GET", "/approvals?status=pending", { token: T() });
    expect(list.body.items.map((x: { id: string }) => x.id)).toContain(a.approvalId);
    const viewer = await w.member(a.owner.tenantId, "operator");
    expect(
      (
        await call(w, "POST", `/approvals/${a.approvalId}/decision`, {
          token: viewer.token,
          body: { decision: "approve" },
        })
      ).status,
    ).toBe(403); // role not eligible
    const no = await call(w, "POST", `/approvals/${a.approvalId}/decision`, {
      token: T(),
      body: { decision: "reject", comment: "no" },
    });
    expect(no.body).toMatchObject({
      status: "rejected",
      comment: "no",
      decided_by: a.owner.memberId,
    });
    expect(
      (
        await call(w, "POST", `/approvals/${a.approvalId}/decision`, {
          token: T(),
          body: { decision: "reject" },
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await call(w, "POST", `/approvals/${a.approvalId}/decision`, {
          token: T(),
          body: { decision: "approve" },
        })
      ).status,
    ).toBe(409);
    expect(
      (await call(w, "GET", "/approvals?status=rejected", { token: T() })).body.items,
    ).toHaveLength(1);
    expect(
      (await call(w, "GET", "/approvals?status=pending", { token: T() })).body.items.map(
        (x: { id: string }) => x.id,
      ),
    ).not.toContain(a.approvalId);
    expect(apiStatus({ status: "pending", level: 2 })).toBe("escalated");
    expect(apiStatus({ status: "expired", level: 1 })).toBe("expired");
  });
  it("paginates", async () => {
    const s = await seed(w);
    for (let i = 0; i < 2; i++)
      await w.approvals.create({
        tenant_id: s.owner.tenantId,
        run_id: s.runId,
        trace_id: s.traceId,
        agent: { name: "claims", version: "1.0.0" },
        tool: `t${i}`,
        args_hash: hex32() + hex32(),
        risk_level: "high",
        requester: { type: "agent", id: "claims", pid: "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV" },
        approval: { roles: ["owner"], sla_seconds: 60, escalate_to: [], on_timeout: "DENY" },
      });
    const p1 = await call(w, "GET", "/approvals?limit=2", { token: s.owner.token });
    expect(p1.body.items).toHaveLength(2);
    const p2 = await call(
      w,
      "GET",
      `/approvals?limit=2&cursor=${encodeURIComponent(p1.body.next_cursor)}`,
      { token: s.owner.token },
    );
    expect(p2.body.items).toHaveLength(1);
    expect(p2.body.next_cursor).toBeNull();
  });
});

describe("policies", () => {
  it("publish, duplicate, invalid, list, and test with the real OPA", async () => {
    const pub = await call(w, "POST", "/policies", {
      token: T(),
      body: { policy: POLICY("tenant-x", "1.0.0") },
    });
    expect(pub.status, pub.text).toBe(201);
    expect(pub.body.content_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(
      (
        await call(w, "POST", "/policies", {
          token: T(),
          body: { policy: POLICY("tenant-x", "1.0.0") },
        })
      ).status,
    ).toBe(409);
    const semantic = POLICY("tenant-y", "1.0.0") as { spec: { rules: { gates?: string[] }[] } };
    semantic.spec.rules[0]!.gates = ["no-such-gate"];
    const inv = await call(w, "POST", "/policies", { token: T(), body: { policy: semantic } });
    expect(inv.status).toBe(422);
    const schemaBad = await call(w, "POST", "/policies", {
      token: T(),
      body: { policy: { kind: "x" } },
    });
    expect(schemaBad.status).toBe(422);
    expect(schemaBad.body.errors.length).toBeGreaterThan(0);
    const list = await call(w, "GET", "/policies?limit=1", { token: T() });
    expect(list.body.items).toHaveLength(1);
    expect(list.body.next_cursor).toBeTruthy();
    const ctx = (amount: number, side = "read") => ({
      policy: POLICY(),
      request: {
        enforcement_point: "tool_call",
        context: { tool: { name: "lookup", side_effects: side }, args: { amount } },
      },
    });
    expect(
      (await call(w, "POST", "/policies:test", { token: T(), body: ctx(5) })).body,
    ).toMatchObject({ decision: "ALLOW", matched_rule_ids: ["tenant-acme/allow-reads"] });
    expect(
      (await call(w, "POST", "/policies:test", { token: T(), body: ctx(500) })).body,
    ).toMatchObject({ decision: "DENY", reason: "tenant-acme/deny-big" });
    expect(
      (await call(w, "POST", "/policies:test", { token: T(), body: ctx(5, "write") })).body,
    ).toMatchObject({ decision: "DENY", reason: "no matching rule (default deny)" });
    // the caller cannot override kernel-owned fields through the context
    const spoof = ctx(5, "write");
    (spoof.request as { context: Record<string, unknown> }).context["enforcement_point"] =
      "tool_call";
    expect(
      (
        await call(w, "POST", "/policies:test", {
          token: T(),
          body: { ...spoof, request: { ...spoof.request, enforcement_point: "mcp_call" } },
        })
      ).body.decision,
    ).toBe("DENY");
    expect(
      (
        await call(w, "POST", "/policies:test", {
          token: T(),
          body: { policy: { kind: "x" }, request: { enforcement_point: "tool_call", context: {} } },
        })
      ).status,
    ).toBe(422);
  });
  it("tester limits: too large is 422, a broken opa binary is 503 (never an allow), concurrency cap is 503", async () => {
    const big = POLICY() as { spec: { rules: unknown[] } };
    big.spec.rules = Array.from({ length: 150 }, (_, i) => ({
      id: `r${i}`,
      enforcementPoints: ["tool_call"],
      decision: "DENY",
    }));
    await expect(new OpaCliPolicyTester().evaluate(big, {})).rejects.toBeInstanceOf(PortInvalid);
    await expect(
      new OpaCliPolicyTester({ bin: "/nonexistent/opa" }).evaluate(POLICY(), {}),
    ).rejects.toBeInstanceOf(PortUnavailable);
    const busy = new OpaCliPolicyTester({
      bin: "sleep",
      maxConcurrent: 1,
      maxQueued: 0,
      timeoutMs: 300,
    });
    const first = busy.evaluate(POLICY(), {}).catch((e) => e);
    await new Promise((r) => setTimeout(r, 20));
    await expect(busy.evaluate(POLICY(), {})).rejects.toBeInstanceOf(PortUnavailable);
    expect(await first).toBeInstanceOf(PortUnavailable);
  });
});

describe("audit", () => {
  it("lists with filters and pagination, verifies, and bounds verification", async () => {
    const s = await seed(w);
    const all = await call(w, "GET", "/audit/events?limit=200", { token: s.owner.token });
    expect(all.body.items.length).toBeGreaterThanOrEqual(5);
    const denies = await call(w, "GET", "/audit/events?decision=DENY", { token: s.owner.token });
    expect(denies.body.items.every((e: { decision: string }) => e.decision === "DENY")).toBe(true);
    const tr = await call(w, "GET", `/audit/events?trace_id=${s.traceId}`, {
      token: s.owner.token,
    });
    expect(tr.body.items.every((e: { trace_id: string }) => e.trace_id === s.traceId)).toBe(true);
    const seen: number[] = [];
    let cur: string | null = null;
    do {
      const r = await call(
        w,
        "GET",
        `/audit/events?limit=2${cur ? `&cursor=${encodeURIComponent(cur)}` : ""}`,
        { token: s.owner.token },
      );
      seen.push(...r.body.items.map((e: { seq: number }) => e.seq));
      cur = r.body.next_cursor;
    } while (cur);
    expect(seen).toEqual(all.body.items.map((e: { seq: number }) => e.seq));
    expect(
      (await call(w, "GET", "/audit/events?from_seq=3&limit=1", { token: s.owner.token })).body
        .items[0].seq,
    ).toBe(3);
    expect(
      (await call(w, "GET", "/audit/events?trace_id=XYZ", { token: s.owner.token })).status,
    ).toBe(422);
    const v = await call(w, "POST", "/audit/verify", {
      token: s.owner.token,
      body: { from_seq: 2, to_seq: 4 },
    });
    expect(v.body).toEqual({ ok: true, verified: 3 });
    expect((await call(w, "POST", "/audit/verify", { token: s.owner.token })).body.ok).toBe(true);
    expect(
      (await call(w, "POST", "/audit/verify", { token: s.owner.token, body: { from_seq: 9999 } }))
        .status,
    ).toBe(422);
    const tiny = await makeWorld({ ...open, maxVerifyEvents: 2 });
    const t = await seed(tiny);
    expect(
      (await call(tiny, "POST", "/audit/verify", { token: t.owner.token, body: {} })).status,
    ).toBe(422);
    await tiny.close();
    const fresh = await w.tenant();
    expect(
      (await call(w, "POST", "/audit/verify", { token: fresh.token, body: {} })).body.verified,
    ).toBeGreaterThanOrEqual(0);
  });
  it("reports a broken chain with the sequence and reason", async () => {
    const t = await makeWorld(open, {
      auditLog: {
        list: async () => [],
        head: async () => 5,
        verify: async () => ({ ok: false, brokenAtSeq: 4, reason: "hash_mismatch" }),
      },
    });
    const o = await t.tenant();
    expect((await call(t, "POST", "/audit/verify", { token: o.token, body: {} })).body).toEqual({
      ok: false,
      verified: 3,
      broken_at_seq: 4,
      reason: "hash_mismatch",
    });
    await t.close();
  });
  it("an unavailable audit store is 503", async () => {
    const t = await makeWorld(open, {
      auditLog: {
        list: async () => Promise.reject(new PortUnavailable("x")),
        head: async () => 0,
        verify: async () => ({ ok: true, length: 0 }),
      },
    });
    const o = await t.tenant();
    expect((await call(t, "GET", "/audit/events", { token: o.token })).status).toBe(503);
    await t.close();
  });
});

describe("kill switches", () => {
  it("engage and release go to the kernel first, are listed, validated and audited", async () => {
    const r = await call(w, "PUT", "/kill-switches", {
      token: T(),
      body: { scope: "agent", target: "claims", engaged: true, reason: "drill" },
    });
    expect(r.body).toMatchObject({
      scope: "agent",
      target: "claims",
      engaged: true,
      reason: "drill",
    });
    expect(w.kernel.calls.at(-1)).toMatchObject({
      tenantId: a.owner.tenantId,
      scope: "agent",
      target: "claims",
      engaged: true,
    });
    expect((await call(w, "GET", "/kill-switches", { token: T() })).body.items).toHaveLength(1);
    await call(w, "PUT", "/kill-switches", {
      token: T(),
      body: { scope: "agent", target: "claims", engaged: false },
    });
    expect((await call(w, "GET", "/kill-switches", { token: T() })).body.items).toEqual([]);
    for (const body of [
      { scope: "tenant", target: "x", engaged: true },
      { scope: "agent", engaged: true },
      { scope: "agent", target: "Bad Name", engaged: true },
      { scope: "tool", engaged: true },
      { scope: "global", engaged: true },
      { scope: "tool", target: "a b", engaged: true },
    ])
      expect(
        (await call(w, "PUT", "/kill-switches", { token: T(), body })).status,
        JSON.stringify(body),
      ).toBe(422);
    expect(
      (
        await call(w, "PUT", "/kill-switches", {
          token: T(),
          body: { scope: "tool", target: "send-report", engaged: true },
        })
      ).status,
    ).toBe(200);
  });
  it("when the kernel is down nothing is recorded and the caller gets 503", async () => {
    w.kernel.down = true;
    const r = await call(w, "PUT", "/kill-switches", {
      token: T(),
      body: { scope: "tenant", engaged: true },
    });
    w.kernel.down = false;
    expect(r.status).toBe(503);
    expect(
      (await call(w, "GET", "/kill-switches", { token: T() })).body.items.map(
        (x: { scope: string }) => x.scope,
      ),
    ).not.toContain("tenant");
  });
  it("tenants never see each other's switches", async () => {
    const o = await w.tenant();
    expect((await call(w, "GET", "/kill-switches", { token: o.token })).body.items).toEqual([]);
  });
  it("a record store failure never undoes a safety action", async () => {
    const svc = new KillSwitchService(
      { apply: async () => ({ auditEventId: "x" }) },
      { upsert: async () => Promise.reject(new Error("db")), list: async () => [] },
    );
    const r = await svc.set(
      { tenantId: "t", memberId: "m", role: "owner", credential: "session" },
      { scope: "tenant", engaged: true },
    );
    expect(r.engaged).toBe(true);
  });

  it("the REAL Risk Kernel over gRPC: the switch is applied for the credential's tenant, with the kernel's own audit row", async () => {
    const audit = new MemoryAuditLog();
    const killSwitches = new MemoryKillSwitchStore();
    const tenant = "11111111-1111-4111-8111-111111111111";
    const server = createGateServer({
      kernel: {} as never,
      audit,
      killSwitches,
      authenticate: async (md) =>
        md.get("authorization")[0] === "Bearer rk-t1"
          ? { tenantId: tenant, subject: "svc", platformOperator: false }
          : undefined,
    });
    const port = await new Promise<number>((res, rej) =>
      server.bindAsync("127.0.0.1:0", grpc.ServerCredentials.createInsecure(), (e, p) =>
        e ? rej(e) : res(p),
      ),
    );
    const applier = new GrpcKernelKillApplier(`127.0.0.1:${port}`, (t) =>
      t === tenant ? "rk-t1" : undefined,
    );
    const r = await applier.apply({
      tenantId: tenant,
      scope: "agent",
      target: "claims",
      engaged: true,
      reason: "drill",
    });
    expect(r.auditEventId).toBeTruthy();
    expect(await killSwitches.isEngaged("agent", { tenantId: tenant, agent: "claims" })).toBe(true);
    await applier.apply({ tenantId: tenant, scope: "agent", target: "claims", engaged: false });
    expect(await killSwitches.isEngaged("agent", { tenantId: tenant, agent: "claims" })).toBe(
      false,
    );
    // no credential for another tenant: refused before any call
    await expect(
      applier.apply({
        tenantId: "22222222-2222-4222-8222-222222222222",
        scope: "tenant",
        engaged: true,
      }),
    ).rejects.toBeInstanceOf(PortUnavailable);
    expect(
      await killSwitches.isEngaged("tenant", {
        tenantId: "22222222-2222-4222-8222-222222222222",
        agent: "x",
      }),
    ).toBe(false);
    // the kernel refuses a tenant that does not match the token
    const wrong = new GrpcKernelKillApplier(`127.0.0.1:${port}`, () => "rk-t1");
    await expect(
      wrong.apply({
        tenantId: "22222222-2222-4222-8222-222222222222",
        scope: "tenant",
        engaged: true,
      }),
    ).rejects.toThrow();
    applier.close();
    wrong.close();
    server.forceShutdown();
    void MemoryCounterStore;
  });
});

describe("usage", () => {
  it("aggregates the ledger by meter, day and model; validates the range", async () => {
    const from = new Date(Date.now() - 86_400_000).toISOString();
    const to = new Date(Date.now() + 86_400_000).toISOString();
    const q = (g: string) =>
      `/usage?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&group_by=${g}`;
    expect((await call(w, "GET", q("meter"), { token: T() })).body.items).toEqual([
      { meter: "tokens", quantity: 120, unit: "tokens" },
    ]);
    expect((await call(w, "GET", q("model"), { token: T() })).body.items[0]).toMatchObject({
      group: "standard",
    });
    expect((await call(w, "GET", q("blueprint"), { token: T() })).body.items[0]).toMatchObject({
      group: "claims",
    });
    expect((await call(w, "GET", q("day"), { token: T() })).body.items[0].group).toMatch(
      /^\d{4}-\d{2}-\d{2}$/,
    );
    const other = await w.tenant();
    expect((await call(w, "GET", q("meter"), { token: other.token })).body.items).toEqual([]);
    expect(
      (
        await call(
          w,
          "GET",
          `/usage?from=${encodeURIComponent(to)}&to=${encodeURIComponent(from)}`,
          { token: T() },
        )
      ).status,
    ).toBe(422);
    expect(
      (
        await call(w, "GET", `/usage?from=2020-01-01T00:00:00Z&to=2026-01-01T00:00:00Z`, {
          token: T(),
        })
      ).status,
    ).toBe(422);
    expect((await call(w, "GET", "/usage?from=x&to=y", { token: T() })).status).toBe(422);
    expect((await call(w, "GET", "/usage", { token: T() })).status).toBe(422);
  });
});

describe("evals and explanations", () => {
  it("evals answer 501 problem+json until Phase 8", async () => {
    const r = await call(w, "POST", "/evals/runs", {
      token: T(),
      body: { suite: "s", blueprint: a.blueprint },
    });
    expect(r.status).toBe(501);
    expect(r.body.type).toContain("not_implemented");
    expect(r.body.code).toBeUndefined();
  });
  it("explains a run and a denial from the audit rows", async () => {
    const run = await call(w, "GET", `/runs/${a.runId}/explanation`, { token: T() });
    expect(run.body.summary).toContain("denied");
    expect(
      run.body.decision_refs.some((d: { rule_ids: string[] }) =>
        d.rule_ids.includes("tenant-acme/deny-restricted"),
      ),
    ).toBe(true);
    const ev = await call(w, "GET", `/audit/events/${a.denySeq}/explanation`, { token: T() });
    expect(ev.body.decision_refs[0]).toMatchObject({ decision: "DENY", gate: "policy_rule" });
    const viewer = await w.member(a.owner.tenantId, "viewer");
    expect(
      (await call(w, "GET", `/runs/${a.runId}/explanation`, { token: viewer.token })).status,
    ).toBe(200);
    expect(
      (await call(w, "GET", `/audit/events/${a.denySeq}/explanation`, { token: viewer.token }))
        .status,
    ).toBe(403); // audit.read needed
  });
});

describe("HttpRunsPort against a stub run service", () => {
  it("maps statuses, parses SSE, never sends the tenant", async () => {
    const seen: { url: string; auth: string | undefined; body: string }[] = [];
    const srv = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        seen.push({ url: req.url ?? "", auth: req.headers.authorization, body });
        const u = req.url ?? "";
        const j = (s: number, o: unknown) => (
          res.writeHead(s, { "content-type": "application/json" }),
          res.end(JSON.stringify(o))
        );
        if (u.includes("missing")) return j(404, {});
        if (u.endsWith("/stream?after_sequence=0")) {
          res.writeHead(200, { "content-type": "text/event-stream" });
          res.write(
            'id: 1\nevent: run_event\ndata: {"sequence":1,"type":"x","pid":"p","at":"t"}\n\n',
          );
          return void res.end("event: end\ndata: {}\n\n");
        }
        if (u.includes("missing")) return j(404, {});
        if (u.includes("conflict")) return j(409, { detail: "terminated" });
        if (u.includes("invalid")) return j(422, { detail: "bad" });
        if (u.includes("boom")) return j(500, {});
        if (u.includes("garbage")) return (res.writeHead(200), res.end("not json"));
        if (u.startsWith("/v1/runs?")) return j(200, { items: [{ id: "1" }], next_cursor: "n" });
        j(200, { id: "r", pid: "p", state: "running", items: [{ sequence: 1 }] });
      });
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
    const base = `http://127.0.0.1:${(srv.address() as { port: number }).port}`;
    const port = new HttpRunsPort(base, (t) => (t === "t1" ? "tok1" : undefined));
    expect(
      (await port.list("t1", { limit: 5, state: "running", blueprint: "b", after: "a" })).next,
    ).toBe("n");
    expect(seen[0]!.auth).toBe("Bearer tok1");
    expect(seen[0]!.url).toContain("limit=5");
    expect(await port.get("t1", "missing")).toBeUndefined();
    await expect(port.signal("t1", "conflict", { signal: "KILL" })).rejects.toBeInstanceOf(
      PortConflict,
    );
    await expect(port.signal("t1", "invalid", { signal: "KILL" })).rejects.toBeInstanceOf(
      PortInvalid,
    );
    await expect(port.signal("t1", "missing", { signal: "KILL" })).rejects.toBeInstanceOf(
      PortNotFound,
    );
    await expect(port.get("t1", "boom")).rejects.toBeInstanceOf(PortUnavailable);
    await expect(port.get("t1", "garbage")).rejects.toBeInstanceOf(PortUnavailable);
    await expect(port.get("other-tenant", "r")).rejects.toBeInstanceOf(PortUnavailable); // no credential: never guesses another tenant's
    expect(await port.events("t1", "missing", { afterSequence: 0, limit: 1 })).toBeUndefined();
    expect((await port.events("t1", "r", { afterSequence: 0, limit: 1 }))![0]!.sequence).toBe(1);
    const evs: unknown[] = [];
    for await (const e of port.stream("t1", "r", 0, new AbortController().signal)) evs.push(e);
    expect(evs).toHaveLength(1);
    await expect(
      (async () => {
        for await (const _ of port.stream("t1", "missing", 0, new AbortController().signal)) void _;
      })(),
    ).rejects.toBeInstanceOf(PortNotFound);
    expect(
      (
        await port.start({
          tenantId: "t1",
          runId: "r",
          traceId: hex32(),
          blueprint: { name: "b", version: "1.0.0" },
          manifest: {},
          input: {},
          principal: { memberId: "m", role: "owner" },
        })
      ).id,
    ).toBe("r");
    expect(JSON.parse(seen.at(-1)!.body)).not.toHaveProperty("tenant_id");
    srv.close();
    const dead = new HttpRunsPort("http://127.0.0.1:1", () => "t");
    await expect(dead.get("t1", "x")).rejects.toBeInstanceOf(PortUnavailable);
    void MemoryKillSwitchRecords;
  });
});

describe("audit list defence in depth", () => {
  it("never relays a row of another tenant even if the store returns one", async () => {
    const other = await makeWorld(open);
    const o = await other.tenant();
    const foreign = await seed(other);
    const rows = await other.audit.listEvents(foreign.owner.tenantId, { limit: 10 });
    const leaky = await makeWorld(open, {
      auditLog: {
        list: async () => rows,
        head: async () => 1,
        verify: async () => ({ ok: true, length: 1 }),
      },
    });
    const me = await leaky.tenant();
    const r = await call(leaky, "GET", "/audit/events", { token: me.token });
    expect(r.status).toBe(200);
    expect(r.body.items).toEqual([]);
    void o;
    await other.close();
    await leaky.close();
  });
});
