import type http from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import {
  ApprovalResolver,
  createDevBridge,
  isApprovalValidFor,
  isDecisionRecord,
  kernelApprovalPorts,
  listenLoopback,
  staticTenantAuthenticator,
  type DecisionRecord,
} from "../src/index.js";
import { HASH, T1, T2, input, setup } from "./helpers.js";

const TOK1 = "tok-1";
const TOK2 = "tok-2";
const FIN = { id: "alice", roles: ["finance"] };

let servers: http.Server[] = [];
afterEach(async () => {
  await Promise.all(servers.map((s) => new Promise((r) => s.close(r))));
  servers = [];
});

async function bridge(over: { maxWaitMs?: number } = {}) {
  const ctx = setup();
  const server = createDevBridge({
    service: ctx.svc,
    resolver: new ApprovalResolver(ctx.svc),
    authenticate: staticTenantAuthenticator({ [TOK1]: T1, [TOK2]: T2 }),
    ...over,
  });
  servers.push(server);
  const port = await listenLoopback(server);
  const call = async (route: string, body: unknown, token: string | null = TOK1, raw?: string) => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/approvals/${route}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: raw ?? JSON.stringify(body),
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- test helper: loosely-typed JSON
    return { status: res.status, json: (await res.json()) as Record<string, any> };
  };
  return { ...ctx, call, port, server };
}

describe("kernel ports", () => {
  it("requester opens a request and the verifier accepts only an APPROVED record for exactly the expected action", async () => {
    const { svc, signer } = setup();
    const ports = kernelApprovalPorts(svc, signer);
    const { id } = await ports.requester.create({
      tenant_id: T1,
      run_id: "run-1",
      trace_id: "b".repeat(32),
      agent: { name: "a", version: "1" },
      tool: "payments",
      args_hash: HASH,
      risk_level: "high",
      requester: { type: "agent", id: "p1", pid: "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV" },
      approval: { roles: ["finance"], sla_seconds: 60, escalate_to: [], on_timeout: "DENY" },
      policy_version: "p@1",
    });
    await svc.approve({ tenant_id: T1, ...FIN }, id);
    const rec = await new ApprovalResolver(svc).resolve(T1, id);
    const expected = { tenant_id: T1, run_id: "run-1", tool: "payments", args_hash: HASH };
    expect(await ports.verifier.verify(rec, expected)).toBe(true);
    expect(await ports.verifier.verify(rec, { ...expected, tenant_id: T2 })).toBe(false);
    expect(await ports.verifier.verify(rec, { ...expected, run_id: "run-2" })).toBe(false);
    expect(await ports.verifier.verify(rec, { ...expected, tool: "other" })).toBe(false);
    expect(await ports.verifier.verify(rec, { ...expected, args_hash: "c".repeat(64) })).toBe(
      false,
    );
    expect(await ports.verifier.verify({ ...rec, outcome: "DENIED" }, expected)).toBe(false);
    expect(await ports.verifier.verify({ ...rec, extra: 1 }, expected)).toBe(false);
    expect(await ports.verifier.verify({ ...rec, signature: "AAAA" }, expected)).toBe(false);
    for (const junk of [
      null,
      undefined,
      4,
      "x",
      [],
      {},
      { ...rec, level: 1.5 },
      { ...rec, tool: 3 },
    ])
      expect(await ports.verifier.verify(junk, expected)).toBe(false);
    expect(await isApprovalValidFor(rec, expected, signer)).toBe(true);
  });

  it("a DENIED or EXPIRED record never verifies, even when correctly signed", async () => {
    const { svc, signer, clock } = setup();
    const ports = kernelApprovalPorts(svc, signer);
    const mk = async () =>
      await svc.create(
        input({
          approval: { roles: ["finance"], sla_seconds: 5, escalate_to: [], on_timeout: "DENY" },
        }),
      );
    const a = await mk();
    await svc.deny({ tenant_id: T1, ...FIN }, a.id);
    const b = await mk();
    clock.advance(10);
    for (const id of [a.id, b.id]) {
      const rec = await new ApprovalResolver(svc).resolve(T1, id);
      expect(rec.decision).toBe("DENY");
      expect(
        await ports.verifier.verify(rec, {
          tenant_id: T1,
          run_id: "run-1",
          tool: "payments.refund",
          args_hash: HASH,
        }),
      ).toBe(false);
    }
  });

  it("isDecisionRecord rejects non-objects and mistyped fields", () => {
    expect(isDecisionRecord(null)).toBe(false);
    expect(isDecisionRecord([])).toBe(false);
  });
});

describe("dev bridge", () => {
  const create = async (svc: ReturnType<typeof setup>["svc"], over = {}) => svc.create(input(over));

  it("authenticates every call and only accepts POST to known routes", async () => {
    const b = await bridge();
    expect((await b.call("resolve", {}, null)).status).toBe(401);
    expect((await b.call("resolve", {}, "nope")).status).toBe(401);
    expect((await b.call("nonsense", {})).status).toBe(404);
    const get = await fetch(`http://127.0.0.1:${b.port}/v1/approvals/get`);
    expect(get.status).toBe(404);
    const other = await fetch(`http://127.0.0.1:${b.port}/elsewhere`, { method: "POST" });
    expect(other.status).toBe(404);
  });

  it("rejects bad bodies and principals", async () => {
    const b = await bridge();
    expect((await b.call("resolve", null, TOK1, "{not json")).status).toBe(400);
    expect((await b.call("resolve", null, TOK1, "[1]")).status).toBe(400);
    expect((await b.call("resolve", null, TOK1, "")).status).toBe(400); // empty body is {}: request_id required
    expect((await b.call("get", { request_id: 4 })).status).toBe(400);
    expect((await b.call("approve", { request_id: "x" })).status).toBe(400);
    expect(
      (await b.call("approve", { request_id: "x", principal: { id: "a", roles: "f" } })).status,
    ).toBe(400);
    expect(
      (await b.call("approve", { request_id: "x", principal: { id: "", roles: [] } })).status,
    ).toBe(400);
    const big = await b.call("get", { request_id: "x".repeat(70_000) });
    expect(big).toMatchObject({ status: 400, json: { error: { message: "body too large" } } });
  });

  it("approve -> resolve returns a signed APPROVED record; the decision is audited in the tenant chain", async () => {
    const b = await bridge();
    const r = await create(b.svc);
    const claim = await b.call("claim", { request_id: r.id, principal: FIN });
    expect(claim.status).toBe(200);
    const ok = await b.call("approve", { request_id: r.id, principal: FIN, comment: "ok" });
    expect(ok.json["request"].status).toBe("approved");
    const res = await b.call("resolve", { request_id: r.id });
    expect(res.status).toBe(200);
    const rec = res.json["record"] as DecisionRecord;
    expect(rec).toMatchObject({
      outcome: "APPROVED",
      decision: "ALLOW",
      tenant_id: T1,
      tool: "payments.refund",
    });
    expect(
      await isApprovalValidFor(
        rec,
        { tenant_id: T1, run_id: "run-1", tool: "payments.refund", args_hash: HASH },
        b.signer,
      ),
    ).toBe(true);
    const actions = (await b.log.read(T1)).map((e) => e.action);
    expect(actions).toEqual(["approval.requested", "approval.claimed", "approval.approved"]);
  });

  it("resolve waits up to wait_ms, then answers 202 pending; it wakes as soon as a decision lands", async () => {
    const b = await bridge();
    const r = await create(b.svc);
    const t0 = Date.now();
    const pending = await b.call("resolve", { request_id: r.id, wait_ms: 60 });
    expect(pending).toMatchObject({ status: 202, json: { status: "pending" } });
    expect(Date.now() - t0).toBeGreaterThanOrEqual(50);
    const waiting = b.call("resolve", { request_id: r.id, wait_ms: 5000 });
    await new Promise((x) => setTimeout(x, 20));
    await b.call("deny", { request_id: r.id, principal: FIN });
    const done = await waiting;
    expect(done.json["record"]).toMatchObject({ outcome: "DENIED", decision: "DENY" });
  });

  it("wait_ms is capped by maxWaitMs and defaults to no wait", async () => {
    const b = await bridge({ maxWaitMs: 30 });
    const r = await create(b.svc);
    const t0 = Date.now();
    expect((await b.call("resolve", { request_id: r.id, wait_ms: 60_000 })).status).toBe(202);
    expect(Date.now() - t0).toBeLessThan(2000);
    expect((await b.call("resolve", { request_id: r.id })).status).toBe(202);
  });

  it("expired requests resolve to an EXPIRED (DENY) record", async () => {
    const b = await bridge();
    const r = await create(b.svc, {
      approval: { roles: ["finance"], sla_seconds: 5, escalate_to: [], on_timeout: "DENY" },
    });
    b.clock.advance(6);
    const res = await b.call("resolve", { request_id: r.id });
    expect(res.json["record"]).toMatchObject({ outcome: "EXPIRED", decision: "DENY" });
  });

  it("maps approval errors to HTTP statuses: self-approval, wrong role, already decided, unknown id", async () => {
    const b = await bridge();
    const r = await create(b.svc);
    const self = await b.call("approve", {
      request_id: r.id,
      principal: { id: "refunder", roles: ["finance"] },
    });
    expect(self).toMatchObject({ status: 403, json: { error: { code: "SELF_APPROVAL" } } });
    // the requester id in `input()` is the agent id; approving as that id is separation-of-duties
    const role = await b.call("approve", {
      request_id: r.id,
      principal: { id: "bob", roles: ["intern"] },
    });
    expect(role).toMatchObject({ status: 403, json: { error: { code: "FORBIDDEN_ROLE" } } });
    await b.call("approve", { request_id: r.id, principal: FIN });
    const again = await b.call("deny", {
      request_id: r.id,
      principal: { id: "carol", roles: ["finance"] },
    });
    expect(again).toMatchObject({ status: 409, json: { error: { code: "ALREADY_DECIDED" } } });
    const unknown = await b.call("get", { request_id: "no-such" });
    expect(unknown).toMatchObject({ status: 404, json: { error: { code: "NOT_FOUND" } } });
  });

  it("a credential for another tenant cannot see, resolve or decide the request (cross-tenant id is unusable)", async () => {
    const b = await bridge();
    const r = await create(b.svc);
    for (const [route, body] of [
      ["get", { request_id: r.id }],
      ["resolve", { request_id: r.id }],
      ["approve", { request_id: r.id, principal: FIN }],
      ["deny", { request_id: r.id, principal: FIN }],
      ["claim", { request_id: r.id, principal: FIN }],
    ] as const) {
      const res = await b.call(route, body, TOK2);
      expect(res.status, route).toBe(404);
    }
    // and a body-supplied tenant is ignored
    const spoof = await b.call(
      "get",
      { request_id: r.id, tenant_id: T1, principal: { ...FIN, tenant_id: T1 } },
      TOK2,
    );
    expect(spoof.status).toBe(404);
    expect((await b.svc.peek(T1, r.id)).status).toBe("pending");
  });

  it("list shows requests the principal may act on", async () => {
    const b = await bridge();
    const r = await create(b.svc);
    const l = await b.call("list", { principal: FIN, status: "pending" });
    expect((l.json["requests"] as { id: string }[]).map((x) => x.id)).toEqual([r.id]);
    expect(((await b.call("list", { principal: FIN })).json["requests"] as unknown[]).length).toBe(
      1,
    );
    expect(
      (
        (await b.call("list", { principal: { id: "x", roles: ["intern"] } })).json[
          "requests"
        ] as unknown[]
      ).length,
    ).toBe(0);
    expect(
      ((await b.call("list", { principal: FIN }, TOK2)).json["requests"] as unknown[]).length,
    ).toBe(0);
  });

  it("an unexpected failure is a 500 with no detail (callers treat anything but 200 as DENY)", async () => {
    const b = await bridge();
    const r = await create(b.svc);
    b.audit.fail = true;
    const res = await b.call("approve", { request_id: r.id, principal: FIN });
    expect(res.status).toBe(500);
    expect(res.json).toEqual({ error: { code: "AUDIT_FAILED", message: "audit append failed" } });
  });

  it("a non-approval failure is a 500 INTERNAL", async () => {
    const b = await bridge();
    b.svc.peek = () => Promise.reject(new Error("store exploded: secret detail"));
    const res = await b.call("get", { request_id: "x" });
    expect(res).toMatchObject({ status: 500, json: { error: { code: "INTERNAL" } } });
    expect(JSON.stringify(res.json)).not.toContain("secret");
  });

  it("listenLoopback binds 127.0.0.1 only and rejects on a bad port", async () => {
    const b = await bridge();
    const addr = b.server.address() as { address: string };
    expect(addr.address).toBe("127.0.0.1");
    const dup = createDevBridge({
      service: b.svc,
      resolver: new ApprovalResolver(b.svc),
      authenticate: async () => T1,
    });
    await expect(listenLoopback(dup, b.port)).rejects.toThrow();
  });

  it("staticTenantAuthenticator ignores prototype keys and malformed headers", async () => {
    const a = staticTenantAuthenticator({ x: T1 });
    expect(await a("Bearer x")).toBe(T1);
    expect(await a("Bearer constructor")).toBeUndefined();
    expect(await a("Bearer toString")).toBeUndefined();
    expect(await a("x")).toBeUndefined();
    expect(await a(undefined)).toBeUndefined();
  });
});
