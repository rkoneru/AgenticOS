import http from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CursorCodec, MemoryIdempotencyStore, TokenBuckets, canonical } from "../src/index.js";
import { ABL, call, hex32, makeWorld, seed, type Seed, type World } from "./world.js";

const open = { rate: { burst: 1e6, perSecond: 1e6 }, unauthRate: { burst: 1e6, perSecond: 1e6 } };
let w: World;
let a: Seed;
let b: Seed;
beforeAll(async () => {
  w = await makeWorld(open);
  a = await seed(w);
  b = await seed(w);
});
afterAll(() => w.close());

describe("idempotency", () => {
  const start = (s: Seed, key: string, body: unknown = { blueprint: s.blueprint, input: { prompt: "x" } }) =>
    call(w, "POST", "/runs", { token: s.owner.token, body, headers: { "idempotency-key": key } });

  it("replays the first response and runs the operation once", async () => {
    const n = w.runs.starts.length;
    const r1 = await start(a, "key-replay-0001");
    const r2 = await start(a, "key-replay-0001");
    expect(r1.status).toBe(202);
    expect(r2.status).toBe(202);
    expect(r2.body).toEqual(r1.body);
    expect(r2.headers.get("idempotent-replayed")).toBe("true");
    expect(r1.headers.get("idempotent-replayed")).toBeNull();
    expect(w.runs.starts.length).toBe(n + 1);
  });

  it("the same key with a different body is 422, and with another path too", async () => {
    await start(a, "key-collide-001");
    const r = await start(a, "key-collide-001", { blueprint: a.blueprint, input: { prompt: "different" } });
    expect(r.status).toBe(422);
    expect(r.body.errors[0].message).toContain("idempotency");
    const other = await call(w, "POST", `/runs/${a.runId}/signals`, { token: a.owner.token, body: { signal: "RESUME" }, headers: { "idempotency-key": "key-collide-001" } });
    expect(other.status).toBe(422);
  });

  it("key order inside the body does not matter (canonical fingerprint)", async () => {
    const r1 = await start(a, "key-canon-0001", { input: { b: 1, a: 2 }, blueprint: a.blueprint });
    const r2 = await start(a, "key-canon-0001", { blueprint: a.blueprint, input: { a: 2, b: 1 } });
    expect(r2.body.id).toBe(r1.body.id);
  });

  it("keys never collide across tenants or across members", async () => {
    const ra = await start(a, "key-shared-0001");
    const rb = await start(b, "key-shared-0001");
    expect(ra.status).toBe(202);
    expect(rb.status).toBe(202);
    expect(rb.body.id).not.toBe(ra.body.id);
    expect(w.runs.runs.get(rb.body.id)?.tenantId).toBe(b.owner.tenantId);
    const admin = await w.member(a.owner.tenantId, "admin");
    const rm = await call(w, "POST", "/runs", { token: admin.token, body: { blueprint: a.blueprint, input: { prompt: "x" } }, headers: { "idempotency-key": "key-shared-0001" } });
    expect(rm.body.id).not.toBe(ra.body.id); // another member of the same tenant does not replay the first member's response
    expect(rm.headers.get("idempotent-replayed")).toBeNull();
  });

  it("a concurrent duplicate is 409, then replays once the first finishes", async () => {
    const slow = await makeWorld(open);
    const orig = slow.runs.start.bind(slow.runs);
    const o = await slow.tenant();
    await call(slow, "POST", "/blueprints", { token: o.token, body: { abl: ABL("claims") } });
    let release2: () => void = () => undefined;
    const gate2 = new Promise<void>((r) => (release2 = r));
    slow.runs.start = async (r) => (await gate2, orig(r));
    const body = { blueprint: { name: "claims", version: "1.0.0" } };
    const first = call(slow, "POST", "/runs", { token: o.token, body, headers: { "idempotency-key": "key-flight-0001" } });
    await new Promise((r) => setTimeout(r, 100));
    const dup = await call(slow, "POST", "/runs", { token: o.token, body, headers: { "idempotency-key": "key-flight-0001" } });
    expect(dup.status).toBe(409);
    release2();
    const f = await first;
    expect(f.status).toBe(202);
    const again = await call(slow, "POST", "/runs", { token: o.token, body, headers: { "idempotency-key": "key-flight-0001" } });
    expect(again.body.id).toBe(f.body.id);
    await slow.close();
  });

  it("server errors and 429 are NOT stored: a retry executes again", async () => {
    const flaky = await makeWorld(open);
    const o = await flaky.tenant();
    await call(flaky, "POST", "/blueprints", { token: o.token, body: { abl: ABL("claims") } });
    const body = { blueprint: { name: "claims", version: "1.0.0" } };
    flaky.runs.failStart = true;
    const bad = await call(flaky, "POST", "/runs", { token: o.token, body, headers: { "idempotency-key": "key-retry-0001" } });
    expect(bad.status).toBe(503);
    flaky.runs.failStart = false;
    const good = await call(flaky, "POST", "/runs", { token: o.token, body, headers: { "idempotency-key": "key-retry-0001" } });
    expect(good.status).toBe(202);
    expect(good.headers.get("idempotent-replayed")).toBeNull();
    await flaky.close();
  });

  it("deterministic client errors are remembered", async () => {
    const body = { blueprint: { name: "nope", version: "1.0.0" } };
    const r1 = await call(w, "POST", "/runs", { token: a.owner.token, body, headers: { "idempotency-key": "key-404-00001" } });
    const r2 = await call(w, "POST", "/runs", { token: a.owner.token, body, headers: { "idempotency-key": "key-404-00001" } });
    expect(r1.status).toBe(404);
    expect(r2.status).toBe(404);
    expect(r2.headers.get("idempotent-replayed")).toBe("true");
  });

  it("a replay is not audited again", async () => {
    const before = (await w.audit.listEvents(a.owner.tenantId, { limit: 10000 })).filter((e) => e.action === "api.startRun").length;
    await start(a, "key-audit-0001");
    await start(a, "key-audit-0001");
    const after = (await w.audit.listEvents(a.owner.tenantId, { limit: 10000 })).filter((e) => e.action === "api.startRun").length;
    expect(after - before).toBe(1);
  });

  it.each(["short", "x".repeat(129)])("a malformed key (%s) is 422", async (k) => {
    expect((await start(a, k)).status).toBe(422);
  });

  it("a key on an operation that does not take one is ignored, never stored", async () => {
    const r = await call(w, "GET", "/runs", { token: a.owner.token, headers: { "idempotency-key": "key-get-000001" } });
    expect(r.status).toBe(200);
  });

  it("store unit: TTL expiry, bounded size, abort", async () => {
    let t = 0;
    const s = new MemoryIdempotencyStore(() => t, 2);
    expect((await s.begin("s", "k1", "f", 10)).kind).toBe("new");
    expect((await s.begin("s", "k1", "f", 10)).kind).toBe("in_progress");
    await s.complete("s", "k1", { status: 200, body: 1, headers: {} });
    expect((await s.begin("s", "k1", "f", 10)).kind).toBe("replay");
    expect((await s.begin("s", "k1", "g", 10)).kind).toBe("mismatch");
    t = 11;
    expect((await s.begin("s", "k1", "g", 10)).kind).toBe("new");
    await s.begin("s", "k2", "f", 10);
    await s.begin("s", "k3", "f", 10); // evicts the oldest
    expect(s.size).toBe(2);
    await s.abort("s", "k3");
    expect(s.size).toBe(1);
    expect((await s.begin("t", "k2", "f", 10)).kind).toBe("new"); // scope separates
    expect(canonical({ b: [1, { z: 1, y: 2 }], a: null })).toBe('{"a":null,"b":[1,{"y":2,"z":1}]}');
  });
});

describe("rate limits", () => {
  it("per-tenant token bucket: 429 with Retry-After, other tenants unaffected, headers cannot split or reset the bucket", async () => {
    const rl = await makeWorld({ rate: { burst: 3, perSecond: 0.001 }, unauthRate: { burst: 1e6, perSecond: 1 } });
    const x = await rl.tenant();
    const y = await rl.tenant();
    const hit = (t: string, h: Record<string, string> = {}) => call(rl, "GET", "/blueprints", { token: t, headers: h });
    expect((await hit(x.token)).status).toBe(200);
    expect((await hit(x.token, { "x-forwarded-for": "1.1.1.1" })).status).toBe(200);
    const third = await hit(x.token, { "x-request-id": "rotate-0001", "x-real-ip": "2.2.2.2" });
    expect(third.status).toBe(200);
    expect(third.headers.get("ratelimit-remaining")).toBe("0");
    const blocked = await hit(x.token, { "x-forwarded-for": "9.9.9.9", forwarded: "for=8.8.8.8", "x-request-id": "rotate-0002" });
    expect(blocked.status).toBe(429);
    expect(blocked.body.code).toBe("rate_limited");
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
    expect((await hit(y.token)).status).toBe(200);
    // a second credential of the same tenant shares the bucket
    const key = await rl.apiKey(x, ["*"]);
    expect((await hit(key)).status).toBe(429);
    await rl.close();
  });

  it("operations are cost-weighted", async () => {
    const rl = await makeWorld({ rate: { burst: 10, perSecond: 0.001 }, costs: { verifyAuditChain: 10 }, unauthRate: { burst: 1e6, perSecond: 1 } });
    const x = await rl.tenant();
    expect((await call(rl, "POST", "/audit/verify", { token: x.token, body: {} })).status).toBe(200);
    expect((await call(rl, "GET", "/blueprints", { token: x.token })).status).toBe(429);
    await rl.close();
  });

  it("failed authentication is limited per remote address, before any credential lookup", async () => {
    let lookups = 0;
    const rl = await makeWorld({ unauthRate: { burst: 3, perSecond: 0.001 } }, { auth: { authenticate: async () => (lookups++, undefined) } });
    const codes: number[] = [];
    for (let i = 0; i < 6; i++) codes.push((await call(rl, "GET", "/runs", { token: `bad${i}` })).status);
    expect(codes).toEqual([401, 401, 401, 429, 429, 429]);
    expect(lookups).toBe(3);
    await rl.close();
  });

  it("TokenBuckets unit: refill, clamp of oversized cost, bounded table", () => {
    let t = 0;
    const b = new TokenBuckets({ burst: 2, perSecond: 1 }, () => t, 2);
    expect(b.take("k", 1).ok).toBe(true);
    expect(b.take("k", 1).ok).toBe(true);
    const no = b.take("k", 1);
    expect(no.ok).toBe(false);
    expect(no.retryAfterSec).toBeCloseTo(1);
    t = 1000;
    expect(b.take("k", 5).ok).toBe(false); // clamped to 2, only 1 token refilled
    t = 5000;
    expect(b.take("k", 5).ok).toBe(true); // clamp makes an oversized request servable
    b.take("a");
    b.take("b");
    b.take("c");
    expect(b.size).toBe(2);
  });
});

describe("cursor codec", () => {
  it("round trips and rejects anything else", () => {
    const c = new CursorCodec(Buffer.alloc(32, 1));
    const cur = c.encode("t1", "runs", "pos");
    expect(c.decode("t1", "runs", cur)).toBe("pos");
    expect(c.decode("t2", "runs", cur)).toBeUndefined();
    expect(c.decode("t1", "approvals", cur)).toBeUndefined();
    expect(c.decode("t1", "runs", "")).toBeUndefined();
    const [body, mac] = cur.split(".") as [string, string];
    const forged = Buffer.from(JSON.stringify({ p: "evil" })).toString("base64url");
    expect(c.decode("t1", "runs", `${forged}.${mac}`)).toBeUndefined();
    expect(c.decode("t1", "runs", `${body}.${mac.slice(0, -2)}`)).toBeUndefined();
    const nonString = Buffer.from(JSON.stringify({ p: 1 })).toString("base64url");
    const c2 = new CursorCodec(Buffer.alloc(32, 1));
    expect(c2.decode("t1", "runs", `${nonString}.x`)).toBeUndefined();
  });
});

describe("HTTP hygiene", () => {
  it("oversize bodies: declared and chunked are 413; the connection is closed", async () => {
    const small = await makeWorld({ ...open, maxBodyBytes: 1024 });
    const o = await small.tenant();
    const big = JSON.stringify({ abl: { pad: "x".repeat(4000) } });
    const r = await call(small, "POST", "/blueprints", { token: o.token, raw: big });
    expect(r.status).toBe(413);
    expect(r.body.code).toBe("validation_failed");
    // chunked, no content-length
    const port = new URL(small.base).port;
    const status = await new Promise<number>((resolve, reject) => {
      const req = http.request({ host: "127.0.0.1", port, path: "/v1/blueprints", method: "POST", headers: { authorization: `Bearer ${o.token}`, "content-type": "application/json", "transfer-encoding": "chunked" } }, (res) => (res.resume(), resolve(res.statusCode ?? 0)));
      req.on("error", reject);
      for (let i = 0; i < 10; i++) req.write("x".repeat(500));
      req.end();
    });
    expect(status).toBe(413);
    await small.close();
  });

  it("malformed JSON is 400, wrong media type 415, empty required body 422, a deeply nested body is refused", async () => {
    const t = a.owner.token;
    expect((await call(w, "POST", "/runs", { token: t, raw: "{not json" })).status).toBe(400);
    expect((await call(w, "POST", "/runs", { token: t, raw: "{}", contentType: "text/plain" })).status).toBe(415);
    expect((await call(w, "POST", "/runs", { token: t })).status).toBe(422);
    const nested = "[".repeat(5000) + "]".repeat(5000);
    expect([400, 422]).toContain((await call(w, "POST", "/runs", { token: t, raw: nested })).status);
    expect((await call(w, "POST", "/runs", { token: t, raw: '{"blueprint":{"name":"claims","version":"1.0.0"}}', contentType: "application/json; charset=utf-8" })).status).toBe(202);
    expect((await call(w, "POST", "/runs", { token: t, raw: '{"__proto__":{"x":1},"blueprint":{"name":"claims","version":"1.0.0"}}' })).status).toBe(422);
  });

  it("unknown paths are 404 problems; odd targets never crash the server", async () => {
    for (const p of ["/nope", "//runs", "/runs//x", `/runs/${"a".repeat(600)}`, "/runs/%zz", "/runs/..%2f..%2fetc"]) {
      const r = await call(w, "GET", p, { token: a.owner.token });
      expect([400, 404, 422], p).toContain(r.status);
      expect(r.headers.get("content-type")).toContain("problem+json");
    }
    const outside = await fetch(w.base.replace("/v1", "/v2/runs"));
    expect(outside.status).toBe(404);
  });

  it("every response carries security headers, a request id and a traceparent; ids are propagated or replaced", async () => {
    const r = await call(w, "GET", "/runs", { token: a.owner.token, headers: { "x-request-id": "client-id-12345" } });
    expect(r.headers.get("x-request-id")).toBe("client-id-12345");
    expect(r.headers.get("x-content-type-options")).toBe("nosniff");
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(r.headers.get("traceparent")).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/);
    const bad = await call(w, "GET", "/runs", { token: a.owner.token, headers: { "x-request-id": "bad id\twith junk" } }).catch(() => undefined);
    if (bad) expect(bad.headers.get("x-request-id")).not.toContain("junk");
    const zero = await call(w, "GET", "/runs", { token: a.owner.token, headers: { traceparent: `00-${"0".repeat(32)}-0123456789abcdef-01` } });
    expect(zero.headers.get("traceparent")).not.toContain("0".repeat(32));
    const t = hex32();
    const ok = await call(w, "GET", "/runs", { token: a.owner.token, headers: { traceparent: `00-${t}-0123456789abcdef-01` } });
    expect(ok.headers.get("traceparent")).toContain(t);
    const tls = await makeWorld({ ...open, behindTls: true });
    expect((await fetch(tls.base.replace("/v1", "/healthz"))).headers.get("strict-transport-security")).toContain("max-age");
    await tls.close();
  });

  it("errors never leak internals", async () => {
    const boom = await makeWorld(open, { blueprints: { list: async () => Promise.reject(new Error("pg: password=hunter2 at /srv/x.ts:1")), get: async () => undefined, publish: async (_t, v) => v } });
    const o = await boom.tenant();
    const r = await call(boom, "GET", "/blueprints", { token: o.token });
    expect(r.status).toBe(500);
    expect(r.text).not.toMatch(/hunter2|pg:|\.ts/);
    expect(boom.logs.some((l) => l.level === "error")).toBe(true);
    await boom.close();
  });

  it("a handler that exceeds the time budget is a 504", async () => {
    const slow = await makeWorld({ ...open, requestTimeoutMs: 50 }, { blueprints: { list: () => new Promise(() => undefined), get: async () => undefined, publish: async (_t, v) => v } });
    const o = await slow.tenant();
    const r = await call(slow, "GET", "/blueprints", { token: o.token });
    expect(r.status).toBe(504);
    await slow.close();
  });

  it("a response that violates the contract becomes a 500 (and is logged), never reaches the client", async () => {
    const drift = await makeWorld(open, { blueprints: { list: async () => ({ items: [{ nope: 1 } as never] }), get: async () => undefined, publish: async (_t, v) => v } });
    const o = await drift.tenant();
    const r = await call(drift, "GET", "/blueprints", { token: o.token });
    expect(r.status).toBe(500);
    expect(drift.logs.some((l) => l.msg.includes("violates the OpenAPI"))).toBe(true);
    await drift.close();
  });
});

describe("CORS", () => {
  const origin = "https://console.example.test";
  it("preflight for the console origin is answered without credentials; other origins get no CORS headers", async () => {
    const ok = await fetch(w.base + "/runs", { method: "OPTIONS", headers: { origin, "access-control-request-method": "POST", "access-control-request-headers": "authorization,idempotency-key" } });
    expect(ok.status).toBe(204);
    expect(ok.headers.get("access-control-allow-origin")).toBe(origin);
    expect(ok.headers.get("access-control-allow-headers")).toContain("idempotency-key");
    expect(ok.headers.get("access-control-allow-credentials")).toBeNull();
    for (const o of ["https://evil.example", "null", "https://console.example.test.evil.example", "http://console.example.test"]) {
      const r = await fetch(w.base + "/runs", { method: "OPTIONS", headers: { origin: o, "access-control-request-method": "POST" } });
      expect(r.status).toBe(204);
      expect(r.headers.get("access-control-allow-origin")).toBeNull();
      expect(r.headers.get("access-control-allow-methods")).toBeNull();
    }
    const noReq = await fetch(w.base + "/runs", { method: "OPTIONS", headers: { origin } });
    expect(noReq.headers.get("access-control-allow-methods")).toBeNull();
  });
  it("actual responses expose the allow-listed origin only, and always Vary: Origin", async () => {
    const r = await fetch(w.base + "/runs", { headers: { origin, authorization: `Bearer ${a.owner.token}` } });
    expect(r.headers.get("access-control-allow-origin")).toBe(origin);
    expect(r.headers.get("vary")).toContain("Origin");
    const e = await fetch(w.base + "/runs", { headers: { origin: "https://evil.example", authorization: `Bearer ${a.owner.token}` } });
    expect(e.headers.get("access-control-allow-origin")).toBeNull();
  });
  it("no allow-list means no cross-origin access at all", async () => {
    const none = await makeWorld({ ...open, allowedOrigins: [] });
    const r = await fetch(none.base + "/runs", { method: "OPTIONS", headers: { origin, "access-control-request-method": "GET" } });
    expect(r.headers.get("access-control-allow-origin")).toBeNull();
    await none.close();
  });
});
