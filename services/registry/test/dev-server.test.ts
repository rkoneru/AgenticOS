import http from "node:http";
import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import {
  RateLimiter,
  RegistryError,
  createRegistryDevServer,
  generatePublisherKey,
  listenLoopback,
  refuseProduction,
  sendError,
  staticTokenAuthenticator,
  MemoryRegistryStore,
  RegistryService,
  ServiceAudit,
} from "../src/index.js";
import { MemoryAuditLog } from "@axis/audit";
import { Publisher, ablDoc, harness, rid } from "./helpers.js";

const T1 = randomUUID();
const T2 = randomUUID();
let server: http.Server | undefined;
afterEach(async () => {
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  server = undefined;
});

async function start(rateLimit?: { max: number; windowMs: number }) {
  const h = harness(new MemoryRegistryStore());
  server = createRegistryDevServer({
    registry: h.svc,
    tokens: {
      "tok-a": { tenantId: T1, subject: "alice", role: "admin" },
      "tok-a-viewer": { tenantId: T1, subject: "vera", role: "viewer" },
      "tok-b": { tenantId: T2, subject: "bob", role: "owner" },
    },
    ...(rateLimit ? { rateLimit } : {}),
  });
  const port = await listenLoopback(server);
  const call = async (method: string, path: string, token: string | undefined, body?: unknown) => {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      headers: {
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        "content-type": "application/json",
      },
      ...(body !== undefined
        ? { body: typeof body === "string" ? body : JSON.stringify(body) }
        : {}),
    });
    return { status: res.status, body: (await res.json()) as Record<string, unknown> };
  };
  return { h, call, port };
}

describe("registry dev server", () => {
  it("full flow over HTTP: namespace, key, publish, resolve, yank; tenant from the token only", async () => {
    const { h, call } = await start();
    const ns = `acme-${rid()}`;
    expect((await call("POST", "/v1/registry/namespaces", "tok-a", { namespace: ns })).status).toBe(
      201,
    );
    const pub = new Publisher(
      h,
      { kind: "tenant", tenantId: T1, subject: "alice", role: "admin" },
      ns,
    );
    pub.key = generatePublisherKey();
    const k = await call("POST", `/v1/registry/namespaces/${ns}/keys`, "tok-a", {
      public_key: pub.key.publicKey,
      valid_from: new Date(h.clock.t.getTime() - 1000).toISOString(),
    });
    expect(k.status).toBe(201);
    expect(
      (await call("GET", `/v1/registry/namespaces/${ns}/keys`, "tok-a")).body["items"],
    ).toHaveLength(1);
    expect((await call("GET", "/v1/registry/namespaces", "tok-a")).body["items"]).toEqual([
      { namespace: ns, public: false },
    ]);

    const sub = pub.submission(ablDoc("helper-agent", "1.0.0"));
    const body = {
      abl: sub.abl,
      signature: {
        key_id: sub.signature.keyId,
        signed_at: sub.signature.signedAt,
        sig: sub.signature.sig,
      },
      provenance: sub.provenance,
    };
    const p = await call("POST", `/v1/registry/namespaces/${ns}/blueprints`, "tok-a", body);
    expect(p.status).toBe(201);
    expect(p.body).toMatchObject({
      name: "helper-agent",
      version: "1.0.0",
      content_hash: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(
      (await call("POST", `/v1/registry/namespaces/${ns}/blueprints`, "tok-a", body)).status,
    ).toBe(409);
    const tampered = { ...body, signature: { ...body.signature, sig: "A".repeat(86) } };
    const bad = await call("POST", `/v1/registry/namespaces/${ns}/blueprints`, "tok-a", {
      ...tampered,
      abl: ablDoc("helper-agent", "1.0.1"),
    });
    expect(bad.status).toBe(422);

    const r = await call(
      "GET",
      `/v1/registry/resolve?ref=${encodeURIComponent(`${ns}/helper-agent@^1.0.0`)}`,
      "tok-a",
    );
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({
      version: "1.0.0",
      verification: { key_id: pub.key.keyId },
      state: "active",
    });
    expect(
      (await call("GET", `/v1/registry/blueprints/${ns}/helper-agent/versions`, "tok-a")).body[
        "items"
      ],
    ).toHaveLength(1);
    expect(
      (await call("GET", `/v1/registry/blueprints/${ns}/helper-agent/versions/1.0.0`, "tok-a"))
        .status,
    ).toBe(200);

    // tenant B: private namespace is invisible; spoofed tenant ids are rejected
    expect(
      (
        await call(
          "GET",
          `/v1/registry/resolve?ref=${encodeURIComponent(`${ns}/helper-agent@^1.0.0`)}`,
          "tok-b",
        )
      ).status,
    ).toBe(404);
    expect(
      (await call("GET", `/v1/registry/blueprints/${ns}/helper-agent/versions/1.0.0`, "tok-b"))
        .status,
    ).toBe(404);
    expect((await call("GET", `/v1/registry/namespaces?tenant_id=${T1}`, "tok-b")).status).toBe(
      403,
    );
    expect(
      (
        await call("POST", "/v1/registry/namespaces", "tok-b", {
          namespace: `bee-${rid()}`,
          tenant_id: T1,
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await call(
          "POST",
          `/v1/registry/blueprints/${ns}/helper-agent/versions/1.0.0/yank`,
          "tok-b",
          { reason: "takedown" },
        )
      ).status,
    ).toBe(403);

    // roles
    expect(
      (
        await call(
          "POST",
          `/v1/registry/blueprints/${ns}/helper-agent/versions/1.0.0/yank`,
          "tok-a-viewer",
          { reason: "nope" },
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await call(
          "POST",
          `/v1/registry/blueprints/${ns}/helper-agent/versions/1.0.0/deprecate`,
          "tok-a",
          { reason: "old" },
        )
      ).status,
    ).toBe(200);
    expect(
      (
        await call(
          "POST",
          `/v1/registry/blueprints/${ns}/helper-agent/versions/1.0.0/yank`,
          "tok-a",
          { reason: "broken" },
        )
      ).status,
    ).toBe(200);
    expect(
      (
        await call(
          "GET",
          `/v1/registry/resolve?ref=${encodeURIComponent(`${ns}/helper-agent@^1.0.0`)}`,
          "tok-a",
        )
      ).status,
    ).toBe(404);

    // key rotate / revoke
    const k2 = generatePublisherKey();
    const rot = await call(
      "POST",
      `/v1/registry/namespaces/${ns}/keys/${pub.key.keyId}/rotate`,
      "tok-a",
      { new_public_key: k2.publicKey },
    );
    expect(rot.status).toBe(200);
    expect(
      (
        await call("POST", `/v1/registry/namespaces/${ns}/keys/${k2.keyId}/revoke`, "tok-a", {
          reason: "bogus",
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await call("POST", `/v1/registry/namespaces/${ns}/keys/${k2.keyId}/revoke`, "tok-a", {
          reason: "compromised",
        })
      ).status,
    ).toBe(200);
  });

  it("authentication, routing, bodies, rate limits", async () => {
    const { call, port } = await start({ max: 7, windowMs: 60_000 });
    expect((await call("GET", "/v1/registry/namespaces", undefined)).status).toBe(401);
    expect((await call("GET", "/v1/registry/namespaces", "wrong")).status).toBe(401);
    expect((await call("GET", "/v1/other", "tok-a")).status).toBe(404);
    expect((await call("GET", "/v1/registry/nope", "tok-a")).status).toBe(404);
    expect((await call("POST", "/v1/registry/namespaces", "tok-a", "not json")).status).toBe(400);
    expect((await call("POST", "/v1/registry/namespaces", "tok-a", "[]")).status).toBe(400);
    expect((await call("POST", "/v1/registry/namespaces", "tok-a", {})).status).toBe(400);
    expect((await call("GET", "/v1/registry/resolve", "tok-a")).status).toBe(400);
    expect((await call("GET", "/v1/registry/resolve?ref=bad", "tok-a")).status).toBe(422);
    const limited = await call("GET", "/v1/registry/namespaces", "tok-a");
    expect(limited.status).toBe(429);
    const raw = await fetch(`http://127.0.0.1:${port}/v1/registry/namespaces`, {
      headers: { authorization: "Bearer tok-a" },
    });
    expect(raw.headers.get("retry-after")).toBeTruthy();
    // a different credential has its own budget
    expect((await call("GET", "/v1/registry/namespaces", "tok-b")).status).toBe(200);
    const big = await fetch(`http://127.0.0.1:${port}/v1/registry/namespaces`, {
      method: "POST",
      headers: { authorization: "Bearer tok-b" },
      body: "x".repeat(4_100_000),
    });
    expect(big.status).toBe(400);
  });

  it("publish needs a signature object; unknown errors never leak", async () => {
    const { call } = await start();
    const ns = `acme-${rid()}`;
    await call("POST", "/v1/registry/namespaces", "tok-a", { namespace: ns });
    expect(
      (
        await call("POST", `/v1/registry/namespaces/${ns}/blueprints`, "tok-a", {
          abl: ablDoc("helper-agent", "1.0.0"),
        })
      ).status,
    ).toBe(400);
    const res = {
      writeHead: () => undefined,
      end: (t: string) => expect(t).not.toContain("secret"),
    } as unknown as http.ServerResponse;
    sendError(res, new Error("secret internals"));
    sendError(res, new RegistryError("unavailable", "x"));
  });

  it("refuses to run in production", () => {
    const prev = process.env["NODE_ENV"];
    process.env["NODE_ENV"] = "production";
    try {
      expect(() => refuseProduction("x")).toThrow(/production/);
      expect(() =>
        createRegistryDevServer({
          registry: new RegistryService({
            store: new MemoryRegistryStore(),
            audit: new ServiceAudit(new MemoryAuditLog(), "registry"),
          }),
          tokens: {},
        }),
      ).toThrow(/production/);
    } finally {
      if (prev === undefined) delete process.env["NODE_ENV"];
      else process.env["NODE_ENV"] = prev;
    }
  });
});

describe("http kit", () => {
  it("rate limiter: sliding window, per key, injectable clock", () => {
    let t = 0;
    const rl = new RateLimiter(2, 1000, () => t);
    expect(rl.check("a")).toBe(0);
    expect(rl.check("a")).toBe(0);
    expect(rl.check("a")).toBeGreaterThan(0);
    expect(rl.check("b")).toBe(0);
    t = 1001;
    expect(rl.check("a")).toBe(0);
  });
  it("static tokens compare in constant time and reject malformed headers", () => {
    const auth = staticTokenAuthenticator({ good: 1 });
    expect(auth("Bearer good")).toBe(1);
    expect(auth("Bearer bad")).toBeUndefined();
    expect(auth("good")).toBeUndefined();
    expect(auth(undefined)).toBeUndefined();
  });
});
