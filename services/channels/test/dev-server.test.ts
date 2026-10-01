import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { createDevServer, listenLoopback, staticTokenAuthenticator } from "../src/index.js";
import { NOW, T1, T2, rig, slackReq, type Rig } from "./helpers.js";
import { hmacSha256Hex } from "../src/index.js";

const TOK1 = "svc-token-tenant-1";
const TOK2 = "svc-token-tenant-2";
let server: http.Server | undefined;
afterEach(async () => {
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  server = undefined;
});

async function start(r: Rig): Promise<number> {
  server = createDevServer({
    gateway: r.gateway,
    routes: r.table,
    store: r.store,
    identity: r.identity,
    hub: r.hub,
    authenticate: staticTokenAuthenticator({ [TOK1]: { tenantId: T1 }, [TOK2]: { tenantId: T2 } }),
    now: r.clock.now,
  });
  return listenLoopback(server);
}

const call = async (
  port: number,
  method: string,
  path: string,
  o: { headers?: Record<string, string>; body?: string | Buffer } = {},
): Promise<{ status: number; headers: http.IncomingHttpHeaders; text: string }> =>
  new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, method, path, headers: o.headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode!,
            headers: res.headers,
            text: Buffer.concat(chunks).toString(),
          }),
        );
      },
    );
    req.on("error", reject);
    req.end(o.body);
  });
const post = (port: number, path: string, body: unknown, token?: string) =>
  call(port, "POST", path, {
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

describe("staticTokenAuthenticator", () => {
  it("matches exactly and rejects everything else", () => {
    const a = staticTokenAuthenticator({ tok: { tenantId: T1 } });
    expect(a("Bearer tok")).toEqual({ tenantId: T1 });
    for (const bad of [
      undefined,
      "tok",
      "Bearer ",
      "Bearer tok2",
      "Bearer to",
      "bearer tok",
      "Basic tok",
    ])
      expect(a(bad)).toBeUndefined();
  });
});

describe("provider webhooks", () => {
  it("POST /v1/channels/slack/inbound: verified message accepted, forged one rejected, handshake answered", async () => {
    const r = rig();
    const port = await start(r);
    const good = slackReq({ text: "via http" });
    const res = await call(port, "POST", "/v1/channels/slack/inbound", {
      headers: good.headers,
      body: good.body,
    });
    expect(res.status).toBe(200);
    expect(r.received.map((m) => m.text)).toEqual(["via http"]);
    const bad = slackReq({ secret: "nope" });
    expect(
      (
        await call(port, "POST", "/v1/channels/slack/inbound", {
          headers: bad.headers,
          body: bad.body,
        })
      ).status,
    ).toBe(401);
    // a body past the cap is refused (413) without reaching the adapter
    expect(
      (
        await call(port, "POST", "/v1/channels/slack/inbound", {
          headers: good.headers,
          body: Buffer.alloc(600_000, 1),
        })
      ).status,
    ).toBe(413);
    const wa = await call(
      port,
      "GET",
      "/v1/channels/whatsapp/inbound?hub.mode=subscribe&hub.verify_token=wa-verify-token&hub.challenge=777",
    );
    expect(wa).toMatchObject({ status: 200, text: "777" });
    expect(
      (
        await call(
          port,
          "GET",
          "/v1/channels/whatsapp/inbound?hub.mode=subscribe&hub.verify_token=x&hub.challenge=777",
        )
      ).status,
    ).toBe(401);
    expect((await call(port, "POST", "/v1/channels/fax/inbound")).status).toBe(404); // not a channel
  });

  it("the provider webhook is NOT authenticated by a bearer token: a service token does not bypass signature checks", async () => {
    const r = rig();
    const port = await start(r);
    const bad = slackReq({ secret: "nope" });
    const res = await call(port, "POST", "/v1/channels/slack/inbound", {
      headers: { ...bad.headers, authorization: `Bearer ${TOK1}` },
      body: bad.body,
    });
    expect(res.status).toBe(401);
    expect(r.received).toHaveLength(0);
  });
});

describe("web widget over HTTP + SSE", () => {
  it("issues a session for an allowed origin only; message in, reply out over SSE", async () => {
    const r = rig();
    const port = await start(r);
    const origin = "https://app.example.test";
    expect((await post(port, "/v1/channels/web/session", { site: "site-1" })).status).toBe(403);
    expect(
      (
        await call(port, "POST", "/v1/channels/web/session", {
          headers: { origin: "https://evil.example" },
          body: JSON.stringify({ site: "site-1" }),
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await call(port, "POST", "/v1/channels/web/session", {
          headers: { origin },
          body: JSON.stringify({ site: "nope" }),
        })
      ).status,
    ).toBe(403);
    const s = await call(port, "POST", "/v1/channels/web/session", {
      headers: { origin },
      body: JSON.stringify({ site: "site-1" }),
    });
    expect(s.status).toBe(200);
    expect(s.headers["access-control-allow-origin"]).toBe(origin);
    const { token } = JSON.parse(s.text) as { token: string };

    // SSE stream
    const events: string[] = [];
    const sse = await new Promise<http.IncomingMessage>((resolve, reject) => {
      const q = http.request(
        {
          host: "127.0.0.1",
          port,
          path: "/v1/channels/web/events",
          headers: { authorization: `Bearer ${token}`, origin },
        },
        resolve,
      );
      q.on("error", reject);
      q.end();
    });
    expect(sse.statusCode).toBe(200);
    expect(sse.headers["content-type"]).toBe("text/event-stream");
    sse.setEncoding("utf8");
    sse.on("data", (d: string) => events.push(d));

    const m = await call(port, "POST", "/v1/channels/web/inbound", {
      headers: { authorization: `Bearer ${token}`, origin, "content-type": "application/json" },
      body: JSON.stringify({ text: "hi from widget", client_message_id: "cm-00000001" }),
    });
    expect(m.status).toBe(200);
    expect(m.headers["access-control-allow-origin"]).toBeUndefined(); // accepted reply path has no rejected-route CORS; browsers use the POST response only for status
    expect(r.received[0]).toMatchObject({ tenant: T1, text: "hi from widget" });

    const conv = r.received[0]!.conv;
    const sent = await post(
      port,
      "/v1/channels/send",
      { channel: "web", conversation_id: conv, text: "hello widget" },
      TOK1,
    );
    expect(sent.status).toBe(200);
    await new Promise((r2) => setTimeout(r2, 30));
    const stream = events.join("");
    expect(stream).toContain("event: message");
    expect(stream).toContain('"text":"hello widget"');
    sse.destroy();

    // a missing / forged token or a foreign origin cannot open a stream
    expect(
      (await call(port, "GET", "/v1/channels/web/events", { headers: { origin } })).status,
    ).toBe(401);
    expect(
      (
        await call(port, "GET", "/v1/channels/web/events", {
          headers: { authorization: "Bearer v1.x.y", origin },
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await call(port, "GET", "/v1/channels/web/events", {
          headers: { authorization: `Bearer ${token}`, origin: "https://evil.example" },
        })
      ).status,
    ).toBe(401);
    expect(
      (await call(port, "OPTIONS", "/v1/channels/web/inbound", { headers: { origin } })).status,
    ).toBe(204);
  });
});

describe("service routes: the bearer token fixes the tenant", () => {
  const seed = async (r: Rig) => {
    await r.gateway.handleInbound("slack", slackReq({ user: "UALICE", channel: "C555" }));
    return r.received[0]!.conv;
  };
  it("send: success, auth, tenant binding, error mapping", async () => {
    const r = rig();
    const port = await start(r);
    const conv = await seed(r);
    expect(
      (
        await post(port, "/v1/channels/send", {
          channel: "slack",
          conversation_id: conv,
          text: "x",
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await post(
          port,
          "/v1/channels/send",
          { channel: "slack", conversation_id: conv, text: "x" },
          "wrong",
        )
      ).status,
    ).toBe(401);
    const ok = await post(
      port,
      "/v1/channels/send",
      {
        channel: "slack",
        conversation_id: conv,
        body: "reply text",
        idempotency_key: "idem-1",
        tenant_id: T1,
      },
      TOK1,
    );
    expect(ok.status).toBe(200);
    expect(JSON.parse(ok.text)).toMatchObject({
      conversation_id: conv,
      parts: 1,
      duplicate: false,
    });
    expect(r.http.calls).toHaveLength(1);
    // body tenant must equal the token's tenant
    expect(
      (
        await post(
          port,
          "/v1/channels/send",
          { channel: "slack", conversation_id: conv, text: "x", tenant_id: T2 },
          TOK1,
        )
      ).status,
    ).toBe(403);
    // tenant 2's token cannot reach tenant 1's conversation
    expect(
      (
        await post(
          port,
          "/v1/channels/send",
          { channel: "slack", conversation_id: conv, text: "x" },
          TOK2,
        )
      ).status,
    ).toBe(404);
    expect(r.http.calls).toHaveLength(1);
    expect(
      (await post(port, "/v1/channels/send", { channel: "fax", text: "x" }, TOK1)).status,
    ).toBe(400);
    expect((await post(port, "/v1/channels/send", { channel: "slack" }, TOK1)).status).toBe(400);
    expect((await post(port, "/v1/channels/send", "not json", TOK1)).status).toBe(400);
    expect((await post(port, "/v1/channels/send", "[]", TOK1)).status).toBe(400);
    expect(
      (await post(port, "/v1/channels/send", { channel: "slack", text: "x", to: "UNKNOWN" }, TOK1))
        .status,
    ).toBe(403);
    expect(
      (
        await call(port, "GET", "/v1/channels/send", {
          headers: { authorization: `Bearer ${TOK1}` },
        })
      ).status,
    ).toBe(405);
    expect(
      (
        await call(port, "PUT", "/v1/channels/send", {
          headers: { authorization: `Bearer ${TOK1}` },
        })
      ).status,
    ).toBe(405);
    r.audit.fail = true;
    expect(
      (
        await post(
          port,
          "/v1/channels/send",
          { channel: "slack", conversation_id: conv, text: "x" },
          TOK1,
        )
      ).status,
    ).toBe(503);
    r.audit.fail = false;
    r.http.respond = () => ({ status: 500, body: "" });
    expect(
      (
        await post(
          port,
          "/v1/channels/send",
          { channel: "slack", conversation_id: conv, text: "y" },
          TOK1,
        )
      ).status,
    ).toBe(502);
    r.http.respond = () => {
      throw new Error("kaboom");
    };
    expect(
      (
        await post(
          port,
          "/v1/channels/send",
          { channel: "slack", conversation_id: conv, text: "z" },
          TOK1,
        )
      ).status,
    ).toBe(502);
    expect(
      (
        await post(
          port,
          "/v1/channels/send",
          { channel: "slack", conversation_id: conv, text: "x".repeat(40000) },
          TOK1,
        )
      ).status,
    ).toBe(413);
    expect(
      (await post(port, "/v1/channels/send", Buffer.alloc(700_000, 65).toString(), TOK1)).status,
    ).toBe(413);
    expect((await call(port, "GET", "/v1/channels/unknown", {})).status).toBe(404);
  });

  it("link-code and message-log routes are tenant scoped", async () => {
    const r = rig();
    const port = await start(r);
    const conv = await seed(r);
    const lc = await post(
      port,
      "/v1/channels/identity/link-code",
      { channel: "slack", external_id: "UALICE" },
      TOK1,
    );
    expect(lc.status).toBe(200);
    expect(JSON.parse(lc.text).code).toHaveLength(10);
    expect(
      (
        await post(
          port,
          "/v1/channels/identity/link-code",
          { channel: "slack", external_id: "UALICE" },
          TOK2,
        )
      ).status,
    ).toBe(404);
    expect(
      (
        await post(
          port,
          "/v1/channels/identity/link-code",
          { channel: "fax", external_id: "UALICE" },
          TOK1,
        )
      ).status,
    ).toBe(400);
    const mine = await call(port, "GET", `/v1/channels/conversations/${conv}/messages`, {
      headers: { authorization: `Bearer ${TOK1}` },
    });
    expect(JSON.parse(mine.text).messages).toHaveLength(1);
    const theirs = await call(port, "GET", `/v1/channels/conversations/${conv}/messages`, {
      headers: { authorization: `Bearer ${TOK2}` },
    });
    expect(JSON.parse(theirs.text).messages).toEqual([]);
    expect((await call(port, "GET", `/v1/channels/conversations/${conv}/messages`)).status).toBe(
      401,
    );
  });

  it("listenLoopback binds 127.0.0.1 only", async () => {
    const r = rig();
    const port = await start(r);
    expect((server!.address() as AddressInfo).address).toBe("127.0.0.1");
    expect(port).toBeGreaterThan(0);
    expect(hmacSha256Hex("k", "d")).toHaveLength(64);
    expect(NOW).toBeGreaterThan(0);
  });
});
