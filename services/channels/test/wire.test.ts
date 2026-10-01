import { readFileSync } from "node:fs";
import type http from "node:http";
import { afterEach, expect, it } from "vitest";
import { createDevServer, listenLoopback, staticTokenAuthenticator } from "../src/index.js";
import { smsParams, smsReq, rig, slackReq, T1 } from "./helpers.js";

const wire = JSON.parse(readFileSync(new URL("../contract/wire-v1.json", import.meta.url), "utf8"));
let server: http.Server | undefined;
afterEach(() => new Promise<void>((r) => (server ? server.close(() => r()) : r())));

it("the real server accepts every request of the shared wire contract and answers with the same key structure", async () => {
  const r = rig();
  await r.gateway.handleInbound("slack", slackReq({ user: "UALICE", channel: "C555" }));
  const conv = r.received[0]!.conv;
  const sms = smsReq(smsParams({ from: "+15557770000" }));
  await r.gateway.handleInbound("sms", sms);
  // link the SMS identity to the Slack user so both exchanges address the same end user's conversation
  const { code } = await r.identity.issueLinkCode(T1, "slack", "UALICE");
  await r.gateway.handleInbound(
    "sms",
    smsReq(smsParams({ from: "+15557770000", body: `link ${code}` })),
  );
  server = createDevServer({
    gateway: r.gateway,
    routes: r.table,
    store: r.store,
    identity: r.identity,
    hub: r.hub,
    authenticate: staticTokenAuthenticator({ tok: { tenantId: T1 } }),
  });
  const port = await listenLoopback(server);
  const sub = (v: unknown): unknown =>
    JSON.parse(JSON.stringify(v).replaceAll("{tenant}", T1).replaceAll("{conversation}", conv));
  for (const c of wire.send) {
    const res = await fetch(`http://127.0.0.1:${port}/v1/channels/send`, {
      method: "POST",
      headers: { authorization: "Bearer tok", "content-type": "application/json" },
      body: JSON.stringify(sub(c.request)),
    });
    expect(res.status, c.name).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(Object.keys(body).sort(), c.name).toEqual(Object.keys(c.response).sort());
  }
});
