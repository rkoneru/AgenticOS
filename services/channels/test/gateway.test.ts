import { describe, expect, it } from "vitest";
import { ChannelError, type RouteConfig } from "../src/index.js";
import { sha256Hex } from "../src/index.js";
import { MemoryAuditLog as Audit } from "@axis/audit";
import {
  AGENT,
  T1,
  T2,
  digestOf,
  emailReq,
  raw,
  rig,
  routes,
  slackReq,
  smsParams,
  smsReq,
  teamsReq,
  waBody,
  waReq,
  NOW,
} from "./helpers.js";

const slackRoute = (over: Partial<RouteConfig>): RouteConfig[] =>
  routes().map((r) => (r.channel === "slack" && r.tenant_id === T1 ? { ...r, ...over } : r));

describe("inbound pipeline", () => {
  it("accepts a signed Slack message: log + audit (hash/size/channel, never raw text) + handler", async () => {
    const r = rig();
    const res = await r.gateway.handleInbound(
      "slack",
      slackReq({ text: "my email is bob@example.com" }),
    );
    expect(res.reply.status).toBe(200);
    expect(res.outcomes).toHaveLength(1);
    const o = res.outcomes[0]!;
    if (o.kind !== "accepted") throw new Error("not accepted");
    const msgs = await r.store.messages(T1, o.conversation_id);
    expect(msgs).toHaveLength(1);
    expect(msgs[0]).toMatchObject({
      direction: "in",
      channel: "slack",
      content_mode: "redacted_preview",
      content: "my email is [email]",
      size_bytes: 27,
      content_hash: digestOf(T1, "text", "my email is bob@example.com"),
    });
    const events = await r.audit.events(T1);
    expect(events).toHaveLength(1);
    const e = events[0]!;
    expect(e).toMatchObject({
      action: "channel.inbound.message",
      decision: "ALLOW",
      enforcement_point: "lifecycle",
      actor: { type: "human" },
      blueprint: AGENT,
    });
    expect(e.reason).toContain("channel=slack");
    expect(e.reason).toContain(`hmac=${digestOf(T1, "text", "my email is bob@example.com")}`);
    expect(e.reason).not.toContain(sha256Hex("my email is bob@example.com"));
    expect(e.reason).toContain("size=27");
    expect(JSON.stringify(e)).not.toContain("bob@example.com");
    expect(JSON.stringify(e)).not.toContain("U111");
    expect(msgs[0]!.audit_hash).toBe(e.hash);
    expect(r.received).toEqual([
      { tenant: T1, text: "my email is bob@example.com", conv: o.conversation_id },
    ]);
  });

  it("a replayed (identical, validly signed) request is acknowledged but not processed again, and is audited", async () => {
    const r = rig();
    const req = slackReq({ eventId: "EvREPLAY" });
    const a = await r.gateway.handleInbound("slack", req);
    const b = await r.gateway.handleInbound("slack", req);
    expect(a.outcomes[0]!.kind).toBe("accepted");
    expect(b.outcomes[0]!.kind).toBe("duplicate");
    expect(b.reply.status).toBe(200);
    expect(r.received).toHaveLength(1);
    const events = await r.audit.events(T1);
    expect(events.map((e) => e.action)).toEqual([
      "channel.inbound.message",
      "channel.inbound.replayed",
    ]);
    expect(events[1]!.decision).toBe("DENY");
  });

  it("a request outside the timestamp window is rejected even though replay store is empty", async () => {
    const r = rig();
    const res = await r.gateway.handleInbound(
      "slack",
      slackReq({ ts: Math.floor(NOW / 1000) - 3600 }),
    );
    expect(res.reply.status).toBe(401);
    expect(res.rejected?.code).toBe("stale");
    expect(r.received).toHaveLength(0);
  });

  it("bad signature: 401, nothing stored, DENY audited under the CLAIMED route's tenant", async () => {
    const r = rig();
    const res = await r.gateway.handleInbound("slack", slackReq({ secret: "wrong" }));
    expect(res.reply.status).toBe(401);
    expect(res.reply.body).toBe('{"error":"rejected"}');
    const ev = await r.audit.events(T1);
    expect(ev).toHaveLength(1);
    expect(ev[0]).toMatchObject({ action: "channel.inbound.rejected", decision: "DENY" });
    expect(ev[0]!.reason).toContain("code=bad_signature");
    expect(await r.audit.events(T2)).toHaveLength(0);
    expect(r.received).toHaveLength(0);
  });

  it("unknown mapping: rejected, indistinguishable from a bad signature, audited only to the platform tenant when configured", async () => {
    const SYS = "99999999-9999-4999-8999-999999999999";
    const sys = new Audit();
    const r = rig({ systemAudit: { sink: sys, tenant_id: SYS } });
    const res = await r.gateway.handleInbound("slack", slackReq({ team: "T7777" }));
    expect(res.reply.status).toBe(401);
    expect(res.rejected?.code).toBe("unknown_route");
    expect(await r.audit.events(T1)).toHaveLength(0);
    expect(await r.audit.events(T2)).toHaveLength(0);
    const sysEvents = await sys.read(SYS);
    expect(sysEvents).toHaveLength(1);
    expect(sysEvents[0]!.reason).toContain("route=unknown");
    // without a system sink the rejection is only logged
    const r2 = rig();
    expect(
      (await r2.gateway.handleInbound("slack", slackReq({ team: "T7777" }))).reply.status,
    ).toBe(401);
  });

  it("rejection audits are rate limited so a forger cannot flood a tenant's chain", async () => {
    const r = rig();
    for (let i = 0; i < 50; i++)
      await r.gateway.handleInbound("slack", slackReq({ secret: "wrong" }));
    expect((await r.audit.events(T1)).length).toBe(20);
  });

  it("an audit failure fails closed: nothing stored, nothing delivered, and the provider's retry succeeds", async () => {
    const r = rig();
    const req = slackReq({ eventId: "EvAUDIT" });
    r.audit.fail = true;
    const res = await r.gateway.handleInbound("slack", req);
    expect(res.reply.status).toBe(503);
    expect(r.received).toHaveLength(0);
    r.audit.fail = false;
    const retry = await r.gateway.handleInbound("slack", req);
    expect(retry.outcomes[0]!.kind).toBe("accepted");
    expect(r.received).toHaveLength(1);
  });

  it("per-sender rate limit: 429 and the retry is accepted later", async () => {
    const r = rig({
      limits: { ...(await import("../src/index.js")).DEFAULT_LIMITS, inboundPerMinute: 2 },
    });
    const reqs = [1, 2, 3].map((i) => slackReq({ eventId: `Ev${i}` }));
    const codes: number[] = [];
    for (const q of reqs) codes.push((await r.gateway.handleInbound("slack", q)).reply.status);
    expect(codes).toEqual([200, 200, 429]);
    r.clock.advance(60_000);
    // signature timestamp window is 5 minutes; the rate-limited request is retried within it
    const retry = await r.gateway.handleInbound("slack", reqs[2]!);
    expect(retry.reply.status).toBe(200);
    expect(r.received).toHaveLength(3);
  });

  it("a throwing handler does not lose or duplicate the recorded message", async () => {
    const r = rig({
      onMessage: async () => {
        throw new Error("queue down");
      },
    });
    const res = await r.gateway.handleInbound("slack", slackReq());
    expect(res.outcomes[0]!.kind).toBe("accepted");
    expect(res.reply.status).toBe(200);
  });

  it("answers provider handshakes without creating anything", async () => {
    const r = rig();
    const wa = await r.gateway.handleInbound(
      "whatsapp",
      raw({
        method: "GET",
        query: {
          "hub.mode": "subscribe",
          "hub.verify_token": "wa-verify-token",
          "hub.challenge": "42",
        },
      }),
    );
    expect(wa.reply).toMatchObject({ status: 200, body: "42" });
    const bad = await r.gateway.handleInbound(
      "whatsapp",
      raw({
        method: "GET",
        query: { "hub.mode": "subscribe", "hub.verify_token": "nope", "hub.challenge": "42" },
      }),
    );
    expect(bad.reply.status).toBe(401);
  });

  it("oversize body, unknown channel, and adapter faults all fail closed", async () => {
    const r = rig();
    expect(
      (await r.gateway.handleInbound("slack", raw({ body: "x".repeat(300_000) }))).reply.status,
    ).toBe(413);
    const g = rig({ adapters: [] }).gateway;
    expect((await g.handleInbound("slack", slackReq())).reply.status).toBe(404);
    expect(() => g.adapter("slack")).toThrow(ChannelError);

    const boom = (phase: "verify" | "normalize") => ({
      channel: "slack" as const,
      capabilities: r.gateway.adapter("slack").capabilities,
      verifyInbound: async (q: never, c: never) => {
        if (phase === "verify") throw new Error("x");
        return r.gateway.adapter("slack").verifyInbound(q, c);
      },
      normalize: () => {
        throw new Error("y");
      },
      render: () => {
        throw new Error("z");
      },
    });
    for (const phase of ["verify", "normalize"] as const) {
      const rr = rig({ adapters: [boom(phase)] });
      const res = await rr.gateway.handleInbound("slack", slackReq());
      expect(res.reply.status).toBe(400);
    }
  });

  it("drops a message an adapter attributes to another tenant or channel", async () => {
    const r = rig();
    const real = r.gateway.adapter("slack");
    const rogue = {
      ...real,
      channel: "slack" as const,
      capabilities: real.capabilities,
      verifyInbound: real.verifyInbound.bind(real),
      render: real.render.bind(real),
      normalize: (v: never) => real.normalize(v).map((m) => ({ ...m, tenant_id: T2 })),
    };
    const rr = rig({ adapters: [rogue] });
    const res = await rr.gateway.handleInbound("slack", slackReq());
    expect(res.outcomes).toEqual([]);
    expect(await rr.audit.events(T2)).toHaveLength(0);
    expect(rr.received).toHaveLength(0);
  });
});

describe("tenant isolation of inbound state", () => {
  it("the same provider user id in two tenants yields two end users, conversations and chains", async () => {
    const r = rig();
    await r.gateway.handleInbound("slack", slackReq({ team: "T0001", user: "UX" }));
    await r.gateway.handleInbound(
      "slack",
      slackReq({ team: "T0002", user: "UX", secret: "slack-signing-secret-2", appId: "A0001" }),
    );
    expect(r.received.map((m) => m.tenant).sort()).toEqual([T1, T2]);
    expect(r.received[0]!.conv).not.toBe(r.received[1]!.conv);
    expect((await r.audit.events(T1)).length).toBe(1);
    expect((await r.audit.events(T2)).length).toBe(1);
    const i1 = await r.store.findIdentity(T1, "slack", "UX");
    const i2 = await r.store.findIdentity(T2, "slack", "UX");
    expect(i1!.end_user_id).not.toBe(i2!.end_user_id);
  });
});

describe("conversation continuity across channels", () => {
  it("a linked identity resumes the same conversation on another channel; an unlinked one does not", async () => {
    const r = rig();
    const a = await r.gateway.handleInbound(
      "slack",
      slackReq({ text: "I need a refund", user: "UALICE" }),
    );
    const convA = (a.outcomes[0] as { conversation_id: string }).conversation_id;

    // unlinked SMS from "the same person" starts a separate conversation: nothing links on a claim
    const s0 = await r.gateway.handleInbound(
      "sms",
      smsReq(smsParams({ body: "it is Alice from Slack, same person", from: "+15557770001" })),
    );
    const convS0 = (s0.outcomes[0] as { conversation_id: string }).conversation_id;
    expect(convS0).not.toBe(convA);

    // explicit link with proof: a code issued on the verified Slack identity, redeemed from the verified SMS identity
    const { code } = await r.identity.issueLinkCode(T1, "slack", "UALICE");
    const linked = await r.gateway.handleInbound(
      "sms",
      smsReq(smsParams({ body: `link ${code}`, from: "+15557770002" })),
    );
    expect(linked.outcomes[0]!.kind).toBe("linked");
    const s1 = await r.gateway.handleInbound(
      "sms",
      smsReq(smsParams({ body: "where is my refund?", from: "+15557770002" })),
    );
    const o = s1.outcomes[0] as { conversation_id: string };
    expect(o.conversation_id).toBe(convA);
    const history = await r.store.messages(T1, convA);
    expect(history.map((m) => m.channel)).toEqual(["slack", "sms"]);
    // the link code never reaches the log
    expect(JSON.stringify(history)).not.toContain(code);
    const actions = (await r.audit.events(T1)).map((e) => e.action);
    expect(actions).toContain("channel.identity.link");
    expect((await r.audit.events(T1)).every((e) => !JSON.stringify(e).includes(code))).toBe(true);
  });

  it("a wrong, replayed or cross-tenant link code is refused and links nothing", async () => {
    const r = rig();
    await r.gateway.handleInbound("slack", slackReq({ user: "UALICE" }));
    const { code } = await r.identity.issueLinkCode(T1, "slack", "UALICE");
    const bad = await r.gateway.handleInbound(
      "sms",
      smsReq(smsParams({ body: "link ABCDEFGHJK", from: "+15557770003" })),
    );
    expect(bad.outcomes[0]).toEqual({ kind: "link_failed", reason: "invalid" });
    // the T2 Slack workspace cannot redeem a T1 code
    const cross = await r.gateway.handleInbound(
      "slack",
      slackReq({
        team: "T0002",
        secret: "slack-signing-secret-2",
        text: `link ${code}`,
        user: "UEVE",
      }),
    );
    expect(cross.outcomes[0]).toEqual({ kind: "link_failed", reason: "invalid" });
    expect((await r.store.findIdentity(T2, "slack", "UEVE"))!.verified_by).toBe("provider");
    const ok = await r.gateway.handleInbound(
      "sms",
      smsReq(smsParams({ body: `link ${code}`, from: "+15557770004" })),
    );
    expect(ok.outcomes[0]!.kind).toBe("linked");
    const again = await r.gateway.handleInbound(
      "sms",
      smsReq(smsParams({ body: `link ${code}`, from: "+15557770005" })),
    );
    expect(again.outcomes[0]).toEqual({ kind: "link_failed", reason: "consumed" });
  });

  it("a Slack thread hint resumes the thread's conversation for the same user only", async () => {
    const r = rig();
    const a1 = await r.gateway.handleInbound(
      "slack",
      slackReq({ user: "UA", thread: "1700000000.000001" }),
    );
    const a2 = await r.gateway.handleInbound(
      "slack",
      slackReq({ user: "UA", thread: "1700000000.000001" }),
    );
    const b = await r.gateway.handleInbound(
      "slack",
      slackReq({ user: "UB", thread: "1700000000.000001" }),
    );
    const id = (x: typeof a1): string =>
      (x.outcomes[0] as { conversation_id: string }).conversation_id;
    expect(id(a2)).toBe(id(a1));
    expect(id(b)).not.toBe(id(a1));
    expect((await r.store.messages(T1, id(a1))).every((m) => m.direction === "in")).toBe(true);
  });
});

describe("other channels end to end", () => {
  it("email, whatsapp, teams, sms and web all land in the log with their channel", async () => {
    const r = rig();
    const { issueWebSession } = await import("../src/index.js");
    const webRoute = routes().find((x) => x.channel === "web")!;
    const tok = issueWebSession(webRoute, { nowMs: NOW, sid: "sid-abcdefghijklmnop" });
    const results = [
      await r.gateway.handleInbound("email", emailReq({})),
      await r.gateway.handleInbound("whatsapp", waReq(waBody({}))),
      await r.gateway.handleInbound("teams", teamsReq()),
      await r.gateway.handleInbound("sms", smsReq(smsParams())),
      await r.gateway.handleInbound(
        "web",
        raw({
          headers: { authorization: `Bearer ${tok}`, origin: "https://app.example.test" },
          body: JSON.stringify({ text: "hello web", client_message_id: "cm-00000001" }),
        }),
      ),
    ];
    expect(results.map((x) => x.reply.status)).toEqual([200, 200, 200, 200, 200]);
    expect(results.map((x) => x.outcomes[0]!.kind)).toEqual(Array(5).fill("accepted"));
    expect((await r.audit.events(T1)).map((e) => /channel=(\w+)/.exec(e.reason ?? "")![1])).toEqual(
      ["email", "whatsapp", "teams", "sms", "web"],
    );
    expect(results[3]!.reply.body).toBe("<Response></Response>");
  });

  it("email loop suppression produces no turn and no reply path", async () => {
    const r = rig();
    const res = await r.gateway.handleInbound(
      "email",
      emailReq({ headers: { "auto-submitted": "auto-generated" } }),
    );
    expect(res.outcomes).toEqual([]);
    expect(r.received).toHaveLength(0);
  });
});

describe("transcript policy", () => {
  const run = async (routeOver: Partial<RouteConfig>, hook?: (t: string) => string) => {
    const rs = slackRoute(routeOver);
    const r = rig({ ...(hook ? { redactionHook: hook } : {}) }, rs);
    const res = await r.gateway.handleInbound(
      "slack",
      slackReq({ text: "Jane Doe jane@example.com" }),
    );
    const id = (res.outcomes[0] as { conversation_id: string }).conversation_id;
    return (await r.store.messages(T1, id))[0]!;
  };
  it("hash_only keeps no text", async () => {
    const m = await run({ transcript: { mode: "hash_only" } });
    expect(m.content).toBeNull();
    expect(m.content_mode).toBe("hash_only");
  });
  it("full keeps raw text outside PHI mode", async () => {
    expect((await run({ transcript: { mode: "full" } })).content).toBe("Jane Doe jane@example.com");
  });
  it("PHI mode forces redaction and the hook, capping full at a preview", async () => {
    const m = await run({ transcript: { mode: "full" }, phi: true }, (t) =>
      t.replace("Jane Doe", "[name]"),
    );
    expect(m).toMatchObject({ content_mode: "redacted_preview", content: "[name] [email]" });
  });
});

describe("outbound send (the perform half)", () => {
  const setup = async () => {
    const r = rig();
    const a = await r.gateway.handleInbound(
      "slack",
      slackReq({ user: "UALICE", text: "hi", thread: "1700000000.000009", channel: "C555" }),
    );
    const conv = (a.outcomes[0] as { conversation_id: string }).conversation_id;
    return { r, conv };
  };

  it("replies in the Slack thread: audit BEFORE perform, then log; text hashed in audit", async () => {
    const { r, conv } = await setup();
    const res = await r.gateway.send(T1, {
      channel: "slack",
      conversation_id: conv,
      text: "Sure, <!channel> let me check",
      run_id: "run-1",
    });
    expect(res).toMatchObject({ conversation_id: conv, parts: 1, duplicate: false });
    expect(r.http.calls).toHaveLength(1);
    const body = JSON.parse(r.http.calls[0]!.body);
    expect(body).toMatchObject({
      channel: "C555",
      thread_ts: "1700000000.000009",
      text: "Sure, &lt;!channel&gt; let me check",
    });
    const ev = (await r.audit.events(T1)).filter((e) => e.action === "channel.outbound.message");
    expect(ev).toHaveLength(1);
    expect(ev[0]).toMatchObject({
      enforcement_point: "message_send",
      decision: "ALLOW",
      actor: { type: "system" },
    });
    expect(ev[0]!.reason).toContain("run=run-1");
    expect(JSON.stringify(ev[0])).not.toContain("let me check");
    const log = await r.store.messages(T1, conv);
    expect(log.map((m) => m.direction)).toEqual(["in", "out"]);
    expect(log[1]!.audit_hash).toBe(ev[0]!.hash);
  });

  it("audit failure means NO send", async () => {
    const { r, conv } = await setup();
    r.audit.fail = true;
    await expect(
      r.gateway.send(T1, { channel: "slack", conversation_id: conv, text: "x" }),
    ).rejects.toMatchObject({ code: "AUDIT_FAILED" });
    expect(r.http.calls).toHaveLength(0);
  });

  it("provider refusal: error, failure audited, retry with the same key is allowed", async () => {
    const { r, conv } = await setup();
    r.http.respond = () => ({ status: 200, body: '{"ok":false,"error":"channel_not_found"}' });
    await expect(
      r.gateway.send(T1, {
        channel: "slack",
        conversation_id: conv,
        text: "x",
        idempotency_key: "k1",
      }),
    ).rejects.toMatchObject({ code: "TRANSPORT" });
    expect((await r.audit.events(T1)).some((e) => e.action === "channel.outbound.failed")).toBe(
      true,
    );
    expect((await r.store.messages(T1, conv)).filter((m) => m.direction === "out")).toHaveLength(0);
    r.http.respond = () => ({ status: 200, body: '{"ok":true}' });
    const ok = await r.gateway.send(T1, {
      channel: "slack",
      conversation_id: conv,
      text: "x",
      idempotency_key: "k1",
    });
    expect(ok.duplicate).toBe(false);
    const again = await r.gateway.send(T1, {
      channel: "slack",
      conversation_id: conv,
      text: "x",
      idempotency_key: "k1",
    });
    expect(again.duplicate).toBe(true);
    expect(r.http.calls.filter((c) => c.body.includes('"text":"x"'))).toHaveLength(2); // one failed + one successful, never three
  });

  it("a transport that throws is reported as TRANSPORT without leaking its message", async () => {
    const { r, conv } = await setup();
    r.http.respond = () => {
      throw new Error("ECONNRESET secret-host");
    };
    await expect(
      r.gateway.send(T1, { channel: "slack", conversation_id: conv, text: "x" }),
    ).rejects.toThrow(/transport failure/);
  });

  it("cannot address another tenant's conversation, nor a destination of another end user", async () => {
    const { r, conv } = await setup();
    await expect(
      r.gateway.send(T2, { channel: "slack", conversation_id: conv, text: "x" }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
    await r.gateway.handleInbound("slack", slackReq({ user: "UBOB", text: "hello" }));
    await expect(
      r.gateway.send(T1, { channel: "slack", conversation_id: conv, to: "UBOB", text: "x" }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(r.http.calls).toHaveLength(0);
  });

  it("refuses unknown destinations unless the route allows unsolicited messages", async () => {
    const rs = routes().map((x) =>
      x.channel === "sms" ? { ...x, settings: { ...x.settings, allow_unsolicited: true } } : x,
    );
    const r = rig({}, rs);
    await expect(
      r.gateway.send(T1, { channel: "slack", to: "UNEW", text: "x" }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    const sent = await r.gateway.send(T1, { channel: "sms", to: "+15558889999", text: "promo" });
    expect(sent.conversation_id).toBeNull();
    expect(r.http.calls).toHaveLength(1);
    expect(r.http.calls[0]!.url).toContain("api.twilio.com");
  });

  it("validates the request and the route", async () => {
    const { r, conv } = await setup();
    await expect(
      r.gateway.send(T1, { channel: "slack", conversation_id: conv, text: "" }),
    ).rejects.toMatchObject({ code: "INVALID" });
    await expect(r.gateway.send(T1, { channel: "slack", text: "x" })).rejects.toMatchObject({
      code: "INVALID",
    });
    await expect(
      r.gateway.send(T1, {
        channel: "slack",
        conversation_id: "00000000-0000-4000-8000-000000000000",
        text: "x",
      }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
    await expect(
      r.gateway.send(T1, { channel: "slack", conversation_id: conv, text: "x".repeat(40_000) }),
    ).rejects.toMatchObject({ code: "TOO_LONG" });
    await expect(
      r.gateway.send(T1, { channel: "slack", conversation_id: conv, text: "x".repeat(20_000) }),
    ).rejects.toMatchObject({ code: "TOO_LONG" }); // > 5 parts of 3000
    await expect(
      r.gateway.send(T1, { channel: "sms", conversation_id: conv, text: "x" }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" }); // no sms identity
    await expect(
      r.gateway.send(T1, { channel: "slack", conversation_id: conv, text: "x", from: "T9999" }),
    ).rejects.toMatchObject({ code: "UNKNOWN_ROUTE" });
    await expect(
      r.gateway.send(T1, { channel: "web", conversation_id: conv, text: "x" }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
    const none = rig({ adapters: [] });
    await expect(
      none.gateway.send(T1, { channel: "slack", text: "x", to: "U1" }),
    ).rejects.toMatchObject({ code: "INVALID" });
    expect(r.http.calls).toHaveLength(0);
  });

  it("splits long text into numbered-safe parts and sends each once", async () => {
    const { r, conv } = await setup();
    const res = await r.gateway.send(T1, {
      channel: "slack",
      conversation_id: conv,
      text: `${"word ".repeat(1500)}`.trim(),
    });
    expect(res.parts).toBe(3);
    expect(r.http.calls).toHaveLength(3);
    expect(res.message_ids).toHaveLength(3);
  });

  it("outbound rate limit per route", async () => {
    const { r, conv } = await setup();
    for (let i = 0; i < 60; i++)
      await r.gateway.send(T1, { channel: "slack", conversation_id: conv, text: `m${i}` });
    await expect(
      r.gateway.send(T1, { channel: "slack", conversation_id: conv, text: "one more" }),
    ).rejects.toMatchObject({ code: "RATE_LIMITED" });
  });

  it("ambiguous routes need `from`", async () => {
    const rs = [
      ...routes(),
      {
        ...routes()[0]!,
        provider_key: "T0003",
        secrets: { signing_secret: "s3", bot_token: "xoxb-3" },
      },
    ];
    const r = rig({}, rs);
    await r.gateway.handleInbound("slack", slackReq({ user: "UALICE" }));
    await expect(
      r.gateway.send(T1, { channel: "slack", to: "UALICE", text: "x" }),
    ).rejects.toMatchObject({ code: "UNKNOWN_ROUTE" });
    await r.gateway.send(T1, { channel: "slack", to: "UALICE", text: "x", from: "T0003" });
    expect(r.http.calls[0]!.headers["authorization"]).toBe("Bearer xoxb-3");
  });

  it("email, whatsapp, teams, sms and web outbound", async () => {
    const r = rig();
    const { issueWebSession } = await import("../src/index.js");
    const webRoute = routes().find((x) => x.channel === "web")!;
    const tok = issueWebSession(webRoute, { nowMs: NOW, sid: "sid-abcdefghijklmnop" });
    const rawWeb = raw({
      headers: { authorization: `Bearer ${tok}`, origin: "https://app.example.test" },
      body: JSON.stringify({ text: "hello web", client_message_id: "cm-00000001" }),
    });
    await r.gateway.handleInbound("email", emailReq({ mid: "<m9@example.org>" }));
    await r.gateway.handleInbound("whatsapp", waReq(waBody({})));
    await r.gateway.handleInbound("teams", teamsReq());
    await r.gateway.handleInbound("sms", smsReq(smsParams()));
    await r.gateway.handleInbound("web", rawWeb);

    const seen: unknown[] = [];
    const un = r.hub.subscribe(T1, "sid-abcdefghijklmnop", (e) => seen.push(e));
    await r.gateway.send(T1, {
      channel: "email",
      to: "alice@example.org",
      text: "e-reply",
      subject: "Re: Help",
    });
    await r.gateway.send(T1, { channel: "whatsapp", to: "15557770000", text: "w-reply" });
    await r.gateway.send(T1, { channel: "teams", to: "aad-user-1", text: "t-reply" });
    await r.gateway.send(T1, { channel: "sms", to: "+15557770000", text: "s-reply" });
    await r.gateway.send(T1, { channel: "web", to: "sid-abcdefghijklmnop", text: "web-reply" });
    un();
    expect(r.email.sent).toHaveLength(1);
    expect(r.email.sent[0]!.raw).toContain("In-Reply-To: <m9@example.org>");
    expect(r.http.calls.map((c) => new URL(c.url).hostname)).toEqual([
      "graph.facebook.com",
      "smba.trafficmanager.net",
      "api.twilio.com",
    ]);
    expect(r.http.calls[1]!.url).toContain("19%3Aconv%40thread.v2");
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ type: "message", data: { text: "web-reply" } });
    // another tenant never receives the stream
    const other: unknown[] = [];
    r.hub.subscribe(T2, "sid-abcdefghijklmnop", (e) => other.push(e));
    await r.gateway.send(T1, { channel: "web", to: "sid-abcdefghijklmnop", text: "again" });
    expect(other).toHaveLength(0);
  });

  it("Teams needs a conversation reference learned from an inbound activity", async () => {
    const r = rig();
    await r.gateway.handleInbound("sms", smsReq(smsParams()));
    const rs = routes();
    const r2 = rig({}, rs);
    await r2.identity.resolve(T1, "teams", "aad-nobody");
    await expect(
      r2.gateway.send(T1, { channel: "teams", to: "aad-nobody", text: "x" }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(r.http.calls).toHaveLength(0);
  });

  it("email without a transport or a hub-less web send is a TRANSPORT error", async () => {
    const r = rig({ email: undefined, hub: undefined });
    await r.gateway.handleInbound("email", emailReq({}));
    await expect(
      r.gateway.send(T1, { channel: "email", to: "alice@example.org", text: "x" }),
    ).rejects.toMatchObject({ code: "TRANSPORT" });
    const { issueWebSession } = await import("../src/index.js");
    const tok = issueWebSession(
      routes().find((x) => x.channel === "web")!,
      { nowMs: NOW, sid: "sid-abcdefghijklmnop" },
    );
    await r.gateway.handleInbound(
      "web",
      raw({
        headers: { authorization: `Bearer ${tok}`, origin: "https://app.example.test" },
        body: JSON.stringify({ text: "hello web", client_message_id: "cm-00000001" }),
      }),
    );
    await expect(
      r.gateway.send(T1, { channel: "web", to: "sid-abcdefghijklmnop", text: "x" }),
    ).rejects.toMatchObject({ code: "TRANSPORT" });
  });

  it("email transport failure is reported and audited", async () => {
    const r = rig();
    await r.gateway.handleInbound("email", emailReq({}));
    r.email.fail = true;
    await expect(
      r.gateway.send(T1, { channel: "email", to: "alice@example.org", text: "x" }),
    ).rejects.toMatchObject({ code: "TRANSPORT" });
    expect((await r.audit.events(T1)).some((e) => e.action === "channel.outbound.failed")).toBe(
      true,
    );
  });

  it("trace ids supplied by the runtime are carried into the audit event", async () => {
    const { r, conv } = await setup();
    const trace = "ab".repeat(16);
    await r.gateway.send(T1, {
      channel: "slack",
      conversation_id: conv,
      text: "x",
      trace_id: trace,
      agent: { name: "other", version: "2" },
    });
    const ev = (await r.audit.events(T1)).find((e) => e.action === "channel.outbound.message")!;
    expect(ev.trace_id).toBe(trace);
    expect(ev.blueprint).toEqual({ name: "other", version: "2" });
  });
});
