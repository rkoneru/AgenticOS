import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  EmailAdapter,
  SlackAdapter,
  SmsAdapter,
  StaticRoutingTable,
  TeamsAdapter,
  WebAdapter,
  WhatsAppAdapter,
  hmacSha256Hex,
  issueWebSession,
  slackEscape,
  verifyWebSession,
  type RawRequest,
  type Reject,
  type VerifiedInbound,
  type VerifyContext,
} from "../src/index.js";
import {
  AGENT,
  EMAIL_SECRET,
  NOW,
  SLACK_SECRET,
  T1,
  T2,
  WA_SECRET,
  WA_VERIFY,
  WEB_SECRET,
  emailReq,
  goodClaims,
  jwks,
  otherRsa,
  raw,
  routes,
  signJwt,
  slackReq,
  smsParams,
  smsReq,
  teamsReq,
  waBody,
  waReq,
} from "./helpers.js";

const ctx = (over: Partial<VerifyContext> = {}): VerifyContext => ({
  routes: new StaticRoutingTable(routes()),
  nowMs: NOW,
  ...over,
});
const ok = (v: Reject | VerifiedInbound): VerifiedInbound => {
  if (!v.ok) throw new Error(`rejected: ${v.code} ${v.reason}`);
  return v;
};
const code = (v: Reject | VerifiedInbound): string => (v.ok ? "ok" : v.code);

describe("Slack", () => {
  const a = new SlackAdapter();
  it("verifies and normalises a message event; tenant/agent come from the route", async () => {
    const v = ok(
      await a.verifyInbound(
        slackReq({ text: "<@UBOT> hi there", thread: "1700000000.000050" }),
        ctx(),
      ),
    );
    const [m] = a.normalize(v);
    expect(m).toMatchObject({
      tenant_id: T1,
      channel: "slack",
      agent: AGENT,
      external_user_id: "U111",
      text: "hi there",
      conversation_hint: "C999:1700000000.000050",
    });
    expect(m!.idempotency_key).toMatch(/^slack:Ev/);
  });
  it("rejects a bad signature, wrong secret, missing headers, bad timestamp shapes", async () => {
    expect(code(await a.verifyInbound(slackReq({ secret: "wrong" }), ctx()))).toBe("bad_signature");
    const r = slackReq();
    expect(code(await a.verifyInbound({ ...r, headers: {} }, ctx()))).toBe("bad_signature");
    expect(
      code(
        await a.verifyInbound(
          { ...r, headers: { ...r.headers, "x-slack-request-timestamp": "12.5" } },
          ctx(),
        ),
      ),
    ).toBe("bad_signature");
    expect(
      code(
        await a.verifyInbound(
          { ...r, body: Buffer.from(r.body.toString().replace("hello", "hellp")) },
          ctx(),
        ),
      ),
    ).toBe("bad_signature");
  });
  it("a request signed with ANOTHER tenant's secret does not verify for the claimed workspace", async () => {
    const r = await a.verifyInbound(
      slackReq({ team: "T0001", secret: "slack-signing-secret-2" }),
      ctx(),
    );
    expect(code(r)).toBe("bad_signature");
  });
  it("replay window: stale and future timestamps are rejected AFTER a valid signature", async () => {
    expect(code(await a.verifyInbound(slackReq({ ts: Math.floor(NOW / 1000) - 301 }), ctx()))).toBe(
      "stale",
    );
    expect(code(await a.verifyInbound(slackReq({ ts: Math.floor(NOW / 1000) + 301 }), ctx()))).toBe(
      "stale",
    );
    expect(code(await a.verifyInbound(slackReq({ ts: Math.floor(NOW / 1000) - 299 }), ctx()))).toBe(
      "ok",
    );
  });
  it("unknown workspace / disabled route / wrong app id / non-event payload", async () => {
    expect(code(await a.verifyInbound(slackReq({ team: "T9999" }), ctx()))).toBe("unknown_route");
    const rs = routes();
    rs[0] = { ...rs[0]!, enabled: false };
    expect(
      code(await a.verifyInbound(slackReq(), ctx({ routes: new StaticRoutingTable(rs) }))),
    ).toBe("route_disabled");
    expect(code(await a.verifyInbound(slackReq({ appId: "AEVIL" }), ctx()))).toBe("bad_signature");
    const body = JSON.stringify({
      type: "app_rate_limited",
      team_id: "T0001",
      api_app_id: "A0001",
    });
    const ts = String(Math.floor(NOW / 1000));
    const sig = `v0=${hmacSha256Hex(SLACK_SECRET, `v0:${ts}:${body}`)}`;
    expect(
      code(
        await a.verifyInbound(
          raw({ headers: { "x-slack-request-timestamp": ts, "x-slack-signature": sig }, body }),
          ctx(),
        ),
      ),
    ).toBe("unsupported");
  });
  it("body hygiene: method, size, json", async () => {
    expect(code(await a.verifyInbound(raw({ method: "GET" }), ctx()))).toBe("unsupported");
    expect(code(await a.verifyInbound(raw({ body: "x".repeat(300_000) }), ctx()))).toBe(
      "too_large",
    );
    expect(code(await a.verifyInbound(raw({ body: "{not json" }), ctx()))).toBe("malformed");
    expect(code(await a.verifyInbound(raw({ body: "[]" }), ctx()))).toBe("malformed");
  });
  it("url_verification is answered only if a configured app's secret signed it", async () => {
    const mk = (secret: string, ts = Math.floor(NOW / 1000)): RawRequest => {
      const body = JSON.stringify({ type: "url_verification", challenge: "abc123", token: "x" });
      return raw({
        headers: {
          "x-slack-request-timestamp": String(ts),
          "x-slack-signature": `v0=${hmacSha256Hex(secret, `v0:${ts}:${body}`)}`,
        },
        body,
      });
    };
    const v = ok(await a.verifyInbound(mk(SLACK_SECRET), ctx()));
    expect(v.reply).toMatchObject({ status: 200, body: "abc123" });
    expect(code(await a.verifyInbound(mk("nope"), ctx()))).toBe("bad_signature");
    expect(
      code(await a.verifyInbound(mk(SLACK_SECRET, Math.floor(NOW / 1000) - 1000), ctx())),
    ).toBe("stale");
    const body = JSON.stringify({ type: "url_verification", challenge: "x".repeat(600) });
    expect(code(await a.verifyInbound(raw({ body }), ctx()))).toBe("malformed");
    expect(
      code(
        await a.verifyInbound(raw({ body: JSON.stringify({ type: "url_verification" }) }), ctx()),
      ),
    ).toBe("malformed");
  });
  it("ignores bots, edits, other event types and oversize text; keeps file metadata only", async () => {
    const norm = async (extra: Record<string, unknown>, text = "hi") =>
      a.normalize(ok(await a.verifyInbound(slackReq({ extra, text }), ctx())));
    expect(await norm({ bot_id: "B1" })).toEqual([]);
    expect(await norm({ subtype: "message_changed" })).toEqual([]);
    expect(await norm({ type: "reaction_added" })).toEqual([]);
    expect(await norm({}, "x".repeat(9000))).toEqual([]);
    expect(await norm({ user: undefined })).toEqual([]);
    const withFiles = await norm({
      subtype: "file_share",
      files: [
        {
          id: "F1",
          name: "a.png",
          mimetype: "image/png",
          size: 5,
          url_private: "https://evil.example/x",
        },
        { id: "F2", name: "x.exe", mimetype: "application/x-msdownload", size: 5 },
      ],
    });
    expect(withFiles[0]!.attachments).toEqual([
      { name: "a.png", content_type: "image/png", size: 5, ref: "F1" },
    ]);
    expect(withFiles[0]!.dropped_attachments).toBe(1);
    expect(JSON.stringify(withFiles)).not.toContain("evil.example");
    expect(a.normalize({ ok: true, route: routes()[0]!, payload: undefined })).toEqual([]);
    expect(
      a.normalize({ ok: true, route: routes()[0]!, payload: { event: { type: "message" } } }),
    ).toEqual([]);
  });
  it("renders a safe chat.postMessage (mentions escaped, ids validated)", () => {
    const route = routes()[0]!;
    const c = a.render(
      {
        channel: "slack",
        to: "C999",
        text: "hey <!channel> <@U1> & co",
        thread: "C999:1700000000.000100",
      },
      route,
    );
    expect(c.kind).toBe("http");
    if (c.kind !== "http") return;
    expect(c.url).toBe("https://slack.com/api/chat.postMessage");
    expect(c.headers["authorization"]).toBe("Bearer xoxb-1");
    expect(JSON.parse(c.body)).toMatchObject({
      channel: "C999",
      text: "hey &lt;!channel&gt; &lt;@U1&gt; &amp; co",
      thread_ts: "1700000000.000100",
      link_names: false,
    });
    expect(() => a.render({ channel: "slack", to: "c9/../x", text: "x" }, route)).toThrow(
      /destination/,
    );
    expect(() => a.render({ channel: "slack", to: "C9", text: "x", thread: "bad" }, route)).toThrow(
      /thread/,
    );
    expect(() =>
      a.render({ channel: "slack", to: "C9", text: "x" }, { ...route, secrets: {} }),
    ).toThrow(/bot_token/);
    expect(slackEscape("<>&")).toBe("&lt;&gt;&amp;");
  });
  it("responseOk reads Slack's ok flag", () => {
    expect(a.responseOk(200, '{"ok":true}')).toBe(true);
    expect(a.responseOk(200, '{"ok":false}')).toBe(false);
    expect(a.responseOk(200, "garbage")).toBe(false);
    expect(a.responseOk(500, '{"ok":true}')).toBe(false);
  });
  it("property: flipping any single byte of the signed body is rejected", async () => {
    const base = slackReq({ eventId: "Evfixed" });
    await fc.assert(
      fc.asyncProperty(fc.nat(), fc.integer({ min: 1, max: 255 }), async (i, x) => {
        const body = Buffer.from(base.body);
        body[i % body.length] = body[i % body.length]! ^ x;
        const r = await a.verifyInbound({ ...base, body }, ctx());
        expect(r.ok).toBe(false);
      }),
      { numRuns: 120 },
    );
  });
});

describe("Teams", () => {
  const a = new TeamsAdapter({ jwks });
  it("verifies the JWT against the route's app id and strips mention markup", async () => {
    const v = ok(await a.verifyInbound(teamsReq(), ctx()));
    const [m] = a.normalize(v);
    expect(m).toMatchObject({
      tenant_id: T1,
      channel: "teams",
      external_user_id: "aad-user-1",
      conversation_hint: "19:conv@thread.v2",
      text: "hi from teams",
    });
  });
  it("rejects missing / malformed / foreign / wrong-audience / expired tokens", async () => {
    expect(code(await a.verifyInbound(raw({ body: teamsReq().body }), ctx()))).toBe(
      "bad_signature",
    );
    expect(code(await a.verifyInbound(teamsReq({ token: "x.y" }), ctx()))).toBe("bad_signature");
    expect(
      code(
        await a.verifyInbound(teamsReq({ token: signJwt(goodClaims(), { kp: otherRsa }) }), ctx()),
      ),
    ).toBe("bad_signature");
    expect(
      code(
        await a.verifyInbound(
          teamsReq({ token: signJwt(goodClaims(NOW, { aud: "other-app" })) }),
          ctx(),
        ),
      ),
    ).toBe("bad_signature");
    expect(
      code(
        await a.verifyInbound(
          teamsReq({ token: signJwt(goodClaims(NOW, { exp: NOW / 1000 - 1000 })) }),
          ctx(),
        ),
      ),
    ).toBe("stale");
    expect(
      code(
        await a.verifyInbound(
          teamsReq({ token: signJwt(goodClaims(NOW, { nbf: NOW / 1000 + 1000 })) }),
          ctx(),
        ),
      ),
    ).toBe("stale");
  });
  it("binds the token to the activity's serviceUrl and the activity timestamp window", async () => {
    expect(
      code(
        await a.verifyInbound(
          teamsReq({ activity: { serviceUrl: "https://evil.example/" } }),
          ctx(),
        ),
      ),
    ).toBe("bad_signature");
    expect(
      code(
        await a.verifyInbound(
          teamsReq({ activity: { timestamp: new Date(NOW - 3_600_000).toISOString() } }),
          ctx(),
        ),
      ),
    ).toBe("stale");
    const noClaim = signJwt(goodClaims(NOW, { serviceurl: undefined }));
    expect(code(await a.verifyInbound(teamsReq({ token: noClaim }), ctx()))).toBe("ok");
  });
  it("route is chosen by the claimed bot id; unknown bot is unknown_route", async () => {
    expect(
      code(await a.verifyInbound(teamsReq({ activity: { recipient: { id: "28:nope" } } }), ctx())),
    ).toBe("unknown_route");
    expect(
      code(await a.verifyInbound(teamsReq({ activity: { recipient: { id: "app-id-1" } } }), ctx())),
    ).toBe("ok");
    expect(
      code(await a.verifyInbound(teamsReq({ activity: { recipient: undefined } }), ctx())),
    ).toBe("unknown_route");
    expect(code(await a.verifyInbound(raw({ method: "GET" }), ctx()))).toBe("unsupported");
    expect(code(await a.verifyInbound(raw({ body: "x" }), ctx()))).toBe("malformed");
  });
  it("normalize ignores non-message activities and drops attachment URLs", async () => {
    const mk = async (activity: Record<string, unknown>) =>
      a.normalize(ok(await a.verifyInbound(teamsReq({ activity }), ctx())));
    expect(await mk({ type: "conversationUpdate" })).toEqual([]);
    expect(await mk({ id: undefined })).toEqual([]);
    expect(await mk({ text: "x".repeat(9000) })).toEqual([]);
    const withAtt = await mk({
      attachments: [
        { contentType: "image/png", name: "p.png", contentUrl: "https://evil.example/p.png" },
      ],
    });
    expect(withAtt[0]!.attachments).toHaveLength(1);
    expect(JSON.stringify(withAtt)).not.toContain("evil.example");
    expect(a.normalize({ ok: true, route: routes()[0]!, payload: undefined })).toEqual([]);
  });
  it("renders to the route's configured service URL only", () => {
    const route = routes().find((r) => r.channel === "teams")!;
    const c = a.render(
      { channel: "teams", to: "19:conv@thread.v2", text: "yo", thread: "act-1" },
      route,
    );
    if (c.kind !== "http") throw new Error("kind");
    expect(c.url).toBe(
      "https://smba.trafficmanager.net/emea/v3/conversations/19%3Aconv%40thread.v2/activities",
    );
    expect(JSON.parse(c.body)).toMatchObject({ type: "message", text: "yo", replyToId: "act-1" });
    expect(() => a.render({ channel: "teams", to: "../../x", text: "x" }, route)).toThrow(
      /conversation id/,
    );
    expect(() =>
      a.render(
        { channel: "teams", to: "19:c", text: "x" },
        { ...route, settings: { service_url: "http://x/" } },
      ),
    ).toThrow(/service_url/);
    expect(() =>
      a.render({ channel: "teams", to: "19:c", text: "x" }, { ...route, secrets: {} }),
    ).toThrow(/access_token/);
  });
});

describe("Email", () => {
  const a = new EmailAdapter();
  it("verifies the HMAC + timestamp and normalises; sender is the parsed address", async () => {
    const v = ok(
      await a.verifyInbound(
        emailReq({ subject: "Order", text: "where is it", mid: "<m1@example.org>" }),
        ctx(),
      ),
    );
    const [m] = a.normalize(v);
    expect(m).toMatchObject({
      tenant_id: T1,
      channel: "email",
      external_user_id: "alice@example.org",
      conversation_hint: "<m1@example.org>",
      text: "Order\n\nwhere is it",
      idempotency_key: "email:<m1@example.org>",
    });
  });
  it("threads by References root", async () => {
    const v = ok(
      await a.verifyInbound(
        emailReq({
          headers: {
            references: "<root@example.org> <mid@example.org>",
            "in-reply-to": "<mid@example.org>",
          },
        }),
        ctx(),
      ),
    );
    expect(a.normalize(v)[0]!.conversation_hint).toBe("<root@example.org>");
  });
  it("rejects bad/missing signatures, stale timestamps, unknown mailboxes", async () => {
    expect(code(await a.verifyInbound(emailReq({ secret: "x" }), ctx()))).toBe("bad_signature");
    const r = emailReq();
    expect(code(await a.verifyInbound({ ...r, headers: {} }, ctx()))).toBe("bad_signature");
    expect(
      code(
        await a.verifyInbound(
          { ...r, headers: { ...r.headers, "x-axis-timestamp": "abc" } },
          ctx(),
        ),
      ),
    ).toBe("bad_signature");
    expect(
      code(
        await a.verifyInbound(
          { ...r, body: Buffer.from(r.body.toString().replace("help", "HELP")) },
          ctx(),
        ),
      ),
    ).toBe("bad_signature");
    expect(code(await a.verifyInbound(emailReq({ ts: Math.floor(NOW / 1000) - 400 }), ctx()))).toBe(
      "stale",
    );
    expect(code(await a.verifyInbound(emailReq({ to: "nobody@axis.example" }), ctx()))).toBe(
      "unknown_route",
    );
    const rs = routes();
    rs[2] = { ...rs[2]!, enabled: false };
    expect(
      code(await a.verifyInbound(emailReq(), ctx({ routes: new StaticRoutingTable(rs) }))),
    ).toBe("route_disabled");
    expect(code(await a.verifyInbound(raw({ method: "PUT" }), ctx()))).toBe("unsupported");
    expect(
      code(await a.verifyInbound(raw({ body: JSON.stringify({ to: ["bad\r\n@x"] }) }), ctx())),
    ).toBe("unknown_route");
  });
  it("suppresses auto-replies, bulk mail, bounces, our own mailbox and bad senders", async () => {
    const norm = async (o: Parameters<typeof emailReq>[0]) =>
      a.normalize(ok(await a.verifyInbound(emailReq(o), ctx())));
    expect(await norm({ headers: { "auto-submitted": "auto-replied" } })).toEqual([]);
    expect(await norm({ headers: { precedence: "bulk" } })).toEqual([]);
    expect(await norm({ from: "MAILER-DAEMON@example.org" })).toEqual([]);
    expect(await norm({ from: "support@axis.example" })).toEqual([]);
    expect(await norm({ from: "not an address" })).toEqual([]);
    expect(await norm({ text: "x".repeat(9000) })).toEqual([]);
    expect(await norm({ text: "ok" })).toHaveLength(1);
    expect(a.normalize({ ok: true, route: routes()[2]!, payload: undefined })).toEqual([]);
  });
  it("falls back to a body hash idempotency key without a valid Message-ID", async () => {
    const v = ok(await a.verifyInbound(emailReq({ mid: "bogus" }), ctx()));
    expect(a.normalize(v)[0]!.idempotency_key).toMatch(/^email:[0-9a-f]{64}$/);
    expect(a.normalize(v)[0]!.conversation_hint).toBeUndefined();
  });
  it("renders a header-injection-safe reply", () => {
    const route = routes()[2]!;
    const c = a.render(
      {
        channel: "email",
        to: "alice@example.org",
        text: "hi",
        subject: "Re: x",
        thread: "<m1@example.org>",
      },
      route,
    );
    if (c.kind !== "email") throw new Error("kind");
    expect(c.envelope_to).toEqual(["alice@example.org"]);
    expect(c.raw).toContain("In-Reply-To: <m1@example.org>");
    expect(c.raw).toContain("Auto-Submitted: auto-replied");
    expect(() =>
      a.render({ channel: "email", to: "a@b.co\r\nBcc: x@y.zz", text: "x" }, route),
    ).toThrow(/recipient/);
    expect(() =>
      a.render({ channel: "email", to: "x@y.zz", text: "x", subject: "a\r\nBcc: z@z.zz" }, route),
    ).toThrow(/control/);
    expect(() =>
      a.render({ channel: "email", to: "support@axis.example", text: "x" }, route),
    ).toThrow(/own mailbox/);
    expect(() =>
      a.render(
        { channel: "email", to: "x@y.zz", text: "x" },
        { ...route, provider_key: "bad", settings: {} },
      ),
    ).toThrow(/from address/);
  });
  it("property: any single-byte mutation of the body invalidates the signature", async () => {
    const base = emailReq({ mid: "<fixed@example.org>" });
    await fc.assert(
      fc.asyncProperty(fc.nat(), fc.integer({ min: 1, max: 255 }), async (i, x) => {
        const body = Buffer.from(base.body);
        body[i % body.length] = body[i % body.length]! ^ x;
        expect((await a.verifyInbound({ ...base, body }, ctx())).ok).toBe(false);
      }),
      { numRuns: 100 },
    );
    expect(EMAIL_SECRET).toBeTruthy();
  });
});

describe("SMS (Twilio-style)", () => {
  const a = new SmsAdapter();
  it("verifies over the CONFIGURED url + sorted params and normalises", async () => {
    const p = smsParams({ body: "hello sms", sid: "SM1234567890abcdef" });
    const v = ok(await a.verifyInbound(smsReq(p), ctx()));
    expect(a.normalize(v)[0]).toMatchObject({
      tenant_id: T1,
      channel: "sms",
      external_user_id: "+15557770000",
      text: "hello sms",
      idempotency_key: "sms:SM1234567890abcdef",
    });
    expect(a.ack()).toMatchObject({ status: 200, body: "<Response></Response>" });
  });
  it("rejects wrong token, wrong url, changed params, missing header, unknown number", async () => {
    const p = smsParams();
    expect(code(await a.verifyInbound(smsReq(p, "bad-token"), ctx()))).toBe("bad_signature");
    expect(
      code(await a.verifyInbound(smsReq(p, undefined, "https://evil.example/hook"), ctx())),
    ).toBe("bad_signature");
    const r = smsReq(p);
    expect(
      code(
        await a.verifyInbound(
          { ...r, body: Buffer.from(new URLSearchParams({ ...p, Body: "changed" }).toString()) },
          ctx(),
        ),
      ),
    ).toBe("bad_signature");
    expect(code(await a.verifyInbound({ ...r, headers: {} }, ctx()))).toBe("bad_signature");
    expect(code(await a.verifyInbound(smsReq(smsParams({ to: "+19998887777" })), ctx()))).toBe(
      "unknown_route",
    );
    const rs = routes();
    rs[3] = { ...rs[3]!, settings: {} };
    expect(
      code(await a.verifyInbound(smsReq(p), ctx({ routes: new StaticRoutingTable(rs) }))),
    ).toBe("bad_signature");
    expect(code(await a.verifyInbound(raw({ method: "GET" }), ctx()))).toBe("unsupported");
    expect(code(await a.verifyInbound(raw({ body: "x".repeat(300_000) }), ctx()))).toBe(
      "too_large",
    );
  });
  it("handles repeated parameters in the signature", async () => {
    const p = smsParams();
    const body = `${new URLSearchParams(p).toString()}&X=1&X=2`;
    const { twilioSignature } = await import("../src/index.js");
    const sig = twilioSignature(
      "twilio-auth-token",
      "https://hooks.example.test/v1/channels/sms/inbound",
      new Map([
        ...Object.entries(p).map(([k, v]) => [k, [v]] as [string, string[]]),
        ["X", ["1", "2"]],
      ]),
    );
    expect(
      code(await a.verifyInbound(raw({ headers: { "x-twilio-signature": sig }, body }), ctx())),
    ).toBe("ok");
  });
  it("normalize validates the sender, caps media and never reads media URLs", async () => {
    const mk = async (p: Record<string, string>) =>
      a.normalize(ok(await a.verifyInbound(smsReq(p), ctx())));
    expect(await mk({ ...smsParams(), From: "5557770000" })).toEqual([]);
    expect(await mk({ ...smsParams(), MessageSid: "x" })).toEqual([]);
    expect(await mk({ ...smsParams(), Body: "x".repeat(9000) })).toEqual([]);
    const withMedia = await mk({
      ...smsParams(),
      NumMedia: "2",
      MediaContentType0: "image/jpeg",
      MediaUrl0: "https://evil.example/a.jpg",
      MediaContentType1: "text/html",
    });
    expect(withMedia[0]!.attachments).toHaveLength(1);
    expect(withMedia[0]!.dropped_attachments).toBe(1);
    expect(JSON.stringify(withMedia)).not.toContain("evil.example");
    expect(a.normalize({ ok: true, route: routes()[3]!, payload: "nope" })).toEqual([]);
  });
  it("renders a Twilio Messages call", () => {
    const route = routes()[3]!;
    const c = a.render({ channel: "sms", to: "+15557770000", text: "a & b" }, route);
    if (c.kind !== "http") throw new Error("kind");
    expect(c.url).toBe(
      `https://api.twilio.com/2010-04-01/Accounts/AC${"a".repeat(32)}/Messages.json`,
    );
    expect(c.headers["authorization"]).toMatch(/^Basic /);
    expect(new URLSearchParams(c.body).get("Body")).toBe("a & b");
    expect(() => a.render({ channel: "sms", to: "555", text: "x" }, route)).toThrow(/E.164/);
    expect(() =>
      a.render({ channel: "sms", to: "+15557770000", text: "x" }, { ...route, settings: {} }),
    ).toThrow(/account_sid/);
    expect(() =>
      a.render({ channel: "sms", to: "+15557770000", text: "x" }, { ...route, secrets: {} }),
    ).toThrow(/auth_token/);
    expect(() =>
      a.render(
        { channel: "sms", to: "+15557770000", text: "x" },
        { ...route, provider_key: "abc" },
      ),
    ).toThrow(/route number/);
  });
  it("property: any mutation of any parameter value is rejected", async () => {
    const p = smsParams({ sid: "SMfixedfixedfixed" });
    const good = smsReq(p);
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom("Body", "From", "MessageSid", "NumMedia"),
        fc.string({ minLength: 1, maxLength: 10 }),
        async (k, extra) => {
          const changed = { ...p, [k]: `${p[k]}${extra}` };
          const r = await a.verifyInbound(
            { ...good, body: Buffer.from(new URLSearchParams(changed).toString()) },
            ctx(),
          );
          expect(r.ok).toBe(false);
        },
      ),
      { numRuns: 80 },
    );
  });
});

describe("WhatsApp (Meta)", () => {
  const a = new WhatsAppAdapter();
  it("verifies X-Hub-Signature-256 and normalises", async () => {
    const v = ok(await a.verifyInbound(waReq(waBody({ id: "wamid.1", text: "hello wa" })), ctx()));
    expect(a.normalize(v)[0]).toMatchObject({
      tenant_id: T1,
      channel: "whatsapp",
      external_user_id: "15557770000",
      text: "hello wa",
      idempotency_key: "whatsapp:wamid.1",
    });
  });
  it("rejects bad signatures, wrong prefix, unknown number, mixed-number batches, stale messages", async () => {
    expect(code(await a.verifyInbound(waReq(waBody(), "wrong"), ctx()))).toBe("bad_signature");
    expect(code(await a.verifyInbound(raw({ body: waBody() }), ctx()))).toBe("bad_signature");
    expect(
      code(
        await a.verifyInbound(
          raw({ headers: { "x-hub-signature-256": `sha1=${"0".repeat(40)}` }, body: waBody() }),
          ctx(),
        ),
      ),
    ).toBe("bad_signature");
    expect(code(await a.verifyInbound(waReq(waBody({ phoneId: "999" })), ctx()))).toBe(
      "unknown_route",
    );
    const mixed = JSON.stringify({
      entry: [
        {
          changes: [
            { value: { metadata: { phone_number_id: "1234567890" } } },
            { value: { metadata: { phone_number_id: "999" } } },
          ],
        },
      ],
    });
    expect(code(await a.verifyInbound(waReq(mixed), ctx()))).toBe("malformed");
    expect(
      code(
        await a.verifyInbound(
          waReq(JSON.stringify({ entry: [{ changes: [{ value: {} }] }] })),
          ctx(),
        ),
      ),
    ).toBe("malformed");
    expect(code(await a.verifyInbound(waReq(JSON.stringify({ entry: [] })), ctx()))).toBe(
      "malformed",
    );
    expect(
      code(await a.verifyInbound(waReq(waBody({ ts: Math.floor(NOW / 1000) - 90_000 })), ctx())),
    ).toBe("stale");
    expect(code(await a.verifyInbound(raw({ method: "PUT" }), ctx()))).toBe("unsupported");
    expect(code(await a.verifyInbound(raw({ body: "nope" }), ctx()))).toBe("malformed");
  });
  it("a malformed message inside a signed payload is rejected, status-only payloads are acked empty", async () => {
    const bad = JSON.stringify({
      entry: [
        {
          changes: [
            {
              value: { metadata: { phone_number_id: "1234567890" }, messages: [{ from: "1555" }] },
            },
          ],
        },
      ],
    });
    expect(code(await a.verifyInbound(waReq(bad), ctx()))).toBe("malformed");
    const status = JSON.stringify({
      entry: [
        {
          changes: [
            { value: { metadata: { phone_number_id: "1234567890" }, statuses: [{ id: "x" }] } },
          ],
        },
      ],
    });
    expect(a.normalize(ok(await a.verifyInbound(waReq(status), ctx())))).toEqual([]);
  });
  it("GET handshake echoes the challenge only for a matching verify token", async () => {
    const q = (o: Record<string, string>): RawRequest => raw({ method: "GET", query: o });
    const good = ok(
      await a.verifyInbound(
        q({
          "hub.mode": "subscribe",
          "hub.verify_token": WA_VERIFY,
          "hub.challenge": "1158201444",
        }),
        ctx(),
      ),
    );
    expect(good.reply).toMatchObject({ status: 200, body: "1158201444" });
    expect(
      code(
        await a.verifyInbound(
          q({ "hub.mode": "subscribe", "hub.verify_token": "nope", "hub.challenge": "1" }),
          ctx(),
        ),
      ),
    ).toBe("bad_signature");
    expect(
      code(
        await a.verifyInbound(
          q({ "hub.mode": "unsubscribe", "hub.verify_token": WA_VERIFY, "hub.challenge": "1" }),
          ctx(),
        ),
      ),
    ).toBe("malformed");
    expect(
      code(
        await a.verifyInbound(
          q({
            "hub.mode": "subscribe",
            "hub.verify_token": WA_VERIFY,
            "hub.challenge": "<script>",
          }),
          ctx(),
        ),
      ),
    ).toBe("malformed");
    expect(
      code(await a.verifyInbound(q({ "hub.mode": "subscribe", "hub.challenge": "1" }), ctx())),
    ).toBe("malformed");
    const rs = routes().map((r) => (r.channel === "whatsapp" ? { ...r, enabled: false } : r));
    expect(
      code(
        await a.verifyInbound(
          q({ "hub.mode": "subscribe", "hub.verify_token": WA_VERIFY, "hub.challenge": "1" }),
          ctx({ routes: new StaticRoutingTable(rs) }),
        ),
      ),
    ).toBe("bad_signature");
  });
  it("normalize: media metadata only, sender validation, size cap", async () => {
    const withMedia = JSON.stringify({
      entry: [
        {
          changes: [
            {
              value: {
                metadata: { phone_number_id: "1234567890" },
                messages: [
                  {
                    id: "w1",
                    from: "15557770000",
                    timestamp: String(Math.floor(NOW / 1000)),
                    type: "image",
                    image: {
                      id: "MEDIA1",
                      mime_type: "image/jpeg",
                      sha256: "x",
                      link: "https://evil.example/i.jpg",
                    },
                  },
                ],
              },
            },
          ],
        },
      ],
    });
    const m = a.normalize(ok(await a.verifyInbound(waReq(withMedia), ctx())));
    expect(m[0]!.attachments).toEqual([
      { name: "media", content_type: "image/jpeg", size: 0, ref: "MEDIA1" },
    ]);
    expect(JSON.stringify(m)).not.toContain("evil.example");
    const bad = a.normalize(
      ok(await a.verifyInbound(waReq(waBody({ from: "not-a-number" })), ctx())),
    );
    expect(bad).toEqual([]);
    expect(
      a.normalize(ok(await a.verifyInbound(waReq(waBody({ text: "x".repeat(9000) })), ctx()))),
    ).toEqual([]);
    expect(a.normalize({ ok: true, route: routes()[4]!, payload: undefined })).toEqual([]);
  });
  it("renders a Graph API message", () => {
    const route = routes()[4]!;
    const c = a.render({ channel: "whatsapp", to: "15557770000", text: "yo" }, route);
    if (c.kind !== "http") throw new Error("kind");
    expect(c.url).toBe("https://graph.facebook.com/v19.0/1234567890/messages");
    expect(JSON.parse(c.body)).toMatchObject({
      messaging_product: "whatsapp",
      to: "15557770000",
      text: { body: "yo", preview_url: false },
    });
    expect(() => a.render({ channel: "whatsapp", to: "+1555", text: "x" }, route)).toThrow(/wa_id/);
    expect(() =>
      a.render({ channel: "whatsapp", to: "15557770000", text: "x" }, { ...route, secrets: {} }),
    ).toThrow(/access_token/);
    expect(() =>
      a.render(
        { channel: "whatsapp", to: "15557770000", text: "x" },
        { ...route, provider_key: "abc" },
      ),
    ).toThrow(/phone_number_id/);
  });
  it("property: any single-byte mutation of the body is rejected", async () => {
    const body = waBody({ id: "wamid.fixed" });
    const good = waReq(body);
    await fc.assert(
      fc.asyncProperty(fc.nat(), fc.integer({ min: 1, max: 255 }), async (i, x) => {
        const b = Buffer.from(good.body);
        b[i % b.length] = b[i % b.length]! ^ x;
        expect((await a.verifyInbound({ ...good, body: b }, ctx())).ok).toBe(false);
      }),
      { numRuns: 120 },
    );
    expect(WA_SECRET).toBeTruthy();
  });
});

describe("Web widget", () => {
  const a = new WebAdapter();
  const route = routes().find((r) => r.channel === "web")!;
  const token = (o: { ttl?: number; now?: number } = {}): string =>
    issueWebSession(route, {
      nowMs: o.now ?? NOW,
      ...(o.ttl !== undefined ? { ttlSec: o.ttl } : {}),
      sid: "sid-abcdefghijklmnop",
    });
  const req = (tok: string, body: unknown, origin = "https://app.example.test"): RawRequest =>
    raw({ headers: { authorization: `Bearer ${tok}`, origin }, body: JSON.stringify(body) });
  it("issues and verifies a session token; tenant comes from the route", async () => {
    const v = ok(
      await a.verifyInbound(req(token(), { text: "hi", client_message_id: "cm-0000001" }), ctx()),
    );
    expect(a.normalize(v)[0]).toMatchObject({
      tenant_id: T1,
      channel: "web",
      external_user_id: "sid-abcdefghijklmnop",
      text: "hi",
      idempotency_key: "web:sid-abcdefghijklmnop:cm-0000001",
    });
  });
  it("rejects missing/forged/expired tokens, foreign origins and bad bodies", async () => {
    const body = { text: "hi", client_message_id: "cm-0000001" };
    expect(code(await a.verifyInbound(raw({ body: JSON.stringify(body) }), ctx()))).toBe(
      "bad_signature",
    );
    expect(code(await a.verifyInbound(req("garbage", body), ctx()))).toBe("bad_signature");
    const t = token();
    const [v1, p, s] = t.split(".") as [string, string, string];
    const forged = Buffer.from(
      JSON.stringify({
        ...JSON.parse(Buffer.from(p, "base64url").toString()),
        sid: "sid-attackerattackers",
      }),
    ).toString("base64url");
    expect(code(await a.verifyInbound(req(`${v1}.${forged}.${s}`, body), ctx()))).toBe(
      "bad_signature",
    );
    expect(
      code(await a.verifyInbound(req(token({ ttl: 10, now: NOW - 20_000 }), body), ctx())),
    ).toBe("stale");
    expect(code(await a.verifyInbound(req(t, body, "https://evil.example"), ctx()))).toBe(
      "bad_signature",
    );
    expect(
      code(
        await a.verifyInbound(
          raw({ headers: { authorization: `Bearer ${t}` }, body: JSON.stringify(body) }),
          ctx(),
        ),
      ),
    ).toBe("bad_signature");
    expect(code(await a.verifyInbound(raw({ method: "GET" }), ctx()))).toBe("unsupported");
    const bad = await a.verifyInbound(
      raw({
        headers: { authorization: `Bearer ${t}`, origin: "https://app.example.test" },
        body: "nope",
      }),
      ctx(),
    );
    expect(code(bad)).toBe("malformed");
    expect(a.normalize(ok(await a.verifyInbound(req(t, { text: "hi" }), ctx())))).toEqual([]);
    expect(
      a.normalize(
        ok(
          await a.verifyInbound(
            req(t, { text: "x".repeat(9000), client_message_id: "cm-0000001" }),
            ctx(),
          ),
        ),
      ),
    ).toEqual([]);
    expect(a.normalize({ ok: true, route, payload: undefined })).toEqual([]);
  });
  it("a token minted for site A is not accepted as site B (the MAC covers the site claim)", () => {
    const rs = routes();
    rs.push({
      ...route,
      tenant_id: T2,
      provider_key: "site-2",
      secrets: { session_secret: "other-secret" },
    });
    const c = ctx({ routes: new StaticRoutingTable(rs) });
    const t = token();
    const [v1, p] = t.split(".") as [string, string, string];
    const swapped = Buffer.from(
      JSON.stringify({ ...JSON.parse(Buffer.from(p, "base64url").toString()), site: "site-2" }),
    ).toString("base64url");
    const r = verifyWebSession(`${v1}.${swapped}.${t.split(".")[2]}`, c);
    expect(r.ok).toBe(false);
    expect(verifyWebSession(t, c).ok).toBe(true);
  });
  it("verifyWebSession edge cases", () => {
    const c = ctx();
    expect(verifyWebSession("a.b", c)).toMatchObject({ code: "bad_signature" });
    expect(verifyWebSession(`v2.${"a"}.${"b"}`, c)).toMatchObject({ code: "bad_signature" });
    expect(verifyWebSession(`v1.!!.sig`, c)).toMatchObject({ code: "unknown_route" });
    const payload = Buffer.from(
      JSON.stringify({ site: "site-1", sid: "short", exp: NOW }),
    ).toString("base64url");
    const sig = hmacSha256Hex(WEB_SECRET, `axis-web-session.v1.${payload}`);
    expect(verifyWebSession(`v1.${payload}.${sig}`, c)).toMatchObject({ code: "malformed" });
    expect(() => issueWebSession({ ...route, secrets: {} }, { nowMs: NOW })).toThrow(
      /session_secret/,
    );
    expect(() => issueWebSession(route, { nowMs: NOW, sid: "no" })).toThrow(/session id/);
    expect(issueWebSession(route, { nowMs: NOW })).toMatch(/^v1\./);
  });
  it("renders an SSE event for the session", () => {
    const c = a.render({ channel: "web", to: "sid-abcdefghijklmnop", text: "yo" });
    expect(c).toEqual({
      kind: "web",
      session_id: "sid-abcdefghijklmnop",
      event: { type: "message", data: { text: "yo" } },
    });
    expect(() => a.render({ channel: "web", to: "bad sid", text: "x" })).toThrow(/session id/);
  });
});
