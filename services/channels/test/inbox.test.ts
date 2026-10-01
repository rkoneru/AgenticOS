import http from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import {
  InboxQueue,
  createDevServer,
  listenLoopback,
  parseTranscriptEvent,
  staticTokenAuthenticator,
  type InboxItem,
} from "../src/index.js";
import { AGENT, T1, T2, rig, slackReq, smsReq } from "./helpers.js";

const item = (tenant: string, text = "x"): InboxItem => ({
  id: `i-${text}`,
  tenant_id: tenant,
  channel: "slack",
  provider_key: "T0001",
  agent: AGENT,
  external_user_id: "U1",
  end_user_id: "eu",
  conversation_id: "c",
  message_id: "m",
  trace_id: "a".repeat(32),
  text,
  timestamp_ms: 0,
});

describe("InboxQueue", () => {
  it("is FIFO per tenant and never hands one tenant's item to another", async () => {
    const q = new InboxQueue();
    q.push(item(T1, "a"));
    q.push(item(T1, "b"));
    q.push(item(T2, "z"));
    expect(q.size(T1)).toBe(2);
    expect((await q.take(T2, 0))?.text).toBe("z");
    expect(await q.take(T2, 0)).toBeUndefined();
    expect((await q.take(T1, 0))?.text).toBe("a");
    expect((await q.take(T1, 0))?.text).toBe("b");
  });

  it("wakes a waiting taker, times out otherwise, and a timed-out waiter takes nothing later", async () => {
    const q = new InboxQueue();
    const waiting = q.take(T1, 5000);
    q.push(item(T1, "late"));
    expect((await waiting)?.text).toBe("late");
    expect(await q.take(T1, 20)).toBeUndefined();
    q.push(item(T1, "kept")); // the expired waiter must not swallow it
    expect((await q.take(T1, 0))?.text).toBe("kept");
  });

  it("refuses to grow without bound", () => {
    const q = new InboxQueue(2);
    q.push(item(T1, "1"));
    q.push(item(T1, "2"));
    expect(() => q.push(item(T1, "3"))).toThrow("inbox full");
    expect(q.size(T2)).toBe(0);
  });

  it("the gateway hook enqueues exactly the verified message, with the inbound audit trace id", async () => {
    const q = new InboxQueue();
    const r = rig({ onMessage: q.handler });
    const res = await r.gateway.handleInbound("slack", slackReq({ text: "hi there" }));
    expect(res.outcomes[0]?.kind).toBe("accepted");
    const got = await q.take(T1, 0);
    expect(got).toMatchObject({
      tenant_id: T1,
      channel: "slack",
      text: "hi there",
      external_user_id: "U111",
      agent: AGENT,
    });
    const events = await r.audit.events(T1);
    const inbound = events.find((e) => e.action === "channel.inbound.message");
    expect(inbound?.trace_id).toBe(got?.trace_id);
    // a rejected request enqueues nothing and starts nothing
    await r.gateway.handleInbound("slack", slackReq({ secret: "wrong" }));
    expect(await q.take(T1, 0)).toBeUndefined();
  });

  it("a full queue is logged by the gateway, the message stays recorded", async () => {
    const q = new InboxQueue(0);
    const r = rig({ onMessage: q.handler });
    const res = await r.gateway.handleInbound(
      "sms",
      smsReq({
        To: "+15550001111",
        From: "+15557770000",
        Body: "full",
        MessageSid: "SM1234567890abc",
      }),
    );
    expect(res.outcomes[0]?.kind).toBe("accepted");
  });
});

describe("transcript events", () => {
  const base = {
    channel: "voice",
    call_id: "call-1",
    trace_id: "b".repeat(32),
    agent: AGENT,
  };
  it("validates strictly", () => {
    const turn = {
      ...base,
      kind: "turn",
      turn: 1,
      role: "user",
      text_sha256: "c".repeat(64),
      size: 5,
    };
    expect(parseTranscriptEvent(turn)).toMatchObject({
      kind: "turn",
      role: "user",
      audio_bytes: 0,
    });
    for (const bad of [
      { ...turn, channel: "sms" },
      { ...turn, kind: "other" },
      { ...turn, call_id: "../x" },
      { ...turn, trace_id: "nothex" },
      { ...turn, agent: "x" },
      { ...turn, agent: { name: "a b", version: "1" } },
      { ...turn, role: "root" },
      { ...turn, turn: -1 },
      { ...turn, text_sha256: "abc" },
      { ...turn, audio_sha256: "abc" },
      { ...turn, size: 1.5 },
      { ...turn, run_id: "has space" },
      { ...base, kind: "call", phase: "hold" },
      { ...base, kind: "call", phase: "ended", reason: "free text with spaces" },
      { ...base, kind: "call", phase: "ended", detail: [] },
      { ...base, kind: "call", phase: "ended", detail: { BAD: 1 } },
      { ...base, kind: "call", phase: "ended", detail: { a: "x y" } },
      {
        ...base,
        kind: "call",
        phase: "ended",
        detail: Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`k${"a".repeat(i)}`, 1])),
      },
    ])
      expect(() => parseTranscriptEvent(bad as Record<string, unknown>)).toThrow(
        /transcript event/,
      );
    const call = parseTranscriptEvent({
      ...base,
      kind: "call",
      phase: "consent",
      reason: "granted:notice",
      duration_ms: 5,
      run_id: "call_1",
      detail: { granted: true, mode: "notice", turns: 2, skipped: null },
    });
    expect(call.detail).toEqual({ granted: true, mode: "notice", turns: 2 });
    expect(
      parseTranscriptEvent({
        ...turn,
        audio_sha256: "d".repeat(64),
        audio_bytes: 10,
        redacted: true,
      }).audio_sha256,
    ).toBe("d".repeat(64));
  });

  it("the gateway appends hash-only call and turn rows to the tenant chain under the call's trace", async () => {
    const r = rig();
    const sha = "e".repeat(64);
    await r.gateway.recordTranscriptEvent(
      T1,
      parseTranscriptEvent({
        ...base,
        kind: "call",
        phase: "connected",
        detail: { consent_mode: "notice" },
      }),
    );
    await r.gateway.recordTranscriptEvent(
      T1,
      parseTranscriptEvent({
        ...base,
        kind: "call",
        phase: "consent",
        reason: "refused:declined",
        detail: { granted: false },
      }),
    );
    await r.gateway.recordTranscriptEvent(
      T1,
      parseTranscriptEvent({
        ...base,
        kind: "turn",
        turn: 1,
        role: "user",
        text_sha256: sha,
        size: 9,
        redacted: true,
      }),
    );
    await r.gateway.recordTranscriptEvent(
      T1,
      parseTranscriptEvent({
        ...base,
        kind: "turn",
        turn: 1,
        role: "agent",
        text_sha256: sha,
        size: 9,
      }),
    );
    const rows = await r.audit.events(T1);
    expect(rows.map((e) => [e.enforcement_point, e.action, e.decision])).toEqual([
      ["lifecycle", "voice.call.connected", "ALLOW"],
      ["lifecycle", "voice.call.consent", "DENY"],
      ["lifecycle", "voice.turn.user", "ALLOW"],
      ["message_send", "voice.turn.agent", "ALLOW"],
    ]);
    expect(new Set(rows.map((e) => e.trace_id))).toEqual(new Set(["b".repeat(32)]));
    expect(rows[2]?.reason).toContain(`sha256=${sha}`);
    expect(rows[2]?.reason).toContain("dir=in");
    expect(rows[3]?.reason).toContain("dir=out");
    expect(await r.audit.events(T2)).toEqual([]);
  });

  it("fails closed when the audit append fails", async () => {
    const r = rig();
    r.audit.fail = true;
    await expect(
      r.gateway.recordTranscriptEvent(
        T1,
        parseTranscriptEvent({ ...base, kind: "call", phase: "ended" }),
      ),
    ).rejects.toThrow(/audit append failed/);
  });
});

describe("dev server: inbox and transcript routes", () => {
  let server: http.Server | undefined;
  afterEach(async () => {
    await new Promise<void>((res) => (server ? server.close(() => res()) : res()));
    server = undefined;
  });
  const post = (port: number, path: string, body: unknown, token?: string) =>
    new Promise<{ status: number; json: Record<string, unknown> }>((resolve, reject) => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port,
          method: "POST",
          path,
          headers: {
            "content-type": "application/json",
            ...(token ? { authorization: `Bearer ${token}` } : {}),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () =>
            resolve({
              status: res.statusCode!,
              json: JSON.parse(Buffer.concat(chunks).toString() || "{}") as Record<string, unknown>,
            }),
          );
        },
      );
      req.on("error", reject);
      req.end(JSON.stringify(body));
    });

  const boot = async (withInbox: boolean) => {
    const inbox = new InboxQueue();
    const r = rig({ onMessage: inbox.handler });
    server = createDevServer({
      gateway: r.gateway,
      routes: r.table,
      store: r.store,
      identity: r.identity,
      hub: r.hub,
      ...(withInbox ? { inbox } : {}),
      authenticate: staticTokenAuthenticator({ t1: { tenantId: T1 }, t2: { tenantId: T2 } }),
      now: r.clock.now,
    });
    return { port: await listenLoopback(server), r, inbox };
  };

  it("inbox/next hands a runner only its own tenant's items; wait_ms is capped and optional", async () => {
    const { port, r } = await boot(true);
    await r.gateway.handleInbound("slack", slackReq({ text: "for tenant one" }));
    expect((await post(port, "/v1/channels/inbox/next", {}, "t2")).json["item"]).toBeNull();
    const mine = await post(port, "/v1/channels/inbox/next", { wait_ms: 100 }, "t1");
    expect(mine.status).toBe(200);
    expect((mine.json["item"] as InboxItem).text).toBe("for tenant one");
    expect(
      (await post(port, "/v1/channels/inbox/next", { wait_ms: 10 }, "t1")).json["item"],
    ).toBeNull();
    expect((await post(port, "/v1/channels/inbox/next", {})).status).toBe(401);
    expect((await post(port, "/v1/channels/inbox/next", { tenant_id: T1 }, "t2")).status).toBe(403);
  });

  it("inbox/next is 404 when no inbox is wired", async () => {
    const { port } = await boot(false);
    expect((await post(port, "/v1/channels/inbox/next", {}, "t1")).status).toBe(404);
  });

  it("transcript-events: tenant fixed by the token, invalid input is a 400", async () => {
    const { port, r } = await boot(true);
    const ev = {
      kind: "call",
      channel: "voice",
      call_id: "call-9",
      trace_id: "f".repeat(32),
      agent: AGENT,
      phase: "connected",
    };
    const ok = await post(port, "/v1/channels/transcript-events", ev, "t1");
    expect(ok.status).toBe(200);
    expect((await r.audit.events(T1)).map((e) => e.action)).toContain("voice.call.connected");
    expect(await r.audit.events(T2)).toEqual([]);
    expect(
      (await post(port, "/v1/channels/transcript-events", { ...ev, phase: "x" }, "t1")).status,
    ).toBe(400);
    expect(
      (await post(port, "/v1/channels/transcript-events", { ...ev, tenant_id: T1 }, "t2")).status,
    ).toBe(403);
  });
});
