import http from "node:http";
import net from "node:net";
import { describe, expect, it } from "vitest";
import {
  EmailNotifier,
  FetchHttpTransport,
  NotificationDispatcher,
  SlackNotifier,
  SmtpClient,
  TeamsNotifier,
  buildEmail,
  buildSlackPayload,
  buildTeamsPayload,
  clean,
  summaryLines,
  type EmailMessage,
  type HttpTransport,
  type Notification,
  type Notifier,
  type SmtpTransport,
} from "../src/index.js";
import { HASH, T1 } from "./helpers.js";

const note = (over: Partial<Notification> = {}): Notification => ({
  kind: "requested",
  tenant_id: T1,
  request_id: "req-1",
  run_id: "run-1",
  agent: "refunder",
  tool: "payments.refund <@here> & co",
  args_hash: HASH,
  risk_level: "high",
  requester_id: "refunder",
  level: 1,
  roles: ["finance"],
  deadline: "2026-01-01T00:01:40.000Z",
  ...over,
});

class FakeHttp implements HttpTransport {
  calls: { url: string; body: unknown; timeoutMs: number }[] = [];
  fail = false;
  async postJson(url: string, body: unknown, o: { timeoutMs: number }): Promise<void> {
    if (this.fail) throw new Error("HTTP 500");
    this.calls.push({ url, body, timeoutMs: o.timeoutMs });
  }
}
class FakeSmtp implements SmtpTransport {
  sent: EmailMessage[] = [];
  async send(m: EmailMessage): Promise<void> {
    this.sent.push(m);
  }
}

describe("payload builders", () => {
  it("escape and never include raw args", () => {
    const s = JSON.stringify(buildSlackPayload(note(), "https://console.example/"));
    expect(s).toContain("&lt;@here&gt; &amp; co");
    expect(s).toContain("https://console.example/approvals/req-1");
    expect(s).not.toContain(HASH); // only a prefix of the hash leaves the platform
    const t = buildTeamsPayload(
      note({ kind: "decided", outcome: "APPROVED", decided_by: "alice" }),
    ) as {
      attachments: { content: { body: { facts?: { title: string }[] }[] } }[];
    };
    const facts = t.attachments[0]?.content.body[1]?.facts?.map((f) => f.title);
    expect(facts).toContain("Outcome");
    expect(facts).toContain("Decided by");
    expect(facts).not.toContain("Link");
  });

  it("clean strips control chars and truncates", () => {
    expect(clean("a\r\nb\u0000c")).toBe("a  b c");
    expect(clean("x".repeat(300)).length).toBe(200);
    expect(summaryLines(note()).length).toBe(9);
  });

  it("email builder validates addresses and strips newlines from the subject", () => {
    const m = buildEmail(note({ tool: "t\r\nBcc: evil@x.io" }), "axis@x.io", ["a@b.co"]);
    expect(m.subject).not.toMatch(/[\r\n]/);
    expect(() => buildEmail(note(), "bad", ["a@b.co"])).toThrow();
    expect(() => buildEmail(note(), "axis@x.io", ["a@b.co\r\nBcc:e@x.io"])).toThrow();
    expect(() => buildEmail(note(), "axis@x.io", [])).toThrow("no recipients");
  });
});

describe("webhook and email notifiers", () => {
  it("post to a per-tenant https webhook on the allowlist; skip when unconfigured", async () => {
    const http = new FakeHttp();
    const slack = new SlackNotifier({
      transport: http,
      target: (t) =>
        t === T1 ? { webhookUrl: "https://hooks.slack.com/services/T/B/X" } : undefined,
    });
    await slack.notify(note());
    await slack.notify(note({ tenant_id: "other" }));
    expect(http.calls.length).toBe(1);
    expect(http.calls[0]?.timeoutMs).toBe(5000);
    const teams = new TeamsNotifier({
      transport: http,
      timeoutMs: 100,
      target: async () => ({ webhookUrl: "https://acme.webhook.office.com/webhookb2/x" }),
    });
    await teams.notify(note());
    expect(http.calls[1]?.timeoutMs).toBe(100);
    expect(slack.channel).toBe("slack");
    expect(teams.channel).toBe("teams");
  });

  it.each([
    ["http://hooks.slack.com/x", "https"],
    ["https://user:pw@hooks.slack.com/x", "credentials"],
    ["https://evil.example/x", "not allowed"],
    ["https://hooks.slack.com.evil.example/x", "not allowed"],
    ["not a url", "valid URL"],
  ])("refuses webhook %s", async (url, msg) => {
    const slack = new SlackNotifier({
      transport: new FakeHttp(),
      target: () => ({ webhookUrl: url }),
    });
    await expect(slack.notify(note())).rejects.toThrow(msg);
  });

  it("custom allowlist; errors never leak the webhook secret", async () => {
    const h = new FakeHttp();
    const n = new SlackNotifier({
      transport: h,
      allowedHosts: ["chat.internal"],
      target: () => ({ webhookUrl: "https://chat.internal/secret-token" }),
    });
    await n.notify(note());
    expect(h.calls.length).toBe(1);
    const bad = new SlackNotifier({
      transport: h,
      target: () => ({ webhookUrl: "https://evil/secret-token" }),
    });
    await expect(bad.notify(note())).rejects.not.toThrow(/secret-token/);
  });

  it("email notifier sends via the transport", async () => {
    const smtp = new FakeSmtp();
    const e = new EmailNotifier({
      transport: smtp,
      from: "axis@x.io",
      target: (t) => (t === T1 ? { to: ["fin@x.io"] } : undefined),
      consoleBaseUrl: "https://c.example",
    });
    await e.notify(note());
    await e.notify(note({ tenant_id: "z" }));
    expect(smtp.sent.length).toBe(1);
    expect(smtp.sent[0]?.text).toContain("https://c.example/approvals/req-1");
    expect(e.channel).toBe("email");
  });
});

describe("NotificationDispatcher", () => {
  class Flaky implements Notifier {
    channel = "flaky";
    calls = 0;
    constructor(private failFirst: number) {}
    async notify(): Promise<void> {
      if (this.calls++ < this.failFirst) throw new Error("nope");
    }
  }

  it("retries with exponential backoff, capped, then succeeds", async () => {
    const sleeps: number[] = [];
    const d = new NotificationDispatcher({
      notifiers: [new Flaky(3)],
      baseDelayMs: 100,
      maxDelayMs: 250,
      maxAttempts: 5,
      sleep: async (ms) => void sleeps.push(ms),
    });
    const [r] = await d.dispatch(note());
    expect(r).toEqual({ channel: "flaky", ok: true, attempts: 4 });
    expect(sleeps).toEqual([100, 200, 250]);
  });

  it("gives up after maxAttempts, reports failure, logs, never throws", async () => {
    const logs: string[] = [];
    const d = new NotificationDispatcher({
      notifiers: [new Flaky(99), new Flaky(0)],
      maxAttempts: 2,
      sleep: async () => {
        throw new Error("sleeper broke");
      },
      logger: { info() {}, warn: (m) => void logs.push(m), error: (m) => void logs.push(m) },
    });
    const res = await d.dispatch(note());
    expect(res.map((r) => r.ok)).toEqual([false, true]);
    expect(res[0]?.error).toBe("nope");
    expect(logs).toContain("notification gave up");
  });

  it("clamps maxAttempts to at least one and uses real timers by default", async () => {
    const d = new NotificationDispatcher({
      notifiers: [new Flaky(1)],
      maxAttempts: 0,
      baseDelayMs: 1,
    });
    expect((await d.dispatch(note()))[0]?.attempts).toBe(1);
    const d2 = new NotificationDispatcher({ notifiers: [new Flaky(1)], baseDelayMs: 1 });
    expect((await d2.dispatch(note()))[0]?.ok).toBe(true);
  });

  it("surfaces non-Error throws", async () => {
    const n: Notifier = { channel: "s", notify: () => Promise.reject("str") };
    const [r] = await new NotificationDispatcher({ notifiers: [n], maxAttempts: 1 }).dispatch(
      note(),
    );
    expect(r?.error).toBe("str");
  });
});

describe("FetchHttpTransport (loopback server)", () => {
  it("posts JSON, fails on non-2xx and does not follow redirects", async () => {
    const seen: string[] = [];
    const srv = http.createServer((req, res) => {
      let b = "";
      req.on("data", (c: Buffer) => (b += c.toString()));
      req.on("end", () => {
        seen.push(`${req.url} ${req.headers["content-type"]} ${b}`);
        if (req.url === "/500") res.writeHead(500).end();
        else if (req.url === "/redir") res.writeHead(302, { location: "/ok" }).end();
        else res.writeHead(200).end("ok");
      });
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as net.AddressInfo).port;
    const t = new FetchHttpTransport();
    await t.postJson(`http://127.0.0.1:${port}/ok`, { a: 1 }, { timeoutMs: 1000 });
    expect(seen[0]).toBe('/ok application/json {"a":1}');
    await expect(
      t.postJson(`http://127.0.0.1:${port}/500`, {}, { timeoutMs: 1000 }),
    ).rejects.toThrow("HTTP 500");
    await expect(
      t.postJson(`http://127.0.0.1:${port}/redir`, {}, { timeoutMs: 1000 }),
    ).rejects.toThrow();
    await new Promise((r) => srv.close(r));
    const fake = new FetchHttpTransport((async () => ({ ok: true })) as unknown as typeof fetch);
    await fake.postJson("https://x", {}, { timeoutMs: 1 });
  });
});

interface FakeSmtpServer {
  port: number;
  transcript: string[];
  close(): Promise<void>;
}

async function smtpServer(
  script: { rejectRcpt?: boolean; dropAfterGreeting?: boolean; silent?: boolean } = {},
): Promise<FakeSmtpServer> {
  const transcript: string[] = [];
  const socks = new Set<net.Socket>();
  const srv = net.createServer((s) => {
    socks.add(s);
    s.setEncoding("utf8");
    if (script.silent) return;
    s.write("220 fake ESMTP\r\n");
    if (script.dropAfterGreeting) return void setTimeout(() => s.destroy(), 5);
    let inData = false;
    let buf = "";
    s.on("data", (c: string) => {
      buf += c;
      for (;;) {
        if (inData) {
          const end = buf.indexOf("\r\n.\r\n");
          if (end < 0) return;
          transcript.push(`DATA:${buf.slice(0, end)}`);
          buf = buf.slice(end + 5);
          inData = false;
          s.write("250 queued\r\n");
          continue;
        }
        const nl = buf.indexOf("\r\n");
        if (nl < 0) return;
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        transcript.push(line);
        if (line.startsWith("EHLO")) s.write("250-fake\r\n250 AUTH PLAIN\r\n");
        else if (line.startsWith("AUTH")) s.write("235 ok\r\n");
        else if (line.startsWith("RCPT") && script.rejectRcpt) s.write("550 no\r\n");
        else if (line === "DATA") {
          inData = true;
          s.write("354 go\r\n");
        } else if (line === "QUIT") s.write("221 bye\r\n");
        else s.write("250 ok\r\n");
      }
    });
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  return {
    port: (srv.address() as net.AddressInfo).port,
    transcript,
    close: () =>
      new Promise((r) => {
        srv.close(() => r());
        socks.forEach((x) => x.destroy());
      }),
  };
}

describe("SmtpClient (loopback fake server)", () => {
  const msg: EmailMessage = {
    from: "a@x.io",
    to: ["b@x.io", "c@x.io"],
    subject: "hi",
    text: ".dot\nline2",
  };

  it("speaks SMTP, dot-stuffs and delivers", async () => {
    const s = await smtpServer();
    await new SmtpClient({ host: "127.0.0.1", port: s.port, secure: false }).send(msg);
    await s.close();
    expect(s.transcript).toContain("MAIL FROM:<a@x.io>");
    expect(s.transcript).toContain("RCPT TO:<c@x.io>");
    const data = s.transcript.find((l) => l.startsWith("DATA:")) ?? "";
    expect(data).toContain("Subject: hi");
    expect(data).toContain("\r\n..dot\r\nline2");
  });

  it("surfaces rejected recipients", async () => {
    const s = await smtpServer({ rejectRcpt: true });
    await expect(
      new SmtpClient({ host: "127.0.0.1", port: s.port, secure: false }).send(msg),
    ).rejects.toThrow("550");
    await s.close();
  });

  it("fails when the server drops the connection or never answers", async () => {
    const a = await smtpServer({ dropAfterGreeting: true });
    await expect(
      new SmtpClient({ host: "127.0.0.1", port: a.port, secure: false }).send(msg),
    ).rejects.toThrow();
    await a.close();
    const b = await smtpServer({ silent: true });
    await expect(
      new SmtpClient({ host: "127.0.0.1", port: b.port, secure: false, timeoutMs: 30 }).send(msg),
    ).rejects.toThrow("timeout");
    await b.close();
  });

  it("rejects header injection, and credentials without TLS", async () => {
    const c = new SmtpClient({ host: "127.0.0.1", port: 1, secure: false });
    await expect(c.send({ ...msg, subject: "x\r\nBcc: e@x.io" })).rejects.toThrow("CR/LF");
    expect(
      () => new SmtpClient({ host: "h", port: 1, secure: false, auth: { user: "u", pass: "p" } }),
    ).toThrow("TLS");
  });

  it("sends AUTH PLAIN when configured over the connect seam (TLS stand-in)", async () => {
    const s = await smtpServer();
    const c = new SmtpClient({
      host: "127.0.0.1",
      port: s.port,
      secure: true,
      auth: { user: "u", pass: "p" },
      connect: (o) => net.connect({ host: o.host, port: o.port }),
    });
    await c.send({ ...msg, text: "x\r\n" });
    await s.close();
    expect(s.transcript.some((l) => l.startsWith("AUTH PLAIN "))).toBe(true);
  });

  it("uses tls.connect for secure connections (fails on a plain server, no credentials leak)", async () => {
    const s = await smtpServer({ silent: true });
    await expect(
      new SmtpClient({
        host: "127.0.0.1",
        port: s.port,
        secure: true,
        timeoutMs: 200,
        auth: { user: "u", pass: "p" },
      }).send(msg),
    ).rejects.toThrow();
    await s.close();
    expect(s.transcript).toEqual([]);
  });
});
