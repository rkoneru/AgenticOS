import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  ChannelError,
  DEFAULT_LIMITS,
  FetchTransport,
  GuardedHttpTransport,
  MemoryIdempotencyStore,
  MemoryRateLimiter,
  PREVIEW_CHARS,
  StaticRoutingTable,
  cleanName,
  composeEmail,
  extractAddress,
  hostAllowed,
  normalizeAttachments,
  redactPatterns,
  splitText,
  suppressReason,
  transcriptContent,
  typeAllowed,
  validateAddress,
  validMessageId,
  withinWindow,
  type HttpCall,
} from "../src/index.js";
import { Clock, FakeHttp, T1, T2, routes } from "./helpers.js";

describe("replay window and stores", () => {
  it("withinWindow", () => {
    expect(withinWindow(1000, 1500, 600)).toBe(true);
    expect(withinWindow(1000, 1700, 600)).toBe(false);
    expect(withinWindow(2000, 1000, 999)).toBe(false);
    expect(withinWindow(Number.NaN, 1, 1e9)).toBe(false);
  });
  it("idempotency: first claim wins, TTL expires, release re-opens", async () => {
    const c = new Clock(0);
    const s = new MemoryIdempotencyStore(c.now);
    expect(await s.claim("k", 1000)).toBe(true);
    expect(await s.claim("k", 1000)).toBe(false);
    expect(await s.claim("other", 1000)).toBe(true);
    c.advance(1001);
    expect(await s.claim("k", 1000)).toBe(true);
    await s.release("k");
    expect(await s.claim("k", 1000)).toBe(true);
  });
  it("idempotency store sweeps expired keys when large", async () => {
    const c = new Clock(0);
    const s = new MemoryIdempotencyStore(c.now);
    for (let i = 0; i < 50_001; i++) await s.claim(`k${i}`, 10);
    c.advance(100);
    expect(await s.claim("fresh", 10)).toBe(true);
    expect(await s.claim("k5", 10)).toBe(true); // swept, so claimable again
  });
  it("rate limiter refills continuously and isolates keys", () => {
    const c = new Clock(0);
    const l = new MemoryRateLimiter(c.now);
    expect([1, 2, 3].map(() => l.take("a", 2))).toEqual([true, true, false]);
    expect(l.take("b", 2)).toBe(true);
    c.advance(30_000);
    expect(l.take("a", 2)).toBe(true);
    expect(l.take("a", 2)).toBe(false);
  });
  it("rate limiter sweeps idle buckets", () => {
    const c = new Clock(0);
    const l = new MemoryRateLimiter(c.now);
    for (let i = 0; i < 50_001; i++) l.take(`k${i}`, 5);
    c.advance(300_000);
    expect(l.take("x", 5)).toBe(true);
  });
});

describe("StaticRoutingTable", () => {
  it("looks up by channel + provider key only; tenant comes from config", () => {
    const t = new StaticRoutingTable(routes());
    expect(t.lookup("slack", "T0001")?.tenant_id).toBe(T1);
    expect(t.lookup("slack", "T0002")?.tenant_id).toBe(T2);
    expect(t.lookup("slack", "T9999")).toBeUndefined();
    expect(t.lookup("sms", "T0001")).toBeUndefined();
    expect(t.lookup("email", " SUPPORT@AXIS.EXAMPLE ")?.channel).toBe("email");
    expect(t.lookup("slack", "")).toBeUndefined();
    expect(t.lookup("slack", "x".repeat(600))).toBeUndefined();
    expect(t.lookup("slack", 5 as unknown as string)).toBeUndefined();
  });
  it("candidates / forTenant / all respect channel, tenant and enabled", () => {
    const r = routes();
    r[1] = { ...r[1]!, enabled: false };
    const t = new StaticRoutingTable(r);
    expect(t.candidates("slack").map((x) => x.provider_key)).toEqual(["T0001"]);
    expect(t.forTenant(T1, "slack")).toHaveLength(1);
    expect(t.forTenant(T2, "slack")).toHaveLength(0);
    expect(t.forTenant(T2, "sms")).toHaveLength(0);
    expect(t.all()).toHaveLength(r.length);
  });
  it("refuses duplicates, bad tenants, unknown channels and empty keys", () => {
    const [a] = routes();
    expect(() => new StaticRoutingTable([a!, { ...a!, tenant_id: T2 }])).toThrow(/duplicate/);
    expect(() => new StaticRoutingTable([{ ...a!, tenant_id: "nope" }])).toThrow(/UUID/);
    expect(() => new StaticRoutingTable([{ ...a!, channel: "fax" as never }])).toThrow(
      /unknown channel/,
    );
    expect(() => new StaticRoutingTable([{ ...a!, provider_key: " " }])).toThrow(/empty/);
  });
});

describe("limits and attachments", () => {
  const L = DEFAULT_LIMITS;
  it("typeAllowed: exact, wildcard, parameters, malformed", () => {
    expect(typeAllowed("image/png", L.allowedAttachmentTypes)).toBe(true);
    expect(typeAllowed("IMAGE/PNG; charset=x", L.allowedAttachmentTypes)).toBe(true);
    expect(typeAllowed("application/pdf", L.allowedAttachmentTypes)).toBe(true);
    expect(typeAllowed("application/x-msdownload", L.allowedAttachmentTypes)).toBe(false);
    expect(typeAllowed("text/html", L.allowedAttachmentTypes)).toBe(false);
    expect(typeAllowed("image", L.allowedAttachmentTypes)).toBe(false);
    expect(typeAllowed("../../etc/passwd", L.allowedAttachmentTypes)).toBe(false);
    expect(typeAllowed("", L.allowedAttachmentTypes)).toBe(false);
  });
  it("cleanName strips controls and separators", () => {
    expect(cleanName("a/b\\c\u0000d‮.exe")).toBe("a_b_c_d_.exe");
    expect(cleanName("   ")).toBe("attachment");
    expect(cleanName("x".repeat(500))).toHaveLength(128);
  });
  it("normalizeAttachments keeps metadata only and drops the rest", () => {
    const r = normalizeAttachments(
      [
        { name: "a.png", content_type: "image/png", size: 10, ref: "F123" },
        { name: "evil.exe", content_type: "application/x-msdownload", size: 10 },
        { name: "big.pdf", content_type: "application/pdf", size: L.maxAttachmentBytes + 1 },
        { name: "neg.pdf", content_type: "application/pdf", size: -1 },
        { name: "frac.pdf", content_type: "application/pdf", size: 1.5 },
        { name: "nosize.pdf", content_type: "application/pdf" },
        { name: 5, content_type: "text/plain", size: 0, ref: "http://169.254.169.254/x" },
        { content_type: 7, size: 1 },
      ],
      L,
    );
    expect(r.kept).toEqual([
      { name: "a.png", content_type: "image/png", size: 10, ref: "F123" },
      { name: "attachment", content_type: "text/plain", size: 0 },
    ]);
    expect(r.dropped).toBe(6);
    expect(JSON.stringify(r.kept)).not.toContain("http");
  });
  it("caps the number of attachments", () => {
    const many = Array.from({ length: 15 }, () => ({
      name: "a",
      content_type: "image/png",
      size: 1,
    }));
    const r = normalizeAttachments(many, L);
    expect(r.kept).toHaveLength(L.maxAttachments);
    expect(r.dropped).toBe(5);
  });
  it("splitText: boundaries, limits, and lossless content", () => {
    expect(splitText("short", 100)).toEqual(["short"]);
    expect(splitText("aaa bbb ccc ddd", 7)).toEqual(["aaa bbb", "ccc ddd"]);
    expect(splitText("x".repeat(30), 10)).toEqual(["x".repeat(10), "x".repeat(10), "x".repeat(10)]);
    expect(splitText("x".repeat(100), 10, 5)).toBeUndefined();
    expect(splitText("x", 0)).toBeUndefined();
    fc.assert(
      fc.property(fc.string({ maxLength: 300 }), fc.integer({ min: 20, max: 80 }), (s, max) => {
        const parts = splitText(s, max, 50);
        if (!parts) return;
        expect(parts.every((p) => p.length <= max)).toBe(true);
        expect(parts.join("").replace(/\s/g, "")).toBe(s.replace(/\s/g, ""));
      }),
    );
  });
});

describe("redaction and transcript policy", () => {
  it("redactPatterns masks emails, ssn, cards, phones, mentions", () => {
    const t = redactPatterns(
      "mail bob@example.com ssn 123-45-6789 card 4111 1111 1111 1111 call +1 (555) 777-0000 hi <@U123ABC> @carol",
    );
    expect(t).toContain("[email]");
    expect(t).toContain("[ssn]");
    expect(t).toContain("[card]");
    expect(t).toContain("[phone]");
    expect(t).toContain("[mention]");
    expect(t).not.toMatch(/bob@|123-45|4111|777-0000|U123ABC|carol/);
  });
  it("hash_only stores nothing; preview is capped and redacted; full is raw outside PHI", () => {
    expect(transcriptContent("secret", "hash_only", false)).toEqual({
      mode: "hash_only",
      content: null,
    });
    const long = `mail a@b.co ${"x".repeat(1000)}`;
    const p = transcriptContent(long, "redacted_preview", false);
    expect(p.content).toHaveLength(PREVIEW_CHARS);
    expect(p.content).toContain("[email]");
    expect(transcriptContent("mail a@b.co", "full", false)).toEqual({
      mode: "full",
      content: "mail a@b.co",
    });
  });
  it("PHI mode redacts always, caps full to a preview, runs the hook, and fails closed if the hook throws", () => {
    const r = transcriptContent("patient Jane Doe a@b.co", "full", true, (t) =>
      t.replace("Jane Doe", "[name]"),
    );
    expect(r).toEqual({ mode: "redacted_preview", content: "patient [name] [email]" });
    expect(
      transcriptContent("x", "full", true, () => {
        throw new Error("boom");
      }),
    ).toEqual({ mode: "hash_only", content: null });
    expect(transcriptContent("a@b.co", "hash_only", true)).toEqual({
      mode: "hash_only",
      content: null,
    });
    expect(transcriptContent("plain", "redacted_preview", true).content).toBe("plain");
  });
});

describe("email composition", () => {
  it("validates addresses strictly", () => {
    expect(validateAddress("Alice@Example.ORG")).toBe("Alice@example.org");
    for (const bad of [
      "a@b",
      "a b@c.de",
      "a@b.c\r\nBcc: x@y.zz",
      "<a@b.co>",
      "a,b@c.de",
      ".a@b.co",
      "a..b@c.de",
      "a@-b.co",
      "a@b.123",
      "@b.co",
      "",
      "a@[1.2.3.4]",
      `${"x".repeat(250)}@b.co`,
      5 as unknown,
    ])
      expect(validateAddress(bad), String(bad)).toBeUndefined();
  });
  it("extractAddress takes one address from a display form", () => {
    expect(extractAddress("Alice <alice@example.org>")).toBe("alice@example.org");
    expect(extractAddress("bob@example.org")).toBe("bob@example.org");
    expect(extractAddress("Evil <a@b.co>\r\nBcc: c@d.co")).toBeUndefined();
    expect(extractAddress("a@b.co, c@d.co")).toBeUndefined();
    expect(extractAddress(7)).toBeUndefined();
    expect(extractAddress("x".repeat(1000))).toBeUndefined();
  });
  it("validMessageId", () => {
    expect(validMessageId("<abc.123@example.org>")).toBe(true);
    for (const bad of ["abc@x", "<a b@x>", "<a\r\n@x>", "<>", 1])
      expect(validMessageId(bad)).toBe(false);
  });
  const base = {
    from: "bot@axis.example",
    to: "alice@example.org",
    subject: "Re: hi",
    text: "line1\nline2",
    messageId: "<id1@axis.example>",
  };
  it("composes loop-safe, injection-free mail with a base64 body", () => {
    const c = composeEmail({ ...base, inReplyTo: "<orig@example.org>", date: new Date(0) });
    const [head, body] = c.raw.split("\r\n\r\n") as [string, string];
    expect(head).toContain("Auto-Submitted: auto-replied");
    expect(head).toContain("X-Auto-Response-Suppress: All");
    expect(head).toContain("In-Reply-To: <orig@example.org>");
    expect(head.split("\r\n").filter((l) => /^[A-Za-z-]+:/.test(l))).toHaveLength(
      head.split("\r\n").length,
    );
    expect(Buffer.from(body.replace(/\r\n/g, ""), "base64").toString()).toBe("line1\r\nline2");
  });
  it("encodes non-ASCII subjects and rejects CR/LF/NUL anywhere", () => {
    expect(composeEmail({ ...base, subject: "Café" }).raw).toContain("Subject: =?UTF-8?B?");
    for (const subject of ["a\r\nBcc: evil@x.co", "a\nb", "a\u0000b", "a\u007fb"])
      expect(() => composeEmail({ ...base, subject })).toThrow(ChannelError);
    expect(() => composeEmail({ ...base, to: "a@b.co\r\nBcc: x@y.zz" })).toThrow(/recipient/);
    expect(() => composeEmail({ ...base, from: "nope" })).toThrow(/from/);
    expect(() => composeEmail({ ...base, messageId: "<a\r\nb>" })).toThrow(/message id/);
    expect(() => composeEmail({ ...base, inReplyTo: "bad" })).toThrow(/In-Reply-To/);
  });
  it("property: no generated subject can add a header line", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 120 }), (subject) => {
        try {
          const raw = composeEmail({ ...base, subject }).raw;
          const head = raw.slice(0, raw.indexOf("\r\n\r\n"));
          expect(head.split("\r\n").every((l) => /^[A-Za-z-]+: /.test(l))).toBe(true);
        } catch (e) {
          expect(e).toBeInstanceOf(ChannelError);
        }
      }),
    );
  });
  it("suppressReason covers every loop signal", () => {
    expect(suppressReason({}, "alice@example.org")).toBeUndefined();
    expect(suppressReason({ "auto-submitted": "auto-replied" }, "a@b.co")).toBe("auto-submitted");
    expect(suppressReason({ "auto-submitted": "no" }, "a@b.co")).toBeUndefined();
    expect(suppressReason({ precedence: "bulk" }, "a@b.co")).toBe("precedence");
    expect(suppressReason({ "x-auto-response-suppress": "All" }, "a@b.co")).toBe(
      "x-auto-response-suppress",
    );
    expect(suppressReason({ "list-id": "<l.example>" }, "a@b.co")).toBe("list");
    expect(suppressReason({ "list-unsubscribe": "<mailto:x>" }, "a@b.co")).toBe("list");
    expect(suppressReason({ "return-path": "<>" }, "a@b.co")).toBe("null-return-path");
    expect(
      suppressReason({ "content-type": "multipart/report; report-type=delivery-status" }, "a@b.co"),
    ).toBe("delivery-report");
    for (const l of ["mailer-daemon", "postmaster", "noreply", "No-Reply", "donotreply"])
      expect(suppressReason({}, `${l}@b.co`)).toBe("system-sender");
  });
});

describe("egress guard", () => {
  const call = (url: string): HttpCall => ({
    kind: "http",
    method: "POST",
    url,
    headers: {},
    body: "",
  });
  const allow = ["slack.com", "*.trafficmanager.net"];
  it("hostAllowed: exact and wildcard suffix, not substring", () => {
    expect(hostAllowed("slack.com", allow)).toBe(true);
    expect(hostAllowed("SLACK.com", allow)).toBe(true);
    expect(hostAllowed("a.trafficmanager.net", allow)).toBe(true);
    expect(hostAllowed("trafficmanager.net", allow)).toBe(false);
    expect(hostAllowed("evilslack.com", allow)).toBe(false);
    expect(hostAllowed("slack.com.evil.example", allow)).toBe(false);
    expect(hostAllowed("eviltrafficmanager.net", allow)).toBe(false);
  });
  it("allows only https + allowlisted host + default port, and never an IP", async () => {
    const inner = new FakeHttp();
    const g = new GuardedHttpTransport(inner, allow);
    await g.request(call("https://slack.com/api/chat.postMessage"), { timeoutMs: 1 });
    expect(inner.calls).toHaveLength(1);
    for (const url of [
      "http://slack.com/x",
      "https://evil.example/x",
      "https://u:p@slack.com/x",
      "https://slack.com:8443/x",
      "https://169.254.169.254/x",
      "https://[::1]/x",
      "https://127.0.0.1/",
      "not a url",
      "ftp://slack.com/",
    ]) {
      await expect(g.request(call(url), { timeoutMs: 1 }), url).rejects.toThrow(ChannelError);
    }
    expect(inner.calls).toHaveLength(1);
  });
  it("FetchTransport uses redirect:error and surfaces the status", async () => {
    let seen: RequestInit | undefined;
    const t = new FetchTransport((async (_u: unknown, init: RequestInit) => {
      seen = init;
      return new Response("x".repeat(5000), { status: 201 });
    }) as unknown as typeof fetch);
    const r = await t.request(call("https://slack.com/x"), { timeoutMs: 100 });
    expect(seen?.redirect).toBe("error");
    expect(r.status).toBe(201);
    expect(r.body).toHaveLength(4096);
  });
});
