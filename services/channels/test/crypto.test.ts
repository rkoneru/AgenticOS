import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  b64urlDecode,
  b64urlEncode,
  hmacSha1Base64,
  hmacSha256Hex,
  randomToken,
  safeEqual,
  sha256Hex,
  twilioSignature,
  verifyHmacSha256Hex,
  slackSignature,
  emailSignature,
} from "../src/index.js";

describe("safeEqual", () => {
  it("is true only for identical inputs", () => {
    expect(safeEqual("abc", "abc")).toBe(true);
    expect(safeEqual("abc", "abd")).toBe(false);
    expect(safeEqual("abc", "abcd")).toBe(false);
    expect(safeEqual("", "")).toBe(true);
    expect(safeEqual(Buffer.from("x"), "x")).toBe(true);
  });
  it("matches === for arbitrary strings", () => {
    fc.assert(fc.property(fc.string(), fc.string(), (a, b) => safeEqual(a, b) === (a === b)));
  });
});

describe("HMAC helpers", () => {
  it("hmacSha256Hex matches the RFC 4231 test case 2", () => {
    expect(hmacSha256Hex("Jefe", "what do ya want for nothing?")).toBe(
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    );
  });
  it("verifyHmacSha256Hex rejects bad shapes without comparing", () => {
    const good = hmacSha256Hex("k", "d");
    expect(verifyHmacSha256Hex("k", "d", good)).toBe(true);
    expect(verifyHmacSha256Hex("k", "d", good.toUpperCase())).toBe(true);
    expect(verifyHmacSha256Hex("k", "d", undefined)).toBe(false);
    expect(verifyHmacSha256Hex("k", "d", good.slice(1))).toBe(false);
    expect(verifyHmacSha256Hex("k", "d", `${good}0`)).toBe(false);
    expect(verifyHmacSha256Hex("", "d", hmacSha256Hex("", "d"))).toBe(false);
    expect(verifyHmacSha256Hex("k", "d", "z".repeat(64))).toBe(false);
  });
  it("hmacSha1Base64 matches a known vector", () => {
    // RFC 2202 test case 2
    expect(hmacSha1Base64("Jefe", "what do ya want for nothing?")).toBe(
      "7/zfauXrL6LSdBbV8YTfnCWafHk=",
    );
  });
});

describe("twilioSignature", () => {
  it("matches the vector in Twilio's documentation", () => {
    const sig = twilioSignature("12345", "https://mycompany.com/myapp.php?foo=1&bar=2", {
      Digits: "1234",
      To: "+18005551212",
      From: "+14158675310",
      Caller: "+14158675310",
      CallSid: "CA1234567890ABCDE",
    });
    expect(sig).toBe("GvWf1cFY/Q7PnoempGyD5oXAezc=");
  });
  it("multi-valued params contribute each value in order", () => {
    const m = new Map([
      ["a", ["1", "2"]],
      ["b", ["3"]],
    ]);
    expect(twilioSignature("k", "u", m)).toBe(hmacSha1Base64("k", "ua1a2b3"));
  });
});

describe("single-byte mutation is always rejected (property)", () => {
  const mutate = (b: Buffer, i: number, x: number): Buffer => {
    const c = Buffer.from(b);
    c[i % c.length] = c[i % c.length]! ^ ((x % 255) + 1);
    return c;
  };
  it("Slack v0 signatures", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 1, maxLength: 200 }),
        fc.nat(),
        fc.nat(),
        (data, i, x) => {
          const body = Buffer.from(data);
          const sig = slackSignature("secret", "1700000000", body);
          expect(slackSignature("secret", "1700000000", body)).toBe(sig);
          expect(slackSignature("secret", "1700000000", mutate(body, i, x))).not.toBe(sig);
        },
      ),
    );
  });
  it("email webhook signatures (body, timestamp and key)", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 1, maxLength: 200 }),
        fc.nat(),
        fc.nat(),
        (data, i, x) => {
          const body = Buffer.from(data);
          const sig = emailSignature("secret", "1700000000", body);
          expect(emailSignature("other", "1700000000", body)).not.toBe(sig);
          expect(emailSignature("secret", "1700000000", mutate(body, i, x))).not.toBe(sig);
          expect(emailSignature("secret", "1700000001", body)).not.toBe(sig);
        },
      ),
    );
  });
  it("a mutated signature never verifies (hex HMAC, any position, any substitution)", () => {
    const body = "payload";
    const good = hmacSha256Hex("k", body);
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 63 }),
        fc.integer({ min: 1, max: 15 }),
        (pos, delta) => {
          const digit = (parseInt(good[pos]!, 16) + delta) % 16;
          const bad = good.slice(0, pos) + digit.toString(16) + good.slice(pos + 1);
          expect(verifyHmacSha256Hex("k", body, bad)).toBe(false);
        },
      ),
    );
  });
  it("Twilio signatures change with any single changed byte of URL, name or value", () => {
    fc.assert(
      fc.property(fc.string({ minLength: 1, maxLength: 40 }), fc.nat(), (v, i) => {
        const params = { To: "+1555", Body: v };
        const sig = twilioSignature("tok", "https://h.example/x", params);
        const chars = [...v];
        chars[i % chars.length] = chars[i % chars.length] === "a" ? "b" : "a";
        expect(
          twilioSignature("tok", "https://h.example/x", { To: "+1555", Body: chars.join("") }),
        ).not.toBe(sig);
        expect(twilioSignature("tok", "https://h.example/y", params)).not.toBe(sig);
        expect(twilioSignature("tok2", "https://h.example/x", params)).not.toBe(sig);
      }),
    );
  });
});

describe("misc", () => {
  it("base64url strictness", () => {
    expect(b64urlDecode("aGk")?.toString()).toBe("hi");
    expect(b64urlDecode("aGk=")).toBeUndefined();
    expect(b64urlDecode("a+b/")).toBeUndefined();
    expect(b64urlDecode("a")).toBeUndefined();
    expect(b64urlEncode("hi")).toBe("aGk");
  });
  it("hashes and tokens", () => {
    expect(sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(randomToken()).not.toBe(randomToken());
    expect(randomToken(8)).toHaveLength(11);
  });
});
