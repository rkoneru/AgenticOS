import { createHmac, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { LocalKms, TokenSigner, open, safeEqual, seal, sha256Hex, fromB64u, b64u } from "../src/index.js";

describe("crypto primitives", () => {
  it("seal/open round-trips and binds the AAD", () => {
    const k = randomBytes(32);
    const box = seal(k, Buffer.from("hello"), "ctx");
    expect(open(k, box, "ctx").toString()).toBe("hello");
    expect(() => open(k, box, "other")).toThrow();
    expect(() => open(randomBytes(32), box, "ctx")).toThrow();
    const bad = Buffer.from(box);
    bad[20] = (bad[20] ?? 0) ^ 1;
    expect(() => open(k, bad, "ctx")).toThrow();
    expect(() => open(k, Buffer.alloc(5), "ctx")).toThrow(/short/);
    expect(() => seal(Buffer.alloc(5), Buffer.from("x"), "c")).toThrow(/32/);
    expect(() => open(Buffer.alloc(5), box, "c")).toThrow(/32/);
    expect(seal(k, Buffer.from("x"), "c").equals(seal(k, Buffer.from("x"), "c"))).toBe(false); // fresh nonce
  });

  it("safeEqual handles lengths", () => {
    expect(safeEqual(Buffer.from("ab"), Buffer.from("ab"))).toBe(true);
    expect(safeEqual(Buffer.from("ab"), Buffer.from("ac"))).toBe(false);
    expect(safeEqual(Buffer.from("ab"), Buffer.from("abc"))).toBe(false);
    expect(sha256Hex("a")).toMatch(/^[0-9a-f]{64}$/);
    expect(fromB64u(b64u(Buffer.from("xyz"))).toString()).toBe("xyz");
  });

  it("TokenSigner: purpose-bound, tamper-evident, key rotation", () => {
    const k1 = { kid: "a", key: randomBytes(32) };
    const k2 = { kid: "b", key: randomBytes(32) };
    const s1 = new TokenSigner([k1]);
    const tok = s1.sign("p", { x: 1 });
    expect(s1.verify("p", tok)).toEqual({ x: 1 });
    expect(s1.verify("other", tok)).toBeUndefined();
    const [kid, body, sig] = tok.split(".") as [string, string, string];
    expect(s1.verify("p", `${kid}.${b64u(Buffer.from('{"x":2}'))}.${sig}`)).toBeUndefined();
    expect(s1.verify("p", `${kid}.${body}`)).toBeUndefined();
    expect(s1.verify("p", `zz.${body}.${sig}`)).toBeUndefined();
    expect(s1.verify("p", `${kid}.${body}.`)).toBeUndefined();
    // rotation: new key signs, old key still verifies; removing the old key invalidates old tokens
    const rotated = new TokenSigner([k2, k1]);
    expect(rotated.verify("p", tok)).toEqual({ x: 1 });
    expect(new TokenSigner([k2]).verify("p", tok)).toBeUndefined();
    // payload that is not an object
    const arr = new TokenSigner([k1]);
    const b = b64u(Buffer.from("[1]"));
    const forged = new TokenSigner([k1]).sign("p", {}).split(".");
    expect(arr.verify("p", `a.${b}.${forged[2]}`)).toBeUndefined();
    expect(() => new TokenSigner([])).toThrow();
    expect(() => new TokenSigner([{ kid: "a", key: Buffer.alloc(8) }])).toThrow();
  });

  it("TokenSigner rejects a validly signed token whose payload is not a JSON object", () => {
    const k = { kid: "a", key: randomBytes(32) };
    const signer = new TokenSigner([k]);
    // craft a correctly-MACed but non-object body via the same primitive
    const body = b64u(Buffer.from("not json"));
    
    const sig = b64u(createHmac("sha256", k.key).update("p").update("\0").update("a").update(".").update(body).digest());
    expect(signer.verify("p", `a.${body}.${sig}`)).toBeUndefined();
    const arrBody = b64u(Buffer.from("[1]"));
    const sig2 = b64u(createHmac("sha256", k.key).update("p").update("\0").update("a").update(".").update(arrBody).digest());
    expect(signer.verify("p", `a.${arrBody}.${sig2}`)).toBeUndefined();
  });

  it("LocalKms binds the tenant and key id", async () => {
    const kms = new LocalKms({ k1: randomBytes(32), k2: randomBytes(32) }, "k1");
    const dk = await kms.generateDataKey("tenant-a");
    expect((await kms.unwrap("tenant-a", "k1", dk.wrapped)).equals(dk.plaintext)).toBe(true);
    await expect(kms.unwrap("tenant-b", "k1", dk.wrapped)).rejects.toThrow(/unwrap/);
    await expect(kms.unwrap("tenant-a", "k2", dk.wrapped)).rejects.toThrow(/unwrap/);
    await expect(kms.unwrap("tenant-a", "nope", dk.wrapped)).rejects.toThrow(/unknown/);
    expect(() => new LocalKms({ k1: randomBytes(32) }, "zz")).toThrow();
  });
});
