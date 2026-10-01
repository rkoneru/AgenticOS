import { describe, expect, it } from "vitest";
import { StaticJwks, verifyRs256Jwt, type JwtOptions } from "../src/index.js";
import { KID, NOW, goodClaims, jwkOf, jwks, otherRsa, rsa, signJwt } from "./helpers.js";
import { generateKeyPairSync } from "node:crypto";

const opts = (over: Partial<JwtOptions> = {}): JwtOptions => ({
  jwks,
  issuers: ["https://api.botframework.com"],
  audience: "app-id-1",
  nowMs: NOW,
  ...over,
});

describe("verifyRs256Jwt", () => {
  it("accepts a valid token", async () => {
    const r = await verifyRs256Jwt(signJwt(goodClaims()), opts());
    expect(r.ok).toBe(true);
  });
  it("accepts an audience array and tolerates skew on exp and nbf", async () => {
    const t = signJwt(
      goodClaims(NOW, { aud: ["x", "app-id-1"], exp: NOW / 1000 - 100, nbf: NOW / 1000 + 100 }),
    );
    expect((await verifyRs256Jwt(t, opts())).ok).toBe(true);
  });
  const bad = async (token: string, why: string, o = opts()): Promise<void> => {
    const r = await verifyRs256Jwt(token, o);
    expect(r).toEqual({ ok: false, reason: why });
  };
  it("rejects wrong algorithms before touching a key", async () => {
    await bad(signJwt(goodClaims(), { alg: "none" }), "unsupported alg");
    await bad(signJwt(goodClaims(), { alg: "HS256" }), "unsupported alg");
    await bad(signJwt(goodClaims(), { alg: "ES256" }), "unsupported alg");
  });
  it("rejects crit headers, missing kid and unknown kid", async () => {
    await bad(signJwt(goodClaims(), { header: { crit: ["x"] } }), "unsupported crit");
    await bad(signJwt(goodClaims(), { kid: "" }), "missing kid");
    await bad(signJwt(goodClaims(), { kid: "nope" }), "unknown key");
  });
  it("rejects a token signed by another key, and any tampering", async () => {
    await bad(signJwt(goodClaims(), { kp: otherRsa }), "signature mismatch");
    const t = signJwt(goodClaims());
    const [h, p, s] = t.split(".") as [string, string, string];
    const forged = Buffer.from(JSON.stringify({ ...goodClaims(), aud: "other" })).toString(
      "base64url",
    );
    await bad(`${h}.${forged}.${s}`, "signature mismatch");
    expect(p).toBeTruthy();
    await bad(`${h}.${p}.${s.slice(0, -2)}AA`, "signature mismatch");
  });
  it("checks iss, aud, exp (required) and nbf", async () => {
    await bad(signJwt(goodClaims(NOW, { iss: "https://evil.example" })), "bad issuer");
    await bad(signJwt(goodClaims(NOW, { aud: "someone-else" })), "bad audience");
    await bad(signJwt(goodClaims(NOW, { aud: undefined })), "bad audience");
    await bad(signJwt(goodClaims(NOW, { exp: NOW / 1000 - 301 })), "expired");
    await bad(signJwt(goodClaims(NOW, { exp: undefined })), "missing exp");
    await bad(signJwt(goodClaims(NOW, { exp: "soon" })), "missing exp");
    await bad(signJwt(goodClaims(NOW, { nbf: NOW / 1000 + 301 })), "not yet valid");
    await bad(signJwt(goodClaims(NOW, { nbf: "later" })), "not yet valid");
  });
  it("rejects malformed tokens", async () => {
    await bad("a.b", "not a compact JWS");
    await bad("a.b.c.d", "not a compact JWS");
    await bad("!!.b.c", "bad header");
    await bad(`${Buffer.from("[]").toString("base64url")}.b.c`, "bad header");
    await bad(`${Buffer.from("not json").toString("base64url")}.b.c`, "bad header");
    await bad("x".repeat(9000), "token too large");
    const t = signJwt(goodClaims()).split(".");
    await bad(`${t[0]}.${t[1]}.`, "bad signature encoding");
    await bad(`${t[0]}.${t[1]}.!!`, "bad signature encoding");
    // a validly signed but non-object payload
    const enc = Buffer.from(JSON.stringify({ alg: "RS256", kid: KID })).toString("base64url");
    await bad(`${enc}.${Buffer.from("[]").toString("base64url")}.AAAA`, "signature mismatch");
  });
  it("refuses weak keys, non-RSA keys and unusable key sets", async () => {
    const weak = generateKeyPairSync("rsa", { modulusLength: 1024 });
    const weakJwks = new StaticJwks([jwkOf(weak as unknown as typeof rsa, "w")]);
    await bad(
      signJwt(goodClaims(), { kp: weak as unknown as typeof rsa, kid: "w" }),
      "weak key",
      opts({ jwks: weakJwks }),
    );
    const ec = new StaticJwks([{ kty: "EC", kid: KID, crv: "P-256", x: "a", y: "b" }]);
    await bad(signJwt(goodClaims()), "unknown key", opts({ jwks: ec }));
    const enc = new StaticJwks([{ ...jwkOf(rsa, KID), use: "enc" }]);
    await bad(signJwt(goodClaims()), "unknown key", opts({ jwks: enc }));
    const noN = new StaticJwks([{ kty: "RSA", kid: KID }]);
    await bad(signJwt(goodClaims()), "weak key", opts({ jwks: noN }));
    const garbage = new StaticJwks([{ kty: "RSA", kid: KID, n: "A".repeat(400), e: "AQAB" }]);
    expect((await verifyRs256Jwt(signJwt(goodClaims()), opts({ jwks: garbage }))).ok).toBe(false);
    await bad(
      signJwt(goodClaims()),
      "jwks unavailable",
      opts({
        jwks: {
          keys: async () => {
            throw new Error("down");
          },
        },
      }),
    );
  });
  it("StaticJwks returns its keys", async () => {
    expect(await new StaticJwks([]).keys()).toEqual([]);
  });
});
