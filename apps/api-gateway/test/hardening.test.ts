import { describe, expect, it } from "vitest";
import { clientAddress } from "../src/limits.js";
import { call, makeWorld } from "./world.js";

describe("rate limits weigh the expensive operations by default", () => {
  it("a tenant cannot run verify/test/explain/audit-scan operations at the rate of /me: each draws more of the bucket", async () => {
    // frozen clock: no refill, so the count of calls that fit in the burst is exact
    const w = await makeWorld({ now: () => 1_000_000, unauthRate: { burst: 1e6, perSecond: 1 } });
    const x = await w.tenant();
    const cheap = async (n: number) => {
      let ok = 0;
      for (let i = 0; i < n; i++)
        if ((await call(w, "GET", "/me", { token: x.token })).status === 200) ok++;
      return ok;
    };
    // /me costs 1: the default burst of 60 serves 60 of them
    expect(await cheap(61)).toBe(60);
    await w.close();

    for (const [method, path, body, max] of [
      ["POST", "/audit/verify", {}, 5],
      ["POST", "/policies:test", undefined, 10],
      ["GET", "/audit/events", undefined, 30],
    ] as const) {
      const w2 = await makeWorld({
        now: () => 1_000_000,
        unauthRate: { burst: 1e6, perSecond: 1 },
      });
      const y = await w2.tenant();
      let served = 0;
      for (let i = 0; i < 61; i++) {
        const r = await call(w2, method, path, { token: y.token, ...(body ? { body } : {}) });
        if (r.status === 429) break;
        served++;
      }
      expect(served, `${method} ${path} served ${served} calls from one burst`).toBeLessThanOrEqual(
        max,
      );
      expect(served).toBeGreaterThan(0);
      await w2.close();
    }
  });
});

describe("failed-authentication throttling behind a trusted proxy", () => {
  it("clientAddress: only a trusted peer may name the client; the right-most untrusted hop wins", () => {
    const trusted = new Set(["10.0.0.1", "10.0.0.2"]);
    // not a trusted peer: the header is ignored whatever it says
    expect(clientAddress("203.0.113.9", "1.2.3.4", trusted)).toBe("203.0.113.9");
    expect(clientAddress("203.0.113.9", "1.2.3.4", new Set())).toBe("203.0.113.9");
    // a trusted peer: the client is the right-most hop that is not a trusted proxy
    expect(clientAddress("10.0.0.1", "198.51.100.7", trusted)).toBe("198.51.100.7");
    expect(clientAddress("10.0.0.1", "6.6.6.6, 198.51.100.7, 10.0.0.2", trusted)).toBe(
      "198.51.100.7",
    );
    // what the client put to the LEFT of the address the proxy appended is its own claim and is never used
    expect(clientAddress("::ffff:10.0.0.1", "7.7.7.7, 198.51.100.7", trusted)).toBe("198.51.100.7");
    // garbage, absence and an all-trusted chain fall back to the peer
    expect(clientAddress("10.0.0.1", "not-an-ip", trusted)).toBe("10.0.0.1");
    expect(clientAddress("10.0.0.1", undefined, trusted)).toBe("10.0.0.1");
    expect(clientAddress("10.0.0.1", "10.0.0.2", trusted)).toBe("10.0.0.1");
    expect(clientAddress(undefined, undefined, trusted)).toBe("unknown");
  });

  it("one client's failed logins no longer lock every user out of the console's gateway", async () => {
    const w = await makeWorld({
      unauthRate: { burst: 3, perSecond: 0.001 },
      rate: { burst: 1e6, perSecond: 1e6 },
      trustedProxies: ["127.0.0.1"],
    });
    const user = await w.tenant();
    const attacker = { "x-forwarded-for": "198.51.100.66" };
    const codes: number[] = [];
    for (let i = 0; i < 6; i++)
      codes.push((await call(w, "GET", "/runs", { token: `bad-${i}`, headers: attacker })).status);
    expect(codes).toEqual([401, 401, 401, 429, 429, 429]);
    // a different client, valid session, same proxy: served
    const ok = await call(w, "GET", "/runs", {
      token: user.token,
      headers: { "x-forwarded-for": "203.0.113.5" },
    });
    expect(ok.status, ok.text).toBe(200);
    // the attacker cannot reset its own count by inventing hops to the left of the one the proxy appended
    const spoof = await call(w, "GET", "/runs", {
      token: "bad-x",
      headers: { "x-forwarded-for": "1.1.1.1, 198.51.100.66" },
    });
    expect(spoof.status).toBe(429);
    await w.close();

    // untrusted by default: the header means nothing and the peer's bucket is shared (the documented, safe default)
    const d = await makeWorld({ unauthRate: { burst: 2, perSecond: 0.001 } });
    for (let i = 0; i < 2; i++) await call(d, "GET", "/runs", { token: `bad-${i}` });
    const shared = await call(d, "GET", "/runs", {
      token: "bad-9",
      headers: { "x-forwarded-for": "5.5.5.5" },
    });
    expect(shared.status).toBe(429);
    await d.close();
  });
});
