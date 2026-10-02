import { describe, expect, it } from "vitest";
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
