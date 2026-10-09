import net from "node:net";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ChaosProxy } from "../src/proxy.js";

let echo: net.Server;
let echoPort: number;
let proxy: ChaosProxy;

beforeEach(async () => {
  echo = net.createServer((s) => s.on("data", (b) => s.write(b)).on("error", () => undefined));
  await new Promise<void>((r) => echo.listen(0, "127.0.0.1", r));
  echoPort = (echo.address() as net.AddressInfo).port;
  proxy = new ChaosProxy("127.0.0.1", echoPort, () => 0.5);
  await proxy.start();
});
afterEach(async () => {
  await proxy.stop();
  await new Promise<void>((r) => echo.close(() => r()));
});

function roundTrip(
  msg: string,
  timeoutMs = 3000,
): Promise<{ data: string; ms: number } | "reset" | "timeout"> {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const c = net.connect(proxy.port, "127.0.0.1");
    let data = "";
    const timer = setTimeout(() => {
      c.destroy();
      resolve("timeout");
    }, timeoutMs);
    c.on("connect", () => c.write(msg));
    c.on("data", (b) => {
      data += b.toString();
      if (data.length >= msg.length) {
        clearTimeout(timer);
        c.destroy();
        resolve({ data, ms: Date.now() - t0 });
      }
    });
    c.on("error", () => {
      clearTimeout(timer);
      resolve("reset");
    });
  });
}

describe("ChaosProxy", () => {
  it("forwards bytes untouched by default", async () => {
    expect(await roundTrip("hello")).toMatchObject({ data: "hello" });
    expect(proxy.stats.accepted).toBe(1);
    expect(proxy.stats.bytesUp).toBe(5);
    expect(proxy.stats.bytesDown).toBe(5);
  });

  it("latency delays both directions", async () => {
    proxy.set({ latencyMs: 150 });
    const r = await roundTrip("hi");
    expect(r).not.toBe("timeout");
    expect((r as { ms: number }).ms).toBeGreaterThanOrEqual(280);
  });

  it("jitter adds up to jitterMs per direction (seeded rng)", async () => {
    proxy.set({ latencyMs: 50, jitterMs: 100 });
    const r = (await roundTrip("hi")) as { ms: number };
    expect(r.ms).toBeGreaterThanOrEqual(190);
  });

  it("down refuses new connections with a reset and counts them", async () => {
    proxy.set({ down: true });
    expect(await roundTrip("x")).toBe("reset");
    expect(proxy.stats.refused).toBe(1);
    proxy.clear();
    expect(await roundTrip("x")).toMatchObject({ data: "x" });
  });

  it("down resets connections that are already open", async () => {
    const c = net.connect(proxy.port, "127.0.0.1");
    await new Promise<void>((r) => c.on("connect", () => r()));
    const closed = new Promise<string>((r) =>
      c.on("error", () => r("error")).on("close", () => r("close")),
    );
    proxy.set({ down: true });
    expect(await closed).toMatch(/error|close/);
    expect(proxy.stats.resets).toBeGreaterThanOrEqual(1);
  });

  it("blackhole swallows traffic: the client only learns by timing out", async () => {
    proxy.set({ blackhole: true });
    expect(await roundTrip("lost", 400)).toBe("timeout");
    expect(proxy.stats.bytesUp).toBe(4);
    expect(proxy.stats.bytesDown).toBe(0);
  });

  it("resetAfterBytes cuts the response mid-stream", async () => {
    proxy.set({ resetAfterBytes: 4 });
    const got = await new Promise<string>((resolve) => {
      const c = net.connect(proxy.port, "127.0.0.1");
      let data = "";
      c.on("connect", () => c.write("0123456789"));
      c.on("data", (b) => (data += b.toString()));
      c.on("error", () => resolve(data));
      c.on("close", () => resolve(data));
    });
    expect(got.length).toBeLessThan(10);
    expect(proxy.stats.resets).toBeGreaterThanOrEqual(1);
  });

  it("trickle delivers the response one byte at a time", async () => {
    proxy.set({ trickleMs: 40 });
    const r = (await roundTrip("abcde")) as { ms: number; data: string };
    expect(r.data).toBe("abcde");
    expect(r.ms).toBeGreaterThanOrEqual(150);
  });

  it("bandwidth cap spreads a large payload over time", async () => {
    proxy.set({ bytesPerSec: 2000 });
    const r = (await roundTrip("x".repeat(2000), 8000)) as { ms: number };
    expect(r.ms).toBeGreaterThanOrEqual(700);
  });

  it("an upstream that is gone resets the client", async () => {
    proxy.retarget(1);
    expect(await roundTrip("x")).toBe("reset");
    proxy.retarget(echoPort);
    expect(await roundTrip("x")).toMatchObject({ data: "x" });
    expect(proxy.current.down).toBe(false);
  });
});

describe("ChaosProxy ordering (a reordered byte stream corrupts HTTP/2: found by the chaos suite)", () => {
  it("back-to-back messages arrive in order under trickle, jitter and a bandwidth cap together", async () => {
    proxy.set({ trickleMs: 3, latencyMs: 20, jitterMs: 40, bytesPerSec: 4000 });
    const msgs = Array.from({ length: 6 }, (_, i) => `[${i}:${"x".repeat(40)}]`);
    const got = await new Promise<string>((resolve) => {
      const c = net.connect(proxy.port, "127.0.0.1");
      let data = "";
      c.on("connect", () => msgs.forEach((m) => c.write(m)));
      c.on("data", (b) => {
        data += b.toString();
        if (data.length >= msgs.join("").length) {
          c.destroy();
          resolve(data);
        }
      });
    });
    expect(got).toBe(msgs.join(""));
  });

  it("changing toxics between chunks never lets a later chunk overtake an earlier one", async () => {
    const got = await new Promise<string>((resolve) => {
      const c = net.connect(proxy.port, "127.0.0.1");
      let data = "";
      c.on("connect", () => {
        proxy.set({ trickleMs: 10 });
        c.write("AAAAAAAAAA");
        setTimeout(() => {
          proxy.clear();
          c.write("BBBBBBBBBB");
        }, 20);
      });
      c.on("data", (b) => {
        data += b.toString();
        if (data.length >= 20) {
          c.destroy();
          resolve(data);
        }
      });
    });
    expect(got).toBe("AAAAAAAAAABBBBBBBBBB");
  });
});
