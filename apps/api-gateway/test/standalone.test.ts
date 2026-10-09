import { mkdtempSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ApprovalError } from "@axis/approvals";
import { describe, expect, it } from "vitest";
import { HttpApprovalsClient } from "../src/adapters/approvals-http.js";
import { ConfigError, RunnerTokenTable, TokenTable, configFromEnv } from "../src/standalone.js";

const HEX = "a".repeat(64);
const good = (): Record<string, string> => ({
  GW_DATABASE_URL: "postgres://x@127.0.0.1/db",
  GW_PEPPER: HEX,
  GW_COOKIE_KEY: HEX,
  GW_SIGNING_KEY: HEX,
  GW_SEAL_KEY: "seal",
  GW_RUN_SERVICE_URL: "http://127.0.0.1:1",
  GW_RUN_TOKENS_FILE: "/tmp/run.json",
  GW_KERNEL_TARGET: "127.0.0.1:2",
  GW_KERNEL_TOKENS_FILE: "/tmp/k.json",
  GW_APPROVALS_URL: "http://127.0.0.1:3",
  GW_APPROVALS_TOKENS_FILE: "/tmp/a.json",
});

describe("configFromEnv (standalone DEV gateway)", () => {
  it("accepts a complete configuration and applies safe defaults", () => {
    const c = configFromEnv(good());
    expect(c).toMatchObject({ port: 0, host: "127.0.0.1", allowedOrigins: [], rate: undefined });
    expect(c.secrets.pepper).toHaveLength(32);
  });
  it("the per-tenant SSE stream cap defaults to 16 and is configurable within bounds (GW_MAX_SSE_STREAMS)", () => {
    expect(configFromEnv(good()).maxSseStreams).toBe(16);
    expect(configFromEnv({ ...good(), GW_MAX_SSE_STREAMS: "500" }).maxSseStreams).toBe(500);
    expect(() => configFromEnv({ ...good(), GW_MAX_SSE_STREAMS: "0" })).toThrow(
      /GW_MAX_SSE_STREAMS/,
    );
  });
  it("REFUSES NODE_ENV=production: the dev composition must never be mistaken for a production one", () => {
    expect(() => configFromEnv({ ...good(), NODE_ENV: "production" })).toThrow(ConfigError);
    expect(() => configFromEnv({ ...good(), NODE_ENV: "production" })).toThrow(/DEV composition/);
  });
  it("refuses every missing or malformed required value, naming it, never printing a secret", () => {
    for (const k of Object.keys(good())) {
      const e = good();
      delete e[k];
      expect(() => configFromEnv(e), k).toThrow(new RegExp(k));
    }
    expect(() => configFromEnv({ ...good(), GW_PEPPER: "short" })).toThrow(/64 hex/);
    expect(() => configFromEnv({ ...good(), GW_RUN_SERVICE_URL: "ftp://x" })).toThrow(/http/);
    expect(() => configFromEnv({ ...good(), GW_RUN_SERVICE_URL: "nope" })).toThrow(/http/);
    expect(() => configFromEnv({ ...good(), GW_PORT: "70000" })).toThrow(/GW_PORT/);
    expect(() => configFromEnv({ ...good(), GW_PORT: "x" })).toThrow(/GW_PORT/);
    try {
      configFromEnv({ ...good(), GW_SEAL_KEY: "", GW_PEPPER: "s3cret-not-hex" });
    } catch (e) {
      expect(String(e)).not.toContain("s3cret-not-hex");
    }
  });
  it("only binds a loopback address and parses origins and rate limits", () => {
    expect(() => configFromEnv({ ...good(), GW_HOST: "0.0.0.0" })).toThrow(/loopback/);
    const c = configFromEnv({
      ...good(),
      GW_HOST: "localhost",
      GW_ALLOWED_ORIGINS: "http://localhost:3100, http://x.test",
      GW_RATE_BURST: "500",
    });
    expect(c.allowedOrigins).toEqual(["http://localhost:3100", "http://x.test"]);
    expect(c.rate).toEqual({ burst: 500, perSecond: 30 });
  });
});

describe("GW_TRUSTED_PROXIES", () => {
  it("is empty by default and only accepts IP literals", () => {
    expect(configFromEnv(good()).trustedProxies).toEqual([]);
    expect(
      configFromEnv({ ...good(), GW_TRUSTED_PROXIES: "127.0.0.1, ::1" }).trustedProxies,
    ).toEqual(["127.0.0.1", "::1"]);
    expect(() => configFromEnv({ ...good(), GW_TRUSTED_PROXIES: "console.internal" })).toThrow(
      /GW_TRUSTED_PROXIES/,
    );
  });
});

describe("TokenTable", () => {
  it("re-reads a rewrite that kept the same mtime (size and inode are part of the cache key)", () => {
    const dir = mkdtempSync(join(tmpdir(), "gw-tok-"));
    const f = join(dir, "t.json");
    const t = new TokenTable(f);
    writeFileSync(f, JSON.stringify({ a: "tok-a" }));
    const when = new Date(Date.now() - 60_000);
    utimesSync(f, when, when);
    expect(t.get("a")).toBe("tok-a");
    expect(t.get("b")).toBeUndefined();
    writeFileSync(f, JSON.stringify({ a: "tok-a", b: "tok-b-new-tenant" }));
    utimesSync(f, when, when); // the tenant was added within the same timestamp tick
    expect(t.get("b")).toBe("tok-b-new-tenant");
  });
  it("re-reads the file when it changes and treats a missing or broken file as no credential", () => {
    const dir = mkdtempSync(join(tmpdir(), "gw-tok-"));
    const f = join(dir, "t.json");
    const t = new TokenTable(f);
    expect(t.get("a")).toBeUndefined(); // missing
    writeFileSync(f, JSON.stringify({ a: "tok-a", b: 5 }));
    expect(t.get("a")).toBe("tok-a");
    expect(t.get("b")).toBeUndefined(); // non-string value
    expect(t.get("__proto__")).toBeUndefined();
    writeFileSync(f, JSON.stringify({ a: "tok-a2" }));
    utimesSync(f, new Date(), new Date(Date.now() + 5000));
    expect(t.get("a")).toBe("tok-a2");
    writeFileSync(f, "{ not json");
    utimesSync(f, new Date(), new Date(Date.now() + 10_000));
    expect(t.get("a")).toBeUndefined();
  });
});

describe("eval runner surface", () => {
  it("is off by default and configured by a tokens file", () => {
    expect(configFromEnv(good()).evalRunner).toBeUndefined();
    expect(
      configFromEnv({
        ...good(),
        GW_EVAL_RUNNER_TOKENS_FILE: "/tmp/r.json",
        GW_EVAL_RUNNER_PORT: "4100",
      }).evalRunner,
    ).toEqual({ tokensFile: "/tmp/r.json", port: 4100 });
    expect(() =>
      configFromEnv({ ...good(), GW_EVAL_RUNNER_TOKENS_FILE: "/x", GW_EVAL_RUNNER_PORT: "99999" }),
    ).toThrow(/GW_EVAL_RUNNER_PORT/);
  });
  it("RunnerTokenTable authenticates by token digest, follows the file and ignores malformed entries", () => {
    const dir = mkdtempSync(join(tmpdir(), "gw-rtok-"));
    const f = join(dir, "r.json");
    const t = new RunnerTokenTable(f);
    expect(t.authenticate("Bearer x")).toBeUndefined(); // missing file
    writeFileSync(
      f,
      JSON.stringify({
        "rk-1": { tenantId: "t1", runnerId: "r1" },
        "rk-2": { tenantId: "t2", runnerId: "r2", signingKey: "sig" },
        "rk-bad": { tenantId: "t3" },
        "rk-str": "nope",
      }),
    );
    expect(t.authenticate("Bearer rk-1")).toEqual({ tenantId: "t1", runnerId: "r1" });
    expect(t.authenticate("Bearer rk-2")).toEqual({
      tenantId: "t2",
      runnerId: "r2",
      signingKey: "sig",
    });
    for (const a of [
      undefined,
      "",
      "rk-1",
      "Basic rk-1",
      "Bearer ",
      "Bearer rk-bad",
      "Bearer rk-str",
      "Bearer rk-3",
    ])
      expect(t.authenticate(a), String(a)).toBeUndefined();
    writeFileSync(f, JSON.stringify({ "rk-3": { tenantId: "t9", runnerId: "r9" } }));
    utimesSync(f, new Date(), new Date(Date.now() + 5000));
    expect(t.authenticate("Bearer rk-3")).toEqual({ tenantId: "t9", runnerId: "r9" });
    expect(t.authenticate("Bearer rk-1")).toBeUndefined();
    writeFileSync(f, "{ not json");
    utimesSync(f, new Date(), new Date(Date.now() + 10_000));
    expect(t.authenticate("Bearer rk-3")).toBeUndefined();
  });
});

describe("HttpApprovalsClient", () => {
  const P = { tenant_id: "t1", id: "m1", roles: ["admin"] };
  const mk = (
    res: () => Response | Promise<Response>,
    tokens: Record<string, string> = { t1: "tok" },
  ) => {
    const calls: { url: string; init: RequestInit }[] = [];
    const c = new HttpApprovalsClient("http://bridge.test/", (t) => tokens[t], 1000, ((
      url: string,
      init: RequestInit,
    ) => {
      calls.push({ url, init });
      return Promise.resolve(res());
    }) as never);
    return { c, calls };
  };
  const json = (status: number, body: unknown) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

  it("sends the tenant's bearer and the principal from the caller, and returns the request", async () => {
    const { c, calls } = mk(() => json(200, { request: { id: "r1", tenant_id: "t1" } }));
    expect((await c.approve(P, "r1", "ok")).id).toBe("r1");
    expect(calls[0]?.url).toBe("http://bridge.test/v1/approvals/approve");
    expect((calls[0]?.init.headers as Record<string, string>)["authorization"]).toBe("Bearer tok");
    expect(JSON.parse(calls[0]?.init.body as string)).toEqual({
      request_id: "r1",
      principal: { id: "m1", roles: ["admin"] },
      comment: "ok",
    });
    expect((await c.deny(P, "r1")).id).toBe("r1");
    expect((await c.get(P, "r1")).id).toBe("r1");
  });
  it("lists and bounds the answer", async () => {
    const { c } = mk(() => json(200, { requests: [{ id: "a" }, { id: "b" }, { id: "c" }] }));
    expect(await c.list(P, { status: "pending", limit: 2 })).toHaveLength(2);
    const bad = mk(() => json(200, { requests: "x" }));
    await expect(bad.c.list(P)).rejects.toBeInstanceOf(ApprovalError);
  });
  it("maps the bridge's error codes and turns every other failure into an error, never a success", async () => {
    const forbidden = mk(() => json(403, { error: { code: "SELF_APPROVAL", message: "no" } }));
    await expect(forbidden.c.approve(P, "r")).rejects.toMatchObject({ code: "SELF_APPROVAL" });
    const odd = mk(() => json(500, { error: { code: "INTERNAL" } }));
    await expect(odd.c.get(P, "r")).rejects.toMatchObject({ code: "AUDIT_FAILED" });
    const garbage = mk(() => new Response("<html>", { status: 200 }));
    await expect(garbage.c.get(P, "r")).rejects.toMatchObject({ code: "AUDIT_FAILED" });
    const noBody = mk(() => json(200, {}));
    await expect(noBody.c.get(P, "r")).rejects.toMatchObject({ code: "AUDIT_FAILED" });
    const down = mk(() => Promise.reject(new Error("ECONNREFUSED")));
    await expect(down.c.get(P, "r")).rejects.toMatchObject({ code: "AUDIT_FAILED" });
    const noToken = mk(() => json(200, { request: {} }), {});
    await expect(noToken.c.get(P, "r")).rejects.toMatchObject({ code: "AUDIT_FAILED" });
    expect(noToken.calls).toHaveLength(0); // no credential: nothing is sent
  });
});
