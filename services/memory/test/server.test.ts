import { readFileSync } from "node:fs";
import type http from "node:http";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { inject } from "vitest";
import type pg from "pg";
import { createDevServer, listenLoopback, staticTokenAuthenticator } from "../src/index.js";
import { adminClient, newPool, newService, newTenant } from "./helpers.js";

const wire = JSON.parse(readFileSync(new URL("../contract/wire-v1.json", import.meta.url), "utf8"));

/** Recursive key structure (arrays by their first element), for comparing a real response with a documented example. */
function shape(v: unknown): unknown {
  if (Array.isArray(v)) return v.length === 0 ? [] : [shape(v[0])];
  if (typeof v === "object" && v !== null)
    return Object.fromEntries(
      Object.keys(v)
        .sort()
        .map((k) => [k, shape((v as Record<string, unknown>)[k])]),
    );
  return typeof v === "string" || v === null ? "scalar" : typeof v;
}
const nullish = (s: unknown): unknown =>
  JSON.parse(JSON.stringify(s).replace(/"(string|number|boolean)"/g, '"scalar"'));

describe("dev HTTP server", () => {
  let pool: pg.Pool;
  let admin: pg.Client;
  let server: http.Server;
  let base: string;
  let tenant: string;
  let other: string;
  const AGENT = "tok-agent";
  const ADMIN = "tok-admin";
  const OTHER = "tok-other";

  const post = async (route: string, body: unknown, token: string | null = AGENT, raw?: string) => {
    const res = await fetch(`${base}/v1/memory/${route}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: raw ?? JSON.stringify(body),
    });
    return { status: res.status, json: (await res.json()) as Record<string, unknown> };
  };
  const P = { id: "alice", groups: ["eng"] };

  beforeAll(async () => {
    pool = newPool();
    admin = await adminClient();
    tenant = await newTenant(admin);
    other = await newTenant(admin);
    server = createDevServer({
      service: newService(pool),
      authenticate: staticTokenAuthenticator({
        [AGENT]: { tenantId: tenant, admin: false },
        [ADMIN]: { tenantId: tenant, admin: true },
        [OTHER]: { tenantId: other, admin: true },
      }),
    });
    base = `http://127.0.0.1:${await listenLoopback(server)}`;
  });
  afterAll(async () => {
    await new Promise((r) => server.close(r));
    await pool.end();
    await admin.end();
  });

  it("matches the shared wire contract (also exercised by the Python client tests)", async () => {
    for (const ex of wire.exchanges) {
      const body = JSON.parse(JSON.stringify(ex.request).replaceAll("{tenant}", tenant));
      const r = await post(ex.route, body);
      expect(r.status, ex.name).toBe(200);
      expect(nullish(shape(r.json)), ex.name).toEqual(nullish(shape(ex.response)));
    }
  });

  it("full admin flow: ingest, search with ACL, set-acl, delete, forget, purge", async () => {
    const ing = await post(
      "ingest",
      {
        kb: "handbook",
        content: "Refunds are processed within five business days.",
        acl: { users: ["alice"] },
        subject: "s1",
        principal: P,
      },
      ADMIN,
    );
    expect(ing.status).toBe(200);
    expect(ing.json).toMatchObject({ chunks: 1, deduped: false });
    const q = { query: "refund processing time", principal: { id: "bob", groups: [] } };
    expect((await post("search", q)).json["hits"]).toEqual([]);
    expect(
      (
        await post(
          "set-acl",
          { document_id: ing.json["document_id"], acl: { tenant: true } },
          ADMIN,
        )
      ).status,
    ).toBe(200);
    expect((await post("search", q)).json["hits"]).toHaveLength(1);
    expect((await post("forget", { subject: "s1" }, ADMIN)).json).toEqual({
      chunks: 1,
      documents: 1,
    });
    expect((await post("search", q)).json["hits"]).toEqual([]);
    const again = await post(
      "ingest",
      { kb: "handbook", content: "temp", acl: { tenant: true }, principal: P },
      ADMIN,
    );
    expect(
      (await post("delete-document", { document_id: again.json["document_id"] }, ADMIN)).status,
    ).toBe(200);
    expect(
      (await post("delete-document", { document_id: again.json["document_id"] }, ADMIN)).status,
    ).toBe(404);
    expect((await post("purge", {}, ADMIN)).json).toEqual({ chunks: 0, documents: 0 });
  });

  it("derives the tenant from the token: another tenant's token never sees these rows; a mismatched body tenant_id is rejected", async () => {
    await post("write", {
      scope: "tenant",
      content: "tenant one fact",
      acl: { tenant: true },
      principal: P,
    });
    const q = { query: "tenant one fact", principal: P };
    expect((await post("search", q)).json["hits"]).toHaveLength(1);
    expect((await post("search", q, OTHER)).json["hits"]).toEqual([]);
    expect((await post("search", { ...q, tenant_id: other }, AGENT)).status).toBe(403);
    expect((await post("search", { ...q, tenant_id: tenant }, AGENT)).status).toBe(200);
  });

  it("authenticates, authorises and validates (fail closed)", async () => {
    expect((await post("search", {}, null)).status).toBe(401);
    expect((await post("search", {}, "bogus")).status).toBe(401);
    for (const route of ["ingest", "set-acl", "delete-document", "forget", "purge"])
      expect((await post(route, {}, AGENT)).status, route).toBe(403);
    expect((await post("nope", {}, AGENT)).status).toBe(404);
    expect((await fetch(`${base}/v1/memory/search`)).status).toBe(404);
    expect((await post("search", null, AGENT, "{not json")).status).toBe(400);
    expect((await post("search", null, AGENT, "[]")).status).toBe(400);
    expect((await post("search", { principal: P })).status).toBe(400); // query required
    expect((await post("search", { query: "x", principal: P, limit: "3" })).status).toBe(400);
    expect((await post("search", { query: "x" })).status).toBe(400); // principal required
    expect((await post("search", { query: "x", principal: { groups: [] } })).status).toBe(400);
    expect((await post("write", { scope: "kb", content: "x", principal: P })).status).toBe(400); // service MemoryError
    expect(
      (
        await post(
          "delete-document",
          { document_id: "00000000-0000-4000-8000-000000000000" },
          ADMIN,
        )
      ).status,
    ).toBe(404);
    expect(
      (await post("write", null, AGENT, JSON.stringify({ content: "x".repeat(1_600_000) }))).status,
    ).toBe(400);
  });

  it("maps embedder failures to 502 and unexpected errors to an opaque 500", async () => {
    const bad = createDevServer({
      service: newService(pool, {
        embedder: { id: "x", dimensions: 1536, embed: () => Promise.reject(new Error("boom")) },
      }),
      authenticate: staticTokenAuthenticator({ t: { tenantId: tenant, admin: false } }),
    });
    const port = await listenLoopback(bad);
    const r = await fetch(`http://127.0.0.1:${port}/v1/memory/write`, {
      method: "POST",
      headers: { authorization: "Bearer t" },
      body: JSON.stringify({ scope: "tenant", content: "x", principal: P }),
    });
    expect(r.status).toBe(502);
    await new Promise((res) => bad.close(res));
    const broken = createDevServer({
      service: newService(pool, {
        pool: { connect: () => Promise.reject(new Error("db password=hunter2")) },
      }),
      authenticate: staticTokenAuthenticator({ t: { tenantId: tenant, admin: false } }),
    });
    const p2 = await listenLoopback(broken);
    const r2 = await fetch(`http://127.0.0.1:${p2}/v1/memory/search`, {
      method: "POST",
      headers: { authorization: "Bearer t" },
      body: JSON.stringify({ query: "x", principal: P }),
    });
    expect(r2.status).toBe(500);
    expect(await r2.text()).not.toContain("hunter2");
    await new Promise((res) => broken.close(res));
  });

  it("main.ts starts as a process, serves a request and exits on SIGTERM", async () => {
    const t = await newTenant(admin);
    const child = spawn(process.execPath, ["--import", "tsx", "src/main.ts"], {
      cwd: new URL("..", import.meta.url).pathname,
      env: {
        ...process.env,
        AXIS_MEMORY_DATABASE_URL: inject("dbUrl"),
        AXIS_MEMORY_ROLE: "axis_app",
        AXIS_MEMORY_TOKENS: JSON.stringify({ k: { tenantId: t, admin: false } }),
      },
      stdio: ["ignore", "pipe", "inherit"],
    });
    const line: string = await new Promise((res, rej) => {
      createInterface({ input: child.stdout }).once("line", res);
      child.once("error", rej);
    });
    const port = /listening (\d+)/.exec(line)?.[1];
    const r = await fetch(`http://127.0.0.1:${port}/v1/memory/write`, {
      method: "POST",
      headers: { authorization: "Bearer k" },
      body: JSON.stringify({ scope: "tenant", content: "from main", principal: P }),
    });
    expect(r.status).toBe(200);
    const exited = new Promise((res) => child.once("exit", res));
    child.kill("SIGTERM");
    await exited;
  });
});
