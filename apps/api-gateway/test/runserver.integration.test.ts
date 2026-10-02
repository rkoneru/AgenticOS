import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { HttpRunsPort } from "../src/index.js";
import { call, makeWorld, seed, type Seed, type World } from "./world.js";

/**
 * The gateway against the REAL Python run service (scripted model and gate behind it): start through the public API, watch the run
 * finish, read its events as JSON and as SSE, and prove another tenant cannot see it.
 */
const RUNTIME = fileURLToPath(new URL("../../../runtime/", import.meta.url));
let proc: ChildProcess;
let w: World;
let s: Seed;
const TOKEN = `rs-${randomUUID()}`;

beforeAll(async () => {
  w = await makeWorld({ rate: { burst: 1e6, perSecond: 1e6 }, unauthRate: { burst: 1e6, perSecond: 1e6 } });
  s = await seed(w); // published blueprint (the fake run service behind it is replaced below)
  proc = spawn("uv", ["run", "--no-sync", "python", "tests/runserver_fake_main.py", TOKEN, s.owner.tenantId], { cwd: RUNTIME, stdio: ["ignore", "pipe", "inherit"] });
  const port = await new Promise<number>((resolve, reject) => {
    proc.once("error", reject);
    proc.stdout?.on("data", (d: Buffer) => {
      const m = /"port": (\d+)/.exec(d.toString());
      if (m) resolve(Number(m[1]));
    });
    setTimeout(() => reject(new Error("run service did not start")), 60_000);
  });
  // the run service's token table binds ONE tenant; other tenants have no credential and are refused before any call
  w.deps.runs = new HttpRunsPort(`http://127.0.0.1:${port}`, (t) => (t === s.owner.tenantId ? TOKEN : undefined));
});
afterAll(async () => {
  proc?.kill();
  await w?.close();
});

describe("gateway <-> real run service", () => {
  it("a run started through /v1 finishes; events and SSE come from the Python event log", async () => {
    const start = await call(w, "POST", "/runs", { token: s.owner.token, body: { blueprint: s.blueprint, input: { prompt: "hello" } } });
    expect(start.status, start.text).toBe(202);
    const id = start.body.id as string;
    let run = start.body;
    for (let i = 0; i < 100 && run.state !== "terminated"; i++) {
      await new Promise((r) => setTimeout(r, 50));
      run = (await call(w, "GET", `/runs/${id}`, { token: s.owner.token })).body;
    }
    expect(run).toMatchObject({ state: "terminated", exit_reason: "completed", trace_id: start.body.trace_id });
    expect(run.tenant_id).toBeUndefined(); // stripped by the gateway
    const ev = await call(w, "GET", `/runs/${id}/events?limit=200`, { token: s.owner.token });
    expect(ev.body.items.map((e: { type: string }) => e.type)).toContain("model_call");
    const sse = await fetch(`${w.base}/runs/${id}/events`, { headers: { accept: "text/event-stream", authorization: `Bearer ${s.owner.token}` } });
    const text = await sse.text();
    expect(text).toContain("event: run_event");
    expect(text).toContain('event: end\ndata: {"reason":"completed"}');
    const list = await call(w, "GET", "/runs?state=terminated", { token: s.owner.token });
    expect(list.body.items.map((r: { id: string }) => r.id)).toContain(id);
    // signalling a finished run is a conflict, mapped by the gateway
    expect((await call(w, "POST", `/runs/${id}/signals`, { token: s.owner.token, body: { signal: "KILL" } })).status).toBe(409);
    // another tenant of the gateway has no run-service credential: 503, never someone else's data (and 404 for ids it does not own)
    const other = await w.tenant();
    expect([404, 503]).toContain((await call(w, "GET", `/runs/${id}`, { token: other.token })).status);
  });
});
