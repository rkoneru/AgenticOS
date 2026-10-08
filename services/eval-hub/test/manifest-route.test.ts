import type http from "node:http";
import { createHmac, randomUUID } from "node:crypto";
import { MemoryAuditLog } from "@axis/audit";
import { ServiceAudit, listenLoopback } from "@axis/registry";
import { afterAll, describe, expect, it } from "vitest";
import {
  MemoryDocStore,
  canonicalAscii,
  createEvalHub,
  createHubDevServer,
  type DevAuth,
  type ManifestSource,
} from "../src/index.js";

const tenantA = randomUUID();
const tenantB = randomUUID();
const H = "b".repeat(64);
const TOKENS: Record<string, DevAuth> = {
  admin: { kind: "tenant", tenantId: tenantA, subject: "alice", role: "admin" },
  runner: { kind: "runner", tenantId: tenantA, runnerId: "r1" },
  runnerB: { kind: "runner", tenantId: tenantB, runnerId: "r1" },
};
const open: http.Server[] = [];
afterAll(() => Promise.all(open.map((s) => new Promise<void>((r) => s.close(() => r())))));

async function boot() {
  const asked: { tenantId: string; ref: unknown }[] = [];
  const manifests: ManifestSource = {
    manifest: (tenantId, ref) => {
      asked.push({ tenantId, ref });
      return Promise.resolve(ref.name === "ghost" ? undefined : { blueprint: { name: ref.name } });
    },
  };
  const hub = createEvalHub({
    docs: new MemoryDocStore(),
    audit: new ServiceAudit(new MemoryAuditLog(), "eval-hub"),
  });
  const server = createHubDevServer({ hub, tokens: TOKENS, manifests });
  open.push(server);
  const url = `http://127.0.0.1:${await listenLoopback(server)}`;
  const call = async (tok: string, method: string, path: string, body?: unknown) => {
    const text = body === undefined ? undefined : canonicalAscii(body);
    const res = await fetch(`${url}/v1/evals${path}`, {
      method,
      headers: {
        authorization: `Bearer ${tok}`,
        ...(tok.startsWith("runner") ? { "x-axis-runner-id": "r1" } : {}),
        ...(text !== undefined
          ? {
              "content-type": "application/json",
              ...(tok.startsWith("runner")
                ? {
                    "x-axis-runner-signature": `v1=${createHmac("sha256", tok).update(text).digest("hex")}`,
                  }
                : {}),
            }
          : {}),
      },
      ...(text !== undefined ? { body: text } : {}),
    });
    return { status: res.status, json: (await res.json()) as Record<string, unknown> };
  };
  return { call, asked };
}

describe("GET /runner/manifest", () => {
  it("serves the manifest only to a runner that holds a running run of exactly that version", async () => {
    const { call, asked } = await boot();
    await call("admin", "PUT", "/runners/r1", {});
    await call("admin", "POST", "/datasets", { name: "ds", cases: [{ id: "c1", input: "q" }] });
    await call("admin", "POST", "/suites", {
      ref: "st@1.0.0",
      dataset_ref: "ds@1",
      graders: [{ id: "g1", kind: "deterministic", config: { type: "exact" } }],
      pass_threshold: 0.5,
    });
    const q = "/runner/manifest?name=agent&version=1.0.0&namespace=pub";
    // nothing claimed yet
    expect((await call("runner", "GET", q)).status).toBe(403);
    const run = await call("admin", "POST", "/runs", {
      suite_ref: "st@1.0.0",
      blueprint: { name: "agent", version: "1.0.0", content_hash: H, namespace: "pub" },
    });
    expect(run.status).toBe(202);
    // queued but not claimed: still no
    expect((await call("runner", "GET", q)).status).toBe(403);
    expect((await call("runner", "POST", "/runner/claim", { runner_id: "r1" })).status).toBe(200);
    const ok = await call("runner", "GET", q);
    expect(ok.status).toBe(200);
    expect(ok.json).toEqual({ manifest: { blueprint: { name: "agent" } } });
    expect(asked).toEqual([
      { tenantId: tenantA, ref: { namespace: "pub", name: "agent", version: "1.0.0" } },
    ]);
    // another version, another name, a tenant member and a runner of another tenant: refused, and the source is not asked
    expect((await call("runner", "GET", "/runner/manifest?name=agent&version=2.0.0")).status).toBe(
      403,
    );
    expect((await call("runner", "GET", "/runner/manifest?name=other&version=1.0.0")).status).toBe(
      403,
    );
    expect((await call("admin", "GET", q)).status).toBe(403);
    expect((await call("runnerB", "GET", q)).status).toBe(403);
    expect((await call("runner", "GET", "/runner/manifest?name=agent")).status).toBe(404);
    expect(asked).toHaveLength(1);
  });

  it("is absent when the composition wires no manifest source", async () => {
    const hub = createEvalHub({
      docs: new MemoryDocStore(),
      audit: new ServiceAudit(new MemoryAuditLog(), "eval-hub"),
    });
    const server = createHubDevServer({ hub, tokens: TOKENS });
    open.push(server);
    const url = `http://127.0.0.1:${await listenLoopback(server)}`;
    const res = await fetch(`${url}/v1/evals/runner/manifest?name=a&version=1`, {
      headers: { authorization: "Bearer runner", "x-axis-runner-id": "r1" },
    });
    expect(res.status).toBe(404);
  });
});
