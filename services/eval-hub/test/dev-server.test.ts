import type http from "node:http";
import { createHmac, randomUUID } from "node:crypto";
import { MemoryAuditLog } from "@axis/audit";
import { ServiceAudit, listenLoopback } from "@axis/registry";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  MemoryDocStore,
  canonicalAscii,
  createEvalHub,
  createHubDevServer,
  type DevAuth,
} from "../src/index.js";
import { conform, loadWire, pick, subst } from "./wire.js";

const tenantA = randomUUID();
const tenantB = randomUUID();
const TOKENS: Record<string, DevAuth> = {
  "tok-admin": { kind: "tenant", tenantId: tenantA, subject: "alice", role: "admin" },
  "tok-builder": { kind: "tenant", tenantId: tenantA, subject: "bob", role: "builder" },
  "tok-viewer": { kind: "tenant", tenantId: tenantA, subject: "vera", role: "viewer" },
  "tok-reviewer": { kind: "tenant", tenantId: tenantA, subject: "rita", role: "reviewer" },
  "tok-runner": { kind: "runner", tenantId: tenantA, runnerId: "ci-runner-1" },
  "tok-other-admin": { kind: "tenant", tenantId: tenantB, subject: "mallory", role: "owner" },
};
const BEARER: Record<string, string | undefined> = {
  admin: "tok-admin",
  builder: "tok-builder",
  reviewer: "tok-reviewer",
  runner: "tok-runner",
  none: undefined,
};

let base: string;
const open: http.Server[] = [];

async function start(
  o: { rateLimit?: { max: number; windowMs: number }; now?: () => number } = {},
): Promise<{ url: string; server: http.Server }> {
  const hub = createEvalHub({
    docs: new MemoryDocStore(),
    audit: new ServiceAudit(new MemoryAuditLog(), "eval-hub"),
  });
  const s = createHubDevServer({ hub, tokens: TOKENS, ...o });
  open.push(s);
  return { url: `http://127.0.0.1:${await listenLoopback(s)}`, server: s };
}

beforeAll(async () => {
  const r = await start();
  base = r.url;
});
afterAll(() => Promise.all(open.map((s) => new Promise<void>((r) => s.close(() => r())))));

async function call(
  token: string | undefined,
  method: string,
  path: string,
  body?: unknown,
  url = base,
  sign = true,
): Promise<{ status: number; json: Record<string, unknown>; headers: Headers }> {
  // The runner signs the exact bytes it sends, like runtime/src/axis_runtime/evals/hubclient.py (canonical JSON, HMAC-SHA256).
  const runner = token === "tok-runner";
  const text =
    body === undefined ? undefined : typeof body === "string" ? body : canonicalAscii(body);
  const res = await fetch(`${url}${path}`, {
    method,
    headers: {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(runner ? { "x-axis-runner-id": "ci-runner-1", "x-axis-runner-version": "1.0.0" } : {}),
      ...(text !== undefined ? { "content-type": "application/json" } : {}),
      ...(runner && text !== undefined && sign
        ? {
            "x-axis-runner-signature": `v1=${createHmac("sha256", token).update(text).digest("hex")}`,
          }
        : {}),
    },
    ...(text !== undefined ? { body: text } : {}),
  });
  return {
    status: res.status,
    json: (await res.json()) as Record<string, unknown>,
    headers: res.headers,
  };
}

describe("wire-v1.json: the documented examples run, in order, against the dev server", () => {
  const wire = loadWire();
  const vars: Record<string, unknown> = {};
  // The wire file is bound to the runner id of its tokens.
  for (const ex of wire.examples) {
    it(ex.name, async () => {
      // (the rate limit of the shared test server is high for this suite: fresh server per example group is not needed)
      const r = await call(
        BEARER[ex.as],
        ex.method,
        wire.base_path + subst(ex.path, vars),
        ex.request === undefined ? undefined : subst(ex.request, vars),
      );
      expect(r.status, JSON.stringify(r.json)).toBe(ex.status);
      expect(conform(subst(ex.response, vars), r.json)).toEqual([]);
      for (const [k, p] of Object.entries(ex.capture ?? {})) vars[k] = pick(r.json, p);
    });
  }
});

const H = "a".repeat(64);

describe("the dev server surface", () => {
  it("refuses to run with NODE_ENV=production", () => {
    const prev = process.env["NODE_ENV"];
    process.env["NODE_ENV"] = "production";
    try {
      expect(() =>
        createHubDevServer({
          hub: createEvalHub({
            docs: new MemoryDocStore(),
            audit: new ServiceAudit(new MemoryAuditLog(), "eval-hub"),
          }),
          tokens: {},
        }),
      ).toThrow(/production/);
    } finally {
      if (prev === undefined) delete process.env["NODE_ENV"];
      else process.env["NODE_ENV"] = prev;
    }
  });

  it("rejects bad credentials, bodies and routes without leaking anything", async () => {
    expect((await call("nope", "GET", "/v1/evals/runs")).status).toBe(401);
    expect((await call(undefined, "GET", "/v1/evals/runs")).status).toBe(401);
    expect((await call("tok-admin", "GET", "/v1/other")).status).toBe(404);
    expect((await call("tok-admin", "GET", "/v1/evals/nothing")).status).toBe(404);
    expect((await call("tok-admin", "DELETE", "/v1/evals/runs")).status).toBe(404);
    const bad = await call("tok-builder", "POST", "/v1/evals/datasets", "{not json");
    expect(bad.status).toBe(400);
    const arr = await call("tok-builder", "POST", "/v1/evals/datasets", "[]");
    expect(arr.status).toBe(400);
    const big = await fetch(`${base}/v1/evals/datasets`, {
      method: "POST",
      headers: { authorization: "Bearer tok-builder", "content-type": "application/json" },
      body: JSON.stringify({ x: "y".repeat(4_100_000) }),
    });
    expect(big.status).toBe(400);
  });

  it("the tenant comes from the credential: a tenant_id that differs is refused, never honoured", async () => {
    expect((await call("tok-admin", "GET", `/v1/evals/runs?tenant_id=${tenantB}`)).status).toBe(
      403,
    );
    expect(
      (
        await call("tok-builder", "POST", "/v1/evals/datasets", {
          name: "x-ds",
          tenant_id: tenantB,
          cases: [{ id: "a", input: 1 }],
        })
      ).status,
    ).toBe(403);
    // the same value as the credential's own tenant is harmless
    expect((await call("tok-admin", "GET", `/v1/evals/runs?tenant_id=${tenantA}`)).status).toBe(
      200,
    );
  });

  it("is rate limited per credential, with Retry-After", async () => {
    let t = 0;
    const s = await start({ rateLimit: { max: 2, windowMs: 1000 }, now: () => t });
    expect((await call("tok-admin", "GET", "/v1/evals/runs", undefined, s.url)).status).toBe(200);
    expect((await call("tok-admin", "GET", "/v1/evals/runs", undefined, s.url)).status).toBe(200);
    const limited = await call("tok-admin", "GET", "/v1/evals/runs", undefined, s.url);
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toBe("1");
    t += 1001;
    expect((await call("tok-admin", "GET", "/v1/evals/runs", undefined, s.url)).status).toBe(200);
    // another credential has its own budget
    expect((await call("tok-runner", "GET", "/v1/evals/runs", undefined, s.url)).status).toBe(200);
  });

  it("serves every route end to end and isolates tenants over HTTP", async () => {
    const s = await start();
    const c = (tok: string, m: string, p: string, b?: unknown) =>
      call(tok, m, `/v1/evals${p}`, b, s.url);
    expect((await c("tok-admin", "PUT", "/runners/ci-runner-1", {})).status).toBe(200);
    expect((await c("tok-admin", "GET", "/runners")).json["items"]).toHaveLength(1);
    const ds1 = await c("tok-builder", "POST", "/datasets", {
      name: "ds",
      cases: [
        { id: "c1", input: "q" },
        { id: "c2", input: "r" },
      ],
    });
    expect(ds1.status).toBe(201);
    expect(
      (
        await c("tok-builder", "POST", "/datasets", {
          name: "ds",
          cases: [{ id: "c1", input: "q" }],
        })
      ).json["version"],
    ).toBe(2);
    expect((await c("tok-viewer", "GET", "/datasets?name=ds")).json["items"]).toHaveLength(2);
    expect((await c("tok-viewer", "GET", "/datasets/ds/versions/latest")).json["version"]).toBe(2);
    const g = [
      { id: "g1", kind: "deterministic", config: { type: "exact" } },
      { id: "h1", kind: "human", config: { rubric: "ok?", sla_hours: 1 } },
    ];
    expect(
      (
        await c("tok-builder", "POST", "/suites", {
          ref: "st@1.0.0",
          dataset_ref: "ds@1",
          graders: g,
          pass_threshold: 0.5,
        })
      ).status,
    ).toBe(201);
    expect((await c("tok-viewer", "GET", "/suites")).json["items"]).toHaveLength(1);
    expect((await c("tok-viewer", "GET", "/suites/st@1.0.0")).json["ref"]).toBe("st@1.0.0");
    expect((await c("tok-viewer", "GET", "/suites/st%401.0.0")).json["ref"]).toBe("st@1.0.0");
    // tenant B sees none of it
    expect((await c("tok-other-admin", "GET", "/suites")).json["items"]).toEqual([]);
    expect((await c("tok-other-admin", "GET", "/suites/st@1.0.0")).status).toBe(404);
    expect((await c("tok-other-admin", "GET", "/datasets/ds/versions/1")).status).toBe(404);

    const q = await c("tok-builder", "POST", "/runs", {
      suite_ref: "st@1.0.0",
      blueprint: { name: "agent", version: "1.0.0", content_hash: H },
    });
    expect(q.status).toBe(202);
    const id = q.json["id"] as string;
    expect((await c("tok-other-admin", "GET", `/runs/${id}`)).status).toBe(404);
    expect((await c("tok-runner", "POST", `/runs/${id}/claim`, {})).status).toBe(200);
    const mkCase = (cid: string) => ({
      case_id: cid,
      status: "completed",
      attempts: 1,
      seed: 3,
      error: null,
      score: null,
      output: "a",
      trace: null,
      grades: [
        {
          grader_id: "g1",
          kind: "deterministic",
          status: "scored",
          score: 1,
          detail: "",
          provenance: {},
        },
        { grader_id: "h1", kind: "human", status: "pending", score: 0, detail: "", provenance: {} },
      ],
    });
    const payload = {
      runner_id: "ci-runner-1",
      run_id: id,
      mode: "ci",
      status: "pending_human",
      suite_ref: "st@1.0.0",
      blueprint: { name: "agent", version: "1.0.0", content_hash: H },
      started_at: "2026-10-08T12:00:00Z",
      finished_at: "2026-10-08T12:00:01Z",
      scores: {
        status: "pending_human",
        overall: null,
        per_grader: {},
        per_case: {},
        passed: null,
        failures: [],
        ungraded: 0,
      },
      case_results: [mkCase("c1"), mkCase("c2")],
      cost: { agent_usd: "0", judge_usd: "0", total_usd: "0", tokens: 0, judge_tokens: 0 },
      provenance: {
        runner_version: "1.0.0",
        runner_id: "ci-runner-1",
        aggregation_version: 1,
        seed: q.json["seed"],
        model_ids: [],
        blueprint_content_hash: H,
        dataset_version_hash: ds1.json["version_hash"],
        suite_ref: "st@1.0.0",
      },
    };
    // a body signed with the wrong key, or by a runner that names another id, is refused before anything is read
    expect(
      (await call("tok-runner", "POST", `/v1/evals/runs/${id}/results`, payload, s.url, false))
        .status,
    ).toBe(403);
    const unsigned = await fetch(`${s.url}/v1/evals/runs/${id}/results`, {
      method: "POST",
      headers: {
        authorization: "Bearer tok-runner",
        "x-axis-runner-id": "someone-else",
        "content-type": "application/json",
      },
      body: canonicalAscii(payload),
    });
    expect(unsigned.status).toBe(403);
    const sub = await c("tok-runner", "POST", `/runs/${id}/results`, payload);
    expect(sub.status, JSON.stringify(sub.json)).toBe(200);
    expect(sub.json["pending_human"]).toBe(2);
    const taskBody = ["c1", "c2"].map((cid) => ({
      case_id: cid,
      grader_id: "h1",
      rubric: "ok?",
      input: "q",
      output: "a",
      expected: null,
    }));
    expect(
      (await c("tok-runner", "POST", `/runs/${id}/review-tasks`, { tasks: taskBody })).json[
        "created"
      ],
    ).toBe(2);
    // reviews
    const tasks = (await c("tok-reviewer", "GET", `/reviews/tasks?run_id=${id}`)).json["items"] as {
      id: string;
    }[];
    expect(tasks).toHaveLength(2);
    const t0 = tasks[0] as { id: string };
    expect((await c("tok-viewer", "GET", "/reviews/tasks")).status).toBe(403);
    expect((await c("tok-reviewer", "GET", `/reviews/tasks/${t0.id}`)).status).toBe(200);
    expect((await c("tok-reviewer", "POST", `/reviews/tasks/${t0.id}/claim`, {})).status).toBe(200);
    expect(
      (await c("tok-reviewer", "POST", `/reviews/tasks/${t0.id}/skip`, { reason: "not mine" }))
        .json["state"],
    ).toBe("open");
    // bob queued the run: he may not review it
    expect((await c("tok-builder", "POST", `/reviews/tasks/${t0.id}/claim`, {})).status).toBe(403);
    expect((await c("tok-admin", "POST", `/reviews/tasks/${t0.id}/claim`, {})).status).toBe(200);
    expect(
      (await c("tok-admin", "POST", `/reviews/tasks/${t0.id}/grade`, { score: 1, comment: "good" }))
        .json["state"],
    ).toBe("resolved");
    const t1 = tasks[1] as { id: string };
    expect((await c("tok-admin", "POST", `/reviews/tasks/${t1.id}/claim`, {})).status).toBe(200);
    expect(
      (await c("tok-admin", "POST", `/reviews/tasks/${t1.id}/grade`, { score: 1, comment: "good" }))
        .status,
    ).toBe(200);
    expect((await c("tok-admin", "POST", "/reviews/sweep", {})).json["marked"]).toEqual([]);
    const done = (await c("tok-admin", "GET", `/runs/${id}`)).json;
    expect(done["status"]).toBe("passed");
    // baselines, comparison, gate, attestation
    expect((await c("tok-admin", "POST", "/baselines", { run_id: id })).status).toBe(201);
    expect(
      (await c("tok-viewer", "GET", "/baselines?blueprint_name=agent&suite_ref=st@1.0.0")).json[
        "items"
      ],
    ).toHaveLength(1);
    expect((await c("tok-viewer", "GET", "/baselines")).status).toBe(422);
    expect((await c("tok-viewer", "GET", `/runs/${id}/comparison`)).json["comparison"]).toBeNull();
    expect(
      (
        await c("tok-viewer", "POST", "/gate", {
          blueprint: { name: "agent", version: "1.0.0", content_hash: H },
          suites: [{ ref: "st@1.0.0" }],
        })
      ).json["allowed"],
    ).toBe(true);
    expect((await c("tok-viewer", "GET", `/runs/${id}/attestation`)).status).toBe(409); // no signing key in this server
    // sampling and online
    expect(
      (
        await c("tok-admin", "PUT", "/sampling/p1", {
          blueprint_name: "agent",
          suite_ref: "st@1.0.0",
          rate: 1,
          max_per_hour: 10,
        })
      ).status,
    ).toBe(200);
    expect((await c("tok-runner", "GET", "/online/configs")).json["configs"]).toHaveLength(1);
    expect(
      (
        await c("tok-runner", "POST", "/online/results", {
          mode: "online",
          runner_id: "ci-runner-1",
          suite_ref: "st@1.0.0",
          source_run_id: "prod-1",
          blueprint: { name: "agent", version: "1.0.0", content_hash: H },
          status: "pending_human",
          score: null,
          grades: [
            {
              grader_id: "g1",
              kind: "deterministic",
              status: "scored",
              score: 1,
              detail: "",
              provenance: {},
            },
            {
              grader_id: "h1",
              kind: "human",
              status: "pending",
              score: 0,
              detail: "",
              provenance: {},
            },
          ],
        })
      ).status,
    ).toBe(201);
    expect((await c("tok-viewer", "GET", "/online/summary")).json["items"]).toHaveLength(1);
    expect((await c("tok-admin", "POST", "/sampling/p1/disable", {})).json["enabled"]).toBe(false);
    expect(
      (await c("tok-admin", "POST", "/runners/ci-runner-1/revoke", {})).json["revoked_at"],
    ).not.toBeNull();
    // the revoked runner can do nothing any more
    expect(
      (
        await c("tok-runner", "POST", "/runs", {
          suite_ref: "st@1.0.0",
          blueprint: { name: "agent", version: "1.0.0", content_hash: H },
        })
      ).status,
    ).toBe(403);
  });
});
