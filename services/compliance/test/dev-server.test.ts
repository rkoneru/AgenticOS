/* eslint-disable @typescript-eslint/no-explicit-any */
import type http from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createComplianceDevServer, listenLoopback, type DevAuth } from "../src/index.js";
import { T1, T2, input, world } from "./helpers.js";

const tokens: Record<string, DevAuth> = {
  owner1: { tenantId: T1, subject: "olivia", role: "owner" },
  builder1: { tenantId: T1, subject: "bob", role: "builder" },
  auditor1: { tenantId: T1, subject: "alice", role: "auditor" },
  viewer1: { tenantId: T1, subject: "vic", role: "viewer" },
  owner2: { tenantId: T2, subject: "mallory", role: "owner" },
};

let server: http.Server;
let base = "";
const w = world();
beforeAll(async () => {
  server = createComplianceDevServer({ compliance: w.svc, tokens });
  base = `http://127.0.0.1:${await listenLoopback(server)}`;
});
afterAll(() => {
  server.close();
});

async function call(
  token: string | null,
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; json: Record<string, any> }> {
  const r = await fetch(`${base}${path}`, {
    method,
    headers: {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      "content-type": "application/json",
    },
    ...(body === undefined ? {} : { body: typeof body === "string" ? body : JSON.stringify(body) }),
  });
  return { status: r.status, json: await r.json() };
}

describe("compliance dev server", () => {
  it("refuses to start with NODE_ENV=production", () => {
    const prev = process.env["NODE_ENV"];
    process.env["NODE_ENV"] = "production";
    try {
      expect(() => createComplianceDevServer({ compliance: w.svc, tokens })).toThrow(/production/);
    } finally {
      if (prev === undefined) delete process.env["NODE_ENV"];
      else process.env["NODE_ENV"] = prev;
    }
  });

  it("requires a bearer token", async () => {
    expect((await call(null, "GET", "/v1/compliance/systems")).status).toBe(401);
    expect((await call("nope", "GET", "/v1/compliance/systems")).status).toBe(401);
  });

  it("serves the whole workflow; the tenant and role come from the token only", async () => {
    const sys = await call(
      "builder1",
      "POST",
      "/v1/compliance/systems",
      input.system({ system_id: "claims-triage" }),
    );
    expect(sys.status).toBe(201);
    expect(sys.json).toMatchObject({ system_id: "claims-triage", version: 1, created_by: "bob" });
    const upd = await call("builder1", "PUT", "/v1/compliance/systems/claims-triage", {
      expected_version: 1,
      lifecycle_stage: "deployed",
    });
    expect(upd.json.version).toBe(2);
    expect(
      (
        await call(
          "viewer1",
          "GET",
          "/v1/compliance/systems?lifecycle_stage=deployed&risk_level=high",
        )
      ).json.items.length,
    ).toBe(1);
    expect(
      (await call("viewer1", "GET", "/v1/compliance/systems/claims-triage?version=1")).json
        .lifecycle_stage,
    ).toBe("design");
    expect(
      (await call("viewer1", "GET", "/v1/compliance/systems/claims-triage")).json.version,
    ).toBe(2);

    const a = await call(
      "builder1",
      "POST",
      "/v1/compliance/impact-assessments",
      input.assessment("claims-triage"),
    );
    expect(a.status).toBe(201);
    const id = a.json.assessment_id;
    const rev = await call("builder1", "PUT", `/v1/compliance/impact-assessments/${id}`, {
      expected_version: 1,
      title: "retitled",
    });
    expect(rev.json.title).toBe("retitled");
    expect(
      (
        await call("builder1", "POST", `/v1/compliance/impact-assessments/${id}/submit`, {
          expected_version: 1,
        })
      ).json.state,
    ).toBe("in_review");
    expect(
      (
        await call("builder1", "POST", `/v1/compliance/impact-assessments/${id}/withdraw`, {
          expected_version: 1,
        })
      ).json.state,
    ).toBe("draft");
    await call("builder1", "POST", `/v1/compliance/impact-assessments/${id}/submit`, {
      expected_version: 1,
    });
    const bad = await call("owner1", "POST", `/v1/compliance/impact-assessments/${id}/review`, {
      expected_version: 1,
      decision: "approve",
    });
    expect(bad.status).toBe(200); // owner olivia did not work on it
    expect(bad.json.reviewed_by).toBe("olivia");
    expect(
      (await call("viewer1", "GET", `/v1/compliance/impact-assessments/${id}?version=1`)).json
        .state,
    ).toBe("approved");
    expect(
      (
        await call(
          "viewer1",
          "GET",
          "/v1/compliance/impact-assessments?state=approved&system_id=claims-triage&overdue=false",
        )
      ).json.items.length,
    ).toBe(1);
    expect(
      (await call("viewer1", "GET", "/v1/compliance/impact-assessments")).json.items.length,
    ).toBe(1);

    const d1 = await call("builder1", "POST", "/v1/compliance/documents", {
      blueprint: { name: "claims-triage", version: "2.3.1" },
    });
    expect(d1.status).toBe(201);
    const d2 = await call("builder1", "POST", "/v1/compliance/documents", {
      blueprint: { name: "claims-triage", version: "2.3.1" },
    });
    expect(d2.status).toBe(200);
    expect(d2.json.created).toBe(false);
    const docId = d1.json.document.meta.document_id;
    const got = await call("auditor1", "GET", `/v1/compliance/documents/${docId}`);
    expect(got.json.verification).toEqual({ ok: true, failed: [] });
    expect(
      (
        await call(
          "auditor1",
          "GET",
          "/v1/compliance/documents?blueprint_name=claims-triage&blueprint_version=2.3.1",
        )
      ).json.items.length,
    ).toBe(1);
    expect((await call("auditor1", "GET", "/v1/compliance/documents")).json.items.length).toBe(1);
  });

  it("another tenant sees nothing; a tenant_id elsewhere in the request must match the token", async () => {
    expect((await call("owner2", "GET", "/v1/compliance/systems")).json.items).toEqual([]);
    expect((await call("owner2", "GET", "/v1/compliance/systems/claims-triage")).status).toBe(404);
    expect((await call("owner2", "GET", "/v1/compliance/documents")).json.items).toEqual([]);
    expect((await call("owner1", "GET", `/v1/compliance/systems?tenant_id=${T2}`)).status).toBe(
      403,
    );
    expect(
      (await call("owner1", "POST", "/v1/compliance/systems", { ...input.system(), tenant_id: T2 }))
        .status,
    ).toBe(403);
    expect((await call("owner1", "GET", `/v1/compliance/systems?tenant_id=${T1}`)).status).toBe(
      200,
    );
  });

  it("maps errors: roles, validation, conflicts, unknown routes, bad bodies", async () => {
    expect((await call("viewer1", "POST", "/v1/compliance/systems", input.system())).status).toBe(
      403,
    );
    const inv = await call("builder1", "POST", "/v1/compliance/systems", { name: "" });
    expect(inv.status).toBe(422);
    expect(inv.json.error.checks.length).toBeGreaterThan(0);
    expect(
      (
        await call("builder1", "PUT", "/v1/compliance/systems/claims-triage", {
          expected_version: 1,
        })
      ).status,
    ).toBe(409);
    expect((await call("builder1", "PUT", "/v1/compliance/systems/claims-triage", {})).status).toBe(
      400,
    );
    expect(
      (
        await call("builder1", "PUT", "/v1/compliance/systems/claims-triage", {
          expected_version: -1,
        })
      ).status,
    ).toBe(400);
    expect(
      (await call("viewer1", "GET", "/v1/compliance/systems/claims-triage?version=x")).status,
    ).toBe(400);
    expect((await call("viewer1", "GET", "/v1/compliance/nothing")).status).toBe(404);
    expect((await call("viewer1", "GET", "/v2/compliance/systems")).status).toBe(404);
    expect((await call("viewer1", "DELETE", "/v1/compliance/systems/claims-triage")).status).toBe(
      404,
    );
    expect((await call("builder1", "POST", "/v1/compliance/systems", "{not json")).status).toBe(
      400,
    );
    expect((await call("builder1", "POST", "/v1/compliance/systems", "[1]")).status).toBe(400);
    expect((await call("builder1", "POST", "/v1/compliance/documents", {})).status).toBe(422);
    expect((await call("viewer1", "GET", "/v1/compliance/documents/cdoc-none")).status).toBe(404);
    const huge = "x".repeat(4_100_000);
    expect((await call("builder1", "POST", "/v1/compliance/systems", { name: huge })).status).toBe(
      400,
    );
  });

  it("an unexpected failure answers 500 without its message; the rate limiter answers 429", async () => {
    const broken = createComplianceDevServer({
      compliance: {
        ...w.svc,
        systems: { list: () => Promise.reject(new Error("db password is hunter2")) } as never,
      },
      tokens,
      rateLimit: { max: 2, windowMs: 60_000 },
      now: () => 1,
    });
    const port = await listenLoopback(broken);
    const get = () =>
      fetch(`http://127.0.0.1:${port}/v1/compliance/systems`, {
        headers: { authorization: "Bearer owner1" },
      });
    const first = await get();
    expect(first.status).toBe(500);
    expect(await first.text()).not.toContain("hunter2");
    await get();
    const limited = await get();
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toBeTruthy();
    broken.close();
  });

  it("supports a custom authenticator", async () => {
    const s = createComplianceDevServer({
      compliance: w.svc,
      tokens: {},
      authenticate: (h) =>
        h === "Bearer dyn" ? { tenantId: T1, subject: "dyn", role: "viewer" } : undefined,
    });
    const port = await listenLoopback(s);
    const ok = await fetch(`http://127.0.0.1:${port}/v1/compliance/systems`, {
      headers: { authorization: "Bearer dyn" },
    });
    expect(ok.status).toBe(200);
    s.close();
  });
});
