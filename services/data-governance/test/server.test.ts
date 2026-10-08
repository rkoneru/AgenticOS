// eslint-disable-next-line @typescript-eslint/no-explicit-any
type J = any;
import type http from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createAdminServer, listenLoopback, staticTokenAuthenticator } from "../src/index.js";
import { FakeProvider, officer, rig, setupTenant } from "./helpers.js";

let server: http.Server;
let base: string;
let tenant: string;
let other: string;
const prov = new FakeProvider("mem", { classes: ["memory"] });
const r = rig([prov]);

beforeAll(async () => {
  tenant = setupTenant(r);
  other = setupTenant(r);
  server = createAdminServer({
    dsar: r.engine,
    holds: r.holds,
    retention: r.retention,
    authenticate: staticTokenAuthenticator({
      off: officer(tenant),
      off2: officer(other),
      plain: { tenantId: tenant, id: "u", roles: ["admin"] },
    }),
  });
  base = `http://127.0.0.1:${await listenLoopback(server)}`;
});
afterAll(() => new Promise<void>((res) => server.close(() => res())));

const call = async (method: string, path: string, token: string | null, body?: unknown) => {
  const res = await fetch(base + path, {
    method,
    headers: {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      "content-type": "application/json",
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  return { status: res.status, json: (await res.json()) as Record<string, J> };
};

describe("admin dev server", () => {
  it("authenticates, role-gates and keeps tenants apart", async () => {
    expect((await call("GET", "/admin/v1/dsar", null)).status).toBe(401);
    expect((await call("GET", "/admin/v1/dsar", "plain")).status).toBe(403);
    expect((await call("GET", "/nope", "off")).status).toBe(404);
    const c = await call("POST", "/admin/v1/dsar", "off", {
      kind: "erase",
      identifiers: [{ kind: "email", value: "a@b.org" }],
    });
    expect(c.status).toBe(201);
    expect(JSON.stringify(c.json)).not.toContain("a@b.org");
    expect((await call("GET", `/admin/v1/dsar/${c.json["id"]}`, "off2")).status).toBe(404);
    expect(
      (await call("POST", "/admin/v1/dsar", "off", { kind: "bogus", identifiers: [] })).status,
    ).toBe(400);
  });

  it("drives export and erase end to end over HTTP", async () => {
    prov.put(tenant, "z@b.org", "secret-row");
    const c = await call("POST", "/admin/v1/dsar", "off", {
      kind: "erase",
      identifiers: [{ kind: "email", value: "z@b.org" }],
    });
    const id = c.json["id"];
    expect((await call("POST", `/admin/v1/dsar/${id}/erase`, "off", {})).status).toBe(409); // not verified
    expect(
      (await call("POST", `/admin/v1/dsar/${id}/verify`, "off", { evidence: "x" })).json["status"],
    ).toBe("verified");
    const ex = await call("POST", `/admin/v1/dsar/${id}/export`, "off", {});
    expect(ex.status).toBe(200);
    expect(ex.json["manifest"].total_records).toBe(1);
    const er = await call("POST", `/admin/v1/dsar/${id}/erase`, "off", {});
    expect(er.json["status"]).toBe("completed");
    expect(prov.all(tenant).filter((x) => x.owner === "z@b.org")).toHaveLength(0);
    expect(
      (await call("GET", "/admin/v1/dsar?status=completed", "off")).json["items"].length,
    ).toBeGreaterThan(0);
    expect((await call("POST", "/admin/v1/dsar/sweep", "off", {})).status).toBe(200);
    const e2 = await call("POST", "/admin/v1/dsar", "off", {
      kind: "export",
      identifiers: [{ kind: "email", value: "q@b.org" }],
    });
    expect(
      (await call("POST", `/admin/v1/dsar/${e2.json["id"]}/extend`, "off", { reason: "complex" }))
        .json["extended"],
    ).toBe(true);
    expect(
      (await call("POST", `/admin/v1/dsar/${e2.json["id"]}/reject`, "off", { reason: "other" }))
        .json["status"],
    ).toBe("rejected");
    const rs = await call("POST", "/admin/v1/dsar", "off", {
      kind: "restrict",
      identifiers: [{ kind: "email", value: "r@b.org" }],
    });
    await call("POST", `/admin/v1/dsar/${rs.json["id"]}/verify`, "off", {});
    expect(
      (await call("POST", `/admin/v1/dsar/${rs.json["id"]}/restrict`, "off", { reason: "contest" }))
        .json["status"],
    ).toBe("completed");
  });

  it("holds and retention routes", async () => {
    const h = await call("POST", "/admin/v1/holds", "off", {
      scope: "tenant",
      reason: "litigation",
      classes: ["memory"],
    });
    expect(h.status).toBe(201);
    expect((await call("GET", "/admin/v1/holds", "off")).json["items"].length).toBeGreaterThan(0);
    const run = await call("POST", "/admin/v1/retention/run", "off", { classes: ["memory"] });
    expect(run.json["dryRun"]).toBe(true);
    expect(run.json["classes"][0].status).toBe("skipped_hold");
    expect(
      (await call("POST", `/admin/v1/holds/${h.json["id"]}/release`, "off", {})).json[
        "released_at"
      ],
    ).not.toBeNull();
    expect((await call("PUT", "/admin/v1/retention/run_logs", "off", { days: 90 })).status).toBe(
      200,
    );
    expect((await call("PUT", "/admin/v1/retention/nope", "off", { days: 90 })).status).toBe(400);
    expect((await call("PUT", "/admin/v1/retention/run_logs", "off", { days: 1 })).status).toBe(
      400,
    );
    expect((await call("GET", "/admin/v1/retention", "off")).json["items"].length).toBe(8);
    const rr = await call("POST", "/admin/v1/holds", "off", {
      restriction: true,
      reason: "contest",
      groups: [[{ kind: "email", value: "r@b.org" }]],
    });
    expect(rr.json["kind"]).toBe("restriction");
    expect((await call("POST", "/admin/v1/holds", "off", { scope: "tenant" })).status).toBe(400);
  });
});
