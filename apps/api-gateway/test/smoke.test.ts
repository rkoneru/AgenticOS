import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ABL, call, makeWorld, type Cred, type World } from "./world.js";

let w: World;
let owner: Cred;
beforeAll(async () => {
  w = await makeWorld();
  owner = await w.tenant();
});
afterAll(() => w.close());

describe("smoke", () => {
  it("health, auth and a blueprint round trip", async () => {
    const h = await fetch(w.base.replace("/v1", "/healthz"));
    expect(h.status).toBe(200);
    const un = await call(w, "GET", "/blueprints");
    expect(un.status).toBe(401);
    expect(un.headers.get("content-type")).toContain("application/problem+json");
    const pub = await call(w, "POST", "/blueprints", {
      token: owner.token,
      body: { abl: ABL("claims") },
    });
    expect(pub.status, pub.text).toBe(201);
    const list = await call(w, "GET", "/blueprints", { token: owner.token });
    expect(list.body.items).toHaveLength(1);
    const run = await call(w, "POST", "/runs", {
      token: owner.token,
      body: { blueprint: { name: "claims", version: "1.0.0" }, input: { prompt: "hi" } },
    });
    expect(run.status, run.text).toBe(202);
    const got = await call(w, "GET", `/runs/${run.body.id}`, { token: owner.token });
    expect(got.status).toBe(200);
  });
});
