import http from "node:http";
import { randomUUID } from "node:crypto";
import { listenLoopback } from "@axis/registry";
import { afterEach, describe, expect, it } from "vitest";
import { createMarketplaceDevServer, type DevAuth } from "../src/index.js";
import { Pub, ablDoc, makeEnv } from "./helpers.js";

let server: http.Server | undefined;
afterEach(async () => {
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  server = undefined;
});

const TOK = {
  pubAdmin: "t-pub-admin",
  pubBuilder: "t-pub-builder",
  buyer: "t-buyer",
  buyerOther: "t-other",
  reviewer: "t-reviewer",
  reviewer2: "t-reviewer2",
  moderator: "t-moderator",
};

async function start(
  opts: {
    rate?: { max: number; windowMs: number };
    strict?: { max: number; windowMs: number };
  } = {},
) {
  const env = makeEnv();
  const pub = await Pub.create(env, { verified: false });
  const buyer = randomUUID();
  const other = randomUUID();
  const tokens: Record<string, DevAuth> = {
    [TOK.pubAdmin]: { kind: "tenant", tenantId: pub.tenantId, subject: "pat", role: "admin" },
    [TOK.pubBuilder]: { kind: "tenant", tenantId: pub.tenantId, subject: "bo", role: "builder" },
    [TOK.buyer]: { kind: "tenant", tenantId: buyer, subject: "bella", role: "admin" },
    [TOK.buyerOther]: { kind: "tenant", tenantId: other, subject: "mallory", role: "owner" },
    [TOK.reviewer]: { kind: "reviewer", subject: "rita" },
    [TOK.reviewer2]: { kind: "reviewer", subject: "ron" },
    [TOK.moderator]: { kind: "moderator", subject: "max" },
  };
  server = createMarketplaceDevServer({
    marketplace: env.mp,
    tokens,
    ...(opts.rate ? { rateLimit: opts.rate } : {}),
    ...(opts.strict ? { sensitiveRateLimit: opts.strict } : {}),
  });
  const port = await listenLoopback(server);
  const call = async (method: string, path: string, token: string | undefined, body?: unknown) => {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      headers: {
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        "content-type": "application/json",
      },
      ...(body !== undefined
        ? { body: typeof body === "string" ? body : JSON.stringify(body) }
        : {}),
    });
    return { status: res.status, body: (await res.json()) as Record<string, any> };
  };
  return { env, pub, buyer, other, call, port };
}

describe("marketplace dev server", () => {
  it("end to end over HTTP: verify publisher, review, list, public catalog, install with consent, update, takedown", async () => {
    const { env, pub, call, buyer } = await start();
    // --- publisher verification
    const domain = `${pub.namespace}.example.com`;
    const st = await call("POST", "/v1/publisher", TOK.pubAdmin, {
      legal_name: "Pat Corp",
      domain,
      contact_email: `pat@${domain}`,
    });
    expect(st.status).toBe(201);
    env.domain.records.set(domain, [`axis-verify=${st.body["challenge"]}`]);
    expect(
      (await call("POST", "/v1/publisher/evidence", TOK.pubAdmin, {})).body["items"],
    ).toHaveLength(2);
    expect((await call("GET", "/v1/publisher/evidence", TOK.pubAdmin)).body["items"]).toHaveLength(
      2,
    );
    expect((await call("GET", "/v1/publisher", TOK.pubAdmin)).body["publisher"].state).toBe(
      "pending",
    );
    const queue = await call("GET", "/v1/review/publishers", TOK.reviewer);
    expect(queue.body["items"].map((i: { tenantId: string }) => i.tenantId)).toContain(
      pub.tenantId,
    );
    expect(
      (await call("GET", `/v1/review/publishers/${pub.tenantId}/evidence`, TOK.reviewer)).body[
        "items"
      ],
    ).toHaveLength(2);
    expect(
      (
        await call("POST", `/v1/review/publishers/${pub.tenantId}/decision`, TOK.reviewer, {
          decision: "approve",
          reason: "all evidence passed",
        })
      ).body["state"],
    ).toBe("verified");

    // --- publish + review + list
    await pub.publish(
      ablDoc("helper-agent", "1.0.0", {
        tools: [
          { name: "crm", kind: "mcp", mcpServer: "https://mcp.example.com", sideEffects: "write" },
        ],
      }),
    );
    expect(
      (
        await call("POST", "/v1/publisher/reviews", TOK.pubBuilder, {
          namespace: pub.namespace,
          name: "helper-agent",
          version: "1.0.0",
        })
      ).status,
    ).toBe(201);
    expect((await call("GET", "/v1/publisher/reviews", TOK.pubBuilder)).body["items"]).toHaveLength(
      1,
    );
    const q = await call("GET", "/v1/review/queue", TOK.reviewer);
    const id = q.body["items"].find(
      (i: { review: { name: string } }) => i.review.name === "helper-agent",
    ).id as string;
    expect(
      (await call("GET", `/v1/review/reviews/${encodeURIComponent(id)}`, TOK.reviewer)).body[
        "state"
      ],
    ).toBe("in_review");
    expect(
      (
        await call("POST", `/v1/review/reviews/${encodeURIComponent(id)}/decision`, TOK.pubAdmin, {
          decision: "approve",
          note: "tenant tries",
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await call("POST", `/v1/review/reviews/${encodeURIComponent(id)}/decision`, TOK.reviewer, {
          decision: "approve",
          note: "reviewed the findings",
          acknowledged_findings: [],
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await call("POST", "/v1/publisher/listings", TOK.pubBuilder, {
          namespace: pub.namespace,
          name: "helper-agent",
          title: "Helper",
          summary: "Does helpful things",
          categories: ["support"],
        })
      ).status,
    ).toBe(201);

    // --- the public catalog needs no credential
    const cat = await call("GET", `/v1/catalog?q=helpful`, undefined);
    expect(cat.status).toBe(200);
    expect(cat.body["items"].some((e: { name: string }) => e.name === "helper-agent")).toBe(true);
    expect(
      (await call("GET", `/v1/catalog/${pub.namespace}/helper-agent`, undefined)).body["latest"]
        .version,
    ).toBe("1.0.0");
    expect((await call("GET", `/v1/catalog?category=support`, undefined)).status).toBe(200);
    expect((await call("GET", `/v1/catalog/${pub.namespace}/nope-agent`, undefined)).status).toBe(
      404,
    );
    expect((await call("GET", "/v1/installs", undefined)).status).toBe(401);

    // --- install with consent
    const pv = await call("POST", "/v1/installs/preview", TOK.buyer, {
      namespace: pub.namespace,
      name: "helper-agent",
      range: "^1.0.0",
    });
    expect(pv.status).toBe(200);
    expect(pv.body["diff"].widening).toBe(true);
    const base = {
      namespace: pub.namespace,
      name: "helper-agent",
      version: "1.0.0",
      content_hash: pv.body["contentHash"],
    };
    expect(
      (await call("POST", "/v1/installs", TOK.buyer, { ...base, consent_digest: "0".repeat(64) }))
        .status,
    ).toBe(409);
    expect(
      (
        await call("POST", "/v1/installs", TOK.buyer, {
          ...base,
          consent_digest: pv.body["consentDigest"],
        })
      ).status,
    ).toBe(201);
    expect((await call("GET", "/v1/installs", TOK.buyer)).body["items"]).toHaveLength(1);
    expect(
      (await call("GET", `/v1/installs/${pub.namespace}/helper-agent`, TOK.buyer)).status,
    ).toBe(200);
    // another tenant: nothing
    expect((await call("GET", "/v1/installs", TOK.buyerOther)).body["items"]).toEqual([]);
    expect(
      (await call("GET", `/v1/installs/${pub.namespace}/helper-agent`, TOK.buyerOther)).status,
    ).toBe(404);
    expect(
      (
        await call(
          "POST",
          `/v1/installs/${pub.namespace}/helper-agent/uninstall`,
          TOK.buyerOther,
          {},
        )
      ).status,
    ).toBe(404);
    expect((await call("GET", `/v1/installs?tenant_id=${buyer}`, TOK.buyerOther)).status).toBe(403);
    expect(
      (
        await call("POST", "/v1/installs/preview", TOK.buyerOther, {
          namespace: pub.namespace,
          name: "helper-agent",
          range: "1.0.0",
          tenant_id: buyer,
        })
      ).status,
    ).toBe(403);
    expect((await call("POST", "/v1/installs/flush-metering", TOK.buyer, {})).body["flushed"]).toBe(
      0,
    );
    // baseline
    expect(
      (await call("PUT", "/v1/tenant/baseline", TOK.buyer, { granted: [{ key: "a", level: 1 }] }))
        .status,
    ).toBe(200);
    expect((await call("GET", "/v1/tenant/baseline", TOK.buyer)).body["granted"]).toEqual([
      { key: "a", level: 1 },
    ]);
    // update path
    await pub.release("helper-agent", "1.1.0", {
      tools: [
        { name: "crm", kind: "mcp", mcpServer: "https://mcp.example.com", sideEffects: "write" },
      ],
    });
    expect(
      (
        await call("POST", `/v1/installs/${pub.namespace}/helper-agent/update`, TOK.buyer, {
          version: "1.1.0",
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await call("POST", `/v1/installs/${pub.namespace}/helper-agent/update`, TOK.buyer, {
          version: "1.0.0",
        })
      ).status,
    ).toBe(409);
    expect(
      (
        await call("POST", `/v1/installs/${pub.namespace}/helper-agent/update`, TOK.buyer, {
          version: "1.0.0",
          allow_downgrade: true,
        })
      ).status,
    ).toBe(200);

    // --- moderation
    expect(
      (
        await call("POST", "/v1/moderation/takedowns", TOK.reviewer, {
          namespace: pub.namespace,
          name: "helper-agent",
          reason: "reviewer cannot take down",
        })
      ).status,
    ).toBe(403);
    const td = await call("POST", "/v1/moderation/takedowns", TOK.moderator, {
      namespace: pub.namespace,
      name: "helper-agent",
      version: "1.1.0",
      reason: "bad behaviour in this version",
    });
    expect(td.body).toEqual({ flagged: 0 });
    expect(
      (
        await call("POST", "/v1/moderation/takedowns", TOK.moderator, {
          namespace: pub.namespace,
          name: "helper-agent",
          reason: "delist the whole listing",
        })
      ).body,
    ).toEqual({ flagged: 1 });
    expect((await call("GET", `/v1/catalog/${pub.namespace}/helper-agent`, undefined)).status).toBe(
      404,
    );
    expect(
      (await call("POST", `/v1/installs/${pub.namespace}/helper-agent/uninstall`, TOK.buyer, {}))
        .status,
    ).toBe(200);
    expect(
      (
        await call("POST", `/v1/moderation/publishers/${pub.tenantId}/suspend`, TOK.moderator, {
          reason: "repeat violations",
        })
      ).status,
    ).toBe(200);
  });

  it("credential types are not interchangeable; unknown routes; bad bodies; rate limits", async () => {
    const { call, port, pub } = await start({
      rate: { max: 40, windowMs: 60_000 },
      strict: { max: 2, windowMs: 60_000 },
    });
    expect((await call("GET", "/v1/publisher", TOK.reviewer)).status).toBe(403);
    expect((await call("GET", "/v1/review/queue", TOK.buyer)).status).toBe(403);
    expect((await call("POST", "/v1/moderation/takedowns", TOK.buyer, {})).status).toBe(403);
    expect((await call("GET", "/v1/review/queue", "wrong-token")).status).toBe(401);
    expect((await call("GET", "/v1/nope", TOK.buyer)).status).toBe(404);
    expect((await call("GET", "/other", TOK.buyer)).status).toBe(404);
    expect((await call("POST", "/v1/publisher", TOK.pubAdmin, "not json")).status).toBe(400);
    expect((await call("POST", "/v1/publisher", TOK.pubAdmin, {})).status).toBe(400);
    expect(
      (
        await call("POST", "/v1/review/reviews/garbage/decision", TOK.reviewer, {
          decision: "approve",
          note: "long enough note",
        })
      ).status,
    ).toBe(422);
    expect(
      (
        await call("POST", "/v1/publisher/reviews", TOK.pubBuilder, {
          namespace: pub.namespace,
          name: "x-agent",
          version: "1.0.0",
        })
      ).status,
    ).toBe(403); // not verified
    expect(
      (
        await call("POST", "/v1/publisher/reviews", TOK.pubBuilder, {
          namespace: pub.namespace,
          name: "x-agent",
          version: "1.0.0",
        })
      ).status,
    ).toBe(403);
    const limited = await call("POST", "/v1/publisher/reviews", TOK.pubBuilder, {
      namespace: pub.namespace,
      name: "x-agent",
      version: "1.0.0",
    });
    expect(limited.status).toBe(429);
    const raw = await fetch(`http://127.0.0.1:${port}/v1/catalog`);
    expect(raw.status).toBe(200);
  });

  it("general rate limit applies to anonymous catalog readers too", async () => {
    const { call } = await start({ rate: { max: 3, windowMs: 60_000 } });
    for (let i = 0; i < 3; i++)
      expect((await call("GET", "/v1/catalog", undefined)).status).toBe(200);
    expect((await call("GET", "/v1/catalog", undefined)).status).toBe(429);
  });

  it("refuses to run in production", async () => {
    const prev = process.env["NODE_ENV"];
    process.env["NODE_ENV"] = "production";
    try {
      expect(() => createMarketplaceDevServer({ marketplace: makeEnv().mp, tokens: {} })).toThrow(
        /production/,
      );
    } finally {
      if (prev === undefined) delete process.env["NODE_ENV"];
      else process.env["NODE_ENV"] = prev;
    }
  });
});
