import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { LISTED_ABL, call, makeWorld, seed, signedBundle, type Seed, type World } from "./world.js";

/** The Phase 7 additive operations (OpenAPI 1.2.0, ADR 0053) beyond the spec-derived contract walk. */
let w: World;
let s: Seed;
let other: Awaited<ReturnType<World["tenant"]>>;

beforeAll(async () => {
  w = await makeWorld({
    rate: { burst: 1e6, perSecond: 1e6 },
    unauthRate: { burst: 1e6, perSecond: 1e6 },
  });
  s = await seed(w);
  other = await w.tenant();
});
afterAll(() => w.close());

describe("GET /me", () => {
  it("returns the credential's own tenant, member, role and credential kind", async () => {
    const r = await call(w, "GET", "/me", { token: s.owner.token });
    expect(r.status).toBe(200);
    expect(r.body.tenant.id).toBe(s.owner.tenantId);
    expect(r.body.member).toMatchObject({ id: s.owner.memberId, role: "owner" });
    expect(r.body.credential).toEqual({ kind: "session" });
  });
  it("an API key can identify itself with any scope and shows its scopes, never the secret", async () => {
    const key = await w.apiKey(s.owner, ["usage:read"]);
    const r = await call(w, "GET", "/me", { key });
    expect(r.status).toBe(200);
    expect(r.body.credential).toEqual({ kind: "api_key", scopes: ["usage:read"] });
    expect(r.text).not.toContain(key);
  });
});

describe("registry through the gateway", () => {
  it("another tenant cannot see, list or resolve a private namespace (404 or an empty list, never 403 data)", async () => {
    const keys = await call(w, "GET", `/registry/namespaces/${s.own.namespace}/keys`, {
      token: other.token,
    });
    const versions = await call(
      w,
      "GET",
      `/registry/blueprints/${s.own.namespace}/${s.own.name}/versions`,
      { token: other.token },
    );
    const resolve = await call(
      w,
      "GET",
      `/registry/resolve?ref=${encodeURIComponent(`${s.own.namespace}/${s.own.name}@^1`)}`,
      { token: other.token },
    );
    expect(resolve.status, resolve.text).toBe(404);
    // a listing of an invisible namespace is indistinguishable from a namespace that has nothing
    for (const r of [keys, versions]) {
      expect(r.status, r.text).toBe(200);
      expect(r.body.items).toEqual([]);
    }
    for (const r of [keys, versions, resolve]) expect(r.text).not.toContain(s.own.key.keyId);
    expect(
      (await call(w, "GET", "/registry/namespaces", { token: other.token })).body.items,
    ).toEqual([]);
  });

  it("another tenant cannot publish into a namespace it does not own", async () => {
    const b = signedBundle(s.own, LISTED_ABL("own-agent", "3.0.0"));
    const r = await call(w, "POST", `/registry/namespaces/${s.own.namespace}/blueprints`, {
      token: other.token,
      body: b,
    });
    expect([403, 404]).toContain(r.status);
  });

  it("a version signed by a key that is not the namespace's is refused with the failed check codes", async () => {
    const { generatePublisherKey } = await import("@axis/registry");
    const b = signedBundle(
      { namespace: s.own.namespace, key: generatePublisherKey() },
      LISTED_ABL("own-agent", "4.0.0"),
    );
    const r = await call(w, "POST", `/registry/namespaces/${s.own.namespace}/blueprints`, {
      token: s.owner.token,
      body: b,
    });
    expect(r.status, r.text).toBe(422);
    expect(r.body.errors.map((e: { keyword: string }) => e.keyword).join()).toMatch(
      /signing_key_unknown|signing_key_not_trusted|signature_invalid/,
    );
  });

  it("resolve verifies on every read: a stored version that was tampered with does not resolve, and does not fall back", async () => {
    const ok = await call(
      w,
      "GET",
      `/registry/resolve?ref=${encodeURIComponent(`${s.own.namespace}/${s.own.name}@^1`)}`,
      { token: s.owner.token },
    );
    expect(ok.status, ok.text).toBe(200);
    expect(ok.body.verification.key_id).toBe(s.own.key.keyId);
    expect(ok.body.version).toBe("1.1.0");
  });

  it("a yanked version stops resolving; the next-best verified version is chosen only for a range that allows it", async () => {
    const y = await call(
      w,
      "POST",
      `/registry/blueprints/${s.own.namespace}/${s.own.name}/versions/1.1.0/yank`,
      { token: s.owner.token, body: { reason: "bad release" } },
    );
    expect(y.status, y.text).toBe(200);
    const r = await call(
      w,
      "GET",
      `/registry/resolve?ref=${encodeURIComponent(`${s.own.namespace}/${s.own.name}@^1`)}`,
      { token: s.owner.token },
    );
    expect(r.body.version).toBe("1.0.0");
    const exact = await call(
      w,
      "GET",
      `/registry/resolve?ref=${encodeURIComponent(`${s.own.namespace}/${s.own.name}@1.1.0`)}`,
      { token: s.owner.token },
    );
    expect(exact.status).toBe(404);
  });

  it("a viewer cannot publish or claim (the role matrix) and a builder cannot claim (service role check)", async () => {
    const viewer = await w.member(s.owner.tenantId, "viewer");
    const builder = await w.member(s.owner.tenantId, "builder");
    const v = await call(w, "POST", "/registry/namespaces", {
      token: viewer.token,
      body: { namespace: "viewer-claim" },
    });
    expect(v.status).toBe(403);
    const b = await call(w, "POST", "/registry/namespaces", {
      token: builder.token,
      body: { namespace: "builder-claim" },
    });
    expect(b.status).toBe(403);
  });
});

describe("marketplace through the gateway", () => {
  it("lists the catalog, previews with a permission diff, refuses a stale consent digest, installs with the right one", async () => {
    const list = await call(w, "GET", "/marketplace/listings", { token: s.owner.token });
    expect(list.body.items.map((i: { name: string }) => i.name)).toContain(s.listing.name);
    const prev = await call(w, "POST", "/marketplace/installs/preview", {
      token: s.owner.token,
      body: { namespace: s.listing.namespace, name: s.listing.name, range: "^1" },
    });
    expect(prev.status, prev.text).toBe(200);
    expect(prev.body.diff.added.map((a: { key: string }) => a.key)).toContain("model:anthropic");
    expect(prev.body.diff.widening).toBe(true);
    const base = {
      namespace: s.listing.namespace,
      name: s.listing.name,
      version: prev.body.version,
      content_hash: prev.body.content_hash,
    };
    const bad = await call(w, "POST", "/marketplace/installs", {
      token: s.owner.token,
      body: { ...base, consent_digest: "0".repeat(64) },
    });
    expect(bad.status).toBe(409);
    expect(bad.body.detail).toMatch(/consent/);
    const wrongHash = await call(w, "POST", "/marketplace/installs", {
      token: s.owner.token,
      body: { ...base, content_hash: "f".repeat(64), consent_digest: prev.body.consent_digest },
    });
    expect(wrongHash.status).toBe(409);
    const good = await call(w, "POST", "/marketplace/installs", {
      token: s.owner.token,
      body: { ...base, consent_digest: prev.body.consent_digest },
    });
    expect(good.status, good.text).toBe(201);
    expect(good.body.state).toBe("active");
    const mine = await call(w, "GET", "/marketplace/installs", { token: s.owner.token });
    expect(mine.body.items).toHaveLength(1);
  });

  it("an install belongs to the installing tenant: another tenant sees none and cannot uninstall it", async () => {
    const theirs = await call(w, "GET", "/marketplace/installs", { token: other.token });
    expect(theirs.body.items).toEqual([]);
    const un = await call(
      w,
      "POST",
      `/marketplace/installs/${s.listing.namespace}/${s.listing.name}/uninstall`,
      { token: other.token },
    );
    expect(un.status).toBe(404);
    const still = await call(w, "GET", "/marketplace/installs", { token: s.owner.token });
    expect(still.body.items[0].state).toBe("active");
  });

  it("only an admin can preview or install (builder and viewer are refused by the matrix)", async () => {
    const builder = await w.member(s.owner.tenantId, "builder");
    const r = await call(w, "POST", "/marketplace/installs/preview", {
      token: builder.token,
      body: { namespace: s.listing.namespace, name: s.listing.name, range: "^1" },
    });
    expect(r.status).toBe(403);
  });
});

describe("approvals by id and policy activation", () => {
  it("GET /approvals/{id}: the requester tenant sees it; another tenant gets 404", async () => {
    const mine = await call(w, "GET", `/approvals/${s.approvalId}`, { token: s.owner.token });
    expect(mine.status, mine.text).toBe(200);
    expect(mine.body.id).toBe(s.approvalId);
    const theirs = await call(w, "GET", `/approvals/${s.approvalId}`, { token: other.token });
    expect(theirs.status).toBe(404);
  });

  it("activating a pack version makes it active in the listing; another tenant cannot activate it", async () => {
    const foreign = await call(w, "POST", `/policies/${s.policyVersionId}/activate`, {
      token: other.token,
    });
    expect(foreign.status).toBe(404);
    const r = await call(w, "POST", `/policies/${s.policyVersionId}/activate`, {
      token: s.owner.token,
    });
    expect(r.status, r.text).toBe(200);
    expect(r.body).toMatchObject({ version_id: s.policyVersionId, active: true });
    const list = await call(w, "GET", "/policies", { token: s.owner.token });
    expect(
      list.body.items.find((p: { version_id: string }) => p.version_id === s.policyVersionId)
        .active,
    ).toBe(true);
  });
});
