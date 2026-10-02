import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CpError } from "../src/index.js";
import { KINDS, makeWorld, type World } from "./world.js";

const rejects = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "ok";
  } catch (e) {
    return e instanceof CpError ? e.code : "other";
  }
};

describe.each(KINDS)("sessions (%s store)", (kind) => {
  let w: World;
  beforeAll(async () => {
    w = await makeWorld(kind, { accessTtlSec: 900, absoluteTtlSec: 3600 });
  });
  afterAll(() => w.close());

  async function fresh() {
    const t = await w.tenant();
    const m = (await w.store.getMember(t.tenantId, t.ownerId))!;
    const s = await w.cp.sessions.issue(m, "sso");
    return { t, m, s };
  }

  it("authenticates a fresh token with the member's CURRENT role (not the token's)", async () => {
    const { t, m, s } = await fresh();
    const p = await w.cp.sessions.authenticate(s.accessToken);
    expect(p).toMatchObject({ tenantId: t.tenantId, memberId: m.id, role: "owner", credential: "session", sessionId: s.sessionId });
    const second = await w.member(t.tenantId, "admin");
    const s2 = await w.cp.sessions.issue((await w.store.getMember(t.tenantId, second.memberId))!);
    await w.store.updateMember(t.tenantId, second.memberId, { role: "viewer" }, w.clock.now());
    expect((await w.cp.sessions.authenticate(s2.accessToken))?.role).toBe("viewer");
  });

  it("rejects an expired access token and a tampered or foreign one", async () => {
    const { s } = await fresh();
    w.clock.advance(901);
    expect(await w.cp.sessions.authenticate(s.accessToken)).toBeUndefined();
    const { s: s2 } = await fresh();
    const [kid, body, sig] = s2.accessToken.split(".") as [string, string, string];
    const payload = JSON.parse(Buffer.from(body, "base64url").toString()) as Record<string, unknown>;
    payload["m"] = "33333333-3333-4333-8333-333333333333";
    const forged = `${kid}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${sig}`;
    expect(await w.cp.sessions.authenticate(forged)).toBeUndefined();
    for (const junk of ["", "a.b", "a.b.c.d", "x".repeat(5000), "k1..", "null"]) expect(await w.cp.sessions.authenticate(junk)).toBeUndefined();
  });

  it("rejects an access token whose session was revoked server-side (revocation list)", async () => {
    const { t, s } = await fresh();
    expect(await w.cp.sessions.authenticate(s.accessToken)).toBeDefined();
    expect(await w.cp.sessions.revoke(t.tenantId, s.sessionId)).toBe(true);
    expect(await w.cp.sessions.authenticate(s.accessToken)).toBeUndefined();
    expect(await w.cp.sessions.revoke(t.tenantId, s.sessionId)).toBe(false);
    expect(await rejects(w.cp.sessions.refresh(s.refreshToken))).toBe("unauthenticated");
  });

  it("rejects after the absolute session lifetime even if the access token is fresh", async () => {
    const { s } = await fresh();
    w.clock.advance(850);
    const r = await w.cp.sessions.refresh(s.refreshToken); // access token minted at t+850 would run to t+1750
    w.clock.advance(800);
    expect(await w.cp.sessions.authenticate(r.accessToken)).toBeDefined();
    w.clock.advance(2000); // past absolute (3600 from issue)
    expect(await w.cp.sessions.authenticate(r.accessToken)).toBeUndefined();
    expect(await rejects(w.cp.sessions.refresh(r.refreshToken))).toBe("unauthenticated");
  });

  it("access token expiry never exceeds the session expiry", async () => {
    const { s } = await fresh();
    w.clock.advance(3500);
    const r = await w.cp.sessions.refresh(s.refreshToken);
    expect(r.accessExpiresAt.getTime()).toBeLessThanOrEqual(r.sessionExpiresAt.getTime());
  });

  it("refresh rotates the token; replaying the previous one revokes the whole session", async () => {
    const { t, s } = await fresh();
    const r1 = await w.cp.sessions.refresh(s.refreshToken);
    expect(r1.refreshToken).not.toBe(s.refreshToken);
    expect(await w.cp.sessions.authenticate(r1.accessToken)).toBeDefined();
    expect(await rejects(w.cp.sessions.refresh(s.refreshToken))).toBe("unauthenticated"); // reuse
    // the legitimate holder of r1 is now locked out too
    expect(await w.cp.sessions.authenticate(r1.accessToken)).toBeUndefined();
    expect(await rejects(w.cp.sessions.refresh(r1.refreshToken))).toBe("unauthenticated");
    expect((await w.store.getSession(t.tenantId, s.sessionId))?.revokedReason).toBe("refresh_token_reuse");
  });

  it("rejects malformed refresh tokens and tokens for another session", async () => {
    const a = await fresh();
    const b = await fresh();
    for (const junk of ["", "axr", "axr.a.b.c", `axr.${a.t.tenantId}.${a.s.sessionId}.short`, "x.y.z.w"]) expect(await rejects(w.cp.sessions.refresh(junk))).toBe("unauthenticated");
    const secretA = a.s.refreshToken.split(".")[3];
    expect(await rejects(w.cp.sessions.refresh(`axr.${b.t.tenantId}.${b.s.sessionId}.${secretA}`))).toBe("unauthenticated");
    // a tenant-A session id presented under tenant B is simply not found
    expect(await rejects(w.cp.sessions.refresh(`axr.${b.t.tenantId}.${a.s.sessionId}.${secretA}`))).toBe("unauthenticated");
  });

  it("an inactive member cannot get, use or refresh a session", async () => {
    const { t, m, s } = await fresh();
    await w.cp.sessions.revokeAllOfMember(t.tenantId, m.id, "x");
    const other = await w.member(t.tenantId, "viewer");
    const om = (await w.store.getMember(t.tenantId, other.memberId))!;
    const os = await w.cp.sessions.issue(om);
    await w.store.updateMember(t.tenantId, om.id, { status: "deprovisioned" }, w.clock.now());
    expect(await w.cp.sessions.authenticate(os.accessToken)).toBeUndefined();
    expect(await rejects(w.cp.sessions.refresh(os.refreshToken))).toBe("unauthenticated");
    expect(await rejects(w.cp.sessions.issue({ ...om, status: "deprovisioned" }))).toBe("unauthenticated");
    void s;
  });

  it("revokeAllOfMember kills every session of that member only", async () => {
    const t = await w.tenant();
    const a = await w.member(t.tenantId, "viewer");
    const b = await w.member(t.tenantId, "viewer");
    const ma = (await w.store.getMember(t.tenantId, a.memberId))!;
    const s1 = await w.cp.sessions.issue(ma);
    const s2 = await w.cp.sessions.issue(ma);
    expect(await w.cp.sessions.revokeAllOfMember(t.tenantId, a.memberId, "test")).toBe(3); // incl. the one from w.member()
    for (const s of [s1, s2]) expect(await w.cp.sessions.authenticate(s.accessToken)).toBeUndefined();
    expect(await w.cp.sessions.authenticate((await w.cp.sessions.issue((await w.store.getMember(t.tenantId, b.memberId))!)).accessToken)).toBeDefined();
  });

  it("key rotation: tokens signed by a retired key stop verifying when it is removed", async () => {
    const { wireControlPlane } = await import("../src/index.js");
    const { secrets } = await import("./world.js");
    const sec = secrets();
    const base = {
      store: w.store, auditSink: w.auditStore, authorizer: await (await import("./world.js")).sharedAuthorizer(), idp: w.idp, kms: w.kms, dns: w.dns,
      region: w.region, regions: ["us-east-1"], redirectUri: "https://x/cb", allowedReturnOrigins: [], now: w.clock.now,
    };
    const old = wireControlPlane({ ...base, secrets: sec });
    const rotated = wireControlPlane({ ...base, secrets: { ...sec, signingKeys: [{ kid: "k2", key: Buffer.alloc(32, 9) }, ...sec.signingKeys] } });
    const dropped = wireControlPlane({ ...base, secrets: { ...sec, signingKeys: [{ kid: "k2", key: Buffer.alloc(32, 9) }] } });
    const tt = await w.tenant();
    const issued = await old.sessions.issue((await w.store.getMember(tt.tenantId, tt.ownerId))!);
    expect(await rotated.sessions.authenticate(issued.accessToken)).toBeDefined();
    expect(await dropped.sessions.authenticate(issued.accessToken)).toBeUndefined();
  });

  it("requires a strong pepper", async () => {
    const { SessionService, TokenSigner } = await import("../src/index.js");
    expect(() => new SessionService({ store: w.store, signer: new TokenSigner([{ kid: "a", key: Buffer.alloc(32) }]), pepper: Buffer.alloc(8) })).toThrow(/pepper/);
  });
});
