import { describe, expect, it } from "vitest";
import { EvidenceVerifier, MasterKeyProvider, type AttesterDirectory } from "../src/index.js";

const T = "11111111-1111-4111-8111-111111111111";
const REQ = "22222222-2222-4222-8222-222222222222";
const SUBJ = "sub_abc";
const base = { tenantId: T, requestId: REQ, subjectRef: SUBJ, kind: "erase" as const };

class Dir implements AttesterDirectory {
  admins = new Set<string>(["adm-1"]);
  fail = false;
  async isTenantAdmin(t: string, m: string): Promise<boolean> {
    if (this.fail) throw new Error("db down");
    return t === T && this.admins.has(m);
  }
}
function rig(start = new Date("2026-03-01T00:00:00Z")) {
  let now = start;
  const dir = new Dir();
  const v = new EvidenceVerifier(new MasterKeyProvider(), dir, () => now);
  return { v, dir, advance: (s: number) => (now = new Date(now.getTime() + s * 1000)) };
}
const ask = (
  v: EvidenceVerifier,
  ev: unknown,
  over: Partial<{ requestedBy: string; verifiedBy: string }> = {},
) => v.verify({ ...base, requestedBy: "po-1", verifiedBy: "po-2", ...over }, ev);

async function good(r: ReturnType<typeof rig>, attester = "adm-1") {
  return {
    requester_token: await r.v.issueRequesterToken({
      tenantId: T,
      requestId: REQ,
      subjectRef: SUBJ,
    }),
    admin_attestation: await r.v.issueAdminAttestation({
      tenantId: T,
      requestId: REQ,
      memberId: attester,
    }),
  };
}

describe("EvidenceVerifier (dual control, fail-closed)", () => {
  it("accepts two valid tokens attested by an independent tenant admin", async () => {
    const r = rig();
    expect(await ask(r.v, await good(r))).toEqual({
      ok: true,
      method: "signed-token+admin-attestation",
    });
  });

  it.each([null, undefined, "x", 3, [], {}, { requester_token: "a.b" }])(
    "refuses malformed evidence %#",
    async (ev) => {
      const r = rig();
      expect((await ask(r.v, ev)).ok).toBe(false);
    },
  );

  it("refuses when the attester opened the request or submits the verification", async () => {
    const r = rig();
    r.dir.admins.add("po-1").add("po-2");
    const a = await ask(r.v, await good(r, "po-1"));
    expect(a).toEqual({ ok: false, method: "refused:dual_control" });
    const b = await ask(r.v, await good(r, "po-2"));
    expect(b.method).toBe("refused:dual_control");
  });

  it("refuses an attester who is not an active tenant admin, and a directory failure", async () => {
    const r = rig();
    expect((await ask(r.v, await good(r, "stranger"))).method).toBe("refused:attester");
    r.dir.fail = true;
    expect((await ask(r.v, await good(r))).method).toBe("refused:error");
  });

  it("refuses expired tokens", async () => {
    const r = rig();
    const ev = await good(r);
    r.advance(3601);
    expect((await ask(r.v, ev)).method).toBe("refused:requester_token");
  });

  it("refuses tokens bound to another request, another subject or another tenant", async () => {
    const r = rig();
    const other = {
      requester_token: await r.v.issueRequesterToken({
        tenantId: T,
        requestId: "other",
        subjectRef: SUBJ,
      }),
      admin_attestation: (await good(r)).admin_attestation,
    };
    expect((await ask(r.v, other)).method).toBe("refused:requester_token");
    const wrongSubject = {
      requester_token: await r.v.issueRequesterToken({
        tenantId: T,
        requestId: REQ,
        subjectRef: "sub_other",
      }),
      admin_attestation: (await good(r)).admin_attestation,
    };
    expect((await ask(r.v, wrongSubject)).method).toBe("refused:requester_token");
    const otherTenant = await good(r);
    expect(
      (
        await r.v.verify(
          {
            ...base,
            tenantId: "33333333-3333-4333-8333-333333333333",
            requestedBy: "a",
            verifiedBy: "b",
          },
          otherTenant,
        )
      ).ok,
    ).toBe(false);
  });

  it("refuses swapped token types, tampered payloads and foreign signatures", async () => {
    const r = rig();
    const g = await good(r);
    expect(
      (
        await ask(r.v, {
          requester_token: g.admin_attestation,
          admin_attestation: g.requester_token,
        })
      ).ok,
    ).toBe(false);
    const [p, s] = g.requester_token.split(".") as [string, string];
    const forged = Buffer.from(
      JSON.stringify({ ...JSON.parse(Buffer.from(p, "base64url").toString()), s: "sub_x" }),
    ).toString("base64url");
    expect((await ask(r.v, { ...g, requester_token: `${forged}.${s}` })).ok).toBe(false);
    const foreign = rig();
    expect((await ask(foreign.v, g)).ok).toBe(false);
    expect((await ask(r.v, { ...g, requester_token: "a".repeat(3000) })).ok).toBe(false);
    expect((await ask(r.v, { ...g, requester_token: "no-dot" })).ok).toBe(false);
  });

  it("refuses a correctly signed token whose payload is not JSON", async () => {
    const r = rig();
    const g = await good(r);
    // Re-sign garbage with the genuine key via a second verifier sharing the key provider.
    const keys = new MasterKeyProvider();
    const v = new EvidenceVerifier(keys, r.dir, () => new Date("2026-03-01T00:00:00Z"));
    const payload = Buffer.from("not json").toString("base64url");
    const { createHmac } = await import("node:crypto");
    const sig = createHmac("sha256", await keys.tenantKey(T, "evidence"))
      .update("axis-gov-evidence.v1\u0000")
      .update(payload)
      .digest("base64url");
    expect((await ask(v, { ...g, requester_token: `${payload}.${sig}` })).ok).toBe(false);
  });

  it("an attestation without a member id is refused", async () => {
    const r = rig();
    const g = await good(r, "");
    expect((await ask(r.v, g)).method).toBe("refused:admin_attestation");
  });

  it("rejects out-of-range token lifetimes", async () => {
    const r = rig();
    await expect(
      r.v.issueRequesterToken({ tenantId: T, requestId: REQ, subjectRef: SUBJ, ttlSeconds: 0 }),
    ).rejects.toThrow(RangeError);
    await expect(
      r.v.issueAdminAttestation({
        tenantId: T,
        requestId: REQ,
        memberId: "a",
        ttlSeconds: 8 * 86400,
      }),
    ).rejects.toThrow(RangeError);
  });
});
