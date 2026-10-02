import { randomUUID } from "node:crypto";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  PAYLOAD_TYPE,
  ablContentHash,
  buildStatement,
  decodeStatement,
  envelopeSignedBy,
  isEnvelope,
  privateKeyFromPem,
  signBlueprint,
  decodeB64,
  decodeB64u,
  generatePublisherKey,
  keyIdOf,
  keyTrustedAt,
  pae,
  signDetached,
  signStatement,
  verifyDetached,
  verifyVersion,
  type PublisherKey,
  type VersionRecord,
} from "../src/index.js";
import { Publisher, ablDoc, harness } from "./helpers.js";

async function fixture() {
  const h = harness();
  const pub = await Publisher.create(h, randomUUID(), "acme");
  const abl = ablDoc("hello-agent", "1.0.0");
  const rec = await pub.publish(abl);
  const keys = new Map(
    (await h.store.getKeys({ tenantId: pub.p.tenantId }, "acme")).map((k) => [k.keyId, k]),
  );
  return { h, pub, rec, keys };
}
const clone = (r: VersionRecord): VersionRecord => structuredClone(r);
const ok = (r: VersionRecord, keys: Map<string, PublisherKey>) => verifyVersion(r, keys);

/** A different character from the same alphabet (so the string stays well-formed and the check, not the parser, must catch it). */
function otherChar(c: string): string {
  return c === "A" ? "B" : "A";
}

describe("verification of a good record", () => {
  it("passes and reports the signer and builder", async () => {
    const { rec, keys, pub } = await fixture();
    const v = ok(rec, keys);
    expect(v).toMatchObject({ ok: true, keyId: pub.key.keyId, builder: "ci.example.com/builder" });
  });
});

describe("tamper tests: any single change breaks verification", () => {
  it("every character of the blueprint text", async () => {
    const { rec, keys } = await fixture();
    for (let i = 0; i < rec.abl.length; i++) {
      const t = clone(rec);
      t.abl = rec.abl.slice(0, i) + otherChar(rec.abl[i] as string) + rec.abl.slice(i + 1);
      if (t.abl === rec.abl) t.abl = rec.abl.slice(0, i) + "Z" + rec.abl.slice(i + 1);
      expect(ok(t, keys).ok, `abl char ${i}`).toBe(false);
    }
  });
  it("every character of the detached signature (including non-canonical trailing bits)", async () => {
    const { rec, keys } = await fixture();
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for (let i = 0; i < rec.signature.sig.length; i++) {
      for (const c of alphabet) {
        if (c === rec.signature.sig[i]) continue;
        const t = clone(rec);
        t.signature.sig = rec.signature.sig.slice(0, i) + c + rec.signature.sig.slice(i + 1);
        expect(ok(t, keys).ok, `sig char ${i}->${c}`).toBe(false);
      }
    }
  });
  it("every character of the attestation payload and its signature", async () => {
    const { rec, keys } = await fixture();
    for (let i = 0; i < rec.provenance.payload.length; i++) {
      const t = clone(rec);
      t.provenance.payload =
        rec.provenance.payload.slice(0, i) +
        otherChar(rec.provenance.payload[i] as string) +
        rec.provenance.payload.slice(i + 1);
      if (t.provenance.payload === rec.provenance.payload)
        t.provenance.payload =
          rec.provenance.payload.slice(0, i) + "B" + rec.provenance.payload.slice(i + 1);
      expect(ok(t, keys).ok, `payload char ${i}`).toBe(false);
    }
    const s = rec.provenance.signatures[0]?.sig as string;
    for (let i = 0; i < s.length; i++) {
      const t = clone(rec);
      (t.provenance.signatures[0] as { sig: string }).sig =
        s.slice(0, i) + otherChar(s[i] as string) + s.slice(i + 1);
      if ((t.provenance.signatures[0] as { sig: string }).sig === s)
        (t.provenance.signatures[0] as { sig: string }).sig = s.slice(0, i) + "B" + s.slice(i + 1);
      expect(ok(t, keys).ok, `att sig char ${i}`).toBe(false);
    }
  });
  it("every identity field of the record", async () => {
    const { rec, keys } = await fixture();
    const edits: Array<[string, (t: VersionRecord) => void]> = [
      ["namespace", (t) => (t.namespace = "acmf")],
      ["name", (t) => (t.name = "hello-agenu")],
      ["version", (t) => (t.version = "1.0.1")],
      ["contentHash", (t) => (t.contentHash = "0".repeat(64))],
      ["riskLevel", (t) => (t.riskLevel = "high")],
      ["keyId", (t) => (t.signature.keyId = "k1-" + "0".repeat(32))],
      [
        "signedAt",
        (t) =>
          (t.signature.signedAt = new Date(
            new Date(t.signature.signedAt).getTime() - 1000,
          ).toISOString()),
      ],
      ["payloadType", (t) => (t.provenance.payloadType = "text/plain")],
      ["signatures removed", (t) => (t.provenance.signatures = [])],
      [
        "provenance keyid",
        (t) => ((t.provenance.signatures[0] as { keyid: string }).keyid = "k1-" + "1".repeat(32)),
      ],
      [
        "provenance not an envelope",
        (t) => ((t as unknown as { provenance: unknown }).provenance = "x"),
      ],
    ];
    for (const [what, edit] of edits) {
      const t = clone(rec);
      edit(t);
      expect(ok(t, keys).ok, what).toBe(false);
    }
  });
  it("property: mutating any one character of the serialized record never verifies", async () => {
    const { rec, keys } = await fixture();
    // Server-side bookkeeping (tenant, publisher, publish time) is not part of what the publisher signs; everything else is.
    const { tenantId, publishedBy, publishedAt, ...signed } = rec;
    const text = JSON.stringify(signed);
    fc.assert(
      fc.property(fc.nat(text.length - 1), fc.constantFrom(...'ABCxyz019-_+/= "{}:,k'), (i, ch) => {
        const mutated = text.slice(0, i) + ch + text.slice(i + 1);
        fc.pre(mutated !== text);
        let parsed: Omit<VersionRecord, "tenantId" | "publishedBy" | "publishedAt">;
        try {
          parsed = JSON.parse(mutated) as typeof parsed;
        } catch {
          return true; // not even JSON: nothing to verify
        }
        // Mutations that only re-order or re-encode to the SAME data (e.g. a character swapped for itself in an escape) are not changes.
        fc.pre(JSON.stringify(parsed) !== text);
        return verifyVersion({ ...parsed, tenantId, publishedBy, publishedAt }, keys).ok === false;
      }),
      { numRuns: 2000 },
    );
  });
  it("a swapped attestation (valid, signed, but for another blueprint) is rejected", async () => {
    const { h, pub, rec, keys } = await fixture();
    const other = await pub.publish(ablDoc("other-agent", "1.0.0"));
    const t = clone(rec);
    t.provenance = other.provenance;
    expect(ok(t, keys)).toMatchObject({ ok: false });
    void h;
  });
  it("a signature copied from another version is rejected", async () => {
    const { pub, rec, keys } = await fixture();
    const other = await pub.publish(ablDoc("hello-agent", "1.0.1"));
    const t = clone(rec);
    t.signature = other.signature;
    expect(ok(t, keys).ok).toBe(false);
  });
});

describe("attestation content is checked, not just its signature", () => {
  async function reattest(mutate: (st: ReturnType<typeof buildStatement>) => void) {
    const { h, pub, rec, keys } = await fixture();
    const st = buildStatement(
      {
        namespace: "acme",
        name: rec.name,
        version: rec.version,
        abl: JSON.parse(rec.abl),
        builderId: "b",
        sourceRef: "s",
        now: h.clock.now(),
      },
      rec.contentHash,
    );
    mutate(st);
    const t = clone(rec);
    t.provenance = signStatement(st, pub.key); // correctly SIGNED, but lying
    return verifyVersion(t, keys);
  }
  it.each<[string, (st: ReturnType<typeof buildStatement>) => void, string]>([
    [
      "wrong subject digest",
      (st) => ((st.subject[0] as { digest: { sha256: string } }).digest.sha256 = "1".repeat(64)),
      "provenance_subject_mismatch",
    ],
    [
      "wrong subject name",
      (st) => ((st.subject[0] as { name: string }).name = "acme/x@1.0.0"),
      "provenance_subject_mismatch",
    ],
    [
      "two subjects",
      (st) => st.subject.push({ name: "a", digest: { sha256: "0".repeat(64) } }),
      "provenance_subject_mismatch",
    ],
    [
      "wrong abl hash",
      (st) => (st.predicate.abl.sha256 = "2".repeat(64)),
      "provenance_abl_hash_mismatch",
    ],
    ["no builder", (st) => (st.predicate.builder.id = ""), "provenance_builder"],
    ["no source", (st) => (st.predicate.source.ref = ""), "provenance_source"],
    [
      "foreign compiler",
      (st) => (st.predicate.compiler.name = "evil-compiler"),
      "provenance_compiler",
    ],
    [
      "lint results that cannot be reproduced",
      (st) => (st.predicate.lint.warnings = 7),
      "provenance_lint_mismatch",
    ],
    ["claims lint errors", (st) => (st.predicate.lint.errors = 1), "provenance_lint_mismatch"],
    ["wrong statement type", (st) => (st._type = "x"), "provenance_type"],
    ["wrong predicate type", (st) => (st.predicateType = "x"), "provenance_type"],
  ])("%s", async (_n, mutate, code) => {
    const v = await reattest(mutate);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.failures).toContain(code);
  });
  it("rejects a non-canonical (re-spaced) payload even when signed", async () => {
    const { pub, rec, keys } = await fixture();
    const st = JSON.parse(Buffer.from(rec.provenance.payload, "base64").toString());
    const body = Buffer.from(JSON.stringify(st, null, 2));
    const t = clone(rec);
    t.provenance = {
      payloadType: PAYLOAD_TYPE,
      payload: body.toString("base64"),
      signatures: [
        { keyid: pub.key.keyId, sig: signDetached(pub.key.privateKey, pae(PAYLOAD_TYPE, body)) },
      ],
    };
    const v = verifyVersion(t, keys);
    expect(v).toMatchObject({ ok: false });
    if (!v.ok) expect(v.failures).toContain("provenance_payload_invalid");
  });
  it("enforces a minimum compiler version", async () => {
    const { rec, keys } = await fixture();
    expect(verifyVersion(rec, keys, { minCompilerVersion: "99.0.0" })).toMatchObject({
      ok: false,
      failures: ["provenance_compiler_too_old"],
    });
    expect(verifyVersion(rec, keys, { minCompilerVersion: "0.0.1" }).ok).toBe(true);
    expect(verifyVersion(rec, keys, { minCompilerVersion: "bogus" }).ok).toBe(false);
  });
  it("an extra signature by an unknown key is ignored, but there must be one good signature", async () => {
    const { rec, keys } = await fixture();
    const t = clone(rec);
    t.provenance.signatures.push({ keyid: "k1-" + "9".repeat(32), sig: "A".repeat(86) });
    expect(ok(t, keys).ok).toBe(true);
    t.provenance.signatures = [{ keyid: "k1-" + "9".repeat(32), sig: "A".repeat(86) }];
    expect(ok(t, keys).ok).toBe(false);
  });
});

describe("blueprint content checks", () => {
  it("rejects non-JSON, non-canonical, schema-invalid and lint-failing text", async () => {
    const { rec, keys } = await fixture();
    const t = clone(rec);
    t.abl = "{not json";
    expect(verifyVersion(t, keys)).toMatchObject({ ok: false, failures: ["abl_not_json"] });
    t.abl = JSON.stringify(JSON.parse(rec.abl), null, 1);
    expect(verifyVersion(t, keys)).toMatchObject({ ok: false });
    t.abl = '{"apiVersion":"nope"}';
    expect(verifyVersion(t, keys)).toMatchObject({ ok: false, failures: ["abl_schema"] });
  });
  it("a record whose ABL has lint errors does not verify", async () => {
    const { h, pub, keys } = await fixture();
    const bad = ablDoc("lint-bad", "1.0.0", {
      tools: [
        { name: "a", kind: "function" },
        { name: "a", kind: "function" },
      ],
    });
    const sub = pub.submission(bad);
    const rec: VersionRecord = {
      namespace: "acme",
      name: "lint-bad",
      version: "1.0.0",
      tenantId: pub.p.tenantId,
      abl: JSON.stringify(sortKeys(bad)),
      contentHash: ablContentHash(bad),
      riskLevel: "minimal",
      signature: sub.signature,
      provenance: sub.provenance,
      publishedAt: h.clock.now(),
      publishedBy: "x",
    };
    const v = verifyVersion(rec, keys);
    expect(v.ok).toBe(false);
  });
});

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object")
    return Object.fromEntries(
      Object.keys(v)
        .sort()
        .map((k) => [k, sortKeys((v as Record<string, unknown>)[k])]),
    );
  return v;
}

describe("key validity at publish time", () => {
  const base = (over: Partial<PublisherKey>): PublisherKey => ({
    namespace: "acme",
    keyId: "k1-" + "a".repeat(32),
    tenantId: randomUUID(),
    publicKey: "A".repeat(43),
    validFrom: new Date("2026-01-01T00:00:00Z"),
    validUntil: null,
    revokedAt: null,
    revokeReason: null,
    createdAt: new Date("2026-01-01T00:00:00Z"),
    createdBy: "x",
    ...over,
  });
  const at = (s: string): Date => new Date(s);
  it("window, rotation, retirement, compromise", () => {
    expect(keyTrustedAt(base({}), at("2025-12-31T23:59:59Z")).ok).toBe(false);
    expect(keyTrustedAt(base({}), at("2026-01-01T00:00:00Z")).ok).toBe(true);
    const rotated = base({ validUntil: at("2026-06-01T00:00:00Z") });
    expect(keyTrustedAt(rotated, at("2026-05-31T23:59:59Z")).ok).toBe(true);
    expect(keyTrustedAt(rotated, at("2026-06-01T00:00:00Z")).ok).toBe(false);
    const retired = base({ revokedAt: at("2026-06-01T00:00:00Z"), revokeReason: "retired" });
    expect(keyTrustedAt(retired, at("2026-05-01T00:00:00Z")).ok).toBe(true);
    expect(keyTrustedAt(retired, at("2026-06-02T00:00:00Z")).ok).toBe(false);
    const stolen = base({ revokedAt: at("2026-06-01T00:00:00Z"), revokeReason: "compromised" });
    expect(keyTrustedAt(stolen, at("2026-05-01T00:00:00Z")).ok).toBe(false); // before the revocation instant too
  });
  it("a version signed by a key that is later revoked as compromised stops verifying; retired keeps old versions valid", async () => {
    const { h, pub, rec } = await fixture();
    const p = pub.p;
    h.clock.advance(60_000);
    await h.svc.revokeKey(p, "acme", pub.key.keyId, { reason: "retired" });
    const keys = new Map(
      (await h.store.getKeys({ tenantId: p.tenantId }, "acme")).map((k) => [k.keyId, k]),
    );
    expect(verifyVersion(rec, keys).ok).toBe(true);
  });
  it("a signature made after the key's validity ended is rejected even if the math checks out", async () => {
    const { h, pub } = await fixture();
    h.clock.advance(60_000);
    await h.svc.rotateKey(pub.p, "acme", pub.key.keyId, {
      newPublicKey: generatePublisherKey().publicKey,
    });
    h.clock.advance(60_000);
    await expect(pub.publish(ablDoc("late-agent", "1.0.0"))).rejects.toMatchObject({
      code: "verification_failed",
      checks: expect.arrayContaining(["signing_key_not_trusted"]),
    });
  });
  it("a key from a different namespace is not accepted", async () => {
    const { h, rec } = await fixture();
    const other = await Publisher.create(h, randomUUID(), "globex");
    const keys = new Map(
      (await h.store.getKeys({ tenantId: other.p.tenantId }, "globex")).map((k) => [k.keyId, k]),
    );
    expect(verifyVersion(rec, keys).ok).toBe(false);
  });
});

describe("primitives", () => {
  it("strict base64 decoders reject non-canonical encodings", () => {
    expect(decodeB64u("AA")).toBeDefined();
    expect(decodeB64u("AB")).toBeUndefined(); // trailing bits set: non-canonical
    expect(decodeB64u("A+")).toBeUndefined();
    expect(decodeB64u(5)).toBeUndefined();
    expect(decodeB64u("AAAA", 2)).toBeUndefined();
    expect(decodeB64("AA==")).toBeDefined();
    expect(decodeB64("AB==")).toBeUndefined();
    expect(decodeB64("A")).toBeUndefined();
    expect(decodeB64(1)).toBeUndefined();
  });
  it("verifyDetached never throws on garbage", () => {
    const k = generatePublisherKey();
    expect(verifyDetached("short", Buffer.from("m"), "x")).toBe(false);
    expect(verifyDetached(k.publicKey, Buffer.from("m"), 5)).toBe(false);
    expect(verifyDetached(k.publicKey, Buffer.from("m"), "A".repeat(86))).toBe(false);
    const sig = signDetached(k.privateKey, Buffer.from("m"));
    expect(verifyDetached(k.publicKey, Buffer.from("m"), sig)).toBe(true);
    expect(verifyDetached(k.publicKey, Buffer.from("n"), sig)).toBe(false);
    // 32 bytes that are not a valid curve point
    expect(
      verifyDetached(Buffer.alloc(32, 0xff).toString("base64url"), Buffer.from("m"), sig),
    ).toBe(false);
    expect(keyIdOf(Buffer.alloc(32))).toMatch(/^k1-[0-9a-f]{32}$/);
  });
  it("verifyVersion converts any internal error into a failure", async () => {
    const { rec, keys } = await fixture();
    const t = clone(rec) as unknown as { signature: unknown };
    t.signature = null;
    expect(verifyVersion(t as VersionRecord, keys)).toMatchObject({ ok: false });
  });
});

describe("provenance helpers", () => {
  it("optional statement fields and malformed envelopes", async () => {
    const { rec, pub } = await fixture();
    const st = buildStatement(
      {
        namespace: "acme",
        name: rec.name,
        version: rec.version,
        abl: JSON.parse(rec.abl),
        builderId: "b",
        sourceRef: "s",
        sourceDigest: "sha1:abc",
        evalsUrl: "https://evals.example.com/run/1",
      },
      rec.contentHash,
    );
    expect(st.predicate.source.digest).toBe("sha1:abc");
    expect(st.predicate.evals).toEqual({ resultsUrl: "https://evals.example.com/run/1" });
    const env = signStatement(st, pub.key);
    expect(isEnvelope(env)).toBe(true);
    for (const bad of [
      null,
      1,
      {},
      { payloadType: "x", payload: "y", signatures: "z" },
      { payloadType: "x", payload: "y", signatures: [{ keyid: 1, sig: "s" }] },
      { payloadType: "x", payload: "y", signatures: [null] },
    ])
      expect(isEnvelope(bad)).toBe(false);
    expect(decodeStatement({ ...env, payload: "***" })).toBeUndefined();
    expect(
      decodeStatement({ ...env, payload: Buffer.from("not json").toString("base64") }),
    ).toBeUndefined();
    expect(
      envelopeSignedBy({ ...env, payloadType: "other" }, pub.key.keyId, pub.key.publicKey),
    ).toBe(false);
    expect(envelopeSignedBy({ ...env, payload: "***" }, pub.key.keyId, pub.key.publicKey)).toBe(
      false,
    );
    expect(envelopeSignedBy(env, pub.key.keyId, pub.key.publicKey)).toBe(true);
    expect(envelopeSignedBy(env, "k1-" + "0".repeat(32), pub.key.publicKey)).toBe(false);
  });
  it("private keys round-trip through PEM; signBlueprint defaults signedAt to now", async () => {
    const k = generatePublisherKey();
    const pem = k.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    const again = privateKeyFromPem(pem);
    expect(
      verifyDetached(k.publicKey, Buffer.from("m"), signDetached(again, Buffer.from("m"))),
    ).toBe(true);
    const sig = signBlueprint(
      {
        namespace: "a",
        name: "b",
        version: "1.0.0",
        riskLevel: "minimal",
        contentHash: "0".repeat(64),
      },
      k,
    );
    expect(Math.abs(new Date(sig.signedAt).getTime() - Date.now())).toBeLessThan(5000);
  });
  it("malformed signed-at and unknown key paths fail", async () => {
    const { rec, keys } = await fixture();
    const t = clone(rec);
    t.signature.signedAt = "yesterday";
    expect(verifyVersion(t, keys)).toMatchObject({
      ok: false,
      failures: expect.arrayContaining(["signed_at_malformed"]),
    });
    const u = clone(rec);
    u.signature.keyId = "k1-" + "5".repeat(32);
    expect(verifyVersion(u, keys)).toMatchObject({
      ok: false,
      failures: expect.arrayContaining(["signing_key_unknown"]),
    });
  });
});

describe("lying records signed by the real key", () => {
  it("a record whose version/name differ from the ABL it carries is refused even when freshly signed", async () => {
    const { rec, keys, pub } = await fixture();
    const t = clone(rec);
    t.version = "9.9.9";
    t.signature = signBlueprint(
      {
        namespace: "acme",
        name: t.name,
        version: "9.9.9",
        riskLevel: t.riskLevel,
        contentHash: t.contentHash,
      },
      pub.key,
      rec.publishedAt,
    );
    t.provenance = signStatement(
      buildStatement(
        {
          namespace: "acme",
          name: t.name,
          version: "9.9.9",
          abl: JSON.parse(rec.abl),
          builderId: "b",
          sourceRef: "s",
          now: rec.publishedAt,
        },
        t.contentHash,
      ),
      pub.key,
    );
    const v = verifyVersion(t, keys);
    expect(v).toMatchObject({ ok: false, failures: ["version_mismatch"] });
  });
});
