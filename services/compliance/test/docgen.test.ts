import { describe, expect, it } from "vitest";
import {
  Ed25519Sealer,
  HmacSealer,
  NeedsLimitations,
  assemble,
  canonicalJson,
  documentIdOf,
  hashOf,
  missing,
  parseNeeds,
  renderMarkdown,
  sealDocument,
  sealPayload,
  sourced,
  verifyDocument,
  type AssembleInput,
  type DocBody,
  type SealedDocument,
} from "../src/index.js";
import { EVIDENCE, STATS, T1, T2, ablDoc, fakeSources, snapshot, user, world } from "./helpers.js";

const REF = { name: "claims-triage", version: "2.3.1" };
const full = (): AssembleInput => ({
  ref: REF,
  blueprint: sourced(snapshot()),
  evals: sourced(EVIDENCE),
  policies: sourced([{ id: "baseline-deny", version: "1.0.0", hash: null, active_since: null }]),
  audit: sourced(STATS),
  limitations: sourced([{ id: "NEEDS-1", title: "t", detail: null, evidence: null }]),
});

describe("assemble", () => {
  it("is a pure function: identical inputs give identical canonical bytes", () => {
    expect(canonicalJson(assemble(full()))).toBe(canonicalJson(assemble(full())));
  });

  it("does not depend on the order of source arrays", () => {
    const a = full();
    const b = full();
    if (b.evals.ok) b.evals.value = { ...EVIDENCE, runs: [...EVIDENCE.runs].reverse() };
    if (b.policies.ok) b.policies.value = [...b.policies.value].reverse();
    expect(hashOf(assemble(a))).toBe(hashOf(assemble(b)));
  });

  it("has every section complete or partial with real data, and states what it cannot evidence", () => {
    const body = assemble(full());
    expect(Object.keys(body.sections)).toHaveLength(10);
    expect(body.sections["general"]?.status).toBe("partial"); // hardware / instructions-for-use are always a gap
    expect(body.sections["performance"]?.status).toBe("complete");
    expect(body.sections["record_keeping"]?.status).toBe("complete");
    const g = body.gaps.find((x) => x.item === "hardware_and_deployer_instructions");
    expect(g?.section).toBe("general");
    // Annex IV points 7 and 8 are never produced by the platform.
    expect(body.annex_iv_coverage.filter((c) => c.status === "gap").map((c) => c.point)).toEqual(
      expect.arrayContaining(["7", "8"]),
    );
    expect(body.disclaimer).toMatch(/not a conformity assessment/);
  });

  it("carries the facts of the blueprint, not invented ones", () => {
    const body = assemble(full());
    const dev = body.sections["development"]?.data as Record<string, unknown>;
    expect((dev["tools"] as { name: string }[]).map((t) => t.name)).toEqual([
      "crm",
      "lookup-policy",
      "notify-adjuster",
    ]);
    expect((dev["system_instructions"] as { sha256: string }).sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(body)).not.toContain("Never state coverage decisions");
    expect(dev["compiled_manifest_sha256"]).toMatch(/^[0-9a-f]{64}$/);
    expect((body.sections["oversight"]?.data as Record<string, unknown>)["approver_roles"]).toEqual(
      ["claims-adjuster"],
    );
    const rm = body.sections["risk_management"]?.data as Record<string, unknown>;
    expect(rm["level"]).toBe("high");
  });

  it("lists every missing source as a gap and never invents data", () => {
    const body = assemble({
      ref: REF,
      blueprint: missing("registry down"),
      evals: missing("hub down"),
      policies: missing("policy store down"),
      audit: missing("audit down"),
      limitations: missing("no needs file"),
    });
    expect(body.blueprint.content_hash).toBeNull();
    expect(body.sources.every((s) => s.status === "gap")).toBe(true);
    for (const k of ["general", "development", "risk_management", "data_governance", "lifecycle"])
      expect(body.sections[k]?.status).toBe("gap");
    expect(body.sections["performance"]?.data).toBeNull();
    expect(body.sections["record_keeping"]?.data).toBeNull();
    expect(body.sections["limitations"]?.data).toBeNull();
    expect(body.gaps.map((g) => g.reason)).toEqual(
      expect.arrayContaining([
        "registry down",
        "hub down",
        "policy store down",
        "audit down",
        "no needs file",
      ]),
    );
    expect(body.annex_iv_coverage.every((c) => c.status === "gap")).toBe(true);
  });

  it("reports a failed audit chain verification as a gap, not as success", () => {
    const i = full();
    i.audit = sourced({
      ...STATS,
      chain: { verified: false, checked_through_seq: 7, reason: "hash mismatch at 8" },
    });
    const body = assemble(i);
    expect(body.sections["record_keeping"]?.status).toBe("partial");
    expect(body.gaps.some((g) => g.item === "audit_chain" && /FAILED/.test(g.reason))).toBe(true);
    const j = full();
    j.audit = sourced({
      ...STATS,
      chain: { verified: false, checked_through_seq: 0, reason: null },
    });
    expect(assemble(j).gaps.some((g) => g.item === "audit_chain" && !/:/.test(g.reason))).toBe(
      true,
    );
  });

  it("flags a tenant-local blueprint (no provenance) and a failed registry verification", () => {
    const a = full();
    a.blueprint = sourced(snapshot({ registry: null, origin: "tenant", versions: null }));
    const ba = assemble(a);
    expect(ba.gaps.some((g) => g.item === "registry_provenance")).toBe(true);
    expect(ba.gaps.some((g) => g.item === "version_history")).toBe(true);
    const b = full();
    b.blueprint = sourced(
      snapshot({
        registry: {
          namespace: "acme",
          signature_key_id: "k",
          signed_at: "x",
          published_at: "y",
          verification: { ok: false, checks: ["signature", "hash"] },
          provenance_attached: false,
        },
      }),
    );
    expect(assemble(b).gaps.find((g) => g.item === "registry_verification")?.reason).toBe(
      "registry verification failed: hash,signature",
    );
  });

  it("flags missing declared purpose and owner, high risk without oversight, lint errors and compile failures", () => {
    const i = full();
    i.blueprint = sourced(
      snapshot({
        abl: ablDoc((d) => {
          delete d.spec.riskClassification.intendedPurpose;
          delete d.metadata.owner;
          d.spec.riskClassification.humanOversight = { required: false };
        }),
      }),
    );
    const items = assemble(i).gaps.map((g) => g.item);
    expect(items).toEqual(
      expect.arrayContaining(["intended_purpose", "provider_owner", "human_oversight"]),
    );

    const bad = full();
    bad.blueprint = sourced(
      snapshot({
        abl: ablDoc((d) => {
          delete d.spec.evals; // ABL004: high risk without evals is a lint ERROR
        }),
      }),
    );
    const bb = assemble(bad);
    expect(bb.gaps.some((g) => g.item === "compiled_manifest")).toBe(true);
    expect(bb.gaps.some((g) => g.item === "lint")).toBe(true);
  });

  it("evaluates evals: no passing run, failing gate, unverified attestation, no sampling", () => {
    const i = full();
    i.evals = sourced({
      runs: [{ ...EVIDENCE.runs[0]!, status: "failed" }],
      attestations: [
        { run_id: "run-1", suite_ref: "claims-regression@1.0.0", overall: 0.5, verified: false },
      ],
      gate: [
        {
          suite_ref: "claims-regression@1.0.0",
          threshold: 0.92,
          pass: false,
          reasons: ["below", "age"],
        },
      ],
      online: [{ id: "x", suite_ref: "s", rate: 0.1, enabled: false }],
    });
    const items = assemble(i).gaps.map((g) => g.item);
    expect(items).toEqual(
      expect.arrayContaining([
        "suite:claims-regression@^1.0.0",
        "gate:claims-regression@1.0.0",
        "attestation:run-1",
        "online_sampling",
      ]),
    );
    const j = full();
    j.evals = sourced({ ...EVIDENCE, online: null });
    expect(assemble(j).gaps.find((g) => g.item === "online_sampling")?.reason).toMatch(
      /cannot report/,
    );
  });

  it("renders gaps only for what is missing (no gaps for a minimal, fully documented system)", () => {
    const i = full();
    i.blueprint = sourced(
      snapshot({
        abl: ablDoc((d) => {
          d.spec.riskClassification.level = "minimal";
          delete d.spec.riskClassification.humanOversight;
          delete d.spec.evals;
        }),
      }),
    );
    const body = assemble(i);
    expect(body.sections["oversight"]?.status).toBe("complete");
    expect(body.sections["risk_management"]?.status).toBe("complete");
  });
});

describe("markdown", () => {
  const meta = {
    document_id: "cdoc-x",
    doc_version: 1,
    generated_at: "2026-03-01T10:00:00.000Z",
    content_hash: "h",
  };
  it("is deterministic and mentions every section and every gap", () => {
    const body = assemble(full());
    const md = renderMarkdown(body, meta);
    expect(md).toBe(renderMarkdown(body, meta));
    for (const s of Object.values(body.sections)) expect(md).toContain(`## ${s.title}`);
    for (const g of body.gaps) expect(md).toContain(`[${g.section}] ${g.item}`);
    expect(md).toContain("| point | title | section | status | note |");
  });
  it("escapes table cells and handles missing data and empty gap lists", () => {
    const body = assemble({
      ref: REF,
      blueprint: missing("a|b\nc"),
      evals: missing("x"),
      policies: missing("x"),
      audit: missing("x"),
      limitations: missing("x"),
    });
    const md = renderMarkdown(body, meta);
    expect(md).toContain("No data: the source of this section was unavailable.");
    expect(md).toContain("- blueprint: gap (a|b c)"); // multi-line reasons are folded to one line
    const clean = assemble({ ...full(), blueprint: sourced(snapshot()) });
    clean.gaps.length = 0;
    expect(renderMarkdown(clean, meta)).toContain("No gaps were found by the generator.");
  });
});

describe("seal and verification", () => {
  const sealer = Ed25519Sealer.generate("k1");
  const mk = (): SealedDocument =>
    sealDocument(
      {
        body: assemble(full()),
        meta: {
          document_id: "cdoc-1",
          tenant_id: T1,
          doc_version: 1,
          generated_at: "2026-03-01T10:00:00.000Z",
          generated_by: "u1",
        },
      },
      sealer,
    );

  it("identical inputs give identical bytes (Ed25519 is deterministic)", () => {
    expect(JSON.stringify(mk())).toBe(JSON.stringify(mk()));
    const h = new HmacSealer(Buffer.from("0123456789abcdef"), "h1");
    const a = sealDocument({ body: assemble(full()), meta: mk().meta }, h);
    const b = sealDocument({ body: assemble(full()), meta: mk().meta }, h);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    expect(verifyDocument(a, [h]).ok).toBe(true);
  });

  it("verifies untouched, and fails on any edit of body, markdown, meta, seal or key", () => {
    const d = mk();
    expect(verifyDocument(d, [sealer])).toEqual({ ok: true, failed: [] });

    const body = structuredClone(d);
    (body.body.sections["general"] as { status: string }).status = "complete";
    expect(verifyDocument(body, [sealer]).failed).toContain("content_hash");

    const md = structuredClone(d);
    md.markdown += "extra";
    expect(verifyDocument(md, [sealer]).failed).toContain("markdown");

    const meta = structuredClone(d);
    meta.meta.generated_by = "someone-else";
    expect(verifyDocument(meta, [sealer]).failed).toEqual(["seal_signature"]);

    const sig = structuredClone(d);
    sig.seal.sig = "AAAA" + sig.seal.sig.slice(4);
    expect(verifyDocument(sig, [sealer]).failed).toEqual(["seal_signature"]);

    const hash = structuredClone(d);
    hash.content_hash = "0".repeat(64);
    expect(verifyDocument(hash, [sealer]).failed).toEqual(
      expect.arrayContaining(["markdown", "seal_signature"]),
    );

    expect(verifyDocument(d, [Ed25519Sealer.generate("k1")]).failed).toEqual(["seal_signature"]);
    expect(verifyDocument(d, [Ed25519Sealer.generate("other")]).failed).toEqual(["seal_key"]);
    expect(verifyDocument(d, []).failed).toEqual(["seal_key"]);
  });

  it("does not throw on malformed documents", () => {
    const d = mk();
    const bad = { ...d, body: { ...d.body, extra: undefined } } as unknown as SealedDocument;
    expect(verifyDocument(bad, [sealer]).ok).toBe(false);
    const bad2 = { ...d, meta: { ...d.meta, evil: undefined } } as unknown as SealedDocument;
    expect(verifyDocument(bad2, [sealer]).failed).toContain("seal_signature");
    const bad3 = { ...d, body: null } as unknown as SealedDocument;
    expect(verifyDocument(bad3, [sealer]).failed).toEqual(
      expect.arrayContaining(["content_hash", "markdown"]),
    );
    expect(sealPayload("h", d.meta)).toContain('"content_hash":"h"');
  });

  it("Ed25519 and HMAC sealers: key ids, public-only keys, bad signatures", () => {
    const e = Ed25519Sealer.generate();
    expect(e.keyId).toMatch(/^ed25519:[0-9a-f]{16}$/);
    const verifyOnly = Ed25519Sealer.fromPublicPem(
      (e as unknown as { pub: { export(o: object): string } }).pub.export({
        type: "spki",
        format: "pem",
      }),
    );
    expect(verifyOnly.keyId).toBe(e.keyId);
    expect(verifyOnly.verify("m", e.sign("m"))).toBe(true);
    expect(() => verifyOnly.sign("m")).toThrow(/cannot sign/);
    expect(e.verify("m", "not base64 sig")).toBe(false);
    expect(e.verify("m", 5 as unknown as string)).toBe(false);
    const pem = (e as unknown as { priv: { export(o: object): string } }).priv.export({
      type: "pkcs8",
      format: "pem",
    });
    expect(Ed25519Sealer.fromPrivatePem(pem, "x").verify("m", e.sign("m"))).toBe(true);
    expect(() => new HmacSealer(Buffer.from("short"))).toThrow();
    const h = new HmacSealer(Buffer.from("0123456789abcdef"));
    expect(h.keyId).toMatch(/^hmac:/);
    expect(h.verify("m", h.sign("m"))).toBe(true);
    expect(h.verify("m", "x")).toBe(false);
    expect(h.verify("m", undefined as unknown as string)).toBe(false);
  });
});

describe("DocumentService", () => {
  const admin = user(T1, "admin", "alice");

  it("generates, seals and stores version 1; regenerating with unchanged sources stores nothing new", async () => {
    const w = world();
    const first = await w.svc.documents.generate(admin, REF);
    expect(first.created).toBe(true);
    expect(first.document.meta.doc_version).toBe(1);
    expect(first.document.meta.document_id).toBe(documentIdOf(T1, REF, 1));
    w.clock.advance(3_600_000);
    const again = await w.svc.documents.generate(admin, REF);
    expect(again.created).toBe(false);
    expect(JSON.stringify(again.document)).toBe(JSON.stringify(first.document));
    expect((await w.svc.documents.list(admin)).length).toBe(1);
    const got = await w.svc.documents.get(admin, first.document.meta.document_id);
    expect(got.verification.ok).toBe(true);
  });

  it("a changed source gives the next version; versions are listed and filterable", async () => {
    let events = 120;
    const w = world({
      sources: {
        audit: {
          statistics: () =>
            Promise.resolve(sourced({ ...STATS, event_count: events, head_seq: events })),
        },
      },
    });
    await w.svc.documents.generate(admin, REF);
    events = 130;
    const second = await w.svc.documents.generate(admin, REF);
    expect(second.created).toBe(true);
    expect(second.document.meta.doc_version).toBe(2);
    const list = await w.svc.documents.list(admin, {
      blueprint_name: "claims-triage",
      blueprint_version: "2.3.1",
    });
    expect(list.map((x) => x.doc_version)).toEqual([1, 2]);
    expect(list[0]?.seal.alg).toBe("ed25519");
    expect(await w.svc.documents.list(admin, { blueprint_name: "other" })).toEqual([]);
    await expect(w.svc.documents.list(admin, { blueprint_version: "1.0.0" })).rejects.toMatchObject(
      { code: "invalid" },
    );
  });

  it("a source that fails or throws becomes a gap; an unknown blueprint gets a gap-only document", async () => {
    const w = world({
      sources: {
        evals: { evidence: () => Promise.reject(new Error("secret connection string")) },
        policies: { activePacks: () => Promise.resolve(missing("")) },
      },
    });
    const r = await w.svc.documents.generate(admin, REF);
    const text = JSON.stringify(r.document);
    expect(text).not.toContain("secret connection string");
    expect(r.document.body.gaps.some((g) => g.reason === "evals source failed")).toBe(true);
    expect(r.document.body.gaps.some((g) => g.reason === "policies source unavailable")).toBe(true);
    const none = await w.svc.documents.generate(admin, { name: "nope", version: "1.0.0" });
    expect(none.document.body.sections["general"]?.status).toBe("gap");
    expect(none.document.body.gaps.some((g) => /evals not read/.test(g.reason))).toBe(true);
  });

  it("reads every source for the caller's tenant only", async () => {
    const w = world();
    await w.svc.documents.generate(user(T2, "builder", "bob"), REF);
    expect(w.calls.length).toBeGreaterThan(0);
    expect(w.calls.every((c) => c.endsWith(`:${T2}`))).toBe(true);
  });

  it("is tenant-isolated: another tenant cannot read, list or verify a document", async () => {
    const w = world();
    const r = await w.svc.documents.generate(admin, REF);
    const other = user(T2, "admin", "mallory");
    await expect(w.svc.documents.get(other, r.document.meta.document_id)).rejects.toMatchObject({
      code: "not_found",
    });
    expect(await w.svc.documents.list(other)).toEqual([]);
    // the same blueprint in the other tenant is a separate document line
    const mine = await w.svc.documents.generate(other, REF);
    expect(mine.document.meta.document_id).not.toBe(r.document.meta.document_id);
    expect(mine.document.meta.tenant_id).toBe(T2);
  });

  it("enforces roles and validates the request", async () => {
    const w = world();
    await expect(w.svc.documents.generate(user(T1, "viewer"), REF)).rejects.toMatchObject({
      code: "forbidden",
    });
    await expect(w.svc.documents.generate(user(T1, "auditor"), REF)).rejects.toMatchObject({
      code: "forbidden",
    });
    await expect(w.svc.documents.get(user(T1, "billing"), "x")).rejects.toMatchObject({
      code: "forbidden",
    });
    await expect(
      w.svc.documents.generate(admin, { name: "Bad Name", version: "x" }),
    ).rejects.toMatchObject({
      code: "invalid",
      checks: ["/name", "/version"],
    });
    await expect(w.svc.documents.generate(admin, undefined as never)).rejects.toMatchObject({
      code: "invalid",
    });
    expect((await w.svc.documents.list(user(T1, "viewer"))).length).toBe(0);
  });

  it("audits generation (allowed, done) and denial; a failed audit append means nothing is generated", async () => {
    const w = world();
    await w.svc.documents.generate(admin, REF);
    await w.svc.documents.generate(user(T1, "viewer"), REF).catch(() => undefined);
    const events = await w.log.read(T1, {});
    expect(events.map((e) => `${e.action}:${e.decision}`)).toEqual([
      "compliance.document.generate:ALLOW",
      "compliance.document.generate.done:ALLOW",
      "compliance.document.generate:DENY",
    ]);
    const broken = world();
    (broken.log as unknown as { append: () => Promise<never> }).append = () =>
      Promise.reject(new Error("down"));
    await expect(broken.svc.documents.generate(admin, REF)).rejects.toMatchObject({
      code: "unavailable",
    });
    expect(await broken.svc.documents.list(admin)).toEqual([]);
  });

  it("a verification failure is visible on read (stored bytes changed behind the service's back)", async () => {
    const w = world();
    const r = await w.svc.documents.generate(admin, REF);
    const id = r.document.meta.document_id;
    const row = await w.docs.get(T1, "documents", id);
    const bad = structuredClone(row!.data) as { document: SealedDocument };
    (bad.document.body.sections["general"] as { status: string }).status = "complete";
    // The memory store hands out clones; mutate through the private map for this tamper test.
    const rows = (w.docs as unknown as { rows: Map<string, { data: unknown }> }).rows;
    for (const v of rows.values())
      if ((v.data as { document_id?: string }).document_id === id) v.data = bad;
    const got = await w.svc.documents.get(admin, id);
    expect(got.verification.ok).toBe(false);
    expect(got.verification.failed).toContain("content_hash");
  });

  it("trusts retired keys for old documents", async () => {
    const old = Ed25519Sealer.generate("old");
    const w = world({ sealer: old });
    const r = await w.svc.documents.generate(admin, REF);
    // a service with a new key that still trusts the old one
    const { createCompliance, ComplianceAudit } = await import("../src/index.js");
    const svc2 = createCompliance({
      docs: w.docs,
      audit: new ComplianceAudit(w.log),
      sources: fakeSources(),
      sealer: Ed25519Sealer.generate("new"),
      trustedSealers: [old],
    });
    expect((await svc2.documents.get(admin, r.document.meta.document_id)).verification.ok).toBe(
      true,
    );
  });
});

describe("NeedsLimitations", () => {
  const text = [
    "| # | Title | Detail | Evidence |",
    "| --- | --- | --- | --- |",
    "| 1 | Single instance | in-memory ledger | services/x |",
    "| 2 | Fixed | RESOLVED: done | a |",
    "| 3 | Long | " + "y".repeat(300) + " |  |",
    "| x | not a number | z | w |",
    "| 4 | no evidence col | d |",
    "not a table",
  ].join("\n");
  it("parses numbered rows, skips resolved ones, truncates detail", () => {
    const items = parseNeeds(text);
    expect(items.map((i) => i.id)).toEqual(["NEEDS-1", "NEEDS-3", "NEEDS-4"]);
    expect(items[1]?.detail?.length).toBe(240);
    expect(items[1]?.evidence).toBeNull();
    expect(items[2]?.evidence).toBeNull();
    expect(items[0]).toMatchObject({ title: "Single instance", evidence: "services/x" });
  });
  it("is a gap when the file is missing, unreadable or empty", async () => {
    const run = (f: () => string | undefined) => new NeedsLimitations(f).list(user(T1), REF);
    expect(await run(() => text)).toMatchObject({ ok: true });
    expect(await run(() => undefined)).toMatchObject({ ok: false });
    expect(
      await run(() => {
        throw new Error("x");
      }),
    ).toMatchObject({ ok: false });
    expect(await run(() => "nothing")).toMatchObject({
      ok: false,
      reason: expect.stringContaining("no limitations"),
    });
  });
});

describe("types", () => {
  it("DocBody is JSON-serialisable without loss", () => {
    const body: DocBody = assemble(full());
    expect(JSON.parse(JSON.stringify(body))).toEqual(body);
    expect(fakeSources()).toBeTruthy();
  });
});

describe("assemble with a minimal blueprint (every optional field absent)", () => {
  const minimal = () =>
    ablDoc((d) => {
      d.metadata = { name: "minimal-agent", version: "1.0.0" };
      d.spec = {
        riskClassification: { level: "minimal", rationale: "internal helper" },
        model: { primary: { provider: "anthropic", model: "m" } },
        instructions: { system: "Help." },
      };
    });
  const run = (over: Partial<AssembleInput> = {}) =>
    assemble({
      ref: { name: "minimal-agent", version: "1.0.0" },
      blueprint: sourced(
        snapshot({ abl: minimal(), registry: null, origin: "tenant", versions: [] }),
      ),
      evals: sourced({ runs: [], attestations: [], gate: [], online: [] }),
      policies: sourced([]),
      audit: sourced(STATS),
      limitations: sourced([]),
      ...over,
    });

  it("applies the compiler's defaults and states the absent facts as gaps, not as invented values", () => {
    const body = run();
    const g = body.sections["general"]?.data as Record<string, unknown>;
    expect(g).toMatchObject({
      description: null,
      owner: null,
      intended_purpose: null,
      channels: [],
      transparency_notice: null,
    });
    const dev = body.sections["development"]?.data as Record<string, unknown>;
    expect(dev["tools"]).toEqual([]);
    expect(dev["routing_stages"]).toEqual(["llm"]);
    expect(dev["memory"]).toEqual({
      run: true,
      session: false,
      long_term: false,
      knowledge_bases: [],
    });
    expect(dev["registry"]).toBeNull();
    expect(dev["budgets"]).toBeNull();
    expect(dev["process"]).toBeNull();
    const o = body.sections["oversight"]?.data as Record<string, unknown>;
    expect(o).toMatchObject({ human_oversight_required: false, approver_roles: [] });
    const dg = body.sections["data_governance"]?.data as Record<string, unknown>;
    expect(dg).toMatchObject({ phi: false, residency: null });
    expect(body.sections["lifecycle"]?.data).toMatchObject({ versions: [] });
    expect(body.gaps.some((x) => x.item === "online_sampling")).toBe(true);
    expect(body.gaps.some((x) => x.item === "registry_provenance")).toBe(true);
    expect(body.sections["performance"]?.status).toBe("complete");
  });

  it("describes models with fallbacks and custom endpoints without leaking the endpoint", () => {
    const abl = ablDoc((d) => {
      d.spec.model.fallbacks = [
        {
          provider: "azure-openai",
          model: "x",
          endpoint: "https://secret.example/v1",
          params: { temperature: 0.2 },
        },
      ];
    });
    const body = run({ blueprint: sourced(snapshot({ abl })) });
    const models = (body.sections["general"]?.data as { models: Record<string, unknown>[] }).models;
    expect(models.map((m) => m["role"])).toEqual(["primary", "fallback"]);
    expect(models[1]).toMatchObject({ custom_endpoint: true, params: { temperature: 0.2 } });
    expect(JSON.stringify(body)).not.toContain("secret.example");
  });

  it("a schema-invalid blueprint is a gap in the manifest and keeps the rest of the document", () => {
    const abl = ablDoc((d) => {
      (d.spec as unknown as Record<string, unknown>)["unknownField"] = 1;
    });
    const body = run({ blueprint: sourced(snapshot({ abl })) });
    expect(body.gaps.find((x) => x.item === "compiled_manifest")?.reason).toMatch(/schema issue/);
    expect(
      (body.sections["development"]?.data as Record<string, unknown>)["compiled_manifest_sha256"],
    ).toBeNull();
  });

  it("high risk without evals on the eval side: declared suites with no runs are listed", () => {
    const body = assemble({
      ref: REF,
      blueprint: sourced(snapshot()),
      evals: sourced({ runs: [], attestations: [], gate: [], online: [] }),
      policies: sourced([]),
      audit: sourced(STATS),
      limitations: sourced([]),
    });
    expect(body.gaps.filter((g) => g.item.startsWith("suite:")).length).toBe(1);
    expect(body.annex_iv_coverage.find((c) => c.point === "2(g)")?.status).toBe("partial");
  });
});

describe("canonical JSON", () => {
  it("does not depend on key order, and refuses what it cannot represent", () => {
    expect(canonicalJson({ b: 1, a: { d: [3, { y: 1, x: 2 }], c: null } })).toBe(
      canonicalJson({ a: { c: null, d: [3, { x: 2, y: 1 }] }, b: 1 }),
    );
    expect(canonicalJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(() => canonicalJson({ a: undefined })).toThrow(TypeError);
    expect(() => canonicalJson({ a: Number.NaN })).toThrow(TypeError);
    expect(() => canonicalJson({ a: () => 1 })).toThrow(TypeError);
    expect(canonicalJson([true, false, "x\n"])).toBe('[true,false,"x\\n"]');
  });
});
