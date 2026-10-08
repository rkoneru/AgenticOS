/* eslint-disable @typescript-eslint/no-explicit-any */
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  Ed25519Sealer,
  assemble,
  canonicalJson,
  hashOf,
  missing,
  sealDocument,
  sourced,
  verifyDocument,
  type AssembleInput,
  type SealedDocument,
} from "../src/index.js";
import { EVIDENCE, STATS, T1, T2, input, snapshot, user, world } from "./helpers.js";

const REF = { name: "claims-triage", version: "2.3.1" };

const arbEvidence = fc.record({
  runs: fc.array(
    fc.record({
      run_id: fc.string({ minLength: 1, maxLength: 8 }),
      suite_ref: fc.constantFrom("s@1", "t@2"),
      declared_ref: fc.constantFrom("claims-regression@^1.0.0", "other@^1"),
      status: fc.constantFrom("passed", "failed", "errored"),
      overall: fc.option(fc.double({ min: 0, max: 1, noNaN: true }), { nil: null }),
      threshold: fc.double({ min: 0, max: 1, noNaN: true }),
      mode: fc.constantFrom("offline", "online"),
      content_hash: fc.constant("a".repeat(64)),
      finished_at: fc.option(fc.constant("2026-01-01T00:00:00.000Z"), { nil: null }),
    }),
    { maxLength: 6 },
  ),
  attestations: fc.array(
    fc.record({
      run_id: fc.string({ minLength: 1, maxLength: 8 }),
      suite_ref: fc.constantFrom("s@1", "t@2"),
      overall: fc.double({ min: 0, max: 1, noNaN: true }),
      verified: fc.boolean(),
    }),
    { maxLength: 4 },
  ),
  gate: fc.array(
    fc.record({
      suite_ref: fc.constantFrom("s@1", "t@2"),
      threshold: fc.double({ min: 0, max: 1, noNaN: true }),
      pass: fc.boolean(),
      reasons: fc.array(fc.constantFrom("a", "b", "c"), { maxLength: 3 }),
    }),
    { maxLength: 3 },
  ),
  online: fc.option(
    fc.array(
      fc.record({
        id: fc.string({ minLength: 1, maxLength: 6 }),
        suite_ref: fc.constant("s@1"),
        rate: fc.double({ min: 0, max: 1, noNaN: true }),
        enabled: fc.boolean(),
      }),
      { maxLength: 3 },
    ),
    { nil: null },
  ),
});

const sourcedOf = <T>(arb: fc.Arbitrary<T>) =>
  fc.oneof(
    arb.map((v) => sourced(v)),
    fc.string({ maxLength: 20 }).map((r) => missing<T>(r)),
  );

const arbInput: fc.Arbitrary<AssembleInput> = fc.record({
  ref: fc.constant(REF),
  blueprint: sourcedOf(fc.constant(snapshot())),
  evals: sourcedOf(arbEvidence),
  policies: sourcedOf(
    fc.array(
      fc.record({
        id: fc.string({ minLength: 1, maxLength: 6 }),
        version: fc.constantFrom("1", "2"),
        hash: fc.constant(null),
        active_since: fc.constant(null),
      }),
      { maxLength: 3 },
    ),
  ),
  audit: sourcedOf(fc.constant(STATS)),
  limitations: sourcedOf(
    fc.array(
      fc.record({
        id: fc.string({ minLength: 1, maxLength: 5 }),
        title: fc.string(),
        detail: fc.constant(null),
        evidence: fc.constant(null),
      }),
      { maxLength: 3 },
    ),
  ),
});

const shuffleEvidence = (i: AssembleInput): AssembleInput => ({
  ...i,
  evals: i.evals.ok
    ? sourced({
        ...i.evals.value,
        runs: [...i.evals.value.runs].reverse(),
        gate: [...i.evals.value.gate].reverse(),
      })
    : i.evals,
});

describe("properties: determinism", () => {
  it("assemble is a function of its inputs (twice = same bytes) and ignores input array order", () => {
    fc.assert(
      fc.property(arbInput, (i) => {
        expect(canonicalJson(assemble(i))).toBe(canonicalJson(assemble(structuredClone(i))));
        expect(hashOf(assemble(i))).toBe(hashOf(assemble(shuffleEvidence(i))));
      }),
      { numRuns: 60 },
    );
  });

  it("sealing is deterministic: same inputs, same bytes", () => {
    const sealer = Ed25519Sealer.generate("p1");
    fc.assert(
      fc.property(arbInput, (i) => {
        const mk = () =>
          sealDocument(
            {
              body: assemble(i),
              meta: {
                document_id: "cdoc-p",
                tenant_id: T1,
                doc_version: 1,
                generated_at: "2026-01-01T00:00:00.000Z",
                generated_by: "u",
              },
            },
            sealer,
          );
        expect(JSON.stringify(mk())).toBe(JSON.stringify(mk()));
      }),
      { numRuns: 40 },
    );
  });

  it("every unavailable source appears as a gap and is never silently omitted", () => {
    fc.assert(
      fc.property(arbInput, (i) => {
        const body = assemble(i);
        const down = (["blueprint", "evals", "policies", "audit", "limitations"] as const).filter(
          (k) => !i[k].ok,
        );
        for (const k of down) {
          expect(body.sources.find((s) => s.name === k)?.status).toBe("gap");
          expect(body.gaps.some((g) => g.section === "sources" && g.item === k)).toBe(true);
        }
        expect(body.sources.filter((s) => s.status === "gap").length).toBe(down.length);
        // a section whose own source is down never carries data
        if (!i.blueprint.ok) expect(body.sections["general"]?.data).toBeNull();
        if (!i.audit.ok) expect(body.sections["record_keeping"]?.data).toBeNull();
        if (!i.limitations.ok) expect(body.sections["limitations"]?.data).toBeNull();
        // coverage is derived: a gap section is never reported as evidenced
        for (const c of body.annex_iv_coverage)
          if (c.section && body.sections[c.section]?.status === "gap") expect(c.status).toBe("gap");
      }),
      { numRuns: 80 },
    );
  });
});

describe("properties: seal tamper detection", () => {
  const sealer = Ed25519Sealer.generate("p2");
  const doc = (): SealedDocument =>
    sealDocument(
      {
        body: assemble({
          ref: REF,
          blueprint: sourced(snapshot()),
          evals: sourced(EVIDENCE),
          policies: sourced([]),
          audit: sourced(STATS),
          limitations: sourced([]),
        }),
        meta: {
          document_id: "cdoc-t",
          tenant_id: T1,
          doc_version: 1,
          generated_at: "2026-01-01T00:00:00.000Z",
          generated_by: "u",
        },
      },
      sealer,
    );

  /** Every leaf of the document, as a path. */
  function leaves(v: unknown, path: (string | number)[] = []): (string | number)[][] {
    if (v === null || typeof v !== "object") return [path];
    return Object.entries(v as object).flatMap(([k, x]) =>
      leaves(x, [...path, Array.isArray(v) ? Number(k) : k]),
    );
  }
  const base = doc();
  const all = leaves(base);

  it("changing ANY single value of the document is detected", () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: all.length - 1 }), (i) => {
        const d = structuredClone(base);
        const path = all[i] as (string | number)[];
        let o: any = d;
        for (const k of path.slice(0, -1)) o = o[k];
        const last = path[path.length - 1] as string | number;
        const cur = o[last];
        o[last] =
          typeof cur === "string"
            ? `${cur}x`
            : typeof cur === "number"
              ? cur + 1
              : typeof cur === "boolean"
                ? !cur
                : "changed";
        expect(verifyDocument(d, [sealer]).ok, path.join("/")).toBe(false);
      }),
      { numRuns: Math.min(all.length, 400) },
    );
  });

  it("a signature from another key never verifies", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 40 }), (garbage) => {
        const d = structuredClone(base);
        d.seal.sig = Buffer.from(garbage).toString("base64url");
        expect(verifyDocument(d, [sealer]).ok).toBe(false);
      }),
      { numRuns: 50 },
    );
  });
});

describe("properties: tenant isolation", () => {
  it("whatever tenant A does, tenant B sees nothing of it", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.constantFrom("system", "assessment", "document"), {
          minLength: 1,
          maxLength: 5,
        }),
        async (ops) => {
          const w = world();
          const a = user(T1, "owner", "olivia");
          const b = user(T2, "owner", "mallory");
          const sys = await w.svc.systems.create(a, input.system({ system_id: "claims-triage" }));
          const ids: string[] = [];
          for (const op of ops) {
            if (op === "system") await w.svc.systems.create(a, input.system());
            if (op === "assessment")
              ids.push(
                (await w.svc.assessments.create(a, input.assessment(sys.system_id))).assessment_id,
              );
            if (op === "document")
              ids.push((await w.svc.documents.generate(a, REF)).document.meta.document_id);
          }
          expect(await w.svc.systems.list(b)).toEqual([]);
          expect(await w.svc.assessments.list(b)).toEqual([]);
          expect(await w.svc.documents.list(b)).toEqual([]);
          for (const id of ids) {
            await expect(w.svc.assessments.get(b, id)).rejects.toMatchObject({ code: "not_found" });
            await expect(w.svc.documents.get(b, id)).rejects.toMatchObject({ code: "not_found" });
          }
          await expect(w.svc.systems.get(b, sys.system_id)).rejects.toMatchObject({
            code: "not_found",
          });
          expect(await w.log.read(T2, {})).toEqual([]);
        },
      ),
      { numRuns: 15 },
    );
  });
});

describe("properties: reviewer is never the author", () => {
  it("for any set of people who worked on a version, none of them can approve or reject it", async () => {
    const people = ["p1", "p2", "p3", "p4"];
    await fc.assert(
      fc.asyncProperty(
        fc.uniqueArray(fc.constantFrom(...people), { minLength: 1, maxLength: 4 }),
        fc.constantFrom(...people),
        fc.constantFrom("approve", "reject"),
        async (editors, submitter, decision) => {
          const w = world();
          const [first, ...rest] = editors as [string, ...string[]];
          const sys = await w.svc.systems.create(
            user(T1, "owner", "olivia"),
            input.system({ system_id: "claims-triage" }),
          );
          const a = await w.svc.assessments.create(
            user(T1, "admin", first),
            input.assessment(sys.system_id),
          );
          for (const e of rest)
            await w.svc.assessments.revise(user(T1, "admin", e), a.assessment_id, 1, {
              title: `by ${e}`,
            });
          await w.svc.assessments.submit(user(T1, "admin", submitter), a.assessment_id, 1);
          for (const who of people) {
            const involved = editors.includes(who) || who === submitter;
            const attempt = w.svc.assessments.review(
              user(T1, "auditor", who),
              a.assessment_id,
              1,
              decision as "approve",
              "because",
            );
            if (involved) await expect(attempt).rejects.toMatchObject({ code: "forbidden" });
            else {
              const r = await attempt;
              expect(r.reviewed_by).toBe(who);
              expect([first, ...rest, submitter]).not.toContain(r.reviewed_by);
              break;
            }
          }
          const final = await w.svc.assessments.get(user(T1, "owner", "olivia"), a.assessment_id);
          if (final.reviewed_by !== null) {
            expect(final.reviewed_by).not.toBe(final.author);
            expect(final.contributors).not.toContain(final.reviewed_by);
          }
        },
      ),
      { numRuns: 30 },
    );
  });
});
