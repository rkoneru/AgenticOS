import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { json } from "../../../packages/sdk-ts/test/mock-server.js";
import { axis } from "./harness.js";

const sys = (over: Record<string, unknown> = {}) => ({
  system_id: "claims-triage",
  version: 1,
  name: "Claims triage",
  purpose: "Routes claims",
  owner: "owner@example.test",
  risk_level: "high",
  lifecycle_stage: "design",
  blueprints: [{ name: "claims", version: "1.0.0" }],
  data_categories: ["claims"],
  stakeholders: [],
  created_at: "2026-01-01T00:00:00.000Z",
  created_by: "m1",
  updated_at: "2026-01-01T00:00:00.000Z",
  updated_by: "m1",
  ...over,
});
const asm = (over: Record<string, unknown> = {}) => ({
  assessment_id: "assessment-1",
  version: 1,
  system_id: "claims-triage",
  title: "Impact",
  state: "draft",
  risk_rating: "high",
  intended_use: "Routing",
  blueprints: [],
  affected_groups: [],
  risks: [],
  stakeholders: [],
  review_due: "2027-01-01",
  author: "m1",
  contributors: ["m1"],
  created_at: "2026-01-01T00:00:00.000Z",
  updated_at: "2026-01-01T00:00:00.000Z",
  submitted_by: null,
  submitted_at: null,
  reviewed_by: null,
  reviewed_at: null,
  review_comment: null,
  supersedes: null,
  overdue: false,
  overdue_reason: null,
  superseded: false,
  ...over,
});
const doc = (over: Record<string, unknown> = {}) => ({
  body: { gaps: [{ section: "general", item: "x", reason: "y" }] },
  content_hash: "a".repeat(64),
  meta: { document_id: "cdoc-1", doc_version: 2, blueprint: { name: "claims", version: "1.0.0" } },
  markdown: "# Technical documentation\n\u001b[2Jhidden",
  seal: { alg: "hmac-sha256", key_id: "k1", sig: "s" },
  ...over,
});
const file = (content: string): string => {
  const d = mkdtempSync(join(tmpdir(), "axis-compliance-"));
  const f = join(d, "in.yaml");
  writeFileSync(f, content);
  return f;
};

describe("axis compliance systems", () => {
  it("lists, gets and prints server text inert", async () => {
    const l = await axis(
      ["compliance", "systems", "list", "--risk-level", "high", "--stage", "design"],
      {
        mock: {
          overrides: {
            listComplianceSystems: () => json({ items: [sys({ name: "Bad\u001b[2Jname" })] }),
          },
        },
      },
    );
    expect(l.code).toBe(0);
    expect(l.out).toContain("claims-triage");
    expect(l.out).not.toContain("\u001b");
    expect(l.server.calls[0]?.url.search).toContain("risk_level=high");
    const g = await axis(["compliance", "systems", "get", "claims-triage", "--revision", "1"], {
      mock: { overrides: { getComplianceSystem: () => json(sys()) } },
    });
    expect(g.out).toContain("claims-triage v1");
    expect(g.server.calls[0]?.url.search).toContain("version=1");
    const j = await axis(["compliance", "systems", "get", "claims-triage", "--json"], {
      mock: { overrides: { getComplianceSystem: () => json(sys()) } },
    });
    expect(JSON.parse(j.out).system_id).toBe("claims-triage");
    expect(
      (await axis(["compliance", "systems", "get", "claims-triage", "--revision", "0"])).code,
    ).toBe(2);
  });

  it("create and update read a file; update needs the version you read", async () => {
    const f = file("name: Claims triage\npurpose: Routes\nowner: o\nrisk_level: high\n");
    const c = await axis(["compliance", "systems", "create", "--file", f], {
      mock: { overrides: { createComplianceSystem: () => json(sys(), 201) } },
    });
    expect(c.code).toBe(0);
    expect(c.server.calls[0]?.body).toMatchObject({ name: "Claims triage", risk_level: "high" });
    expect(c.server.calls[0]?.headers.get("idempotency-key")).toBeTruthy();
    const patch = file("lifecycle_stage: deployed\n");
    const u = await axis(
      [
        "compliance",
        "systems",
        "update",
        "claims-triage",
        "--file",
        patch,
        "--expected-version",
        "1",
      ],
      {
        mock: { overrides: { updateComplianceSystem: () => json(sys({ version: 2 })) } },
      },
    );
    expect(u.out).toContain("version 2");
    expect(u.server.calls[0]?.body).toEqual({ lifecycle_stage: "deployed", expected_version: 1 });
    const no = await axis(["compliance", "systems", "update", "claims-triage", "--file", patch]);
    expect(no.code).toBe(2);
    expect(no.err).toContain("--expected-version");
    expect((await axis(["compliance", "systems", "create"])).code).toBe(2);
    expect(
      (await axis(["compliance", "systems", "create", "--file", "/nonexistent/x.yaml"])).code,
    ).toBe(1);
    expect(
      (await axis(["compliance", "systems", "create", "--file", file("- a\n- b\n")])).code,
    ).toBe(1);
    expect((await axis(["compliance", "systems", "create", "--file", file("a: [")])).code).toBe(1);
    const stdin = await axis(["compliance", "systems", "create", "--file", "-"], {
      stdin: "name: x\n",
      mock: { overrides: { createComplianceSystem: () => json(sys(), 201) } },
    });
    expect(stdin.code).toBe(0);
  });
});

describe("axis compliance assessments", () => {
  it("list shows overdue reasons; get shows the review trail", async () => {
    const l = await axis(
      [
        "compliance",
        "assessments",
        "list",
        "--system",
        "claims-triage",
        "--state",
        "approved",
        "--overdue",
      ],
      {
        mock: {
          overrides: {
            listComplianceImpactAssessments: () =>
              json({
                items: [
                  asm({ state: "approved", overdue: true, overdue_reason: "review_due_passed" }),
                ],
              }),
          },
        },
      },
    );
    expect(l.out).toContain("review_due_passed");
    expect(l.server.calls[0]?.url.search).toMatch(/overdue=true/);
    const g = await axis(["compliance", "assessments", "get", "assessment-1"], {
      mock: {
        overrides: {
          getComplianceImpactAssessment: () =>
            json(
              asm({
                state: "approved",
                reviewed_by: "m2",
                reviewed_at: "2026-02-01T00:00:00.000Z",
                review_comment: "ok",
                superseded: true,
                submitted_by: "m1",
                submitted_at: "2026-01-02T00:00:00.000Z",
              }),
            ),
        },
      },
    });
    expect(g.out).toContain("reviewed:  m2");
    expect(g.out).toContain("a later version exists");
  });

  it("walks the workflow commands and sends the version it read", async () => {
    const f = file(
      "system_id: claims-triage\ntitle: T\nrisk_rating: high\nintended_use: u\nreview_due: 2027-01-01\n",
    );
    const mock = {
      overrides: {
        createComplianceImpactAssessment: () => json(asm(), 201),
        reviseComplianceImpactAssessment: () => json(asm({ version: 2 })),
        submitComplianceImpactAssessment: () => json(asm({ state: "in_review" })),
        withdrawComplianceImpactAssessment: () => json(asm()),
        reviewComplianceImpactAssessment: () => json(asm({ state: "approved" })),
      },
    };
    expect((await axis(["compliance", "assessments", "create", "-f", f], { mock })).out).toContain(
      "draft",
    );
    const rev = await axis(
      [
        "compliance",
        "assessments",
        "revise",
        "assessment-1",
        "--file",
        f,
        "--expected-version",
        "1",
      ],
      { mock },
    );
    expect(rev.out).toContain("version 2");
    expect(
      (
        await axis(
          ["compliance", "assessments", "submit", "assessment-1", "--expected-version", "1"],
          { mock },
        )
      ).out,
    ).toContain("waiting for review");
    expect(
      (
        await axis(
          ["compliance", "assessments", "withdraw", "assessment-1", "--expected-version", "1"],
          { mock },
        )
      ).out,
    ).toContain("draft again");
    const ok = await axis(
      [
        "compliance",
        "assessments",
        "review",
        "assessment-1",
        "--expected-version",
        "1",
        "--decision",
        "approve",
        "--comment",
        "fine",
      ],
      { mock },
    );
    expect(ok.out).toContain("approved");
    expect(ok.server.calls[0]?.body).toEqual({
      expected_version: 1,
      decision: "approve",
      comment: "fine",
    });
    expect(
      (
        await axis([
          "compliance",
          "assessments",
          "review",
          "assessment-1",
          "--expected-version",
          "1",
        ])
      ).code,
    ).toBe(2);
    expect((await axis(["compliance", "assessments", "submit", "assessment-1"])).code).toBe(2);
    expect(
      (
        await axis([
          "compliance",
          "assessments",
          "submit",
          "assessment-1",
          "--expected-version",
          "1.5",
        ])
      ).code,
    ).toBe(2);
    expect((await axis(["compliance", "assessments", "get"])).code).toBe(2);
    expect((await axis(["compliance", "assessments", "get", "a", "b"])).code).toBe(2);
  });

  it("a refused review is exit 3 with the server's reason, and nothing else changes", async () => {
    const r = await axis(
      [
        "compliance",
        "assessments",
        "review",
        "assessment-1",
        "--expected-version",
        "1",
        "--decision",
        "approve",
      ],
      {
        mock: {
          overrides: {
            reviewComplianceImpactAssessment: () =>
              new Response(
                JSON.stringify({
                  type: "https://axis.example/problems/forbidden",
                  title: "Forbidden",
                  status: 403,
                  code: "forbidden",
                  detail: "review refused: reviewer is the author",
                }),
                {
                  status: 403,
                  headers: { "content-type": "application/problem+json" },
                },
              ),
          },
        },
      },
    );
    expect(r.code).toBe(3);
  });
});

describe("axis compliance documents", () => {
  it("generate reports whether a new version was stored and how many gaps it lists", async () => {
    const g = await axis(["compliance", "documents", "generate", "claims@1.0.0"], {
      mock: {
        overrides: {
          generateComplianceDocument: () => json({ document: doc(), created: true }, 201),
        },
      },
    });
    expect(g.out).toContain("generated: cdoc-1 (version 2, 1 gap");
    expect(g.server.calls[0]?.body).toEqual({ blueprint: { name: "claims", version: "1.0.0" } });
    const same = await axis(["compliance", "documents", "generate", "claims@1.0.0"], {
      mock: {
        overrides: {
          generateComplianceDocument: () =>
            json({ document: doc({ body: { gaps: [] } }), created: false }),
        },
      },
    });
    expect(same.out).toContain("unchanged");
    expect(same.out).toContain("0 gaps");
    expect((await axis(["compliance", "documents", "generate", "claims"])).code).toBe(2);
  });

  it("list filters by blueprint; get verifies and exits 1 when the document does not verify", async () => {
    const l = await axis(["compliance", "documents", "list", "--blueprint", "claims@1.0.0"], {
      mock: {
        overrides: {
          listComplianceDocuments: () =>
            json({
              items: [
                {
                  document_id: "cdoc-1",
                  blueprint: { name: "claims", version: "1.0.0" },
                  doc_version: 1,
                  content_hash: "a".repeat(64),
                  generated_at: "2026-01-01T00:00:00.000Z",
                  generated_by: "m1",
                  gap_count: 3,
                  seal: { alg: "hmac-sha256", key_id: "k1" },
                },
              ],
            }),
        },
      },
    });
    expect(l.out).toContain("cdoc-1");
    expect(l.server.calls[0]?.url.search).toContain("blueprint_name=claims");
    expect(l.server.calls[0]?.url.search).toContain("blueprint_version=1.0.0");
    const name = await axis(["compliance", "documents", "list", "--blueprint", "claims"], {
      mock: { overrides: { listComplianceDocuments: () => json({ items: [] }) } },
    });
    expect(name.server.calls[0]?.url.search).not.toContain("blueprint_version");
    const good = await axis(["compliance", "documents", "get", "cdoc-1"], {
      mock: {
        overrides: {
          getComplianceDocument: () =>
            json({ document: doc(), verification: { ok: true, failed: [] } }),
        },
      },
    });
    expect(good.code).toBe(0);
    expect(good.out).toContain("verification: OK");
    const bad = await axis(["compliance", "documents", "get", "cdoc-1"], {
      mock: {
        overrides: {
          getComplianceDocument: () =>
            json({ document: doc(), verification: { ok: false, failed: ["seal_signature"] } }),
        },
      },
    });
    expect(bad.code).toBe(1);
    expect(bad.out).toContain("FAILED (seal_signature)");
    expect(bad.err).toContain("does not verify");
  });

  it("--markdown prints inert text; --out writes the file", async () => {
    const mock = {
      overrides: {
        getComplianceDocument: () =>
          json({ document: doc(), verification: { ok: true, failed: [] } }),
      },
    };
    const md = await axis(["compliance", "documents", "get", "cdoc-1", "--markdown"], { mock });
    expect(md.out).toContain("# Technical documentation");
    expect(md.out).not.toContain("\u001b");
    const dir = mkdtempSync(join(tmpdir(), "axis-compliance-"));
    const out = join(dir, "doc.md");
    expect(
      (
        await axis(["compliance", "documents", "get", "cdoc-1", "--markdown", "--out", out], {
          mock,
        })
      ).code,
    ).toBe(0);
    expect(readFileSync(out, "utf8")).toContain("# Technical documentation");
    const outJson = join(dir, "doc.json");
    await axis(["compliance", "documents", "get", "cdoc-1", "--out", outJson], { mock });
    expect(JSON.parse(readFileSync(outJson, "utf8")).content_hash).toBe("a".repeat(64));
    const unwritable = await axis(
      ["compliance", "documents", "get", "cdoc-1", "--out", join(dir, "no", "such", "dir", "x")],
      { mock },
    );
    expect(unwritable.code).toBe(1);
    expect((await axis(["compliance", "documents", "get"])).code).toBe(2);
  });
});
