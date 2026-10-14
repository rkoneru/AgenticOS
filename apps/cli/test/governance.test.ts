import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { json } from "../../../packages/sdk-ts/test/mock-server.js";
import { axis } from "./harness.js";

const req = (over: Record<string, unknown> = {}) => ({
  id: "00000000-0000-4000-8000-000000000001",
  kind: "erase",
  subject_ref: "sub_abc",
  status: "received",
  received_at: "2026-03-01T00:00:00.000Z",
  due_at: "2026-03-31T00:00:00.000Z",
  extended: false,
  verified_at: null,
  verified_method: null,
  destination_region: null,
  result: {},
  ...over,
});
const hold = (over: Record<string, unknown> = {}) => ({
  id: "00000000-0000-4000-8000-0000000000h1",
  kind: "legal_hold",
  scope: "tenant",
  case_ref: null,
  classes: null,
  reason: "Bad\u001b[2Jreason",
  placed_by: "m1",
  placed_at: "2026-03-01T00:00:00.000Z",
  released_at: null,
  ...over,
});
const report = (over: Record<string, unknown> = {}) => ({
  run_id: "run-1",
  dry_run: true,
  started_at: "2026-03-01T00:00:00.000Z",
  finished_at: null,
  classes: [
    {
      data_class: "memory",
      status: "dry_run",
      requested_days: 30,
      effective_days: 30,
      matched: 4,
      purged: 0,
      protected_by_hold: 1,
    },
  ],
  ...over,
});
const file = (text: string): string => {
  const d = mkdtempSync(join(tmpdir(), "axis-gov-"));
  const f = join(d, "doc.yaml");
  writeFileSync(f, text);
  return f;
};

describe("axis governance requests", () => {
  it("lists, shows and never echoes identifiers", async () => {
    const l = await axis(["governance", "requests", "list", "--status", "received"], {
      mock: { overrides: { listGovernanceDsarRequests: () => json({ items: [req()] }) } },
    });
    expect(l.code).toBe(0);
    expect(l.out).toContain("sub_abc");
    const g = await axis(["governance", "requests", "get", "r1"], {
      mock: { overrides: { getGovernanceDsarRequest: () => json(req({ extended: true })) } },
    });
    expect(g.out).toContain("(extended)");
    expect((await axis(["governance", "requests", "get"])).code).toBe(2);
  });

  it("creates from flags and from a file; validates kind and identifiers", async () => {
    const mock = { overrides: { createGovernanceDsarRequest: () => json(req(), 201) } };
    const a = await axis(
      [
        "governance",
        "requests",
        "create",
        "--kind",
        "erase",
        "--identifier",
        "email:a@example.test",
        "--destination-region",
        "eu-west-1",
      ],
      { mock },
    );
    expect(a.code, a.err).toBe(0);
    expect(a.server.calls[0]?.body).toEqual({
      kind: "erase",
      identifiers: [{ kind: "email", value: "a@example.test" }],
      destination_region: "eu-west-1",
    });
    expect(a.out).not.toContain("a@example.test");
    const f = file("identifiers:\n  - { kind: phone, value: '+15550100' }\n");
    const b = await axis(["governance", "requests", "create", "--kind", "export", "-f", f], {
      mock,
    });
    expect(b.code, b.err).toBe(0);
    expect((await axis(["governance", "requests", "create", "--kind", "export"])).code).toBe(2);
    expect(
      (await axis(["governance", "requests", "create", "--identifier", "email:a@b.test"])).code,
    ).toBe(2);
    expect(
      (await axis(["governance", "requests", "create", "--kind", "export", "--identifier", "nope"]))
        .code,
    ).toBe(2);
    expect(
      (
        await axis([
          "governance",
          "requests",
          "create",
          "--kind",
          "export",
          "--identifier",
          "fax:1",
        ])
      ).code,
    ).toBe(2);
    expect(
      (await axis(["governance", "requests", "create", "--kind", "export", "-f", file("a: 1\n")]))
        .code,
    ).toBe(1);
  });

  it("verify exits 1 when the evidence is refused and 0 when accepted", async () => {
    const f = file("requester_token: a.b\nadmin_attestation: c.d\n");
    const refused = await axis(["governance", "requests", "verify", "r1", "-f", f], {
      mock: {
        overrides: {
          verifyGovernanceDsarRequest: () => json(req({ verified_method: "refused:dual_control" })),
        },
      },
    });
    expect(refused.code).toBe(1);
    expect(refused.out).toContain("NOT verified");
    expect(refused.server.calls[0]?.body).toEqual({
      evidence: { requester_token: "a.b", admin_attestation: "c.d" },
    });
    const ok = await axis(["governance", "requests", "verify", "r1", "-f", f], {
      mock: {
        overrides: {
          verifyGovernanceDsarRequest: () =>
            json(
              req({
                status: "verified",
                verified_at: "2026-03-01T00:00:00.000Z",
                verified_method: "signed-token+admin-attestation",
              }),
            ),
        },
      },
    });
    expect(ok.code).toBe(0);
    expect((await axis(["governance", "requests", "verify", "r1"])).code).toBe(2);
  });

  it("export writes the bundle with mode 0600; erase exits 1 unless completed", async () => {
    const bundle = {
      manifest: {},
      records: {},
      signature: { alg: "Ed25519", key_id: "k1", value: "v" },
    };
    const out = join(mkdtempSync(join(tmpdir(), "axis-gov-")), "bundle.json");
    const e = await axis(["governance", "requests", "export", "r1", "--out", out], {
      mock: { overrides: { exportGovernanceDsarRequest: () => json(bundle) } },
    });
    expect(e.code, e.err).toBe(0);
    expect(JSON.parse(readFileSync(out, "utf8")).signature.key_id).toBe("k1");
    expect(statSync(out).mode & 0o777).toBe(0o600);
    const p = await axis(["governance", "requests", "export", "r1"], {
      mock: { overrides: { exportGovernanceDsarRequest: () => json(bundle) } },
    });
    expect(p.out).toContain("--out");
    expect(
      (
        await axis(["governance", "requests", "export", "r1", "--out", "/nonexistent/dir/x"], {
          mock: { overrides: { exportGovernanceDsarRequest: () => json(bundle) } },
        })
      ).code,
    ).toBe(1);
    for (const [status, code] of [
      ["completed", 0],
      ["held", 1],
      ["partial", 1],
    ] as const) {
      const r = await axis(["governance", "requests", "erase", "r1"], {
        mock: {
          overrides: {
            eraseGovernanceDsarRequest: () => json({ status, request: req(), providers: [] }),
          },
        },
      });
      expect(r.code, status).toBe(code);
    }
  });

  it("restrict needs a reason", async () => {
    const r = await axis(["governance", "requests", "restrict", "r1", "--reason", "objection"], {
      mock: {
        overrides: { restrictGovernanceDsarRequest: () => json(req({ status: "completed" })) },
      },
    });
    expect(r.code).toBe(0);
    expect(r.server.calls[0]?.body).toEqual({ reason: "objection" });
    expect((await axis(["governance", "requests", "restrict", "r1"])).code).toBe(2);
  });
});

describe("axis governance holds, retention, residency", () => {
  it("lists holds with server text printed inert, places and releases", async () => {
    const l = await axis(["governance", "holds", "list", "--all"], {
      mock: { overrides: { listGovernanceHolds: () => json({ items: [hold()] }) } },
    });
    expect(l.out).not.toContain("\u001b");
    expect(l.server.calls[0]?.url.searchParams.get("all")).toBe("true");
    const p = await axis(
      [
        "governance",
        "holds",
        "place",
        "--scope",
        "case",
        "--reason",
        "litigation",
        "--case-ref",
        "C-1",
        "--class",
        "memory",
        "--class",
        "audit",
        "-f",
        file("groups:\n  - [{ kind: email, value: a@example.test }]\n"),
      ],
      { mock: { overrides: { placeGovernanceHold: () => json(hold({ scope: "case" }), 201) } } },
    );
    expect(p.code, p.err).toBe(0);
    expect(p.server.calls[0]?.body).toMatchObject({
      scope: "case",
      case_ref: "C-1",
      classes: ["memory", "audit"],
    });
    expect((await axis(["governance", "holds", "place", "--reason", "x"])).code).toBe(2);
    expect((await axis(["governance", "holds", "place", "--scope", "tenant"])).code).toBe(2);
    expect(
      (
        await axis([
          "governance",
          "holds",
          "place",
          "--scope",
          "tenant",
          "--reason",
          "x",
          "--class",
          "bogus",
        ])
      ).code,
    ).toBe(2);
    expect(
      (
        await axis([
          "governance",
          "holds",
          "place",
          "--scope",
          "case",
          "--reason",
          "x",
          "-f",
          file("a: 1\n"),
        ])
      ).code,
    ).toBe(1);
    const r = await axis(["governance", "holds", "release", "h1"], {
      mock: {
        overrides: {
          releaseGovernanceHold: () => json(hold({ released_at: "2026-03-02T00:00:00.000Z" })),
        },
      },
    });
    expect(r.out).toContain("released");
  });

  it("retention get/set/runs/run; a dry run is the default and --execute is explicit", async () => {
    const g = await axis(["governance", "retention", "get"], {
      mock: {
        overrides: {
          getGovernanceRetention: () =>
            json({
              items: [
                {
                  data_class: "memory",
                  requested_days: 5,
                  effective_days: 30,
                  clamped: "min",
                  source: "default",
                },
              ],
            }),
        },
      },
    });
    expect(g.out).toContain("min");
    const s = await axis(["governance", "retention", "set", "memory", "60"], {
      mock: {
        overrides: { setGovernanceRetention: () => json({ data_class: "memory", days: 60 }) },
      },
    });
    expect(s.code).toBe(0);
    expect(s.server.calls[0]?.body).toEqual({ days: 60 });
    expect((await axis(["governance", "retention", "set", "memory", "abc"])).code).toBe(2);
    expect((await axis(["governance", "retention", "set", "nope", "5"])).code).toBe(2);
    const runs = await axis(["governance", "retention", "runs"], {
      mock: { overrides: { listGovernanceRetentionRuns: () => json({ items: [report()] }) } },
    });
    expect(runs.out).toContain("DRY RUN");
    const none = await axis(["governance", "retention", "runs"], {
      mock: { overrides: { listGovernanceRetentionRuns: () => json({ items: [] }) } },
    });
    expect(none.out).toContain("no retention runs");
    const dry = await axis(["governance", "retention", "run", "--class", "memory"], {
      mock: { overrides: { runGovernanceRetention: () => json(report()) } },
    });
    expect(dry.server.calls[0]?.body).toEqual({ dry_run: true, classes: ["memory"] });
    const ex = await axis(["governance", "retention", "run", "--execute"], {
      mock: { overrides: { runGovernanceRetention: () => json(report({ dry_run: false })) } },
    });
    expect(ex.server.calls[0]?.body).toEqual({ dry_run: false });
    const bad = await axis(["governance", "retention", "run"], {
      mock: {
        overrides: {
          runGovernanceRetention: () =>
            json(report({ classes: [{ ...report().classes[0], status: "settings_unavailable" }] })),
        },
      },
    });
    expect(bad.code).toBe(1);
  });

  it("residency", async () => {
    const r = await axis(["governance", "residency"], {
      mock: {
        overrides: {
          getGovernanceResidency: () =>
            json({ home_region: "eu-west-1", allowed_regions: ["eu-west-1"] }),
        },
      },
    });
    expect(r.out).toContain("eu-west-1");
  });

  it("a 403 from a non-officer is reported, not hidden", async () => {
    const r = await axis(["governance", "holds", "release", "h1"], {
      mock: {
        overrides: {
          releaseGovernanceHold: () =>
            json(
              {
                type: "about:blank",
                title: "Forbidden",
                status: 403,
                code: "forbidden",
                detail: "only the privacy officer",
              },
              403,
              { "content-type": "application/problem+json" },
            ),
        },
      },
    });
    expect(r.code).not.toBe(0);
  });
});
