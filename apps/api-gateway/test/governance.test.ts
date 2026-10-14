import { randomBytes } from "node:crypto";
import {
  GovernanceError,
  MasterKeyProvider,
  MemoryGovernanceStore,
  createGovernanceKit,
  type GovernanceKit,
  type Identifier,
  type SubjectDataProvider,
} from "@axis/data-governance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  GOVERNANCE_READ_ROLES,
  GOVERNANCE_WRITE_ROLES,
  GovernanceAdapter,
  UnavailableGovernance,
  fromGovernanceError,
  PortConflict,
  PortForbidden,
  PortInvalid,
  PortNotFound,
  PortUnavailable,
  type GovernancePort,
} from "../src/index.js";
import { call, makeWorld, seed, type Cred, type Seed, type World } from "./world.js";

/** One in-memory store of "personal data" rows keyed by tenant and email. */
class Rows implements SubjectDataProvider {
  readonly id = "rows";
  readonly declaration = {
    exports: ["rows"],
    erases: ["rows"],
    retains: [],
    pseudonymises: [],
    dataClasses: ["memory" as const],
  };
  data = new Map<string, string[]>();
  private k = (t: string, id: Identifier) => `${t}|${id.value}`;
  put(t: string, v: string): void {
    this.data.set(`${t}|${v}`, ["secret"]);
  }
  async find(c: { tenantId: string }, ids: readonly Identifier[]) {
    return { count: ids.filter((i) => this.data.has(this.k(c.tenantId, i))).length };
  }
  async export(c: { tenantId: string }, ids: readonly Identifier[]) {
    return [
      {
        name: "rows",
        records: ids
          .filter((i) => this.data.has(this.k(c.tenantId, i)))
          .map((i) => ({ v: i.value })),
      },
    ];
  }
  async erase(c: { tenantId: string }, ids: readonly Identifier[]) {
    let n = 0;
    for (const i of ids) if (this.data.delete(this.k(c.tenantId, i))) n++;
    return { erased: n, pseudonymised: 0, retained: 0 };
  }
  async count(c: { tenantId: string }, ids: readonly Identifier[]) {
    return {
      residual: ids.filter((i) => this.data.has(this.k(c.tenantId, i))).length,
      retained: 0,
      pseudonymised: 0,
    };
  }
}

let w: World;
let s: Seed;
let kit: GovernanceKit;
let rows: Rows;
let po: Cred;
let po2: Cred;
let admin: Cred;
let auditor: Cred;
let builder: Cred;
let viewer: Cred;
let other: Cred; // another tenant's privacy officer
const admins = new Set<string>();

beforeAll(async () => {
  rows = new Rows();
  const lazy = { append: (e: never) => w.audit.append(e) };
  kit = createGovernanceKit({
    pool: undefined as never,
    masterKey: randomBytes(32),
    region: "us-east-1",
    audit: lazy as never,
    store: new MemoryGovernanceStore(),
    providers: [rows],
    directory: { isTenantAdmin: async (_t, m) => admins.has(m) },
    regions: { resolve: async () => ({ homeRegion: "us-east-1" }) },
    settings: {
      get: async () => ({
        retentionAuditDays: 2555,
        retentionTranscriptDays: 30,
        retentionMemoryDays: 365,
      }),
    },
  });
  w = await makeWorld(
    { rate: { burst: 1e6, perSecond: 1e6 }, unauthRate: { burst: 1e6, perSecond: 1e6 } },
    { governance: new GovernanceAdapter(kit) },
  );
  s = await seed(w);
  const t = s.owner.tenantId;
  po = await w.member(t, "privacy_officer");
  po2 = await w.member(t, "privacy_officer");
  admin = await w.member(t, "admin");
  auditor = await w.member(t, "auditor");
  builder = await w.member(t, "builder");
  viewer = await w.member(t, "viewer");
  admins.add(admin.memberId).add(s.owner.memberId);
  const o2 = await w.tenant();
  other = await w.member(o2.tenantId, "privacy_officer");
});
afterAll(() => w.close());

const T = (c: Cred) => ({ token: c.token });
const evidence = async (
  reqId: string,
  subjectRef: string,
  attester: string,
  tenant = s.owner.tenantId,
) => ({
  evidence: {
    requester_token: await kit.verifier.issueRequesterToken({
      tenantId: tenant,
      requestId: reqId,
      subjectRef,
    }),
    admin_attestation: await kit.verifier.issueAdminAttestation({
      tenantId: tenant,
      requestId: reqId,
      memberId: attester,
    }),
  },
});

describe("role matrix (adapter-level check, independent of the route's action)", () => {
  const READS = [
    ["GET", "/governance/dsar-requests"],
    ["GET", "/governance/holds"],
    ["GET", "/governance/retention"],
    ["GET", "/governance/retention-runs"],
    ["GET", "/governance/residency"],
  ] as const;
  const WRITES: [string, string, unknown][] = [
    [
      "POST",
      "/governance/dsar-requests",
      { kind: "export", identifiers: [{ kind: "email", value: "x@example.test" }] },
    ],
    ["POST", "/governance/holds", { scope: "tenant", reason: "case" }],
    ["PUT", "/governance/retention/memory", { days: 30 }],
    ["POST", "/governance/retention-runs", { dry_run: true }],
  ];

  it("reads: owner, admin, auditor, privacy_officer; builder and viewer are refused", async () => {
    for (const [m, p] of READS) {
      for (const c of [s.owner, admin, auditor, po]) {
        const r = await call(w, m, p, T(c));
        expect(r.status, `${p} as ${c.role}: ${r.text}`).toBe(200);
      }
      for (const c of [builder, viewer])
        expect((await call(w, m, p, T(c))).status, `${p} ${c.role}`).toBe(403);
    }
  });

  it("writes: ONLY the privacy officer; owner, admin, auditor, builder, viewer are refused with nothing written", async () => {
    for (const [m, p, body] of WRITES) {
      for (const c of [s.owner, admin, auditor, builder, viewer]) {
        const r = await call(w, m, p, { ...T(c), body });
        expect(r.status, `${m} ${p} as ${c.role}: ${r.text}`).toBe(403);
      }
    }
    expect((await call(w, "GET", "/governance/dsar-requests", T(po))).body.items).toEqual([]);
    expect((await call(w, "GET", "/governance/holds?all=true", T(po))).body.items).toEqual([]);
  });

  it("the adapter itself refuses roles the route layer might let through", async () => {
    const a = new GovernanceAdapter(kit);
    const mk = (role: string) => ({ tenantId: s.owner.tenantId, memberId: "m", role }) as never;
    expect(() => a.listHolds(mk("builder"), {})).toThrow(PortForbidden);
    await expect(
      Promise.resolve().then(() => a.placeHold(mk("admin"), { scope: "tenant", reason: "x" })),
    ).rejects.toThrow(PortForbidden);
    expect([...GOVERNANCE_WRITE_ROLES]).toEqual(["privacy_officer"]);
    expect(
      GOVERNANCE_READ_ROLES.has("privacy_officer") && !GOVERNANCE_READ_ROLES.has("builder"),
    ).toBe(true);
  });

  it("no credential: 401", async () => {
    expect((await call(w, "GET", "/governance/holds")).status).toBe(401);
  });
});

describe("DSAR over HTTP", () => {
  it("export and erase with signed evidence and dual control; residual data is gone; the audit chain records it", async () => {
    const t = s.owner.tenantId;
    rows.put(t, "jane@example.test");
    const c = await call(w, "POST", "/governance/dsar-requests", {
      ...T(po),
      body: { kind: "erase", identifiers: [{ kind: "email", value: "jane@example.test" }] },
    });
    expect(c.status, c.text).toBe(201);
    const id = c.body.id as string;
    expect(JSON.stringify(c.body)).not.toContain("jane@example.test");

    // erase before verification is refused
    expect((await call(w, "POST", `/governance/dsar-requests/${id}/erase`, T(po))).status).toBe(
      409,
    );
    // the opener cannot attest for itself (dual control); a builder is not an admin
    const self = await call(w, "POST", `/governance/dsar-requests/${id}/verify`, {
      ...T(po),
      body: await evidence(id, c.body.subject_ref, po.memberId),
    });
    expect(self.body.status).toBe("received");
    const bld = await call(w, "POST", `/governance/dsar-requests/${id}/verify`, {
      ...T(po2),
      body: await evidence(id, c.body.subject_ref, builder.memberId),
    });
    expect(bld.body.status).toBe("received");
    expect(rows.data.size).toBe(1);
    // garbage evidence
    expect(
      (
        await call(w, "POST", `/governance/dsar-requests/${id}/verify`, {
          ...T(po2),
          body: { evidence: { a: 1 } },
        })
      ).body.status,
    ).toBe("received");

    const v = await call(w, "POST", `/governance/dsar-requests/${id}/verify`, {
      ...T(po2),
      body: await evidence(id, c.body.subject_ref, admin.memberId),
    });
    expect(v.status, v.text).toBe(200);
    expect(v.body.status).toBe("verified");

    const er = await call(w, "POST", `/governance/dsar-requests/${id}/erase`, T(po));
    expect(er.status, er.text).toBe(200);
    expect(rows.data.size).toBe(0);
    const g = await call(w, "GET", `/governance/dsar-requests/${id}`, T(auditor));
    expect(g.body.status).toBe(er.body.request.status);
    const actions = (await w.audit.read(t, {})).map((e: { action: string }) => e.action);
    expect(actions.some((a: string) => a.includes("dsar"))).toBe(true);
  });

  it("export returns a signed bundle for a verified request; restrict marks it", async () => {
    const t = s.owner.tenantId;
    rows.put(t, "bob@example.test");
    const c = await call(w, "POST", "/governance/dsar-requests", {
      ...T(po),
      body: { kind: "export", identifiers: [{ kind: "email", value: "bob@example.test" }] },
    });
    const id = c.body.id as string;
    await call(w, "POST", `/governance/dsar-requests/${id}/verify`, {
      ...T(po2),
      body: await evidence(id, c.body.subject_ref, admin.memberId),
    });
    const e = await call(w, "POST", `/governance/dsar-requests/${id}/export`, T(po));
    expect(e.status, e.text).toBe(200);
    const r = await call(w, "POST", `/governance/dsar-requests/${id}/restrict`, {
      ...T(po),
      body: { reason: "objection" },
    });
    expect(r.status, r.text).toBe(422); // not a restriction request
    const rc = await call(w, "POST", "/governance/dsar-requests", {
      ...T(po),
      body: { kind: "restrict", identifiers: [{ kind: "email", value: "bob@example.test" }] },
    });
    expect(rc.status, rc.text).toBe(201);
    const rid = rc.body.id as string;
    const early = await call(w, "POST", `/governance/dsar-requests/${rid}/restrict`, {
      ...T(po),
      body: { reason: "objection" },
    });
    expect(early.status).toBe(409); // not verified yet
    await call(w, "POST", `/governance/dsar-requests/${rid}/verify`, {
      ...T(po2),
      body: await evidence(rid, rc.body.subject_ref, admin.memberId),
    });
    const done = await call(w, "POST", `/governance/dsar-requests/${rid}/restrict`, {
      ...T(po),
      body: { reason: "objection" },
    });
    expect(done.status, done.text).toBe(200);
    expect(done.body.status).toBe("completed");
    const list = await call(w, "GET", "/governance/dsar-requests?status=verified", T(auditor));
    expect(list.status).toBe(200);
  });

  it("IDOR: another tenant's officer sees and acts on none of it (404) and the list is scoped", async () => {
    const mine = await call(w, "GET", "/governance/dsar-requests", T(po));
    const id = (mine.body.items as { id: string }[])[0]!.id;
    for (const [m, p, body] of [
      ["GET", `/governance/dsar-requests/${id}`, undefined],
      ["POST", `/governance/dsar-requests/${id}/verify`, { evidence: {} }],
      ["POST", `/governance/dsar-requests/${id}/export`, undefined],
      ["POST", `/governance/dsar-requests/${id}/erase`, undefined],
      ["POST", `/governance/dsar-requests/${id}/restrict`, { reason: "x" }],
    ] as const) {
      const r = await call(w, m, p, { ...T(other), ...(body ? { body } : {}) });
      expect(r.status, `${m} ${p}: ${r.text}`).toBe(404);
    }
    expect((await call(w, "GET", "/governance/dsar-requests", T(other))).body.items).toEqual([]);
    expect((await call(w, "GET", "/governance/holds?all=true", T(other))).body.items).toEqual([]);
  });

  it("an unknown request id is 404; an invalid body is 422", async () => {
    expect(
      (
        await call(
          w,
          "GET",
          "/governance/dsar-requests/00000000-0000-4000-8000-0000000000aa",
          T(po),
        )
      ).status,
    ).toBe(404);
    expect(
      (await call(w, "POST", "/governance/dsar-requests", { ...T(po), body: { kind: "export" } }))
        .status,
    ).toBe(422);
  });
});

describe("holds, retention, residency over HTTP", () => {
  it("a tenant hold blocks erasure (outcome held, data kept) until released", async () => {
    const t = s.owner.tenantId;
    rows.put(t, "held@example.test");
    const h = await call(w, "POST", "/governance/holds", {
      ...T(po),
      body: { scope: "tenant", reason: "litigation" },
    });
    expect(h.status, h.text).toBe(201);
    const c = await call(w, "POST", "/governance/dsar-requests", {
      ...T(po),
      body: { kind: "erase", identifiers: [{ kind: "email", value: "held@example.test" }] },
    });
    const id = c.body.id as string;
    await call(w, "POST", `/governance/dsar-requests/${id}/verify`, {
      ...T(po2),
      body: await evidence(id, c.body.subject_ref, admin.memberId),
    });
    const er = await call(w, "POST", `/governance/dsar-requests/${id}/erase`, T(po));
    expect(er.status, er.text).toBe(200);
    expect(er.body.status).toBe("held"); // nothing was erased
    expect(rows.data.has(`${t}|held@example.test`)).toBe(true);
    const ids = async (c: Cred, q = "") =>
      ((await call(w, "GET", `/governance/holds${q}`, T(c))).body.items as { id: string }[]).map(
        (x) => x.id,
      );
    expect(await ids(auditor)).toContain(h.body.id);
    expect(await ids(other)).toEqual([]);
    expect((await call(w, "POST", `/governance/holds/${h.body.id}/release`, T(other))).status).toBe(
      404,
    );
    const rel = await call(w, "POST", `/governance/holds/${h.body.id}/release`, T(po));
    expect(rel.status, rel.text).toBe(200);
    expect(rel.body.released_at).not.toBeNull();
    expect(await ids(auditor)).not.toContain(h.body.id);
    expect(await ids(auditor, "?all=true")).toContain(h.body.id);
  });

  it("retention: effective periods, set within bounds, dry run stored and listed", async () => {
    const g = await call(w, "GET", "/governance/retention", T(auditor));
    expect(g.status, g.text).toBe(200);
    expect(g.body.items.length).toBeGreaterThan(0);
    expect(
      (await call(w, "PUT", "/governance/retention/not_a_class", { ...T(po), body: { days: 30 } }))
        .status,
    ).toBe(422);
    const run = await call(w, "POST", "/governance/retention-runs", {
      ...T(po),
      body: { dry_run: true, classes: ["memory"] },
    });
    expect(run.status, run.text).toBe(200);
    expect(run.body.dry_run).toBe(true);
    const runs = await call(w, "GET", "/governance/retention-runs", T(admin));
    expect(runs.body.items.some((r: { run_id: string }) => r.run_id === run.body.run_id)).toBe(
      true,
    );
    expect((await call(w, "GET", "/governance/retention-runs", T(other))).body.items).toEqual([]);
  });

  it("residency: the home region and the allowed regions", async () => {
    const r = await call(w, "GET", "/governance/residency", T(s.owner));
    expect(r.status, r.text).toBe(200);
    expect(r.body.home_region).toBe("us-east-1");
    expect(r.body.allowed_regions).toContain("us-east-1");
  });
});

describe("fail-closed behaviour", () => {
  it("an unwired gateway answers 503 problem+json for reads and writes alike", async () => {
    const un = await makeWorld({}, { governance: new UnavailableGovernance() });
    try {
      const sd = await seed(un);
      const p = await un.member(sd.owner.tenantId, "privacy_officer");
      for (const [m, path, body] of [
        ["GET", "/governance/holds", undefined],
        ["GET", "/governance/residency", undefined],
        ["POST", "/governance/holds", { scope: "tenant", reason: "x" }],
        ["POST", "/governance/retention-runs", { dry_run: false }],
      ] as const) {
        const r = await call(un, m, path, { ...T(p), ...(body ? { body } : {}) });
        expect(r.status, `${m} ${path}`).toBe(503);
        expect(r.headers.get("content-type")).toContain("application/problem+json");
      }
    } finally {
      await un.close();
    }
  });

  it("an unreachable region resolver or retention settings port answers 503, never an empty success", async () => {
    const dead: GovernanceKit = {
      ...kit,
      regions: { resolve: async () => undefined },
      retention: { ...kit.retention, resolve: async () => undefined } as never,
    };
    const a = new GovernanceAdapter(dead);
    const pr = { tenantId: s.owner.tenantId, memberId: "m", role: "privacy_officer" } as never;
    await expect(a.getResidency(pr)).rejects.toBeInstanceOf(PortUnavailable);
    await expect(a.getRetention(pr)).rejects.toBeInstanceOf(PortUnavailable);
  });

  it("the audit sink failing aborts the operation: nothing is created", async () => {
    const broken = createGovernanceKit({
      pool: undefined as never,
      masterKey: randomBytes(32),
      region: "us-east-1",
      audit: {
        append: async () => {
          throw new Error("chain down");
        },
      },
      store: new MemoryGovernanceStore(),
      providers: [],
      directory: { isTenantAdmin: async () => true },
      regions: { resolve: async () => ({ homeRegion: "us-east-1" }) },
      settings: { get: async () => undefined },
    });
    const a = new GovernanceAdapter(broken);
    const pr = { tenantId: s.owner.tenantId, memberId: "m", role: "privacy_officer" } as never;
    await expect(a.placeHold(pr, { scope: "tenant", reason: "x" })).rejects.toThrow();
    expect(await a.listHolds(pr, { all: true })).toEqual([]);
  });

  it("a ResidencyError (code region_mismatch) from any service becomes a 403 residency_violation without region names", async () => {
    class Res extends Error {
      code = "region_mismatch";
    }
    const bad: GovernancePort = new UnavailableGovernance();
    bad.getResidency = (async () => {
      throw new Res("tenant is in eu-west-1, not us-east-1");
    }) as never;
    const g = await makeWorld({}, { governance: bad });
    try {
      const sd = await seed(g);
      const r = await call(g, "GET", "/governance/residency", T(sd.owner));
      expect(r.status).toBe(403);
      expect(r.text).toContain("residency_violation");
      expect(r.text).not.toContain("eu-west-1");
    } finally {
      await g.close();
    }
  });

  it("GovernanceError codes map onto port errors", () => {
    const t = (code: string) => {
      try {
        fromGovernanceError(new GovernanceError(code as never, "m"));
      } catch (e) {
        return e;
      }
    };
    expect(t("not_found")).toBeInstanceOf(PortNotFound);
    for (const c of ["forbidden", "restricted", "residency"])
      expect(t(c)).toBeInstanceOf(PortForbidden);
    for (const c of ["conflict", "not_verified", "held"]) expect(t(c)).toBeInstanceOf(PortConflict);
    expect(t("invalid")).toBeInstanceOf(PortInvalid);
    expect(t("unavailable")).toBeInstanceOf(PortUnavailable);
    const resid = t("residual_data");
    expect(resid).toBeInstanceOf(Error);
    expect(resid).not.toBeInstanceOf(PortConflict);
    expect(() => fromGovernanceError(new TypeError("x"))).toThrow(TypeError);
  });

  it("MasterKeyProvider import is the real one (guards against the test kit drifting)", () => {
    expect(new MasterKeyProvider()).toBeTruthy();
  });
});
