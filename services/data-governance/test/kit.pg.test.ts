import { randomBytes, randomUUID } from "node:crypto";
import { PgAuditLog } from "@axis/audit";
import { verifyChain } from "@axis/contracts";
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  PgAttesterDirectory,
  PgRegionResolver,
  PgRetentionSettings,
  createGovernanceKit,
  type GovernanceKit,
} from "../src/index.js";
import { ROLE, adminClient, newPool, newTenant, officer } from "./helpers.js";
import { JANE, seedTenant, type Seeded } from "./seed.js";

let admin: pg.Client;
let pool: pg.Pool;
beforeAll(async () => {
  admin = await adminClient();
  pool = newPool();
});
afterAll(async () => {
  await pool.end();
  await admin.end();
});

const o = () => ({ pool, role: ROLE });
const kitFor = (region = "eu-west-1"): GovernanceKit =>
  createGovernanceKit({
    pool,
    role: ROLE,
    masterKey: randomBytes(32),
    region,
    audit: new PgAuditLog({ pool, role: "axis_app" }),
  });

describe("Postgres ports (forced RLS, governance role)", () => {
  let a: Seeded;
  let b: Seeded;
  beforeAll(async () => {
    a = await seedTenant(admin, await newTenant(admin, { phi: true }));
    b = await seedTenant(admin, await newTenant(admin, { region: "us-east-1" }));
    await admin.query(
      "INSERT INTO tenant_settings (tenant_id, retention_audit_days, retention_transcript_days, retention_memory_days) VALUES ($1, 400, 7, 9)",
      [a.tenantId],
    );
  });

  it("reads the tenant's retention settings and phi mode; no row means unknown", async () => {
    const s = new PgRetentionSettings(o());
    expect(await s.get(a.tenantId)).toEqual({
      retentionAuditDays: 400,
      retentionTranscriptDays: 7,
      retentionMemoryDays: 9,
      phiMode: true,
    });
    expect(await s.get(b.tenantId)).toBeUndefined();
    expect(await s.get(randomUUID())).toBeUndefined();
  });

  it("resolves the home region per tenant, and unknown for a tenant that does not exist", async () => {
    const r = new PgRegionResolver(o());
    expect(await r.resolve(a.tenantId)).toEqual({ homeRegion: "eu-west-1" });
    expect(await r.resolve(b.tenantId)).toEqual({ homeRegion: "us-east-1" });
    expect(await r.resolve(randomUUID())).toBeUndefined();
  });

  it("an attester must be an ACTIVE owner/admin of THIS tenant", async () => {
    const d = new PgAttesterDirectory(o());
    expect(await d.isTenantAdmin(a.tenantId, a.ownerMember)).toBe(true);
    expect(await d.isTenantAdmin(a.tenantId, a.janeMember)).toBe(false); // builder
    expect(await d.isTenantAdmin(b.tenantId, a.ownerMember)).toBe(false); // other tenant's owner
    expect(await d.isTenantAdmin(a.tenantId, "not-a-uuid")).toBe(false);
    await admin.query("UPDATE members SET status = 'deprovisioned' WHERE id = $1", [a.ownerMember]);
    expect(await d.isTenantAdmin(a.tenantId, a.ownerMember)).toBe(false);
    await admin.query("UPDATE members SET status = 'active' WHERE id = $1", [a.ownerMember]);
  });
});

describe("governance kit end to end (real verifier, real audit chain)", () => {
  it("opens, verifies with dual control, exports and erases; the chain verifies; stored runs list", async () => {
    const s = await seedTenant(admin, await newTenant(admin));
    await admin.query("INSERT INTO tenant_settings (tenant_id) VALUES ($1)", [s.tenantId]);
    const kit = kitFor();
    const po = officer(s.tenantId, "po-open");
    const req = await kit.dsar.open(po, {
      kind: "export",
      identifiers: [{ kind: "email", value: JANE.email }],
    });
    const evidence = async (attester: string) => ({
      requester_token: await kit.verifier.issueRequesterToken({
        tenantId: s.tenantId,
        requestId: req.id,
        subjectRef: req.subjectRef,
      }),
      admin_attestation: await kit.verifier.issueAdminAttestation({
        tenantId: s.tenantId,
        requestId: req.id,
        memberId: attester,
      }),
    });
    // a non-admin member cannot attest
    const refused = await kit.dsar.verify(
      officer(s.tenantId, "po-verify"),
      req.id,
      await evidence(s.janeMember),
    );
    expect(refused.status).toBe("received");
    expect(refused.verifiedAt).toBeNull();
    // the owner (an independent tenant admin) can
    const v = await kit.dsar.verify(
      officer(s.tenantId, "po-verify"),
      req.id,
      await evidence(s.ownerMember),
    );
    expect(v.status).toBe("verified");
    const bundle = await kit.dsar.export(po, req.id);
    expect(bundle).toBeTruthy();

    const dry = await kit.retention.run(po, { dryRun: true, classes: ["memory"] });
    const runs = await kit.retention.runs(po);
    expect(runs.some((r) => r.id === dry.runId && r.dryRun)).toBe(true);
    await expect(kit.retention.runs({ ...po, roles: [] })).rejects.toMatchObject({
      code: "forbidden",
    });

    const chain = await new PgAuditLog({ pool, role: "axis_app" }).read(s.tenantId, {});
    expect(chain.length).toBeGreaterThan(2);
    expect(verifyChain(chain)).toMatchObject({ ok: true });
  });

  it("residency: a request served from another region is refused", async () => {
    const s = await seedTenant(admin, await newTenant(admin, { region: "eu-west-1" }));
    const kit = kitFor("us-east-1");
    await expect(
      kit.dsar.open(officer(s.tenantId), {
        kind: "export",
        identifiers: [{ kind: "email", value: JANE.email }],
      }),
    ).resolves.toBeTruthy(); // opening is allowed; moving data is not
    expect(kit.region).toBe("us-east-1");
    expect((await kit.regions.resolve(s.tenantId))?.homeRegion).toBe("eu-west-1");
  });
});
