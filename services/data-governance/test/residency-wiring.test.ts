import { PgConversationStore } from "@axis/channels";
import { PgUsageLedger } from "@axis/billing";
import { PgDocStore } from "@axis/eval-hub";
import { HashEmbedder, PgMemoryService } from "@axis/memory";
import { PgRegistryStore } from "@axis/registry";
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ResidencyError, ResidencyPolicy, StaticRegionResolver } from "../src/residency.js";
import { adminClient, newPool, newTenant } from "./helpers.js";

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

/** Two regions, two service instances (one per region) sharing one database: the wrong region's instance must refuse every write. */
describe("residency enforcement on service write paths (two regions)", () => {
  it("refuses cross-region writes in memory, channels, eval-hub, billing and registry; allows same-region writes", async () => {
    const eu = await newTenant(admin, { region: "eu-west-1" });
    const us = await newTenant(admin, { region: "us-east-1" });
    const policy = new ResidencyPolicy(
      new StaticRegionResolver({
        [eu]: { homeRegion: "eu-west-1" },
        [us]: { homeRegion: "us-east-1" },
      }),
    );
    const inEu = policy.forService("eu-west-1");
    const inUs = policy.forService("us-east-1");
    const who = { id: "svc", groups: [] as string[] };
    const role = "axis_app";

    // memory
    const memEU = new PgMemoryService({
      pool,
      embedder: new HashEmbedder(),
      role,
      residency: inEu,
    });
    await expect(
      memEU.write(eu, { scope: "tenant", content: "ok", principal: who }),
    ).resolves.toBeTruthy();
    await expect(
      memEU.write(us, { scope: "tenant", content: "nope", principal: who }),
    ).rejects.toBeInstanceOf(ResidencyError);
    await expect(
      memEU.ingestDocument(us, {
        kb: "kb-x",
        content: "x",
        acl: { tenant: true },
        principal: who,
      } as never),
    ).rejects.toBeInstanceOf(ResidencyError);
    expect(
      (await admin.query("SELECT count(*)::int n FROM memory_chunks WHERE tenant_id = $1", [us]))
        .rows[0].n,
    ).toBe(0);

    // channels
    const chEU = new PgConversationStore({ pool, role, residency: inEu });
    await expect(chEU.resolveIdentity(eu, "slack", "U1")).resolves.toBeTruthy();
    await expect(chEU.resolveIdentity(us, "slack", "U1")).rejects.toBeInstanceOf(ResidencyError);
    await expect(
      chEU.createConversation(
        us,
        "00000000-0000-4000-8000-000000000001",
        { name: "a", version: "1" },
        "slack",
      ),
    ).rejects.toBeInstanceOf(ResidencyError);
    await expect(chEU.appendMessage(us, {} as never)).rejects.toBeInstanceOf(ResidencyError);

    // eval hub documents
    const docsUS = new PgDocStore({ pool, role, residency: inUs });
    await expect(docsUS.insert(us, "runs", "r1", { status: "queued" })).resolves.toBeTruthy();
    await expect(docsUS.insert(eu, "runs", "r1", { status: "queued" })).rejects.toBeInstanceOf(
      ResidencyError,
    );
    await expect(docsUS.update(eu, "runs", "r1", 1, {})).rejects.toBeInstanceOf(ResidencyError);

    // billing ledger
    const ledEU = new PgUsageLedger({ pool, role, residency: inEu, signer: {} as never });
    await expect(
      ledEU.append({
        tenantId: us,
        idempotencyKey: "k1",
        meter: "tokens_in",
        quantity: 1n,
        eventTime: new Date(),
        source: "t",
      }),
    ).rejects.toBeInstanceOf(ResidencyError);
    await expect(
      ledEU.append({
        tenantId: eu,
        idempotencyKey: "k1",
        meter: "tokens_in",
        quantity: 1n,
        eventTime: new Date(),
        source: "t",
      }),
    ).resolves.toBeTruthy();

    // registry
    const regEU = new PgRegistryStore({ pool, role, residency: inEu });
    await expect(regEU.insertVersion({ tenantId: us } as never, "n")).rejects.toBeInstanceOf(
      ResidencyError,
    );

    // fail closed: a tenant unknown to the resolver cannot be written by anyone
    const ghost = await newTenant(admin, { region: "eu-west-1" });
    await expect(
      memEU.write(ghost, { scope: "tenant", content: "x", principal: who }),
    ).rejects.toBeInstanceOf(ResidencyError);
  });
});
