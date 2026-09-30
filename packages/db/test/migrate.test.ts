import pg from "pg";
import { afterEach, beforeEach, describe, expect, it, inject } from "vitest";
import { loadMigrations, migrate, withTenant, type Migration } from "../src/index.js";
import { A, connect } from "./helpers.js";

describe("migration runner", () => {
  it("is idempotent: re-running applies nothing", async () => {
    const c = await connect();
    try {
      expect(await migrate(c)).toEqual([]);
    } finally {
      await c.end();
    }
  });

  it("loads migrations in version order with checksums", () => {
    const m = loadMigrations();
    expect(m.map((x) => x.version)).toEqual([
      "0001_tenancy_and_rls",
      "0002_core_tables",
      "0003_audit_and_memory",
    ]);
    for (const x of m) expect(x.checksum).toMatch(/^[0-9a-f]{64}$/);
  });

  describe("on a scratch database", () => {
    let admin: pg.Client;
    let scratch: pg.Client;
    const name = `axis_scratch_${Date.now()}`;
    beforeEach(async () => {
      const url = new URL(inject("dbUrl"));
      admin = new pg.Client({ connectionString: inject("dbUrl") });
      await admin.connect();
      await admin.query(`CREATE DATABASE ${name}`);
      url.pathname = `/${name}`;
      scratch = new pg.Client({ connectionString: url.toString() });
      await scratch.connect();
    });
    afterEach(async () => {
      await scratch.end();
      await admin.query(`DROP DATABASE ${name} WITH (FORCE)`);
      await admin.end();
    });

    const good: Migration = {
      version: "9001_a",
      sql: "CREATE TABLE t9001 (x int)",
      checksum: "c1",
    };

    it("applies, records, and refuses a modified applied migration", async () => {
      expect(await migrate(scratch, [good])).toEqual(["9001_a"]);
      expect(await migrate(scratch, [good])).toEqual([]);
      await expect(migrate(scratch, [{ ...good, checksum: "changed" }])).rejects.toThrow(
        /modified after being applied/,
      );
    });

    it("rolls back a failing migration and records nothing", async () => {
      const bad: Migration = {
        version: "9002_bad",
        sql: "CREATE TABLE t9002 (x int); SELECT 1/0;",
        checksum: "c2",
      };
      await expect(migrate(scratch, [good, bad])).rejects.toThrow(/division by zero/);
      const r = await scratch.query(
        "SELECT to_regclass('t9002') AS t, (SELECT count(*) FROM schema_migrations)::int AS n",
      );
      expect(r.rows[0]).toEqual({ t: null, n: 1 });
    });
  });
});

describe("withTenant", () => {
  it("rejects non-UUID tenant ids before touching the database", async () => {
    const c = await connect();
    try {
      await expect(withTenant(c, "x'; drop table runs;--", async () => 1)).rejects.toThrow(/UUID/);
    } finally {
      await c.end();
    }
  });

  it("rolls back and rethrows when the callback fails", async () => {
    const c = await connect();
    try {
      await expect(
        withTenant(c, A, async (x) => {
          await x.query("CREATE TEMP TABLE probe (x int)");
          throw new Error("boom");
        }),
      ).rejects.toThrow("boom");
      const r = await c.query("SELECT to_regclass('pg_temp.probe') AS t");
      expect(r.rows[0].t).toBeNull();
    } finally {
      await c.end();
    }
  });
});
