import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  A,
  B,
  appendAudit,
  asApp,
  asAppNoTenant,
  connect,
  H,
  PID1,
  seedTenant,
  ZERO,
} from "./helpers.js";

let c: pg.Client;
let runA: string;
let tenantTables: string[];
/** Readable by every tenant and by anonymous readers BY DESIGN (public registry namespaces and their rows, migration 0010; the seed's private namespace is checked by the loop through the child tables, and services/registry tests cover the namespace table's private rows). */
const PUBLIC_BY_DESIGN = new Set(["registry_public_namespaces", "registry_namespaces"]);

beforeAll(async () => {
  c = await connect();
  runA = (await seedTenant(c, A, "tenant-a")).runId;
  await seedTenant(c, B, "tenant-b");
  const r = await c.query(
    `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname IN ('tenant_id') AND NOT a.attisdropped
     WHERE n.nspname = 'public' AND c.relkind = 'r' ORDER BY 1`,
  );
  tenantTables = [...r.rows.map((x) => x.relname as string), "tenants"].sort();
});
afterAll(async () => {
  await c.end();
});

const code = async (p: Promise<unknown>): Promise<string | undefined> => {
  try {
    await p;
    return undefined;
  } catch (e) {
    return (e as { code?: string }).code;
  }
};

describe("schema meta-tests (fail the build on drift)", () => {
  it("every table is either tenant-scoped or explicitly allow-listed", async () => {
    const all = await c.query(
      "SELECT relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND relkind='r'",
    );
    const names = all.rows.map((r) => r.relname as string);
    const allowed = new Set(["schema_migrations"]);
    const untenanted = names.filter((n) => !tenantTables.includes(n) && !allowed.has(n));
    expect(untenanted).toEqual([]);
  });

  it("every tenant table has ENABLE + FORCE row level security and a policy", async () => {
    const r = await c.query(
      `SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
              (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid) AS policies
       FROM pg_class c WHERE c.relname = ANY($1) AND c.relkind = 'r'`,
      [tenantTables],
    );
    expect(r.rows.length).toBe(tenantTables.length);
    for (const row of r.rows) {
      expect(row.relrowsecurity, row.relname).toBe(true);
      expect(row.relforcerowsecurity, row.relname).toBe(true);
      expect(Number(row.policies), row.relname).toBeGreaterThanOrEqual(1);
    }
  });

  it("the app role is not a superuser, cannot bypass RLS, and owns nothing", async () => {
    const role = await c.query(
      "SELECT rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = 'axis_app'",
    );
    expect(role.rows[0]).toMatchObject({ rolsuper: false, rolbypassrls: false });
    const owned = await c.query(
      "SELECT count(*)::int AS n FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner WHERE r.rolname = 'axis_app'",
    );
    expect(owned.rows[0].n).toBe(0);
  });

  it("the seed covers every tenant table (so the isolation loop below is exhaustive)", async () => {
    for (const t of tenantTables) {
      const col = t === "tenants" ? "id" : "tenant_id";
      const r = await c.query(`SELECT count(*)::int AS n FROM ${t} WHERE ${col} = $1`, [A]);
      expect(r.rows[0].n, t).toBeGreaterThanOrEqual(1);
    }
  });
});

describe("cross-tenant isolation at the database layer", () => {
  it("each tenant sees only its own rows in every tenant table", async () => {
    for (const t of tenantTables) {
      const col = t === "tenants" ? "id" : "tenant_id";
      for (const [me, other] of [
        [A, B],
        [B, A],
      ] as const) {
        const { own, foreign } = await asApp(c, me, async (x) => ({
          own: (await x.query(`SELECT count(*)::int AS n FROM ${t} WHERE ${col} = $1`, [me]))
            .rows[0].n as number,
          foreign: (await x.query(`SELECT count(*)::int AS n FROM ${t} WHERE ${col} = $1`, [other]))
            .rows[0].n as number,
        }));
        expect(own, `${t} own`).toBeGreaterThanOrEqual(1);
        if (!PUBLIC_BY_DESIGN.has(t)) expect(foreign, `${t} foreign`).toBe(0);
      }
    }
  });

  it("no tenant set => zero rows in every table", async () => {
    for (const t of tenantTables) {
      const n = await asAppNoTenant(
        c,
        async (x) => (await x.query(`SELECT count(*)::int AS n FROM ${t}`)).rows[0].n as number,
      );
      if (!PUBLIC_BY_DESIGN.has(t)) expect(n, t).toBe(0);
    }
  });

  it("a malformed tenant setting fails closed to zero rows", async () => {
    const n = await asAppNoTenant(c, async (x) => {
      await x.query("SELECT set_config('axis.tenant_id', 'not-a-uuid', true)");
      return (await x.query("SELECT count(*)::int AS n FROM runs")).rows[0].n as number;
    });
    expect(n).toBe(0);
  });

  it("a tenant cannot INSERT a row for another tenant (WITH CHECK)", async () => {
    const e = await code(
      asApp(c, A, (x) =>
        x.query(
          "INSERT INTO members (tenant_id, user_ref, email, role) VALUES ($1, 'evil', 'e@x.io', 'admin')",
          [B],
        ),
      ),
    );
    expect(e).toBe("42501");
  });

  it("no tenant set => INSERT is rejected", async () => {
    const e = await code(
      asAppNoTenant(c, (x) =>
        x.query(
          "INSERT INTO members (tenant_id, user_ref, email, role) VALUES ($1, 'u', 'u@x.io', 'admin')",
          [A],
        ),
      ),
    );
    expect(e).toBe("42501");
  });

  it("a tenant cannot UPDATE or DELETE another tenant's rows (0 rows affected)", async () => {
    const r = await asApp(c, A, async (x) => ({
      upd: (await x.query("UPDATE members SET role = 'owner' WHERE tenant_id = $1", [B])).rowCount,
      del: (await x.query("DELETE FROM members WHERE tenant_id = $1", [B])).rowCount,
    }));
    expect(r).toEqual({ upd: 0, del: 0 });
    const still = await c.query("SELECT role FROM members WHERE tenant_id = $1", [B]);
    expect(still.rows[0].role).toBe("admin");
  });

  it("a tenant cannot move its own row to another tenant (UPDATE WITH CHECK)", async () => {
    const e = await code(
      asApp(c, A, (x) => x.query("UPDATE members SET tenant_id = $1 WHERE tenant_id = $2", [B, A])),
    );
    expect(e).toBe("42501");
  });

  it("the app role cannot create or alter tenants", async () => {
    const e = await code(
      asApp(c, A, (x) =>
        x.query("INSERT INTO tenants (slug, name, region) VALUES ('x-tenant', 'x', 'us')"),
      ),
    );
    expect(e).toBe("42501");
    const e2 = await code(asApp(c, A, (x) => x.query("UPDATE tenants SET tier = 'dedicated'")));
    expect(e2).toBe("42501");
  });

  it("tenant scope does not leak past the transaction (pool safety)", async () => {
    await asApp(c, A, (x) => x.query("SELECT 1"));
    const n = await asAppNoTenant(
      c,
      async (x) => (await x.query("SELECT count(*)::int AS n FROM runs")).rows[0].n as number,
    );
    expect(n).toBe(0);
  });

  it("composite foreign keys stop a tenant referencing another tenant's parent row", async () => {
    const e = await code(
      asApp(c, B, (x) =>
        x.query(
          "INSERT INTO run_events (tenant_id, run_id, sequence, type, pid) VALUES ($1, $2, 1, 't', $3)",
          [B, runA, PID1],
        ),
      ),
    );
    expect(e).toBe("23503");
  });

  it("vector search is tenant-scoped", async () => {
    const q = `[${[1, ...Array<number>(1535).fill(0)].join(",")}]`;
    const mine = await asApp(c, A, (x) =>
      x.query("SELECT id FROM memory_chunks ORDER BY embedding <=> $1::vector LIMIT 5", [q]),
    );
    expect(mine.rowCount).toBe(1);
    const none = await asAppNoTenant(c, (x) =>
      x.query("SELECT id FROM memory_chunks ORDER BY embedding <=> $1::vector LIMIT 5", [q]),
    );
    expect(none.rowCount).toBe(0);
  });
});

describe("append-only and immutable tables", () => {
  it("audit_events, run_events and version tables reject UPDATE/DELETE even for the owner", async () => {
    const cases = [
      "UPDATE audit_events SET reason = 'x'",
      "DELETE FROM audit_events",
      "TRUNCATE audit_events",
      "UPDATE run_events SET type = 'x'",
      "DELETE FROM run_events",
      "UPDATE blueprint_versions SET version = '9.9.9'",
      "DELETE FROM blueprint_versions",
      "UPDATE policy_pack_versions SET rego = 'x'",
      "DELETE FROM policy_pack_versions",
    ];
    for (const sql of cases) expect(await code(c.query(sql)), sql).toBe("42501");
  });

  it("the app role has no UPDATE/DELETE privilege on the audit log", async () => {
    expect(await code(asApp(c, A, (x) => x.query("UPDATE audit_events SET reason = 'x'")))).toBe(
      "42501",
    );
    expect(await code(asApp(c, A, (x) => x.query("DELETE FROM audit_events")))).toBe("42501");
  });
});

describe("audit chain guard", () => {
  const ins = (t: string, seq: number, prev: string, hash: string) =>
    asApp(c, t, (x) => appendAudit(x, t, seq, prev, hash));

  it("accepts the next event and rejects gaps, replays and wrong prev_hash", async () => {
    await ins(A, 2, H("1"), H("2"));
    expect(await code(ins(A, 4, H("2"), H("4"))), "gap").toBe("23514");
    expect(await code(ins(A, 2, H("1"), H("9"))), "replay").toBe("23514");
    expect(await code(ins(A, 3, H("7"), H("3"))), "wrong prev").toBe("23514");
    await ins(A, 3, H("2"), H("3"));
  });

  it("genesis must be seq 1 with zero prev_hash", async () => {
    const t = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    await c.query(
      "INSERT INTO tenants (id, slug, name, region) VALUES ($1, 'tenant-c', 'c', 'us')",
      [t],
    );
    expect(await code(ins(t, 2, ZERO, H("1"))), "seq").toBe("23514");
    expect(await code(ins(t, 1, H("5"), H("1"))), "prev").toBe("23514");
    await ins(t, 1, ZERO, H("1"));
  });

  it("chains are independent per tenant", async () => {
    await ins(B, 2, H("1"), H("2"));
  });

  it("concurrent appends to the same tenant serialize; exactly one wins", async () => {
    const c2 = await connect();
    try {
      const head = await c.query(
        "SELECT seq, hash FROM audit_events WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1",
        [A],
      );
      const { seq, hash } = head.rows[0];
      const results = await Promise.all([
        code(asApp(c, A, (x) => appendAudit(x, A, Number(seq) + 1, hash, H("e")))),
        code(asApp(c2, A, (x) => appendAudit(x, A, Number(seq) + 1, hash, H("f")))),
      ]);
      expect(results.filter((r) => r === undefined)).toHaveLength(1);
      expect(results.filter((r) => r === "23514")).toHaveLength(1);
    } finally {
      await c2.end();
    }
  });
});

describe("row-level constraints", () => {
  it("terminated iff exit_reason is set", async () => {
    expect(
      await code(c.query("UPDATE processes SET state = 'terminated' WHERE tenant_id = $1", [A])),
    ).toBe("23514");
    expect(
      await code(
        c.query("UPDATE processes SET exit_reason = 'completed' WHERE tenant_id = $1", [A]),
      ),
    ).toBe("23514");
    expect(
      await code(
        c.query(
          "UPDATE processes SET state = 'terminated', exit_reason = 'bogus' WHERE tenant_id = $1",
          [A],
        ),
      ),
    ).toBe("23514");
  });

  it("kill-switch target rules", async () => {
    expect(
      await code(
        c.query(
          "INSERT INTO kill_switches (tenant_id, scope, target, engaged) VALUES ($1, 'agent', '', true)",
          [A],
        ),
      ),
    ).toBe("23514");
    expect(
      await code(
        c.query(
          "INSERT INTO kill_switches (tenant_id, scope, target, engaged) VALUES ($1, 'tenant', 'x', true)",
          [A],
        ),
      ),
    ).toBe("23514");
  });

  it("budget soft cap cannot exceed hard cap; risk level is constrained", async () => {
    expect(
      await code(
        c.query(
          "INSERT INTO budgets (tenant_id, scope, metric, period, soft, hard) VALUES ($1, 'agent', 'tokens', 'day', 5, 1)",
          [A],
        ),
      ),
    ).toBe("23514");
    expect(
      await code(
        c.query(
          "INSERT INTO blueprint_versions (tenant_id, blueprint_id, version, risk_level, abl, content_hash) SELECT tenant_id, id, '2.0.0', 'unacceptable', '{}', $2 FROM blueprints WHERE tenant_id = $1",
          [A, H("d")],
        ),
      ),
    ).toBe("23514");
  });
});
