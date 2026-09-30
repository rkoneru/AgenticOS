import { sealEvent, verifyChain, type AuditEvent } from "@axis/contracts";
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { asApp, connect, H, PID1, PID2, seedTenant } from "./helpers.js";

// Own tenants so this file never interferes with tenancy.test.ts (files share one database).
const D = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const E = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
let c: pg.Client;
let runD: string;

beforeAll(async () => {
  c = await connect();
  runD = (await seedTenant(c, D, "tenant-d")).runId;
  await seedTenant(c, E, "tenant-e");
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

describe("search_path hijack (review finding 1)", () => {
  it("axis_app cannot create TEMP tables, so audit_events cannot be shadowed", async () => {
    const e = await code(
      asApp(c, D, (x) => x.query("CREATE TEMP TABLE audit_events (LIKE public.audit_events)")),
    );
    expect(e).toBe("42501");
  });

  it("every function in schema axis pins search_path", async () => {
    const r = await c.query(
      `SELECT p.proname, p.proconfig FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'axis'`,
    );
    expect(r.rows.length).toBeGreaterThanOrEqual(8);
    for (const row of r.rows) {
      expect(JSON.stringify(row.proconfig), row.proname).toMatch(/search_path=pg_catalog, pg_temp/);
    }
  });

  it("forging a chain via a hostile search_path still fails", async () => {
    const e = await code(
      asApp(c, D, async (x) => {
        await x.query("SET LOCAL search_path = pg_temp, public");
        await x.query(
          `INSERT INTO audit_events (tenant_id, seq, id, ts, trace_id, actor_type, actor_id, blueprint_name, blueprint_version,
             policy_version, enforcement_point, action, decision, inputs_hash, outputs_hash, prev_hash, hash)
           VALUES ($1, 51, gen_random_uuid(), now(), $2, 'system', 's', 'b', '1', 'p', 'admin', 'a', 'ALLOW', $3, $3, $3, $3)`,
          [D, "a".repeat(32), H("f")],
        );
      }),
    );
    expect(e).toBe("23514");
  });
});

describe("audit hash is reproducible from database rows (review finding 5)", () => {
  it("events sealed by the reference implementation verify after a DB round trip", async () => {
    const t = "99999999-9999-4999-8999-999999999999";
    await c.query(
      "INSERT INTO tenants (id, slug, name, region) VALUES ($1, 'tenant-rt', 'rt', 'us')",
      [t],
    );
    const sealed: AuditEvent[] = [];
    for (let i = 1; i <= 3; i++) {
      sealed.push(
        sealEvent(
          {
            schema_version: 1,
            id: `00000000-0000-4000-8000-00000000000${i}`,
            tenant_id: t,
            ts: `2026-01-01T00:00:0${i}.123Z`,
            trace_id: "a".repeat(32),
            actor: { type: "agent", id: "claims-triage", pid: PID1 },
            blueprint: { name: "claims-triage", version: "1.0.0" },
            policy_version: "baseline-deny@1.0.0",
            enforcement_point: "tool_call",
            action: "lookup-policy",
            decision: i === 2 ? "DENY" : "ALLOW",
            ...(i === 2 ? { reason: "over cap" } : {}),
            inputs_hash: H("b"),
            outputs_hash: H("c"),
          },
          sealed[i - 2],
        ),
      );
    }
    for (const e of sealed) {
      await asApp(c, t, (x) =>
        x.query(
          `INSERT INTO audit_events (tenant_id, seq, id, ts, trace_id, actor_type, actor_id, actor_pid, blueprint_name,
             blueprint_version, policy_version, enforcement_point, action, decision, reason, inputs_hash, outputs_hash, prev_hash, hash)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
          [
            t,
            e.seq,
            e.id,
            e.ts,
            e.trace_id,
            e.actor.type,
            e.actor.id,
            e.actor.pid,
            e.blueprint.name,
            e.blueprint.version,
            e.policy_version,
            e.enforcement_point,
            e.action,
            e.decision,
            e.reason ?? null,
            e.inputs_hash,
            e.outputs_hash,
            e.prev_hash,
            e.hash,
          ],
        ),
      );
    }
    const rows = await asApp(c, t, (x) => x.query("SELECT * FROM audit_events ORDER BY seq"));
    const rebuilt: AuditEvent[] = rows.rows.map((r) => ({
      schema_version: 1,
      id: r.id,
      tenant_id: r.tenant_id,
      seq: Number(r.seq),
      ts: (r.ts as Date).toISOString(),
      trace_id: r.trace_id,
      actor: { type: r.actor_type, id: r.actor_id, ...(r.actor_pid ? { pid: r.actor_pid } : {}) },
      blueprint: { name: r.blueprint_name, version: r.blueprint_version },
      policy_version: r.policy_version,
      enforcement_point: r.enforcement_point,
      action: r.action,
      decision: r.decision,
      ...(r.reason ? { reason: r.reason } : {}),
      inputs_hash: r.inputs_hash,
      outputs_hash: r.outputs_hash,
      prev_hash: r.prev_hash,
      hash: r.hash,
    }));
    expect(verifyChain(rebuilt)).toEqual({ ok: true, length: 3 });
  });
});

describe("state guards (review finding 6)", () => {
  it("run_events sequence must be gapless per run", async () => {
    const ins = (seq: number) =>
      asApp(c, D, (x) =>
        x.query(
          "INSERT INTO run_events (tenant_id, run_id, sequence, type, pid) VALUES ($1, $2, $3, 't', $4)",
          [D, runD, seq, PID1],
        ),
      );
    // seed already inserted sequence 1
    expect(await code(ins(5))).toBe("23514");
    expect(await code(ins(1))).toBe("23514");
    expect(await code(ins(2))).toBeUndefined();
    expect(await code(ins(4))).toBe("23514");
  });

  it("terminated processes and runs are absorbing", async () => {
    expect(
      await code(
        asApp(c, D, (x) =>
          x.query("UPDATE processes SET state = 'terminated', exit_reason = 'completed'"),
        ),
      ),
    ).toBeUndefined();
    expect(
      await code(
        asApp(c, D, (x) => x.query("UPDATE processes SET state = 'running', exit_reason = NULL")),
      ),
    ).toBe("23514");
    expect(
      await code(
        asApp(c, D, (x) =>
          x.query(
            "UPDATE runs SET state = 'terminated', exit_reason = 'completed', finished_at = now()",
          ),
        ),
      ),
    ).toBeUndefined();
    expect(await code(asApp(c, D, (x) => x.query("UPDATE runs SET state = 'running'")))).toBe(
      "23514",
    );
  });

  it("process identity columns are immutable", async () => {
    expect(await code(asApp(c, E, (x) => x.query("UPDATE processes SET ppid = $1", [PID2])))).toBe(
      "23514",
    );
    expect(
      await code(asApp(c, E, (x) => x.query("UPDATE runs SET blueprint_version = '9.9.9'"))),
    ).toBe("23514");
  });

  it("approvals: SLA and roles are immutable, decisions are complete and final", async () => {
    const upd = (sql: string, params: unknown[] = []) =>
      code(asApp(c, E, (x) => x.query(sql, params)));
    expect(await upd("UPDATE approvals SET sla_deadline = now() + interval '1 year'")).toBe(
      "23514",
    );
    expect(await upd("UPDATE approvals SET roles = '{anyone}'")).toBe("23514");
    expect(await upd("UPDATE approvals SET status = 'approved'")).toBe("23514"); // no decided_by/at
    expect(
      await upd("UPDATE approvals SET status = 'approved', decided_by = 'u1', decided_at = now()"),
    ).toBeUndefined();
    expect(
      await upd("UPDATE approvals SET status = 'rejected', decided_by = 'u2', decided_at = now()"),
    ).toBe("23514");
  });

  it("blueprint version risk_level must match the ABL document", async () => {
    const e = await code(
      c.query(
        `INSERT INTO blueprint_versions (tenant_id, blueprint_id, version, risk_level, abl, content_hash)
         SELECT tenant_id, id, '3.0.0', 'minimal', '{"spec":{"riskClassification":{"level":"high"}}}', $2 FROM blueprints WHERE tenant_id = $1`,
        [D, H("d")],
      ),
    );
    expect(e).toBe("23514");
  });
});

describe("cross-tenant existence leaks (review finding 3)", () => {
  it("the same API key prefix may exist in two tenants", async () => {
    const ins = (t: string) =>
      asApp(c, t, (x) =>
        x.query(
          "INSERT INTO api_keys (tenant_id, name, prefix, key_hash) VALUES ($1, 'k2', 'pre_shared', '\\x02')",
          [t],
        ),
      );
    await ins(D);
    await ins(E);
  });
});

describe("documented limitation (review finding 2): tenant scope is a GUC", () => {
  // ADR-0008: RLS protects against forgotten filters and cross-tenant bugs, NOT against a fully compromised
  // axis_app session, which can set the GUC to any tenant. Per-tenant credentials are required for regulated/dedicated tiers.
  // If this test starts failing, update ADR-0008 and docs/security.
  it("a compromised app session can switch tenant with set_config", async () => {
    const n = await asApp(c, D, async (x) => {
      await x.query("SELECT set_config('axis.tenant_id', $1, true)", [E]);
      return (await x.query("SELECT count(*)::int AS n FROM api_keys WHERE tenant_id = $1", [E]))
        .rows[0].n as number;
    });
    expect(n).toBeGreaterThan(0);
  });
});
