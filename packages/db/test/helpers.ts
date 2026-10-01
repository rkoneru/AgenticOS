import pg from "pg";
import { inject } from "vitest";
import { withTenant } from "../src/index.js";

export const A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
export const B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
export const ZERO = "0".repeat(64);
export const H = (c: string) => c.repeat(64);

export async function connect(): Promise<pg.Client> {
  const c = new pg.Client({ connectionString: inject("dbUrl") });
  await c.connect();
  return c;
}

/** Run as the non-superuser app role scoped to a tenant (the production access path). */
export const asApp = <T>(c: pg.Client, tenant: string, fn: (c: pg.Client) => Promise<T>) =>
  withTenant(c, tenant, (x) => fn(x as pg.Client), { role: "axis_app" });

/** App role with NO tenant set. */
export async function asAppNoTenant<T>(c: pg.Client, fn: (c: pg.Client) => Promise<T>): Promise<T> {
  await c.query("BEGIN");
  try {
    await c.query("SET LOCAL ROLE axis_app");
    const out = await fn(c);
    await c.query("COMMIT");
    return out;
  } catch (e) {
    await c.query("ROLLBACK");
    throw e;
  }
}

export const PID1 = "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV";
export const PID2 = "axp_01ARZ3NDEKTSV4RRFFQ69G5FAW";

/** Seeds one row in every tenant-owned table for `t` (as the owner/superuser). Returns ids for assertions. */
export async function seedTenant(
  c: pg.Client,
  t: string,
  slug: string,
): Promise<{ runId: string }> {
  const q = (sql: string, params: unknown[] = []) => c.query(sql, params);
  await q("INSERT INTO tenants (id, slug, name, region) VALUES ($1, $2, $2, 'us-east-1')", [
    t,
    slug,
  ]);
  await q("INSERT INTO members (tenant_id, user_ref, email, role) VALUES ($1, $2, $3, 'admin')", [
    t,
    `u-${slug}`,
    `${slug}@x.io`,
  ]);
  await q(
    "INSERT INTO api_keys (tenant_id, name, prefix, key_hash) VALUES ($1, 'k', $2, '\\x01')",
    [t, `pre_${slug}`],
  );
  await q(
    "INSERT INTO model_credentials (tenant_id, provider, label, secret_ref) VALUES ($1, 'anthropic', 'main', 'kms://x')",
    [t],
  );
  const bp = await q(
    "INSERT INTO blueprints (tenant_id, name) VALUES ($1, 'agent-one') RETURNING id",
    [t],
  );
  await q(
    "INSERT INTO blueprint_versions (tenant_id, blueprint_id, version, risk_level, abl, content_hash) VALUES ($1, $2, '1.0.0', 'minimal', '{}', $3)",
    [t, bp.rows[0].id, H("a")],
  );
  const pp = await q(
    "INSERT INTO policy_packs (tenant_id, name) VALUES ($1, 'baseline') RETURNING id",
    [t],
  );
  await q(
    "INSERT INTO policy_pack_versions (tenant_id, pack_id, version, source, rego, content_hash) VALUES ($1, $2, '1.0.0', '{}', 'package x', $3)",
    [t, pp.rows[0].id, H("b")],
  );
  const run = await q(
    "INSERT INTO runs (tenant_id, blueprint_name, blueprint_version, trace_id) VALUES ($1, 'agent-one', '1.0.0', $2) RETURNING id",
    [t, "a".repeat(32)],
  );
  const runId = run.rows[0].id as string;
  await q("INSERT INTO processes (tenant_id, pid, run_id) VALUES ($1, $2, $3)", [t, PID1, runId]);
  await q(
    "INSERT INTO run_events (tenant_id, run_id, sequence, type, pid) VALUES ($1, $2, 1, 'state_transition', $3)",
    [t, runId, PID1],
  );
  await q(
    "INSERT INTO approvals (tenant_id, run_id, pid, action, roles, sla_deadline) VALUES ($1, $2, $3, 'payments', '{finance}', now() + interval '1 hour')",
    [t, runId, PID1],
  );
  await q("INSERT INTO kill_switches (tenant_id, scope, engaged) VALUES ($1, 'tenant', false)", [
    t,
  ]);
  await q(
    "INSERT INTO budgets (tenant_id, scope, metric, period, soft, hard) VALUES ($1, 'tenant', 'tokens', 'day', 10, 20)",
    [t],
  );
  await appendAudit(c, t, 1, ZERO, H("1"));
  await q(
    "INSERT INTO audit_checkpoints (tenant_id, seq, hash, ts, signature) VALUES ($1, 1, $2, now(), 'c2ln')",
    [t, H("1")],
  );
  const kb = await q(
    "INSERT INTO knowledge_bases (tenant_id, name) VALUES ($1, 'handbook') RETURNING id",
    [t],
  );
  await q(
    "INSERT INTO memory_documents (tenant_id, kb_id, content_hash, acl, acl_key, created_by) VALUES ($1, $2, $3, '{}', '{}', 'seed')",
    [t, kb.rows[0].id, H("d")],
  );
  await q(
    "INSERT INTO memory_chunks (tenant_id, kb_id, scope, content, embedding) VALUES ($1, $2, 'kb', 'hello', $3::vector)",
    [t, kb.rows[0].id, `[${[1, ...Array<number>(1535).fill(0)].join(",")}]`],
  );
  return { runId };
}

export function appendAudit(c: pg.Client, t: string, seq: number, prev: string, hash: string) {
  return c.query(
    `INSERT INTO audit_events (tenant_id, seq, id, ts, trace_id, actor_type, actor_id, actor_pid, blueprint_name,
       blueprint_version, policy_version, enforcement_point, action, decision, inputs_hash, outputs_hash, prev_hash, hash)
     VALUES ($1, $2, gen_random_uuid(), now(), $3, 'agent', 'agent-one', $4, 'agent-one', '1.0.0', 'baseline@1.0.0',
       'tool_call', 'lookup', 'ALLOW', $5, $5, $6, $7)`,
    [t, seq, "a".repeat(32), PID1, H("c"), prev, hash],
  );
}
