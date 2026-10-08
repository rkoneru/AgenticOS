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
  const eu = await q("INSERT INTO end_users (tenant_id) VALUES ($1) RETURNING id", [t]);
  await q(
    "INSERT INTO channel_identities (tenant_id, end_user_id, channel, external_id, verified_by) VALUES ($1, $2, 'slack', 'U1', 'provider')",
    [t, eu.rows[0].id],
  );
  await q(
    "INSERT INTO link_challenges (tenant_id, end_user_id, code_hash, expires_at) VALUES ($1, $2, $3, now())",
    [t, eu.rows[0].id, H("e")],
  );
  const conv = await q(
    "INSERT INTO conversations (tenant_id, end_user_id, agent_name, agent_version, last_channel) VALUES ($1, $2, 'a', '1', 'slack') RETURNING id",
    [t, eu.rows[0].id],
  );
  await q(
    "INSERT INTO conversation_threads (tenant_id, channel, thread_key, conversation_id) VALUES ($1, 'slack', 'C1:1.1', $2)",
    [t, conv.rows[0].id],
  );
  await q(
    "INSERT INTO conversation_messages (tenant_id, conversation_id, direction, channel, idempotency_key, content_mode, content_hash, size_bytes) VALUES ($1, $2, 'in', 'slack', 'k1', 'hash_only', $3, 1)",
    [t, conv.rows[0].id, H("f")],
  );
  await q(
    "INSERT INTO usage_events (tenant_id, idempotency_key, payload_hash, entry_type, meter, quantity, event_time, period_id, source) VALUES ($1, 'k1', $2, 'usage', 'tokens_in', 5, now(), '2026-09', 'seed')",
    [t, H("1")],
  );
  await q(
    "INSERT INTO billing_period_seals (tenant_id, period_id, seq, prev_seal_hash, seal_hash, signature, key_id, event_count, rows_digest, totals, closed_at) VALUES ($1, '2026-08', 1, $2, $3, 'sig', 'k', 0, $4, '{}', now())",
    [t, "0".repeat(64), H("2"), H("3")],
  );
  await q(
    "INSERT INTO usage_conflicts (tenant_id, idempotency_key, existing_payload_hash, offered_payload_hash, source) VALUES ($1, 'k1', $2, $3, 'seed')",
    [t, H("1"), H("4")],
  );
  const inv = await q(
    "INSERT INTO invoices (tenant_id, period_id, revision, plan_id, price_book, currency, lines, total_micro, invoice_hash) VALUES ($1, '2026-08', 1, 'p', 'pb@1', 'USD', '{}', 0, $2) RETURNING id",
    [t, H("5")],
  );
  await q(
    "INSERT INTO invoice_provider_links (tenant_id, invoice_id, provider, provider_invoice_id) VALUES ($1, $2, 'fake', 'in_1')",
    [t, inv.rows[0].id],
  );
  await q(
    "INSERT INTO memory_chunks (tenant_id, kb_id, scope, content, embedding) VALUES ($1, $2, 'kb', 'hello', $3::vector)",
    [t, kb.rows[0].id, `[${[1, ...Array<number>(1535).fill(0)].join(",")}]`],
  );
  // registry (0010): a PRIVATE namespace with one of everything, plus a separate public namespace (public rows are readable by every tenant by design)
  await q(
    "INSERT INTO registry_namespaces (namespace, tenant_id, normalized, created_at, created_by) VALUES ($1, $2, $1, now(), 'seed')",
    [`seedns-${slug}`, t],
  );
  await q(
    "INSERT INTO registry_keys (namespace, key_id, tenant_id, public_key, valid_from, created_at, created_by) VALUES ($1, $2, $3, $4, now(), now(), 'seed')",
    [`seedns-${slug}`, `k1-${H("a").slice(0, 32)}`, t, "A".repeat(43)],
  );
  await q(
    "INSERT INTO registry_names (namespace, name, tenant_id, normalized, created_at) VALUES ($1, 'seed-agent', $2, 'seedagent', now())",
    [`seedns-${slug}`, t],
  );
  await q(
    "INSERT INTO registry_versions (namespace, name, version, tenant_id, abl, content_hash, risk_level, signature, provenance, published_at, published_by) VALUES ($1, 'seed-agent', '1.0.0', $2, '{}', $3, 'minimal', '{}', '{}', now(), 'seed')",
    [`seedns-${slug}`, t, H("6")],
  );
  await q(
    "INSERT INTO registry_version_events (tenant_id, namespace, name, version, kind, reason, actor, at) VALUES ($1, $2, 'seed-agent', '1.0.0', 'deprecate', 'seed reason', 'seed', now())",
    [t, `seedns-${slug}`],
  );
  await q(
    "INSERT INTO registry_namespaces (namespace, tenant_id, normalized, created_at, created_by) VALUES ($1, $2, $1, now(), 'seed')",
    [`seedpub-${slug}`, t],
  );
  await q(
    "INSERT INTO registry_public_namespaces (namespace, tenant_id, listed_at, listed_by) VALUES ($1, $2, now(), 'seed')",
    [`seedpub-${slug}`, t],
  );
  await q(
    "INSERT INTO registry_names (namespace, name, tenant_id, normalized, created_at) VALUES ($1, 'released-agent', $2, 'releasedagent', now())",
    [`seedpub-${slug}`, t],
  );
  await q(
    "INSERT INTO registry_versions (namespace, name, version, tenant_id, abl, content_hash, risk_level, signature, provenance, published_at, published_by) VALUES ($1, 'released-agent', '1.0.0', $2, '{}', $3, 'minimal', '{}', '{}', now(), 'seed')",
    [`seedpub-${slug}`, t, H("7")],
  );
  await q(
    "INSERT INTO registry_public_versions (namespace, name, version, tenant_id, listed_at, listed_by) VALUES ($1, 'released-agent', '1.0.0', $2, now(), 'seed')",
    [`seedpub-${slug}`, t],
  );
  await q(
    "INSERT INTO marketplace_docs (tenant_id, coll, key, rev, data) VALUES ($1, 'publishers', 'self', 1, '{\"state\": \"pending\"}')",
    [t],
  );
  const mem = await q("SELECT id FROM members WHERE tenant_id = $1", [t]);
  const memberId = mem.rows[0].id as string;
  await q(
    "INSERT INTO sessions (tenant_id, member_id, refresh_hash, auth_method, expires_at) VALUES ($1, $2, decode($3, 'hex'), 'dev', now() + interval '1 day')",
    [t, memberId, H("1")],
  );
  const dir = await q(
    "INSERT INTO directories (tenant_id, name, token_prefix, token_hash) VALUES ($1, 'd', $2, decode($3, 'hex')) RETURNING id",
    [t, `scim_${slug}`, H("2")],
  );
  const grp = await q(
    "INSERT INTO scim_groups (tenant_id, directory_id, display_name) VALUES ($1, $2, 'g') RETURNING id",
    [t, dir.rows[0].id],
  );
  await q("INSERT INTO scim_group_members (tenant_id, group_id, member_id) VALUES ($1, $2, $3)", [
    t,
    grp.rows[0].id,
    memberId,
  ]);
  await q(
    "INSERT INTO directory_role_mappings (tenant_id, directory_id, group_name, role) VALUES ($1, $2, 'g', 'builder')",
    [t, dir.rows[0].id],
  );
  await q(
    "INSERT INTO identity_connections (tenant_id, idp_org_id, connection_type) VALUES ($1, $2, 'saml')",
    [t, `org_${slug}`],
  );
  await q("INSERT INTO verified_domains (tenant_id, domain) VALUES ($1, $2)", [
    t,
    `${slug}.example.com`,
  ]);
  await q(
    "INSERT INTO tenant_keys (tenant_id, version, kms_key_id, wrapped_dek) VALUES ($1, 1, 'k', '\\x01')",
    [t],
  );
  await q(
    "INSERT INTO policy_assignments (tenant_id, pack_id, version_id, activated_by) VALUES ($1, $2, (SELECT id FROM policy_pack_versions WHERE tenant_id = $1 LIMIT 1), 'seed')",
    [t, pp.rows[0].id],
  );
  await q("INSERT INTO tenant_settings (tenant_id) VALUES ($1)", [t]);
  await q("INSERT INTO tenant_placements (tenant_id) VALUES ($1)", [t]);
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
