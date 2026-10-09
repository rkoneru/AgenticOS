/**
 * Audit chain benchmark: append throughput (single chain, concurrent callers on ONE tenant, and many tenants) and the time to verify
 * N events, on the real Postgres of the stack. Usage: tsx src/audit-bench.ts <db-url> <events> [concurrency] [tenants]
 * Writes JSON to stdout. NOT a unit-tested module (it needs Postgres): `make loadtest` runs it.
 */
import { randomBytes, randomUUID } from "node:crypto";
import { PgAuditLog, type AuditInput } from "@axis/audit";
import { sealEvent, type AuditEvent, type UnsealedEvent } from "@axis/contracts";
import { withTenant } from "@axis/db";
import pg from "pg";
import { Histogram } from "./hdr.js";

const hex = (n: number): string => randomBytes(n / 2).toString("hex");

export function input(tenantId: string, i: number): AuditInput {
  return {
    schema_version: 1,
    tenant_id: tenantId,
    trace_id: hex(32),
    actor: { type: "agent", id: "bench", pid: "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV" },
    blueprint: { name: "bench", version: "1.0.0" },
    policy_version: "bench@1.0.0",
    enforcement_point: "tool_call",
    action: `lookup-${i % 7}`,
    decision: "ALLOW",
    inputs_hash: hex(64),
    outputs_hash: hex(64),
  };
}

export interface AuditBenchResult {
  events: number;
  concurrency: number;
  tenants: number;
  appendSeconds: number;
  appendsPerSec: number;
  appendLatencyUs: ReturnType<Histogram["summary"]>;
  errors: Record<string, number>;
  verifySeconds: number;
  verifyEventsPerSec: number;
  verifyOk: boolean;
}

export async function newTenant(admin: pg.Client): Promise<string> {
  const id = randomUUID();
  await admin.query(
    "INSERT INTO tenants (id, slug, name, region) VALUES ($1, $2, $2, 'us-east-1')",
    [id, `bench-${hex(8)}`],
  );
  return id;
}

export async function runAuditBench(
  adminUrl: string,
  appUrl: string,
  events: number,
  concurrency: number,
  tenantCount: number,
): Promise<AuditBenchResult> {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  const tenants: string[] = [];
  for (let i = 0; i < tenantCount; i++) tenants.push(await newTenant(admin));
  await admin.end();
  const pool = new pg.Pool({ connectionString: appUrl, max: Math.max(8, concurrency + 2) });
  const log = new PgAuditLog({ pool, role: "axis_app" });
  const hist = new Histogram();
  const errors: Record<string, number> = {};
  let next = 0;
  const t0 = performance.now();
  const worker = async (w: number): Promise<void> => {
    for (;;) {
      const i = next++;
      if (i >= events) return;
      const tenant = tenants[(i + w) % tenants.length] as string;
      const s = performance.now();
      try {
        await log.append(input(tenant, i));
        hist.record((performance.now() - s) * 1000);
      } catch (e) {
        const k = e instanceof Error ? e.name : "error";
        errors[k] = (errors[k] ?? 0) + 1;
      }
    }
  };
  await Promise.all(Array.from({ length: concurrency }, (_, w) => worker(w)));
  const appendSeconds = (performance.now() - t0) / 1000;
  const v0 = performance.now();
  let verified = 0;
  let ok = true;
  for (const t of tenants) {
    const verdict = await log.verify(t);
    ok &&= verdict.ok;
    if (verdict.ok) verified += verdict.length;
  }
  const verifySeconds = (performance.now() - v0) / 1000;
  await pool.end();
  return {
    events,
    concurrency,
    tenants: tenantCount,
    appendSeconds: round(appendSeconds),
    appendsPerSec: round(hist.count / appendSeconds),
    appendLatencyUs: hist.summary(),
    errors,
    verifySeconds: round(verifySeconds),
    verifyEventsPerSec: round(verified / verifySeconds),
    verifyOk: ok,
  };
}

const COLS = `tenant_id, seq, id, ts, trace_id, actor_type, actor_id, actor_pid, blueprint_name, blueprint_version,
  policy_version, enforcement_point, action, decision, reason, inputs_hash, outputs_hash, prev_hash, hash`;

/**
 * Bulk-seed a valid chain of ``n`` events for one tenant: events are sealed with the SAME ``sealEvent`` the audit service uses and inserted
 * in batches as the app role, so every row still passes the database chain guard. Used ONLY to build a large chain quickly for the
 * verify-time and DR measurements; append throughput is measured through ``PgAuditLog.append`` (above), never through this.
 */
export async function seedChain(pool: pg.Pool, tenantId: string, n: number): Promise<AuditEvent> {
  let prev: AuditEvent | undefined;
  const base = Date.parse("2026-01-01T00:00:00Z");
  for (let from = 0; from < n; from += 500) {
    const rows: AuditEvent[] = [];
    for (let i = from; i < Math.min(n, from + 500); i++) {
      const e: UnsealedEvent = {
        schema_version: 1,
        id: randomUUID(),
        tenant_id: tenantId,
        ts: new Date(base + i * 1000).toISOString(),
        trace_id: hex(32),
        actor: { type: "agent", id: "seed", pid: "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV" },
        blueprint: { name: "seed", version: "1.0.0" },
        policy_version: "seed@1.0.0",
        enforcement_point: "tool_call",
        action: `lookup-${i % 7}`,
        decision: i % 11 === 0 ? "DENY" : "ALLOW",
        inputs_hash: hex(64),
        outputs_hash: hex(64),
      };
      prev = sealEvent(e, prev);
      rows.push(prev);
    }
    const client = await pool.connect();
    try {
      await withTenant(
        client,
        tenantId,
        async (c) => {
          const params: unknown[] = [];
          const tuples = rows.map((r, k) => {
            params.push(
              r.tenant_id,
              r.seq,
              r.id,
              r.ts,
              r.trace_id,
              r.actor.type,
              r.actor.id,
              r.actor.pid ?? null,
              r.blueprint.name,
              r.blueprint.version,
              r.policy_version,
              r.enforcement_point,
              r.action,
              r.decision,
              r.reason ?? null,
              r.inputs_hash,
              r.outputs_hash,
              r.prev_hash,
              r.hash,
            );
            const o = k * 19;
            return `(${Array.from({ length: 19 }, (_, j) => `$${o + j + 1}`).join(",")})`;
          });
          await c.query(`INSERT INTO audit_events (${COLS}) VALUES ${tuples.join(",")}`, params);
        },
        { role: "axis_app" },
      );
    } finally {
      client.release();
    }
  }
  return prev as AuditEvent;
}

export interface VerifyBenchResult {
  events: number;
  seedSeconds: number;
  verifySeconds: number;
  verifyOk: boolean;
  verifySecondsPer100k: number;
}

export async function runVerifyBench(adminUrl: string, events: number): Promise<VerifyBenchResult> {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  const tenant = await newTenant(admin);
  await admin.end();
  const pool = new pg.Pool({ connectionString: adminUrl, max: 4 });
  const s0 = performance.now();
  await seedChain(pool, tenant, events);
  const seedSeconds = (performance.now() - s0) / 1000;
  const log = new PgAuditLog({ pool, role: "axis_app" });
  const v0 = performance.now();
  const verdict = await log.verify(tenant);
  const verifySeconds = (performance.now() - v0) / 1000;
  await pool.end();
  return {
    events,
    seedSeconds: round(seedSeconds),
    verifySeconds: round(verifySeconds),
    verifyOk: verdict.ok && verdict.length === events,
    verifySecondsPer100k: round((verifySeconds / events) * 100_000),
  };
}

const round = (x: number): number => Math.round(x * 100) / 100;

if (process.argv[1]?.endsWith("audit-bench.ts") || process.argv[1]?.endsWith("audit-bench.js")) {
  const [adminUrl, events = "10000", concurrency = "1", tenants = "1"] = process.argv.slice(2);
  if (!adminUrl)
    throw new Error("usage: audit-bench <admin-db-url> <events> [concurrency] [tenants]");
  if (concurrency === "verify") {
    console.log(JSON.stringify(await runVerifyBench(adminUrl, Number(events))));
    process.exit(0);
  }
  const appUrl = adminUrl; // the benchmark connects as the owner but SETs ROLE axis_app inside each transaction (PgAuditLog role option)
  console.log(
    JSON.stringify(
      await runAuditBench(adminUrl, appUrl, Number(events), Number(concurrency), Number(tenants)),
    ),
  );
}
