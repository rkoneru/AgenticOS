import { randomBytes, randomUUID } from "node:crypto";
import type { AuditEvent } from "@axis/contracts";
import pg from "pg";
import { inject } from "vitest";
import type { AuditInput, PgPoolLike } from "../src/index.js";

export const ROLE = "axis_app";
export const PID = "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV";

export const hex = (n: number): string => randomBytes(n / 2).toString("hex");

export function ev(tenantId: string, over: Partial<AuditInput> = {}): AuditInput {
  return {
    schema_version: 1,
    tenant_id: tenantId,
    trace_id: hex(32),
    actor: { type: "agent", id: "agent-one", pid: PID },
    blueprint: { name: "agent-one", version: "1.0.0" },
    policy_version: "baseline@1.0.0",
    enforcement_point: "tool_call",
    action: "lookup",
    decision: "ALLOW",
    inputs_hash: hex(64),
    outputs_hash: hex(64),
    ...over,
  };
}

export function newPool(max = 30): pg.Pool {
  return new pg.Pool({ connectionString: inject("dbUrl"), max });
}

/** Superuser/owner connection (bypasses RLS; used for seeding tenants and tampering, never by the code under test). */
export async function adminClient(): Promise<pg.Client> {
  const c = new pg.Client({ connectionString: inject("dbUrl") });
  await c.connect();
  return c;
}

export async function newTenant(admin: pg.Client): Promise<string> {
  const id = randomUUID();
  await admin.query(
    "INSERT INTO tenants (id, slug, name, region) VALUES ($1, $2, $2, 'us-east-1')",
    [id, `t-${hex(10)}`],
  );
  return id;
}

/** Run `fn` with the named audit_events trigger disabled (tamper tests only), re-enabled afterwards. */
export async function withoutTrigger<T>(
  admin: pg.Client,
  trigger: string,
  fn: () => Promise<T>,
): Promise<T> {
  await admin.query(`ALTER TABLE audit_events DISABLE TRIGGER ${trigger}`);
  try {
    return await fn();
  } finally {
    await admin.query(`ALTER TABLE audit_events ENABLE TRIGGER ${trigger}`);
  }
}

/** Pool wrapper counting queries that match `needle` (the client is unwrapped again on release). */
export function countingPool(pool: pg.Pool, needle: RegExp): PgPoolLike & { count: () => number } {
  let n = 0;
  return {
    count: () => n,
    async connect() {
      const client = await pool.connect();
      const origQuery = client.query;
      const origRelease = client.release;
      const q = origQuery.bind(client) as (...a: unknown[]) => unknown;
      (client as unknown as { query: unknown }).query = (...a: unknown[]) => {
        if (typeof a[0] === "string" && needle.test(a[0])) n++;
        return q(...a);
      };
      client.release = (err?: Error | boolean) => {
        client.query = origQuery;
        client.release = origRelease;
        origRelease.call(client, err);
      };
      return client;
    },
  };
}

/** Pool wrapper that runs `after` once, right after the first query matching `needle` completes (forces interleavings). */
export function interleavePool(
  pool: pg.Pool,
  needle: RegExp,
  after: () => Promise<void>,
): PgPoolLike {
  let fired = false;
  return {
    async connect() {
      const client = await pool.connect();
      const origQuery = client.query;
      const origRelease = client.release;
      const q = origQuery.bind(client) as (...a: unknown[]) => Promise<unknown>;
      (client as unknown as { query: unknown }).query = async (...a: unknown[]) => {
        const r = await q(...a);
        if (!fired && typeof a[0] === "string" && needle.test(a[0])) {
          fired = true;
          await after();
        }
        return r;
      };
      client.release = (err?: Error | boolean) => {
        client.query = origQuery;
        client.release = origRelease;
        origRelease.call(client, err);
      };
      return client;
    },
  };
}

export const seqs = (events: AuditEvent[]): number[] => events.map((e) => e.seq);
