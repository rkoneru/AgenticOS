import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { ClientBase } from "pg";

export const MIGRATIONS_DIR = fileURLToPath(new URL("../migrations/", import.meta.url));

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface Migration {
  version: string;
  sql: string;
  checksum: string;
}

export function loadMigrations(dir: string = MIGRATIONS_DIR): Migration[] {
  return readdirSync(dir)
    .filter((f) => f.endsWith(".sql"))
    .sort()
    .map((f) => {
      const sql = readFileSync(`${dir}${f}`, "utf8");
      return {
        version: f.replace(/\.sql$/, ""),
        sql,
        checksum: createHash("sha256").update(sql).digest("hex"),
      };
    });
}

/**
 * Apply pending migrations in order, each in its own transaction. Already-applied migrations are
 * verified by checksum: editing an applied migration is an error (migrations are append-only, ADR-0007).
 * Must run as the schema owner (never as axis_app). Returns the versions applied by this call.
 */
export async function migrate(
  client: ClientBase,
  migrations: Migration[] = loadMigrations(),
): Promise<string[]> {
  await client.query(
    `CREATE TABLE IF NOT EXISTS schema_migrations (
       version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`,
  );
  await client.query("SELECT pg_advisory_lock(727274)"); // one migrator at a time
  try {
    const { rows } = await client.query<{ version: string; checksum: string }>(
      "SELECT version, checksum FROM schema_migrations",
    );
    const applied = new Map(rows.map((r) => [r.version, r.checksum]));
    const done: string[] = [];
    for (const m of migrations) {
      const prior = applied.get(m.version);
      if (prior !== undefined) {
        if (prior !== m.checksum)
          throw new Error(`migration ${m.version} was modified after being applied`);
        continue;
      }
      await client.query("BEGIN");
      try {
        await client.query(m.sql);
        await client.query("INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)", [
          m.version,
          m.checksum,
        ]);
        await client.query("COMMIT");
      } catch (err) {
        await client.query("ROLLBACK");
        throw err;
      }
      done.push(m.version);
    }
    return done;
  } finally {
    await client.query("SELECT pg_advisory_unlock(727274)");
  }
}

/**
 * Run `fn` in a transaction scoped to one tenant. The tenant is set transaction-locally, so it cannot leak
 * across pooled connections. `role` (tests only) switches to a non-superuser role for the transaction;
 * production connects as axis_app directly.
 */
export async function withTenant<T>(
  client: ClientBase,
  tenantId: string,
  fn: (client: ClientBase) => Promise<T>,
  opts: { role?: string } = {},
): Promise<T> {
  if (!UUID_RE.test(tenantId)) throw new Error("withTenant: tenantId must be a UUID");
  await client.query("BEGIN");
  try {
    if (opts.role) await client.query(`SET LOCAL ROLE ${client.escapeIdentifier(opts.role)}`);
    await client.query("SELECT axis.set_tenant($1::uuid)", [tenantId]);
    const out = await fn(client);
    await client.query("COMMIT");
    return out;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  }
}
