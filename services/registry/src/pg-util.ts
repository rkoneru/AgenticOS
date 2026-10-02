import type { ClientBase, PoolClient } from "pg";

export interface PgPoolLike {
  connect(): Promise<PoolClient>;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface TxContext {
  /** Tenant of the transaction; `null` = none set (anonymous: RLS then exposes public rows only). */
  tenantId: string | null;
  /** Marketplace platform paths only (see migration 0021). */
  platform?: boolean;
  /** Tests only: `SET LOCAL ROLE` (production connects as axis_app). */
  role?: string;
}

/** One transaction with the tenant (and optionally platform flag) set transaction-locally. The tenant comes from the caller's credential. */
export async function inTx<T>(
  pool: PgPoolLike,
  ctx: TxContext,
  fn: (c: ClientBase) => Promise<T>,
): Promise<T> {
  if (ctx.tenantId !== null && !UUID_RE.test(ctx.tenantId))
    throw new Error("tenantId must be a UUID");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    try {
      if (ctx.role) await client.query(`SET LOCAL ROLE ${client.escapeIdentifier(ctx.role)}`);
      if (ctx.tenantId !== null)
        await client.query("SELECT axis.set_tenant($1::uuid)", [ctx.tenantId]);
      if (ctx.platform) await client.query("SELECT axis.set_platform(true)");
      const out = await fn(client);
      await client.query("COMMIT");
      return out;
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    }
  } finally {
    client.release();
  }
}

/** Postgres error classification shared by the stores. */
export const pgCode = (err: unknown): string | undefined =>
  typeof err === "object" && err !== null ? (err as { code?: string }).code : undefined;
export const pgConstraint = (err: unknown): string =>
  typeof err === "object" && err !== null
    ? ((err as { constraint?: string }).constraint ?? "")
    : "";
