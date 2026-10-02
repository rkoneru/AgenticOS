import { randomBytes, randomUUID } from "node:crypto";
import pg from "pg";
import { inject } from "vitest";
import { HmacSealSigner, MemoryUsageLedger, PgUsageLedger, type UsageInput } from "../src/index.js";

export const ROLE = "axis_app";
export const hex = (n: number): string => randomBytes(n / 2).toString("hex");
export const SEAL_KEY = Buffer.alloc(32, 7);
export const signer = (): HmacSealSigner => new HmacSealSigner(SEAL_KEY);

export class Clock {
  constructor(public t: Date) {}
  now = (): Date => new Date(this.t.getTime());
  set(iso: string): void {
    this.t = new Date(iso);
  }
}

export const newPool = (max = 10): pg.Pool =>
  new pg.Pool({ connectionString: inject("dbUrl"), max });

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

export const memLedger = (clock: Clock): MemoryUsageLedger =>
  new MemoryUsageLedger({ signer: signer(), now: clock.now });

export const pgLedger = (pool: pg.Pool, clock: Clock): PgUsageLedger =>
  new PgUsageLedger({ pool, signer: signer(), role: ROLE, now: clock.now });

export const usage = (tenantId: string, over: Partial<UsageInput> = {}): UsageInput => ({
  tenantId,
  idempotencyKey: `k-${randomUUID()}`,
  meter: "tokens_in",
  quantity: 100n,
  eventTime: new Date("2026-09-10T12:00:00Z"),
  source: "test",
  dimensions: { agent: "a1", run: "r1", model: "m", model_class: "standard" },
  ...over,
});
