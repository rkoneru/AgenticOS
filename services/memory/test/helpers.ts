import { randomBytes, randomUUID } from "node:crypto";
import pg from "pg";
import { inject } from "vitest";
import { HashEmbedder, PgMemoryService, type Embedder, type Principal } from "../src/index.js";

export const ROLE = "axis_app";
export const hex = (n: number): string => randomBytes(n / 2).toString("hex");

export const newPool = (max = 10): pg.Pool =>
  new pg.Pool({ connectionString: inject("dbUrl"), max });

/** Owner connection: bypasses nothing under FORCE RLS for the app role, but is used for seeding and raw inspection. */
export async function adminClient(): Promise<pg.Client> {
  const c = new pg.Client({ connectionString: inject("dbUrl") });
  await c.connect();
  return c;
}

export async function newTenant(admin: pg.Client, phi = false): Promise<string> {
  const id = randomUUID();
  await admin.query(
    "INSERT INTO tenants (id, slug, name, region, phi_mode) VALUES ($1, $2, $2, 'us-east-1', $3)",
    [id, `t-${hex(10)}`, phi],
  );
  return id;
}

export const who = (id: string, ...groups: string[]): Principal => ({ id, groups });

/** Embedder wrapper recording every text it was asked to embed. */
export class SpyEmbedder implements Embedder {
  readonly seen: string[] = [];
  private readonly inner = new HashEmbedder();
  readonly id = this.inner.id;
  readonly dimensions = this.inner.dimensions;
  embed(texts: readonly string[]): Promise<number[][]> {
    this.seen.push(...texts);
    return this.inner.embed(texts);
  }
}

export function newService(
  pool: pg.Pool,
  over: Partial<ConstructorParameters<typeof PgMemoryService>[0]> = {},
): PgMemoryService {
  return new PgMemoryService({ pool, embedder: new HashEmbedder(), role: ROLE, ...over });
}
