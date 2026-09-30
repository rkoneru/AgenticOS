import { randomBytes } from "node:crypto";
import pg from "pg";
import type { TestProject } from "vitest/node";
import { migrate } from "../src/index.js";

declare module "vitest" {
  export interface ProvidedContext {
    dbUrl: string;
  }
}

/** Creates a fresh database per test run and migrates it. Requires PG_ADMIN_URL (see infra/scripts/with-pg.sh). */
export default async function setup(project: TestProject): Promise<() => Promise<void>> {
  const admin = process.env["PG_ADMIN_URL"];
  if (!admin)
    throw new Error("PG_ADMIN_URL is required; run via `pnpm test` / infra/scripts/with-pg.sh");
  const name = `axis_test_${randomBytes(4).toString("hex")}`;
  const adminClient = new pg.Client({ connectionString: admin });
  await adminClient.connect();
  await adminClient.query(`CREATE DATABASE ${name}`);
  const url = new URL(admin);
  url.pathname = `/${name}`;
  const owner = new pg.Client({ connectionString: url.toString() });
  await owner.connect();
  await migrate(owner);
  await owner.end();
  project.provide("dbUrl", url.toString());
  return async () => {
    await adminClient.query(`DROP DATABASE ${name} WITH (FORCE)`);
    await adminClient.end();
  };
}
