import { randomBytes } from "node:crypto";
import { migrate } from "@axis/db";
import pg from "pg";
import type { TestProject } from "vitest/node";

declare module "vitest" {
  export interface ProvidedContext {
    dbUrl: string;
    dbUrl2: string;
  }
}

/** Creates two fresh, migrated databases per test run (the second proves dedicated-database routing). Requires PG_ADMIN_URL. */
export default async function setup(project: TestProject): Promise<() => Promise<void>> {
  const admin = process.env["PG_ADMIN_URL"];
  if (!admin) throw new Error("PG_ADMIN_URL is required; run via `pnpm test` / infra/scripts/with-pg.sh");
  const adminClient = new pg.Client({ connectionString: admin });
  await adminClient.connect();
  const names: string[] = [];
  const urls: string[] = [];
  for (const tag of ["a", "b"]) {
    const name = `axis_cp_test_${tag}_${randomBytes(4).toString("hex")}`;
    names.push(name);
    await adminClient.query(`CREATE DATABASE ${name}`);
    const url = new URL(admin);
    url.pathname = `/${name}`;
    const owner = new pg.Client({ connectionString: url.toString() });
    await owner.connect();
    await migrate(owner);
    await owner.end();
    urls.push(url.toString());
  }
  project.provide("dbUrl", urls[0] as string);
  project.provide("dbUrl2", urls[1] as string);
  return async () => {
    for (const n of names) await adminClient.query(`DROP DATABASE ${n} WITH (FORCE)`);
    await adminClient.end();
  };
}
