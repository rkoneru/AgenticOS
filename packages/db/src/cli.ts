import pg from "pg";
import { migrate } from "./index.js";

const url = process.env["DATABASE_URL"];
if (!url) {
  console.error("DATABASE_URL (owner role) is required");
  process.exit(1);
}
const client = new pg.Client({ connectionString: url });
await client.connect();
try {
  const applied = await migrate(client);
  console.log(applied.length ? `applied: ${applied.join(", ")}` : "up to date");
} finally {
  await client.end();
}
