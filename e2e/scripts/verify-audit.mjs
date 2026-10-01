// usage: node verify-audit.mjs <db-url> <tenant-id>  -> {verdict, events[]} for the tenant's audit chain
import { PgAuditLog } from "@axis/audit";
import pg from "pg";

const [url, tenant] = process.argv.slice(2);
const pool = new pg.Pool({ connectionString: url });
try {
  const log = new PgAuditLog({ pool, role: "axis_app" });
  const verdict = await log.verify(tenant);
  const events = await log.listEvents(tenant, { limit: 1000 });
  console.log(
    JSON.stringify({
      verdict,
      events: events.map((e) => ({
        id: e.id,
        seq: e.seq,
        decision: e.decision,
        action: e.action,
        enforcement_point: e.enforcement_point,
        reason: e.reason ?? null,
        policy_version: e.policy_version,
        trace_id: e.trace_id,
        actor: e.actor,
        blueprint: e.blueprint,
      })),
    }),
  );
} finally {
  await pool.end();
}
