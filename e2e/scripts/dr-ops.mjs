// Phase 9 D: the DR drill's database-side operations. usage: node dr-ops.mjs <seed|manifest|verify> '<json args>'
//   seed     {db_url, tenants:[uuid], out}                 memory entries + a SIGNED audit checkpoint per tenant (public key and checkpoints
//                                                           are written to ``out`` OUTSIDE the database: that is the tamper-evidence anchor)
//   manifest {db_url, tenants, out}                        row count + md5 per tenant-table and the audit head of each tenant
//   verify   {db_url, manifest, anchor, seal_key, refs, periods, mode}  every post-restore check; prints {ok, checks[]}
import { createPublicKey } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { AuditCheckpointer, PgAuditLog, PgCheckpointStore, generateEd25519 } from "@axis/audit";
import { HmacSealSigner, PgUsageLedger } from "@axis/billing";
import { withTenant } from "@axis/db";
import { HashEmbedder, PgMemoryService } from "@axis/memory";
import { PgRegistryStore, RegistryService, ServiceAudit } from "@axis/registry";
import pg from "pg";

const [cmd, raw] = process.argv.slice(2);
const a = JSON.parse(raw);
const pool = new pg.Pool({ connectionString: a.db_url, max: 4 });
pool.on("error", () => undefined);
const ROLE = "axis_app";

async function tenantTables() {
  const r = await pool.query(
    `SELECT table_name FROM information_schema.columns
      WHERE table_schema = 'public' AND column_name = 'tenant_id'
        AND table_name IN (SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE')
      ORDER BY table_name`,
  );
  return r.rows.map((x) => x.table_name);
}

async function manifest() {
  const tables = await tenantTables();
  const out = { tables: {}, heads: {} };
  const c = await pool.connect();
  try {
    await c.query("SET TimeZone = 'UTC'");
    for (const t of a.tenants) {
      out.tables[t] = {};
      for (const tbl of tables) {
        const r = await c.query(
          `SELECT count(*)::int AS n, coalesce(md5(string_agg(x::text, '|' ORDER BY x::text)), '') AS h FROM "${tbl}" x WHERE tenant_id = $1`,
          [t],
        );
        out.tables[t][tbl] = { n: r.rows[0].n, h: r.rows[0].h };
      }
      const h = await c.query(
        "SELECT seq::int AS seq, hash, ts FROM audit_events WHERE tenant_id=$1 ORDER BY seq DESC LIMIT 1",
        [t],
      );
      out.heads[t] = h.rows[0] ? { seq: h.rows[0].seq, hash: h.rows[0].hash } : null;
    }
  } finally {
    c.release();
  }
  return out;
}

async function seed() {
  const log = new PgAuditLog({ pool, role: ROLE });
  const mem = new PgMemoryService({ pool, embedder: new HashEmbedder(), role: ROLE });
  const { signer, publicKey } = generateEd25519();
  const cps = new AuditCheckpointer(log, new PgCheckpointStore({ pool, role: ROLE }), signer);
  const anchor = {
    public_key_pem: publicKey.export({ type: "spki", format: "pem" }),
    checkpoints: {},
  };
  for (const t of a.tenants) {
    for (let i = 0; i < 3; i++)
      await mem.write(t, {
        scope: "tenant",
        content: `dr drill memory entry ${i} for ${t}`,
        acl: { tenant: true },
        principal: { id: "dr-drill", groups: [] },
      });
    anchor.checkpoints[t] = await cps.createCheckpoint(t);
  }
  writeFileSync(a.out, JSON.stringify(anchor, null, 2));
  return { ok: true };
}

async function verify() {
  const checks = [];
  const add = (name, ok, detail = "") => checks.push({ name, ok, detail });
  const m = JSON.parse(readFileSync(a.manifest, "utf8"));
  const anchor = JSON.parse(readFileSync(a.anchor, "utf8"));
  const log = new PgAuditLog({ pool, role: ROLE });
  const cps = new AuditCheckpointer(log, new PgCheckpointStore({ pool, role: ROLE }), {
    sign: async () => new Uint8Array(),
  });
  const pub = createPublicKey(anchor.public_key_pem);
  const tenants = Object.keys(m.heads);
  for (const t of tenants) {
    const v = await log.verify(t);
    add(`audit chain verifies (${t.slice(0, 8)})`, v.ok, JSON.stringify(v));
    const head = await log.head(t);
    const want = m.heads[t];
    if (want) {
      if (a.mode === "exact")
        add(
          `chain head == pre-backup head (${t.slice(0, 8)})`,
          head?.seq === want.seq && head?.hash === want.hash,
          `got seq ${head?.seq}, want ${want.seq}`,
        );
      else {
        const [at] = await log.read(t, { fromSeq: want.seq, toSeq: want.seq, limit: 1 });
        add(
          `pre-backup head is inside the restored chain (${t.slice(0, 8)})`,
          at?.hash === want.hash && (head?.seq ?? 0) >= want.seq,
          `restored head seq ${head?.seq}, backup head seq ${want.seq}`,
        );
      }
    }
    const cp = anchor.checkpoints[t];
    if (cp) {
      const cv = await cps.verifyAgainstCheckpoint(t, cp, pub);
      add(
        `signed checkpoint (held outside the DB) matches (${t.slice(0, 8)})`,
        cv.ok,
        JSON.stringify(cv),
      );
    }
  }
  // RLS isolation as the application role
  const c = await pool.connect();
  try {
    for (let i = 0; i < tenants.length; i++) {
      const me = tenants[i];
      const other = tenants[(i + 1) % tenants.length];
      if (me === other) continue;
      const leaked = await withTenant(
        c,
        me,
        async (x) =>
          (await x.query("SELECT count(*)::int n FROM audit_events WHERE tenant_id = $1", [other]))
            .rows[0].n,
        { role: ROLE },
      );
      add(
        `RLS: tenant ${me.slice(0, 8)} sees 0 rows of ${other.slice(0, 8)}`,
        leaked === 0,
        `saw ${leaked}`,
      );
    }
    await c.query("BEGIN");
    await c.query(`SET LOCAL ROLE ${ROLE}`);
    const none = (await c.query("SELECT count(*)::int n FROM audit_events")).rows[0].n;
    await c.query("ROLLBACK");
    add(
      "RLS: the application role with NO tenant set sees 0 audit rows",
      none === 0,
      `saw ${none}`,
    );
  } finally {
    c.release();
  }
  // row counts and content hashes (only for a restore that must equal the backup point exactly)
  if (a.mode === "exact") {
    const now = await manifestNow(tenants);
    for (const t of tenants)
      for (const [tbl, want] of Object.entries(m.tables[t])) {
        const got = now[t][tbl];
        add(
          `rows ${tbl} (${t.slice(0, 8)}): ${want.n}`,
          got.n === want.n && got.h === want.h,
          `got ${got.n}/${got.h.slice(0, 8)}, want ${want.n}/${want.h.slice(0, 8)}`,
        );
      }
  } else {
    const now = await manifestNow(tenants);
    for (const t of tenants)
      for (const [tbl, want] of Object.entries(m.tables[t]))
        if (tbl !== "audit_events" && !["usage_entries"].includes(tbl))
          add(
            `rows ${tbl} (${t.slice(0, 8)}) >= backup`,
            now[t][tbl].n >= want.n,
            `got ${now[t][tbl].n}, backup ${want.n}`,
          );
  }
  // billing seals
  const ledger = new PgUsageLedger({
    pool,
    signer: new HmacSealSigner(Buffer.from(a.seal_key, "utf8")),
    role: ROLE,
  });
  for (const [t, period] of Object.entries(a.periods ?? {})) {
    const v = await ledger.verifySeal(t, period);
    add(`billing seal ${period} verifies (${t.slice(0, 8)})`, v.ok === true, JSON.stringify(v));
  }
  // registry signatures
  const registry = new RegistryService({
    store: new PgRegistryStore({ pool, role: ROLE }),
    audit: new ServiceAudit(log, "registry"),
  });
  for (const [t, ref] of Object.entries(a.refs ?? {})) {
    try {
      const r = await registry.resolve({ tenantId: t }, ref);
      add(
        `registry resolve verifies hash+signature+provenance (${ref})`,
        Boolean(r.verification),
        "",
      );
    } catch (e) {
      add(`registry resolve verifies (${ref})`, false, String(e.message ?? e));
    }
  }
  return { ok: checks.every((x) => x.ok), checks };
}

async function manifestNow(tenants) {
  const saved = a.tenants;
  a.tenants = tenants;
  const r = await manifest();
  a.tenants = saved;
  return r.tables;
}

try {
  let out;
  if (cmd === "seed") out = await seed();
  else if (cmd === "manifest") {
    out = await manifest();
    if (a.out) writeFileSync(a.out, JSON.stringify(out, null, 2));
  } else if (cmd === "verify") out = await verify();
  else throw new Error(`unknown command ${cmd}`);
  console.log(JSON.stringify(out));
} finally {
  await pool.end();
}
