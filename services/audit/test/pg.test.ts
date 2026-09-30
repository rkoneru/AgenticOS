import { randomUUID } from "node:crypto";
import type pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  AuditAppendError,
  AuditCheckpointer,
  AuditConflictError,
  MemoryCheckpointStore,
  PgAuditLog,
  PgCheckpointStore,
  generateEd25519,
  rowToEvent,
} from "../src/index.js";
import {
  adminClient,
  countingPool,
  interleavePool,
  ev,
  newPool,
  newTenant,
  ROLE,
  seqs,
  withoutTrigger,
} from "./helpers.js";
import { storeContract } from "./store-contract.js";

let pool: pg.Pool;
let admin: pg.Client;
let log: PgAuditLog;

beforeAll(async () => {
  pool = newPool();
  admin = await adminClient();
  log = new PgAuditLog({ pool, role: ROLE });
});
afterAll(async () => {
  await admin.end();
  await pool.end();
});

storeContract("PgAuditLog", async () => ({
  log: new PgAuditLog({ pool, role: ROLE }),
  tenant: () => newTenant(admin),
}));

describe("PgAuditLog concurrency", () => {
  it("30 parallel appends to one tenant yield a gapless valid chain (retry path exercised)", async () => {
    const t = await newTenant(admin);
    const counted = countingPool(pool, /pg_advisory_xact_lock/);
    const racing = new PgAuditLog({ pool: counted, role: ROLE });
    const out = await Promise.all(Array.from({ length: 30 }, () => racing.append(ev(t))));
    expect(new Set(out.map((e) => e.seq)).size).toBe(30);
    const stored = await log.read(t, {});
    expect(seqs(stored)).toEqual(Array.from({ length: 30 }, (_, i) => i + 1));
    expect(await log.verify(t)).toEqual({ ok: true, length: 30 });
    expect(counted.count()).toBeGreaterThan(0); // the DB guard did reject racers and they retried
  });

  it("two tenants interleaved under load stay independent", async () => {
    const [t1, t2] = [await newTenant(admin), await newTenant(admin)];
    await Promise.all(Array.from({ length: 40 }, (_, i) => log.append(ev(i % 2 ? t1 : t2))));
    expect(await log.verify(t1)).toEqual({ ok: true, length: 20 });
    expect(await log.verify(t2)).toEqual({ ok: true, length: 20 });
    expect((await log.read(t1, {})).every((e) => e.tenant_id === t1)).toBe(true);
  });

  it("concurrent appends of the same client id produce exactly one event", async () => {
    const t = await newTenant(admin);
    const input = ev(t, { id: randomUUID() });
    const out = await Promise.all(Array.from({ length: 8 }, () => log.append({ ...input })));
    expect(new Set(out.map((e) => e.hash)).size).toBe(1);
    expect((await log.read(t, {})).length).toBe(1);
  });

  it("an identical append that slips in between the duplicate check and the head read resolves idempotently", async () => {
    const t = await newTenant(admin);
    const input = ev(t, { id: randomUUID(), ts: "2026-01-02T03:04:05.678Z" });
    // Deterministic interleaving: after our duplicate check finds nothing, the same event is committed by someone else.
    // Our head read then sees it, we seal seq 2 and hit unique(tenant_id, id); the retry must return the stored event.
    const slow = new PgAuditLog({
      pool: interleavePool(pool, /WHERE tenant_id = \$1 AND id = \$2::uuid/, async () => {
        await log.append({ ...input });
      }),
      role: ROLE,
    });
    const r = await slow.append({ ...input });
    expect(r.seq).toBe(1);
    expect((await log.read(t, {})).length).toBe(1);
  });

  it("gives up after the bounded number of attempts and acknowledges nothing", async () => {
    const t = await newTenant(admin);
    await admin.query(
      `CREATE OR REPLACE FUNCTION test_always_check_violation() RETURNS trigger LANGUAGE plpgsql AS
       $$ BEGIN RAISE EXCEPTION 'forced' USING ERRCODE = 'check_violation'; END $$`,
    );
    await admin.query(
      `CREATE TRIGGER a_force_fail BEFORE INSERT ON audit_events FOR EACH ROW
       WHEN (NEW.tenant_id = '${t}') EXECUTE FUNCTION test_always_check_violation()`,
    );
    try {
      const counted = countingPool(pool, /pg_advisory_xact_lock/);
      const l = new PgAuditLog({ pool: counted, role: ROLE, maxAttempts: 3 });
      await expect(l.append(ev(t))).rejects.toBeInstanceOf(AuditAppendError);
      expect(counted.count()).toBe(2); // attempts 2 and 3 took the lock
      expect(await log.head(t)).toBeUndefined();
    } finally {
      await admin.query("DROP TRIGGER a_force_fail ON audit_events");
    }
  });

  it("does not acknowledge before COMMIT: a failure at commit time rejects and leaves nothing behind", async () => {
    const t = await newTenant(admin);
    await admin.query(
      `CREATE OR REPLACE FUNCTION test_fail_at_commit() RETURNS trigger LANGUAGE plpgsql AS
       $$ BEGIN RAISE EXCEPTION 'commit refused'; END $$`,
    );
    await admin.query(
      `CREATE CONSTRAINT TRIGGER z_commit_fail AFTER INSERT ON audit_events DEFERRABLE INITIALLY DEFERRED
       FOR EACH ROW WHEN (NEW.tenant_id = '${t}') EXECUTE FUNCTION test_fail_at_commit()`,
    );
    try {
      await expect(log.append(ev(t))).rejects.toThrow(/commit refused/);
    } finally {
      await admin.query("DROP TRIGGER z_commit_fail ON audit_events");
    }
    expect(await log.head(t)).toBeUndefined();
    expect(await log.append(ev(t))).toMatchObject({ seq: 1 }); // and the tenant is still usable
  });

  it("an unknown tenant is rejected by the database and nothing is acknowledged", async () => {
    await expect(log.append(ev(randomUUID()))).rejects.toMatchObject({ code: "23503" });
  });

  it("a conflicting id raised inside the transaction is not retried", async () => {
    const t = await newTenant(admin);
    const id = randomUUID();
    await log.append(ev(t, { id }));
    await expect(log.append(ev(t, { id, action: "different" }))).rejects.toBeInstanceOf(
      AuditConflictError,
    );
  });
});

describe("PgAuditLog: DB round trip and tenancy", () => {
  it("rowToEvent rebuilds the hashed event exactly (timestamptz -> ISO ms Z, NULLs omitted)", async () => {
    const t = await newTenant(admin);
    const a = await log.append(
      ev(t, { ts: "2026-03-04T05:06:07.008Z", actor: { type: "system", id: "s" } }),
    );
    const r = await admin.query("SELECT * FROM audit_events WHERE tenant_id = $1", [t]);
    expect(rowToEvent(r.rows[0])).toEqual(a);
  });

  it("an axis_app session scoped to another tenant sees nothing", async () => {
    const [t1, t2] = [await newTenant(admin), await newTenant(admin)];
    await log.append(ev(t1));
    expect(await log.read(t2, {})).toEqual([]);
    expect(await log.head(t2)).toBeUndefined();
  });
});

describe("PgAuditLog: verification against a tampered database", () => {
  async function build(n: number): Promise<string> {
    const t = await newTenant(admin);
    for (let i = 0; i < n; i++) await log.append(ev(t));
    return t;
  }

  it("content tampering via superuser UPDATE => hash_mismatch at that seq", async () => {
    const t = await build(6);
    await withoutTrigger(admin, "audit_append_only", () =>
      admin.query("UPDATE audit_events SET action = 'evil' WHERE tenant_id = $1 AND seq = 4", [t]),
    );
    expect(await log.verify(t)).toEqual({ ok: false, brokenAtSeq: 4, reason: "hash_mismatch" });
    expect(await log.verify(t, { toSeq: 3 })).toEqual({ ok: true, length: 3 });
    // slices are anchored on the preceding event, whose own hash is checked
    expect(await log.verify(t, { fromSeq: 5 })).toEqual({
      ok: false,
      brokenAtSeq: 4,
      reason: "hash_mismatch",
    });
    expect(await log.verify(t, { fromSeq: 6 })).toEqual({ ok: true, length: 1 });
  });

  it("a tampered anchor event is reported on slice verification", async () => {
    const t = await build(5);
    await withoutTrigger(admin, "audit_append_only", () =>
      admin.query("UPDATE audit_events SET decision = 'DENY' WHERE tenant_id = $1 AND seq = 2", [
        t,
      ]),
    );
    expect(await log.verify(t, { fromSeq: 3 })).toEqual({
      ok: false,
      brokenAtSeq: 2,
      reason: "hash_mismatch",
    });
  });

  it("a deleted middle row => seq_gap", async () => {
    const t = await build(6);
    await withoutTrigger(admin, "audit_append_only", () =>
      admin.query("DELETE FROM audit_events WHERE tenant_id = $1 AND seq = 3", [t]),
    );
    expect(await log.verify(t)).toEqual({ ok: false, brokenAtSeq: 4, reason: "seq_gap" });
    // slice whose anchor row was deleted
    expect(await log.verify(t, { fromSeq: 4 })).toEqual({
      ok: false,
      brokenAtSeq: 4,
      reason: "seq_gap",
    });
  });

  it("a rewritten prev_hash => prev_hash_mismatch", async () => {
    const t = await build(4);
    await withoutTrigger(admin, "audit_append_only", () =>
      admin.query(
        "UPDATE audit_events SET prev_hash = repeat('9', 64) WHERE tenant_id = $1 AND seq = 3",
        [t],
      ),
    );
    expect(await log.verify(t)).toEqual({
      ok: false,
      brokenAtSeq: 3,
      reason: "prev_hash_mismatch",
    });
  });

  it("a deleted TAIL is NOT detected by verifyChain alone, but IS detected with a signed checkpoint", async () => {
    const t = await build(7);
    const { signer, publicKey } = generateEd25519();
    const cps = new PgCheckpointStore({ pool, role: ROLE });
    const cp = new AuditCheckpointer(log, cps, signer);
    const checkpoint = await cp.createCheckpoint(t);
    expect(checkpoint.seq).toBe(7);
    expect(await cp.verifyAgainstCheckpoint(t, checkpoint, publicKey)).toMatchObject({
      ok: true,
      headSeq: 7,
    });

    await withoutTrigger(admin, "audit_append_only", () =>
      admin.query("DELETE FROM audit_events WHERE tenant_id = $1 AND seq > 4", [t]),
    );
    // the remaining prefix still verifies: this is the documented limit of a bare hash chain
    expect(await log.verify(t)).toEqual({ ok: true, length: 4 });
    // ... and the checkpoint catches it
    const v = await cp.verifyAgainstCheckpoint(t, (await cps.latest(t))!, publicKey);
    expect(v).toMatchObject({ ok: false, reason: "truncated" });
  });

  it("a rewritten history (same length) is detected against the checkpoint at the checkpoint seq", async () => {
    const t = await build(5);
    const { signer, publicKey } = generateEd25519();
    const cp = new AuditCheckpointer(log, new PgCheckpointStore({ pool, role: ROLE }), signer);
    const checkpoint = await cp.createCheckpoint(t);
    await withoutTrigger(admin, "audit_append_only", () =>
      admin.query(
        "UPDATE audit_events SET hash = repeat('7', 64) WHERE tenant_id = $1 AND seq = 5",
        [t],
      ),
    );
    expect(await cp.verifyAgainstCheckpoint(t, checkpoint, publicKey)).toMatchObject({
      ok: false,
      reason: "hash_mismatch",
    });
  });
});

describe("PgCheckpointStore", () => {
  it("round-trips checkpoints; latest = highest seq; stays tenant-scoped", async () => {
    const [t1, t2] = [await newTenant(admin), await newTenant(admin)];
    const { signer } = generateEd25519();
    const store = new PgCheckpointStore({ pool, role: ROLE });
    const cp = new AuditCheckpointer(log, store, signer);
    expect(await store.latest(t1)).toBeUndefined();
    await log.append(ev(t1));
    const c1 = await cp.createCheckpoint(t1);
    await log.append(ev(t1));
    const c2 = await cp.createCheckpoint(t1);
    const c2b = await cp.createCheckpoint(t1); // same seq again is allowed; later one wins
    await log.append(ev(t2));
    expect(await store.list(t1)).toEqual([c1, c2, c2b]);
    expect(await store.latest(t1)).toEqual(c2b);
    expect(await store.list(t2)).toEqual([]);
  });

  it("the database refuses a checkpoint that matches no chain event, and checkpoints are append-only", async () => {
    const t = await newTenant(admin);
    await log.append(ev(t));
    const store = new PgCheckpointStore({ pool, role: ROLE });
    const good = await new AuditCheckpointer(log, store, generateEd25519().signer).createCheckpoint(
      t,
    );
    await expect(store.save({ ...good, hash: "f".repeat(64) })).rejects.toMatchObject({
      code: "23514",
    });
    await expect(store.save({ ...good, seq: 2 })).rejects.toMatchObject({ code: "23514" });
    await expect(
      admin.query("UPDATE audit_checkpoints SET seq = 1 WHERE tenant_id = $1", [t]),
    ).rejects.toMatchObject({ code: "42501" });
    await expect(
      admin.query("DELETE FROM audit_checkpoints WHERE tenant_id = $1", [t]),
    ).rejects.toMatchObject({
      code: "42501",
    });
    await expect(admin.query("TRUNCATE audit_checkpoints")).rejects.toMatchObject({
      code: "42501",
    });
  });

  it("works against the memory store too (same checkpointer, same verdicts)", async () => {
    const t = await newTenant(admin);
    await log.append(ev(t));
    const { signer, publicKey } = generateEd25519();
    const cp = new AuditCheckpointer(log, new MemoryCheckpointStore(), signer);
    expect((await cp.verifyAgainstCheckpoint(t, await cp.createCheckpoint(t), publicKey)).ok).toBe(
      true,
    );
  });
});
