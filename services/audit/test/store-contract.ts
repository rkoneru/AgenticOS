import { randomUUID } from "node:crypto";
import { GENESIS_HASH, validateAuditEvent } from "@axis/contracts";
import { describe, expect, it } from "vitest";
import { AuditConflictError, AuditValidationError, type AuditStore } from "../src/index.js";
import { ev, hex, PID, seqs } from "./helpers.js";

export interface Harness {
  log: AuditStore;
  tenant: () => Promise<string>;
}

/** Behaviour every AuditStore implementation must share (memory and Postgres run the same suite). */
export function storeContract(name: string, make: () => Promise<Harness>): void {
  describe(`${name}: AuditStore contract`, () => {
    it("assigns id, ts, seq, prev_hash, hash and produces a schema-valid event", async () => {
      const { log, tenant } = await make();
      const t = await tenant();
      const a = await log.append(ev(t));
      expect(a.seq).toBe(1);
      expect(a.prev_hash).toBe(GENESIS_HASH);
      expect(a.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
      expect(a.ts).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
      expect(validateAuditEvent(a)).toBe(true);
      const b = await log.append(ev(t, { decision: "DENY", reason: "nope" }));
      expect(b.seq).toBe(2);
      expect(b.prev_hash).toBe(a.hash);
      expect(await log.verify(t)).toEqual({ ok: true, length: 2 });
    });

    it("keeps caller-supplied id and ts, and optional fields round-trip (reason, human/system actors)", async () => {
      const { log, tenant } = await make();
      const t = await tenant();
      const id = randomUUID();
      const a = await log.append(
        ev(t, {
          id,
          ts: "2026-01-02T03:04:05.678Z",
          actor: { type: "human", id: "alice" },
          reason: "",
        }),
      );
      expect(a.id).toBe(id);
      expect(a.ts).toBe("2026-01-02T03:04:05.678Z");
      const [read] = await log.read(t, {});
      expect(read).toEqual(a); // what was acknowledged is exactly what is stored
      expect(read?.actor).toEqual({ type: "human", id: "alice" });
      expect(read?.reason).toBe("");
      expect(await log.verify(t)).toEqual({ ok: true, length: 1 });
    });

    it("rejects malformed events before touching storage", async () => {
      const { log, tenant } = await make();
      const t = await tenant();
      const bad: unknown[] = [
        ev(t, { tenant_id: t.toUpperCase() }), // uppercase uuid
        ev(t, { trace_id: "xyz" }),
        ev(t, { ts: "2026-01-02T03:04:05Z" }), // no ms
        ev(t, { ts: "2026-01-02T03:04:05.678+00:00" }),
        ev(t, { id: randomUUID().toUpperCase() }),
        ev(t, { actor: { type: "agent", id: "a" } }), // agent without pid
        ev(t, { decision: "MAYBE" as never }),
        ev(t, { enforcement_point: "nowhere" }),
        ev(t, { inputs_hash: "abc" }),
        ev(t, { reason: "x".repeat(1001) }),
        { ...ev(t), extra: 1 },
        { ...ev(t), schema_version: 2 },
        { ...ev(t), seq: 9 },
        { ...ev(t), prev_hash: GENESIS_HASH },
        { ...ev(t), hash: GENESIS_HASH },
        { ...ev(t), reason: undefined }, // not canonicalizable
        { ...ev(t), action: 1.5 },
        null,
        "string",
        [],
      ];
      for (const b of bad) {
        await expect(log.append(b as never), JSON.stringify(b)).rejects.toBeInstanceOf(
          AuditValidationError,
        );
      }
      expect(await log.head(t)).toBeUndefined();
    });

    it("is idempotent on a client-supplied id; different content is a conflict", async () => {
      const { log, tenant } = await make();
      const t = await tenant();
      const input = ev(t, { id: randomUUID(), ts: "2026-01-02T03:04:05.678Z" });
      const a = await log.append(input);
      const again = await log.append({ ...input });
      expect(again).toEqual(a);
      await log.append(ev(t)); // seq 2 so a duplicate must not become seq 3
      expect((await log.read(t, {})).length).toBe(2);
      await expect(log.append({ ...input, action: "other" })).rejects.toBeInstanceOf(
        AuditConflictError,
      );
      await expect(log.append({ ...input, ts: "2026-01-02T03:04:05.679Z" })).rejects.toBeInstanceOf(
        AuditConflictError,
      );
      expect((await log.read(t, {})).length).toBe(2);
    });

    it("idempotent replay without ts ignores the assigned ts but still compares content", async () => {
      const { log, tenant } = await make();
      const t = await tenant();
      const input = ev(t, { id: randomUUID() });
      const a = await log.append(input);
      await new Promise((r) => setTimeout(r, 5));
      expect(await log.append({ ...input })).toEqual(a);
      await expect(log.append({ ...input, decision: "DENY" })).rejects.toBeInstanceOf(
        AuditConflictError,
      );
    });

    it("the same id in different tenants is independent", async () => {
      const { log, tenant } = await make();
      const [t1, t2] = [await tenant(), await tenant()];
      const id = randomUUID();
      const a = await log.append(ev(t1, { id }));
      const b = await log.append(ev(t2, { id }));
      expect([a.seq, b.seq]).toEqual([1, 1]);
    });

    it("chains are per tenant and independent when interleaved", async () => {
      const { log, tenant } = await make();
      const [t1, t2] = [await tenant(), await tenant()];
      for (let i = 0; i < 6; i++) {
        await log.append(ev(i % 2 ? t1 : t2));
        await log.append(ev(t1));
      }
      const r1 = await log.read(t1, {});
      const r2 = await log.read(t2, {});
      expect(seqs(r1)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);
      expect(seqs(r2)).toEqual([1, 2, 3]);
      expect(r1.every((e) => e.tenant_id === t1)).toBe(true);
      expect(await log.verify(t1)).toEqual({ ok: true, length: 9 });
      expect(await log.verify(t2)).toEqual({ ok: true, length: 3 });
      expect((await log.head(t2))?.seq).toBe(3);
    });

    it("read supports ranges and limits; listEvents filters by trace and seq", async () => {
      const { log, tenant } = await make();
      const t = await tenant();
      const trace = hex(32);
      for (let i = 1; i <= 7; i++) await log.append(ev(t, i % 3 === 0 ? { trace_id: trace } : {}));
      expect(seqs(await log.read(t, { fromSeq: 3, toSeq: 5 }))).toEqual([3, 4, 5]);
      expect(seqs(await log.read(t, { limit: 2 }))).toEqual([1, 2]);
      expect(seqs(await log.read(t, { fromSeq: 6 }))).toEqual([6, 7]);
      expect(seqs(await log.listEvents(t, { limit: 100 }))).toHaveLength(7);
      expect(seqs(await log.listEvents(t, { traceId: trace, limit: 100 }))).toEqual([3, 6]);
      expect(seqs(await log.listEvents(t, { traceId: trace, fromSeq: 4, limit: 100 }))).toEqual([
        6,
      ]);
      expect(seqs(await log.listEvents(t, { limit: 3 }))).toEqual([1, 2, 3]);
      expect(await log.listEvents(await tenant(), { limit: 5 })).toEqual([]);
      await expect(log.listEvents(t, { limit: 0 })).rejects.toThrow(RangeError);
      await expect(log.listEvents(t, { limit: 10_001 })).rejects.toThrow(RangeError);
      await expect(log.listEvents(t, { limit: 1.5 })).rejects.toThrow(RangeError);
      await expect(log.listEvents(t, { limit: 1, fromSeq: 0 })).rejects.toThrow(RangeError);
      await expect(log.listEvents(t, { limit: 1, traceId: "nope" })).rejects.toBeInstanceOf(
        AuditValidationError,
      );
      await expect(log.read(t, { fromSeq: 0 })).rejects.toThrow(RangeError);
    });

    it("verify works on slices using the preceding event, and validates its range", async () => {
      const { log, tenant } = await make();
      const t = await tenant();
      for (let i = 0; i < 8; i++) await log.append(ev(t));
      expect(await log.verify(t, { fromSeq: 4 })).toEqual({ ok: true, length: 5 });
      expect(await log.verify(t, { fromSeq: 4, toSeq: 6 })).toEqual({ ok: true, length: 3 });
      expect(await log.verify(t, { toSeq: 3 })).toEqual({ ok: true, length: 3 });
      expect(await log.verify(t, { fromSeq: 8 })).toEqual({ ok: true, length: 1 });
      expect(await log.verify(t, { fromSeq: 99 })).toEqual({ ok: true, length: 0 });
      expect(await log.verify(await tenant())).toEqual({ ok: true, length: 0 });
      await expect(log.verify(t, { fromSeq: 5, toSeq: 4 })).rejects.toThrow(RangeError);
      await expect(log.verify(t, { fromSeq: 0 })).rejects.toThrow(RangeError);
    });

    it("an agent actor keeps its pid", async () => {
      const { log, tenant } = await make();
      const t = await tenant();
      const a = await log.append(ev(t));
      expect(a.actor.pid).toBe(PID);
    });
  });
}
