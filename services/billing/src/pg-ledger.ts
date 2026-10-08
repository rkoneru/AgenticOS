import { withTenant } from "@axis/db";
import type { ClientBase, PoolClient } from "pg";
import { BillingError } from "./errors.js";
import {
  assertClosable,
  foldRollup,
  foldTotals,
  type RollupRow,
  type TotalRow,
  type UsageLedger,
} from "./ledger.js";
import { attributePeriod, periodBounds, type Granularity } from "./periods.js";
import {
  GENESIS_SEAL,
  buildSeal,
  verifySeal,
  type PeriodSeal,
  type SealRow,
  type SealSigner,
  type SealVerdict,
} from "./seal.js";
import {
  canonicalTenant,
  payloadHash,
  validateInput,
  type AdjustmentInput,
  type AnyInput,
  type AppendResult,
  type ConflictReport,
  type EntryType,
  type Meter,
  type UsageEntry,
  type UsageInput,
} from "./types.js";

export interface PgPoolLike {
  connect(): Promise<PoolClient>;
}

export interface PgLedgerOptions {
  /** Residency guard (`@axis/data-governance/residency`): when set, every write for a tenant is refused unless this instance's region is allowed. */
  residency?: { assertWrite(tenantId: string): Promise<void> };
  pool: PgPoolLike;
  signer: SealSigner;
  /** Tests only: `SET LOCAL ROLE` per transaction (production connects as axis_app). */
  role?: string;
  now?: () => Date;
}

const LOCK_CLASS = 727280; // shared by inserts, exclusive for the sealer; matches axis.usage_period_guard

interface EntryRow {
  tenant_id: string;
  id: string;
  idempotency_key: string;
  payload_hash: string;
  entry_type: EntryType;
  meter: Meter;
  quantity: string;
  event_time: Date;
  recorded_at: Date;
  period_id: string;
  original_period_id: string | null;
  dimensions: Record<string, string>;
  source: string;
  reason: string | null;
  actor: string | null;
  corrects_key: string | null;
}

const toEntry = (r: EntryRow): UsageEntry => ({
  tenantId: r.tenant_id,
  id: r.id,
  idempotencyKey: r.idempotency_key,
  payloadHash: r.payload_hash,
  entryType: r.entry_type,
  meter: r.meter,
  quantity: BigInt(r.quantity),
  eventTime: r.event_time,
  recordedAt: r.recorded_at,
  periodId: r.period_id,
  originalPeriodId: r.original_period_id,
  dimensions: r.dimensions,
  source: r.source,
  reason: r.reason,
  actor: r.actor,
  correctsKey: r.corrects_key,
});

interface SealDbRow {
  tenant_id: string;
  period_id: string;
  seq: number;
  prev_seal_hash: string;
  seal_hash: string;
  signature: string;
  key_id: string;
  event_count: string;
  rows_digest: string;
  totals: Record<string, string>;
  closed_at: Date;
}

const toSeal = (r: SealDbRow): PeriodSeal => ({
  tenantId: r.tenant_id,
  periodId: r.period_id,
  seq: r.seq,
  prevSealHash: r.prev_seal_hash,
  sealHash: r.seal_hash,
  signature: r.signature,
  keyId: r.key_id,
  eventCount: Number(r.event_count),
  rowsDigest: r.rows_digest,
  totals: r.totals,
  closedAt: r.closed_at,
});

export class PgUsageLedger implements UsageLedger {
  private readonly now: () => Date;
  constructor(private readonly o: PgLedgerOptions) {
    this.now = o.now ?? (() => new Date());
  }

  private async tx<T>(tenantId: string, fn: (c: ClientBase) => Promise<T>): Promise<T> {
    const client = await this.o.pool.connect();
    try {
      return await withTenant(client, tenantId, fn, this.o.role ? { role: this.o.role } : {});
    } finally {
      client.release();
    }
  }

  async append(
    input: UsageInput | (AdjustmentInput & { entryType: "adjustment" }),
  ): Promise<AppendResult> {
    const now = this.now();
    const v = validateInput(input as AnyInput, now);
    await this.o.residency?.assertWrite(v.tenantId);
    const hash = payloadHash(v);
    return this.tx(v.tenantId, async (c) => {
      await c.query("SELECT pg_advisory_xact_lock_shared($1, hashtext($2))", [
        LOCK_CLASS,
        v.tenantId,
      ]);
      const resolveExisting = async (): Promise<AppendResult | undefined> => {
        const found = await c.query<EntryRow>(
          "SELECT * FROM usage_events WHERE tenant_id = $1 AND idempotency_key = $2",
          [v.tenantId, v.idempotencyKey],
        );
        const existing = found.rows[0];
        if (!existing) return undefined;
        if (existing.payload_hash === hash)
          return { status: "duplicate", entry: toEntry(existing) };
        await c.query(
          `INSERT INTO usage_conflicts (tenant_id, idempotency_key, existing_payload_hash, offered_payload_hash, source, detected_at)
           VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`,
          [v.tenantId, v.idempotencyKey, existing.payload_hash, hash, v.source, now],
        );
        return {
          status: "conflict",
          conflict: {
            tenantId: v.tenantId,
            idempotencyKey: v.idempotencyKey,
            existingPayloadHash: existing.payload_hash,
            offeredPayloadHash: hash,
            source: v.source,
            detectedAt: now,
          },
        };
      };
      const prior = await resolveExisting();
      if (prior) return prior;
      const sealedRows = await c.query<{ period_id: string }>(
        "SELECT period_id FROM billing_period_seals WHERE tenant_id = $1",
        [v.tenantId],
      );
      const { periodId, originalPeriodId } = attributePeriod(
        v.eventTime,
        new Set(sealedRows.rows.map((r) => r.period_id)),
      );
      const ins = await c.query<EntryRow>(
        `INSERT INTO usage_events (tenant_id, idempotency_key, payload_hash, entry_type, meter, quantity, event_time, recorded_at,
                                   period_id, original_period_id, dimensions, source, reason, actor, corrects_key)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$14,$15)
         ON CONFLICT (tenant_id, idempotency_key) DO NOTHING RETURNING *`,
        [
          v.tenantId,
          v.idempotencyKey,
          hash,
          v.entryType,
          v.meter,
          v.quantity.toString(),
          v.eventTime,
          now,
          periodId,
          originalPeriodId,
          JSON.stringify(v.dimensions),
          v.source,
          v.reason,
          v.actor,
          v.correctsKey,
        ],
      );
      const row = ins.rows[0];
      if (row) return { status: "inserted", entry: toEntry(row) };
      // A concurrent transaction inserted the same key between our read and write; it has committed, so it is visible now.
      // (the row cannot have vanished: the table is insert-only, so the lookup always finds it)
      return (await resolveExisting()) as AppendResult;
    });
  }

  async entries(
    tenantIdIn: string,
    filter: { periodId?: string; meter?: Meter } = {},
  ): Promise<UsageEntry[]> {
    const tenantId = canonicalTenant(tenantIdIn);
    return this.tx(tenantId, async (c) => {
      const r = await c.query<EntryRow>(
        `SELECT * FROM usage_events WHERE tenant_id = $1 AND ($2::text IS NULL OR period_id = $2)
           AND ($3::text IS NULL OR meter = $3) ORDER BY recorded_at, id`,
        [tenantId, filter.periodId ?? null, filter.meter ?? null],
      );
      return r.rows.map(toEntry);
    });
  }

  async totals(tenantIdIn: string, periodId: string): Promise<TotalRow[]> {
    const tenantId = canonicalTenant(tenantIdIn);
    return this.tx(tenantId, async (c) => {
      const r = await c.query<{ meter: Meter; mc: string | null; tk: string | null; q: string }>(
        `SELECT meter, dimensions->>'model_class' AS mc, dimensions->>'tool_kind' AS tk, sum(quantity)::text AS q
           FROM usage_events WHERE tenant_id = $1 AND period_id = $2 GROUP BY 1, 2, 3`,
        [tenantId, periodId],
      );
      const dims = (x: { mc: string | null; tk: string | null }): Record<string, string> => ({
        ...(x.mc === null ? {} : { model_class: x.mc }),
        ...(x.tk === null ? {} : { tool_kind: x.tk }),
      });
      return foldTotals(
        r.rows.map((x) => ({ meter: x.meter, quantity: BigInt(x.q), dimensions: dims(x) })),
      );
    });
  }

  async rollup(
    tenantIdIn: string,
    q: { granularity: Granularity; from: Date; to: Date; meter?: Meter },
  ): Promise<RollupRow[]> {
    const tenantId = canonicalTenant(tenantIdIn);
    return this.tx(tenantId, async (c) => {
      const r = await c.query<{ meter: Meter; event_time: Date; quantity: string }>(
        `SELECT meter, event_time, quantity FROM usage_events
          WHERE tenant_id = $1 AND event_time >= $2 AND event_time < $3 AND ($4::text IS NULL OR meter = $4)`,
        [tenantId, q.from, q.to, q.meter ?? null],
      );
      return foldRollup(
        r.rows.map((x) => ({
          meter: x.meter,
          eventTime: x.event_time,
          quantity: BigInt(x.quantity),
        })),
        q,
      );
    });
  }

  async closePeriod(tenantIdIn: string, periodId: string): Promise<PeriodSeal> {
    const tenantId = canonicalTenant(tenantIdIn);
    periodBounds(periodId);
    const now = this.now();
    assertClosable(periodId, now);
    return this.tx(tenantId, async (c) => {
      await c.query("SELECT pg_advisory_xact_lock($1, hashtext($2))", [LOCK_CLASS, tenantId]);
      const prior = await c.query<SealDbRow>(
        "SELECT * FROM billing_period_seals WHERE tenant_id = $1 ORDER BY seq",
        [tenantId],
      );
      if (prior.rows.some((x) => x.period_id === periodId))
        throw new BillingError("PERIOD_ALREADY_CLOSED", `period ${periodId} is already closed`);
      const rows = await c.query<EntryRow>(
        "SELECT * FROM usage_events WHERE tenant_id = $1 AND period_id = $2",
        [tenantId, periodId],
      );
      const last = prior.rows[prior.rows.length - 1];
      const seal = buildSeal({
        tenantId,
        periodId,
        seq: prior.rows.length + 1,
        prevSealHash: last?.seal_hash ?? GENESIS_SEAL,
        rows: rows.rows.map(toSealRow),
        closedAt: now,
        signer: this.o.signer,
      });
      await c.query(
        `INSERT INTO billing_period_seals (tenant_id, period_id, seq, prev_seal_hash, seal_hash, signature, key_id, event_count,
                                           rows_digest, totals, closed_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11)`,
        [
          tenantId,
          periodId,
          seal.seq,
          seal.prevSealHash,
          seal.sealHash,
          seal.signature,
          seal.keyId,
          seal.eventCount,
          seal.rowsDigest,
          JSON.stringify(seal.totals),
          now,
        ],
      );
      return seal;
    });
  }

  async seals(tenantIdIn: string): Promise<PeriodSeal[]> {
    const tenantId = canonicalTenant(tenantIdIn);
    return this.tx(tenantId, async (c) => {
      const r = await c.query<SealDbRow>(
        "SELECT * FROM billing_period_seals WHERE tenant_id = $1 ORDER BY seq",
        [tenantId],
      );
      return r.rows.map(toSeal);
    });
  }

  async verifySeal(tenantId: string, periodId: string): Promise<SealVerdict> {
    const seal = (await this.seals(tenantId)).find((x) => x.periodId === periodId);
    if (!seal) throw new BillingError("PERIOD_NOT_SEALED", `period ${periodId} is not closed`);
    const entries = await this.entries(tenantId, { periodId });
    return verifySeal(seal, entries.map(toSealRow), this.o.signer);
  }

  async conflicts(tenantIdIn: string): Promise<ConflictReport[]> {
    const tenantId = canonicalTenant(tenantIdIn);
    return this.tx(tenantId, async (c) => {
      const r = await c.query<{
        idempotency_key: string;
        existing_payload_hash: string;
        offered_payload_hash: string;
        source: string;
        detected_at: Date;
      }>("SELECT * FROM usage_conflicts WHERE tenant_id = $1 ORDER BY detected_at, id", [tenantId]);
      return r.rows.map((x) => ({
        tenantId,
        idempotencyKey: x.idempotency_key,
        existingPayloadHash: x.existing_payload_hash,
        offeredPayloadHash: x.offered_payload_hash,
        source: x.source,
        detectedAt: x.detected_at,
      }));
    });
  }
}

function toSealRow(e: EntryRow | UsageEntry): SealRow {
  if ("idempotencyKey" in e)
    return {
      idempotencyKey: e.idempotencyKey,
      payloadHash: e.payloadHash,
      meter: e.meter,
      quantity: e.quantity,
    };
  return {
    idempotencyKey: e.idempotency_key,
    payloadHash: e.payload_hash,
    meter: e.meter,
    quantity: BigInt(e.quantity),
  };
}
