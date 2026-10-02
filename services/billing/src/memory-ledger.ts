import { randomUUID } from "node:crypto";
import { BillingError } from "./errors.js";
import {
  assertClosable,
  foldRollup,
  foldTotals,
  type RollupRow,
  type TotalRow,
  type UsageLedger,
} from "./ledger.js";
import { attributePeriod, type Granularity } from "./periods.js";
import {
  GENESIS_SEAL,
  buildSeal,
  verifySeal,
  type PeriodSeal,
  type SealSigner,
  type SealVerdict,
} from "./seal.js";
import {
  payloadHash,
  validateInput,
  type AdjustmentInput,
  type AnyInput,
  type AppendResult,
  type ConflictReport,
  type Meter,
  type UsageEntry,
  type UsageInput,
} from "./types.js";

interface TenantState {
  byKey: Map<string, UsageEntry>;
  seals: PeriodSeal[];
  conflicts: Map<string, ConflictReport>;
}

/** Reference implementation of the ledger semantics (and the test double). PgUsageLedger must behave identically. */
export class MemoryUsageLedger implements UsageLedger {
  private readonly tenants = new Map<string, TenantState>();
  private readonly now: () => Date;
  private readonly signer: SealSigner;

  constructor(opts: { signer: SealSigner; now?: () => Date }) {
    this.signer = opts.signer;
    this.now = opts.now ?? (() => new Date());
  }

  private st(tenantId: string): TenantState {
    let s = this.tenants.get(tenantId);
    if (!s) {
      s = { byKey: new Map(), seals: [], conflicts: new Map() };
      this.tenants.set(tenantId, s);
    }
    return s;
  }

  async append(
    input: UsageInput | (AdjustmentInput & { entryType: "adjustment" }),
  ): Promise<AppendResult> {
    return this.appendSync(input as AnyInput);
  }

  private appendSync(input: AnyInput): AppendResult {
    const now = this.now();
    const v = validateInput(input, now);
    const s = this.st(v.tenantId);
    const hash = payloadHash(v);
    const existing = s.byKey.get(v.idempotencyKey);
    if (existing) {
      if (existing.payloadHash === hash) return { status: "duplicate", entry: existing };
      const conflict: ConflictReport = {
        tenantId: v.tenantId,
        idempotencyKey: v.idempotencyKey,
        existingPayloadHash: existing.payloadHash,
        offeredPayloadHash: hash,
        source: v.source,
        detectedAt: now,
      };
      s.conflicts.set(`${v.idempotencyKey}\u0000${hash}`, conflict);
      return { status: "conflict", conflict };
    }
    const { periodId, originalPeriodId } = attributePeriod(
      v.eventTime,
      new Set(s.seals.map((x) => x.periodId)),
    );
    const entry: UsageEntry = {
      tenantId: v.tenantId,
      id: randomUUID(),
      idempotencyKey: v.idempotencyKey,
      payloadHash: hash,
      entryType: v.entryType,
      meter: v.meter,
      quantity: v.quantity,
      eventTime: v.eventTime,
      recordedAt: now,
      periodId,
      originalPeriodId,
      dimensions: v.dimensions,
      source: v.source,
      reason: v.reason,
      actor: v.actor,
      correctsKey: v.correctsKey,
    };
    s.byKey.set(v.idempotencyKey, entry);
    return { status: "inserted", entry };
  }

  entries(
    tenantId: string,
    filter: { periodId?: string; meter?: Meter } = {},
  ): Promise<UsageEntry[]> {
    return Promise.resolve(
      [...this.st(tenantId).byKey.values()].filter(
        (e) =>
          (filter.periodId === undefined || e.periodId === filter.periodId) &&
          (filter.meter === undefined || e.meter === filter.meter),
      ),
    );
  }

  async totals(tenantId: string, periodId: string): Promise<TotalRow[]> {
    return foldTotals(await this.entries(tenantId, { periodId }));
  }

  async rollup(
    tenantId: string,
    q: { granularity: Granularity; from: Date; to: Date; meter?: Meter },
  ): Promise<RollupRow[]> {
    return foldRollup(await this.entries(tenantId), q);
  }

  async closePeriod(tenantId: string, periodId: string): Promise<PeriodSeal> {
    const s = this.st(tenantId);
    if (s.seals.some((x) => x.periodId === periodId))
      throw new BillingError("PERIOD_ALREADY_CLOSED", `period ${periodId} is already closed`);
    const now = this.now();
    assertClosable(periodId, now);
    const rows = await this.entries(tenantId, { periodId });
    const prev = s.seals[s.seals.length - 1];
    const seal = buildSeal({
      tenantId,
      periodId,
      seq: s.seals.length + 1,
      prevSealHash: prev?.sealHash ?? GENESIS_SEAL,
      rows,
      closedAt: now,
      signer: this.signer,
    });
    s.seals.push(seal);
    return seal;
  }

  seals(tenantId: string): Promise<PeriodSeal[]> {
    return Promise.resolve([...this.st(tenantId).seals]);
  }

  async verifySeal(tenantId: string, periodId: string): Promise<SealVerdict> {
    const seal = this.st(tenantId).seals.find((x) => x.periodId === periodId);
    if (!seal) throw new BillingError("PERIOD_NOT_SEALED", `period ${periodId} is not closed`);
    return verifySeal(seal, await this.entries(tenantId, { periodId }), this.signer);
  }

  conflicts(tenantId: string): Promise<ConflictReport[]> {
    return Promise.resolve([...this.st(tenantId).conflicts.values()]);
  }
}
