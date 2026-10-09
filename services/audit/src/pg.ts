import type { AuditEvent, ChainVerdict } from "@axis/contracts";
import { withTenant } from "@axis/db";
import type { ClientBase, PoolClient } from "pg";
import { assertSeq, verifyRange } from "./chain.js";
import { AuditAppendError, AuditConflictError } from "./errors.js";
import { contentKey, prepare, sealValidated } from "./prepare.js";
import { assertListQuery } from "./query.js";
import type {
  AuditInput,
  AuditStore,
  Checkpoint,
  CheckpointStore,
  ListQuery,
  ReadRange,
  VerifyRange,
} from "./types.js";

/** Anything that hands out connections (pg.Pool). */
export interface PgPoolLike {
  connect(): Promise<PoolClient>;
}

export interface PgOptions {
  pool: PgPoolLike;
  /** Tests only: `SET LOCAL ROLE` for the transaction (production connects as axis_app). */
  role?: string;
}

export interface PgAuditLogOptions extends PgOptions {
  /** Total attempts per append when the DB chain guard rejects a racing insert (check_violation). Default 5. */
  maxAttempts?: number;
  now?: () => Date;
}

const CHECK_VIOLATION = "23514";
const UNIQUE_VIOLATION = "23505";

/**
 * Losing a race shows up as check_violation (the chain guard saw a newer head) or, when an append of the same client id
 * slips between the duplicate check and the head read, as unique_violation on (tenant_id, id) / (tenant_id, seq).
 * Both are resolved by re-reading; a genuine duplicate id then returns idempotently or raises AuditConflictError.
 */
function isRace(err: unknown): boolean {
  const code = (err as { code?: string }).code;
  return code === CHECK_VIOLATION || code === UNIQUE_VIOLATION;
}

async function inTenant<T>(
  o: PgOptions,
  tenantId: string,
  fn: (c: ClientBase) => Promise<T>,
): Promise<T> {
  const client = await o.pool.connect();
  try {
    return await withTenant(client, tenantId, fn, o.role ? { role: o.role } : {});
  } finally {
    client.release();
  }
}

const COLS = `tenant_id, seq, id, ts, trace_id, actor_type, actor_id, actor_pid, blueprint_name, blueprint_version,
  policy_version, enforcement_point, action, decision, reason, inputs_hash, outputs_hash, prev_hash, hash`;

interface Row {
  tenant_id: string;
  seq: string | number;
  id: string;
  ts: Date;
  trace_id: string;
  actor_type: "human" | "agent" | "system";
  actor_id: string;
  actor_pid: string | null;
  blueprint_name: string;
  blueprint_version: string;
  policy_version: string;
  enforcement_point: string;
  action: string;
  decision: AuditEvent["decision"];
  reason: string | null;
  inputs_hash: string;
  outputs_hash: string;
  prev_hash: string;
  hash: string;
}

/** timestamptz -> ISO ms Z, bigint -> number; optional columns are omitted when NULL (hash input must match). */
export function rowToEvent(r: Row): AuditEvent {
  return {
    schema_version: 1,
    id: r.id,
    tenant_id: r.tenant_id,
    seq: Number(r.seq),
    ts: r.ts.toISOString(),
    trace_id: r.trace_id,
    actor: {
      type: r.actor_type,
      id: r.actor_id,
      ...(r.actor_pid === null ? {} : { pid: r.actor_pid }),
    },
    blueprint: { name: r.blueprint_name, version: r.blueprint_version },
    policy_version: r.policy_version,
    enforcement_point: r.enforcement_point,
    action: r.action,
    decision: r.decision,
    ...(r.reason === null ? {} : { reason: r.reason }),
    inputs_hash: r.inputs_hash,
    outputs_hash: r.outputs_hash,
    prev_hash: r.prev_hash,
    hash: r.hash,
  };
}

const INSERT_SQL = `INSERT INTO audit_events (${COLS}) VALUES
  ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`;

export class PgAuditLog implements AuditStore {
  private readonly maxAttempts: number;
  private readonly now: () => Date;

  constructor(private readonly opts: PgAuditLogOptions) {
    this.maxAttempts = opts.maxAttempts ?? 5;
    this.now = opts.now ?? (() => new Date());
  }

  /**
   * Validates, then appends in one transaction and resolves only after COMMIT. The transaction takes the per-tenant advisory lock the
   * database chain guard uses before reading the head, so concurrent appends to one chain are serialised without losing a race. The retry
   * loop remains as a backstop for the guard's check_violation / unique_violation (e.g. a writer that does not take the lock).
   */
  async append(input: AuditInput): Promise<AuditEvent> {
    const { event, tsSupplied } = prepare(input, this.now);
    for (let attempt = 1; ; attempt++) {
      try {
        return await inTenant(this.opts, event.tenant_id, async (c) => {
          // Taken on EVERY attempt, up front (Phase 9 perf fix): concurrent appends to one tenant queue on this lock in the database instead of
          // racing optimistically, failing the chain guard and retrying (which made a hot chain slower the more callers it had).
          // Same key as axis.audit_chain_guard (migration 0004): class 727275 + hashtext(tenant).
          await c.query("SELECT pg_advisory_xact_lock(727275, hashtext($1::text))", [
            event.tenant_id,
          ]);
          const dup = await c.query<Row>(
            `SELECT ${COLS} FROM audit_events WHERE tenant_id = $1 AND id = $2::uuid`,
            [event.tenant_id, event.id],
          );
          if (dup.rows[0]) {
            const existing = rowToEvent(dup.rows[0]);
            if (contentKey(existing, tsSupplied) !== contentKey(event, tsSupplied)) {
              throw new AuditConflictError(
                `audit event id ${event.id} already exists with different content`,
              );
            }
            return existing;
          }
          const head = await c.query<Row>(
            `SELECT ${COLS} FROM audit_events WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1`,
            [event.tenant_id],
          );
          const s = sealValidated(event, head.rows[0] && rowToEvent(head.rows[0]));
          await c.query(INSERT_SQL, [
            s.tenant_id,
            s.seq,
            s.id,
            s.ts,
            s.trace_id,
            s.actor.type,
            s.actor.id,
            s.actor.pid ?? null,
            s.blueprint.name,
            s.blueprint.version,
            s.policy_version,
            s.enforcement_point,
            s.action,
            s.decision,
            s.reason ?? null,
            s.inputs_hash,
            s.outputs_hash,
            s.prev_hash,
            s.hash,
          ]);
          return s;
        });
      } catch (err) {
        if (!isRace(err)) throw err;
        if (attempt >= this.maxAttempts) {
          throw new AuditAppendError(
            `audit append failed after ${attempt} attempts (lost the append race every time): ${(err as Error).message}`,
            { cause: err },
          );
        }
      }
    }
  }

  async head(tenantId: string): Promise<AuditEvent | undefined> {
    const [h] = await this.read(tenantId, { limit: 1, descending: true });
    return h;
  }

  async read(
    tenantId: string,
    range: ReadRange & { descending?: boolean } = {},
  ): Promise<AuditEvent[]> {
    assertSeq("fromSeq", range.fromSeq);
    assertSeq("toSeq", range.toSeq);
    return inTenant(this.opts, tenantId, async (c) => {
      const r = await c.query<Row>(
        `SELECT ${COLS} FROM audit_events WHERE tenant_id = $1 AND seq >= $2 AND seq <= $3
         ORDER BY seq ${range.descending ? "DESC" : "ASC"} LIMIT $4`,
        [tenantId, range.fromSeq ?? 1, range.toSeq ?? Number.MAX_SAFE_INTEGER, range.limit ?? null],
      );
      return r.rows.map(rowToEvent);
    });
  }

  async listEvents(tenantId: string, query: ListQuery): Promise<AuditEvent[]> {
    assertListQuery(query);
    return inTenant(this.opts, tenantId, async (c) => {
      const r = await c.query<Row>(
        `SELECT ${COLS} FROM audit_events WHERE tenant_id = $1 AND seq >= $2 AND ($3::text IS NULL OR trace_id = $3)
         ORDER BY seq ASC LIMIT $4`,
        [tenantId, query.fromSeq ?? 1, query.traceId ?? null, query.limit],
      );
      return r.rows.map(rowToEvent);
    });
  }

  async verify(tenantId: string, range: VerifyRange = {}): Promise<ChainVerdict> {
    return verifyRange(this, tenantId, range);
  }
}

interface CpRow {
  tenant_id: string;
  seq: string | number;
  hash: string;
  ts: Date;
  signature: string;
}
const toCheckpoint = (r: CpRow): Checkpoint => ({
  tenant_id: r.tenant_id,
  seq: Number(r.seq),
  hash: r.hash,
  ts: r.ts.toISOString(),
  signature: r.signature,
});

/** Checkpoints in `audit_checkpoints` (migration 0005): tenant RLS, append-only, must match a real chain event. */
export class PgCheckpointStore implements CheckpointStore {
  constructor(private readonly opts: PgOptions) {}

  save(c: Checkpoint): Promise<void> {
    return inTenant(this.opts, c.tenant_id, async (x) => {
      await x.query(
        "INSERT INTO audit_checkpoints (tenant_id, seq, hash, ts, signature) VALUES ($1, $2, $3, $4, $5)",
        [c.tenant_id, c.seq, c.hash, c.ts, c.signature],
      );
    });
  }

  async latest(tenantId: string): Promise<Checkpoint | undefined> {
    const r = await inTenant(this.opts, tenantId, (x) =>
      x.query<CpRow>(
        `SELECT tenant_id, seq, hash, ts, signature FROM audit_checkpoints WHERE tenant_id = $1
         ORDER BY seq DESC, created_at DESC LIMIT 1`,
        [tenantId],
      ),
    );
    return r.rows[0] && toCheckpoint(r.rows[0]);
  }

  async list(tenantId: string): Promise<Checkpoint[]> {
    const r = await inTenant(this.opts, tenantId, (x) =>
      x.query<CpRow>(
        `SELECT tenant_id, seq, hash, ts, signature FROM audit_checkpoints WHERE tenant_id = $1
         ORDER BY seq ASC, created_at ASC`,
        [tenantId],
      ),
    );
    return r.rows.map(toCheckpoint);
  }
}
