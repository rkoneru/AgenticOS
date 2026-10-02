import type { UsageInput } from "./types.js";
import { BillingError } from "./errors.js";

/**
 * Pure mapping from a run's event log (the subset the runtime forwards, see runtime/src/axis_runtime/usage.py) to usage records.
 *
 *  - model_call        -> tokens_in (fresh input = input - cached) and tokens_out, ONLY if the gate ALLOWed that action.
 *                         Cache hits (NEXUS cache/rules, provider-cached tokens) are billed as zero model tokens.
 *  - tool_call_result  -> one tool_executions, ONLY if ok and the gate ALLOWed that action. Denied, blocked, failed and
 *                         approval-pending actions are never billed as executions.
 *  - voice_call ended  -> voice_minutes (milliseconds of call time).
 *  - process_transition-> runtime_seconds (milliseconds a process spent RUNNING).
 * Idempotency keys are `run:<run>:<seq>:<meter>`: re-sending the whole log (or any prefix) is a no-op in the ledger.
 */
export interface RunEventLite {
  run_id: string;
  seq: number;
  ts: string;
  type: string;
  pid: string | null;
  data: Readonly<Record<string, unknown>>;
}

export interface Skipped {
  seq: number;
  type: string;
  reason: string;
}

export interface MapResult {
  records: UsageInput[];
  skipped: Skipped[];
}

export interface MapOptions {
  tenantId: string;
  /** model -> price class (`small`, `standard`, `frontier`, ...). */
  classifyModel?: (provider: string, model: string) => string;
  source?: string;
}

const BILLABLE = new Set(["ALLOW", "ALLOW_WITH_REDACTION"]);

/** enforcement point -> tool_kind. model_call-point results (speech sessions) are not tool executions. */
export const TOOL_KINDS: Readonly<Record<string, string>> = {
  tool_call: "tool",
  mcp_call: "mcp",
  code_exec: "code",
  browser_exec: "browser",
  memory_write: "memory_write",
  message_send: "message",
};

export function modelClassifier(
  rules: readonly { prefix: string; class: string }[],
  fallback = "standard",
): (provider: string, model: string) => string {
  return (_provider, model) => rules.find((r) => model.startsWith(r.prefix))?.class ?? fallback;
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v !== "" ? v : undefined);
const nonNegInt = (v: unknown): bigint | undefined =>
  typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : undefined;

export function mapRunEvents(events: readonly RunEventLite[], opts: MapOptions): MapResult {
  const classify = opts.classifyModel ?? (() => "standard");
  const source = opts.source ?? "runtime";
  const records: UsageInput[] = [];
  const skipped: Skipped[] = [];
  const first = events[0];
  if (!first) return { records, skipped };
  const runId = first.run_id;

  const agents = new Map<string, string>();
  const decisions = new Map<string, string>(); // action_id -> decision
  const runningSince = new Map<string, number>(); // pid -> ms
  let lastSeq = -1;
  let started = false;

  const skip = (e: RunEventLite, reason: string): void => {
    skipped.push({ seq: e.seq, type: e.type, reason });
  };
  const emit = (
    e: RunEventLite,
    meter: UsageInput["meter"],
    quantity: bigint,
    dims: Record<string, string>,
    time: Date,
  ): void => {
    if (quantity === 0n) return;
    const agent = e.pid === null ? undefined : agents.get(e.pid);
    records.push({
      tenantId: opts.tenantId,
      idempotencyKey: `run:${runId}:${e.seq}:${meter}`,
      meter,
      quantity,
      eventTime: time,
      dimensions: { run: runId, ...(agent ? { agent } : {}), ...dims },
      source,
    });
  };

  for (const e of events) {
    if (e.run_id !== runId) throw new BillingError("INVALID", "events of more than one run");
    if (!Number.isSafeInteger(e.seq) || e.seq <= lastSeq)
      throw new BillingError("INVALID", "event sequence must be strictly increasing");
    lastSeq = e.seq;
    const time = new Date(e.ts);
    if (Number.isNaN(time.getTime()))
      throw new BillingError("INVALID", `bad timestamp at seq ${e.seq}`);
    const d = e.data;

    if (e.type === "run_started") {
      if (d["tenant_id"] !== opts.tenantId)
        throw new BillingError("TENANT_MISMATCH", "run belongs to a different tenant");
      started = true;
      continue;
    }
    if (!started) throw new BillingError("INVALID", "the run log must begin with run_started");

    switch (e.type) {
      case "process_spawned": {
        const agent = str(d["agent"]);
        if (e.pid !== null && agent) agents.set(e.pid, agent);
        break;
      }
      case "gate_decision": {
        const id = str(d["action_id"]);
        const dec = str(d["decision"]);
        if (id && dec) decisions.set(id, dec);
        break;
      }
      case "process_transition": {
        if (e.pid === null) break;
        const since = runningSince.get(e.pid);
        if (since !== undefined) {
          runningSince.delete(e.pid);
          const ms = time.getTime() - since;
          if (ms < 0) skip(e, "negative running interval (clock went backwards)");
          else emit(e, "runtime_seconds", BigInt(ms), {}, time);
        }
        if (d["to"] === "running") runningSince.set(e.pid, time.getTime());
        break;
      }
      case "model_call": {
        const id = str(d["action_id"]);
        if (!id || !BILLABLE.has(decisions.get(id) ?? "")) {
          skip(e, "no ALLOW decision for this action");
          break;
        }
        const input = nonNegInt(d["input_tokens"]);
        const output = nonNegInt(d["output_tokens"]);
        const cached = nonNegInt(d["cached_tokens"]) ?? 0n;
        const provider = str(d["provider"]);
        const model = str(d["model"]);
        if (input === undefined || output === undefined || !provider || !model) {
          skip(e, "malformed model_call");
          break;
        }
        const fresh = input > cached ? input - cached : 0n;
        const dims = { model, provider, model_class: classify(provider, model) };
        emit(e, "tokens_in", fresh, dims, time);
        emit(e, "tokens_out", output, dims, time);
        break;
      }
      case "tool_call_result": {
        const id = str(d["action_id"]);
        const point = str(d["enforcement_point"]);
        if (!id || !BILLABLE.has(decisions.get(id) ?? "")) {
          skip(e, "no ALLOW decision for this action");
          break;
        }
        if (d["ok"] !== true) {
          skip(e, "failed execution is not billed");
          break;
        }
        const kind = point === undefined ? undefined : TOOL_KINDS[point];
        if (kind === undefined) {
          skip(e, "not a tool execution");
          break;
        }
        emit(e, "tool_executions", 1n, { tool_kind: kind }, time);
        break;
      }
      case "voice_call": {
        if (d["phase"] !== "ended") break;
        const ms = nonNegInt(d["duration_ms"]);
        const call = str(d["call_id"]);
        if (ms === undefined || !call) {
          skip(e, "voice call ended without a valid duration");
          break;
        }
        emit(e, "voice_minutes", ms, { call }, time);
        break;
      }
      default:
        break; // nexus_*, voice_turn/stage, action_blocked, signals ...: never billed
    }
  }
  return { records, skipped };
}

/** One storage sample: bytes held during one hour -> milli-GB-hours (integer, rounded half up). */
export function storageSample(args: {
  tenantId: string;
  hourStart: Date;
  bytes: bigint;
  source?: string;
}): UsageInput {
  if (args.bytes < 0n) throw new BillingError("INVALID", "bytes must not be negative");
  const milliGbHours = (args.bytes * 1000n + 500_000_000n) / 1_000_000_000n;
  return {
    tenantId: args.tenantId,
    idempotencyKey: `storage:${args.hourStart.toISOString()}`,
    meter: "storage_gb_hours",
    quantity: milliGbHours,
    eventTime: args.hourStart,
    source: args.source ?? "storage-sampler",
  };
}

export function marketplaceInstall(args: {
  tenantId: string;
  listingId: string;
  installId: string;
  at: Date;
}): UsageInput {
  return {
    tenantId: args.tenantId,
    idempotencyKey: `install:${args.installId}`,
    meter: "marketplace_installs",
    quantity: 1n,
    eventTime: args.at,
    dimensions: { listing: args.listingId },
    source: "marketplace",
  };
}
