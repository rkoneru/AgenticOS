import { MemoryAuditLog } from "@axis/audit";
import {
  ApprovalService,
  HmacSigner,
  MemoryApprovalStore,
  NotificationDispatcher,
  type ApprovalStore,
  type CreateApprovalInput,
  type Notification,
  type Notifier,
  type Principal,
} from "../src/index.js";
import type { AuditSink, UnsealedEvent, AuditEvent } from "@axis/contracts";

export const T1 = "11111111-1111-4111-8111-111111111111";
export const T2 = "22222222-2222-4222-8222-222222222222";
export const HASH = "a".repeat(64);
export const TRACE = "b".repeat(32);
export const KEY = new Uint8Array(32).fill(7);

export class Clock {
  constructor(public ms = Date.UTC(2026, 0, 1)) {}
  now = (): number => this.ms;
  advance(sec: number): void {
    this.ms += sec * 1000;
  }
}

export function seqIds(): () => string {
  let n = 0;
  return () => {
    n++;
    const h = n.toString(16).padStart(12, "0");
    return `00000000-0000-4000-8000-${h}`;
  };
}

export const principal = (id: string, roles: string[], tenant = T1): Principal => ({
  tenant_id: tenant,
  id,
  roles,
});

export function input(over: Partial<CreateApprovalInput> = {}): CreateApprovalInput {
  return {
    tenant_id: T1,
    run_id: "run-1",
    trace_id: TRACE,
    agent: { name: "refunder", version: "1.0.0", pid: "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV" },
    tool: "payments.refund",
    args_hash: HASH,
    risk_level: "high",
    requester: { type: "agent", id: "refunder", pid: "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV" },
    approval: {
      roles: ["finance"],
      sla_seconds: 100,
      escalate_to: ["cfo", "ceo"],
      on_timeout: "DENY",
    },
    ...over,
  };
}

export class FailingAudit implements AuditSink {
  fail = false;
  constructor(private readonly inner: MemoryAuditLog) {}
  async append(e: UnsealedEvent): Promise<AuditEvent> {
    if (this.fail) throw new Error("audit down");
    return this.inner.append(e);
  }
}

export class RecordingNotifier implements Notifier {
  readonly channel = "rec";
  readonly seen: Notification[] = [];
  failTimes = 0;
  hang = false;
  async notify(n: Notification): Promise<void> {
    if (this.hang) return new Promise<void>(() => {});
    if (this.failTimes > 0) {
      this.failTimes--;
      throw new Error("channel down");
    }
    this.seen.push(n);
  }
}

export function setup(opts: { store?: ApprovalStore; notifier?: RecordingNotifier } = {}) {
  const clock = new Clock();
  const log = new MemoryAuditLog({ now: () => new Date(clock.now()) });
  const audit = new FailingAudit(log);
  const notifier = opts.notifier ?? new RecordingNotifier();
  const store = opts.store ?? new MemoryApprovalStore();
  const dispatcher = new NotificationDispatcher({
    notifiers: [notifier],
    sleep: async () => {},
    baseDelayMs: 1,
  });
  const svc = new ApprovalService({
    store,
    audit,
    signer: new HmacSigner(KEY),
    clock: clock.now,
    idGen: seqIds(),
    dispatcher,
  });
  return { clock, log, audit, notifier, store, svc, signer: new HmacSigner(KEY) };
}
