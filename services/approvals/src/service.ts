import { randomUUID } from "node:crypto";
import { hashJson, sha256Hex, type AuditSink, type UnsealedEvent } from "@axis/contracts";
import type { Notification, NotificationDispatcher, NotificationKind } from "./notify.js";
import { chainFromSpec, invalid, validateCreate } from "./spec.js";
import { signRecord, type DecisionSigner } from "./signer.js";
import type { ApprovalStore } from "./store.js";
import {
  ApprovalError,
  silentLogger,
  type Actor,
  type ApprovalRequest,
  type ApprovalStatus,
  type CreateApprovalInput,
  type DecisionRecord,
  type Logger,
  type Outcome,
  type Principal,
} from "./types.js";

export interface ServiceDeps {
  store: ApprovalStore;
  audit: AuditSink;
  signer: DecisionSigner;
  clock?: () => number;
  idGen?: () => string;
  dispatcher?: NotificationDispatcher;
  logger?: Logger;
}

export interface Timers {
  setInterval(fn: () => void, ms: number): unknown;
  clearInterval(handle: unknown): void;
}

const MAX_COMMENT = 1000;
const SYSTEM: Actor = { type: "system", id: "approvals-sla" };

type AuditAction =
  | "approval.requested"
  | "approval.claimed"
  | "approval.released"
  | "approval.escalated"
  | "approval.approved"
  | "approval.denied"
  | "approval.expired";

const isTerminal = (s: ApprovalStatus): boolean => s !== "pending";

export class ApprovalService {
  private readonly store: ApprovalStore;
  private readonly audit: AuditSink;
  private readonly signer: DecisionSigner;
  private readonly clock: () => number;
  private readonly idGen: () => string;
  private readonly dispatcher: NotificationDispatcher | undefined;
  private readonly log: Logger;
  private readonly locks = new Map<string, Promise<unknown>>();
  private readonly pendingNotifications = new Set<Promise<unknown>>();
  private readonly listeners = new Set<(tenantId: string, id: string) => void>();
  private sweeping = false;

  constructor(deps: ServiceDeps) {
    this.store = deps.store;
    this.audit = deps.audit;
    this.signer = deps.signer;
    this.clock = deps.clock ?? Date.now;
    this.idGen = deps.idGen ?? randomUUID;
    this.dispatcher = deps.dispatcher;
    this.log = deps.logger ?? silentLogger;
  }

  now(): number {
    return this.clock();
  }

  // ---- create ---------------------------------------------------------------------------------------------------

  /** Opens an approval request. The `approval.requested` audit event is appended BEFORE the request exists. */
  async create(input: CreateApprovalInput): Promise<ApprovalRequest> {
    validateCreate(input);
    const chain = chainFromSpec(input.approval);
    if (input.idempotency_key !== undefined) {
      const prior = await this.store.findByIdempotencyKey(input.tenant_id, input.idempotency_key);
      if (prior) {
        if (
          prior.run_id !== input.run_id ||
          prior.tool !== input.tool ||
          prior.args_hash !== input.args_hash
        )
          throw new ApprovalError("CONFLICT", "idempotency key reused for a different request");
        return prior;
      }
    }
    const now = this.clock();
    const first = chain[0];
    /* v8 ignore next */
    if (!first) throw invalid("empty chain");
    const r: ApprovalRequest = {
      id: this.idGen(),
      tenant_id: input.tenant_id,
      run_id: input.run_id,
      trace_id: input.trace_id,
      agent: { ...input.agent },
      tool: input.tool,
      args_hash: input.args_hash,
      risk_level: input.risk_level,
      requester: { ...input.requester },
      conflicted: [...(input.conflicted ?? [])],
      policy_version: input.policy_version ?? "none",
      chain,
      level: 1,
      created_at_ms: now,
      deadline_ms: now + first.sla_seconds * 1000,
      status: "pending",
      claimed_by: null,
      decided_by: null,
      decided_at_ms: null,
      decision_level: null,
      comment: null,
      reason: null,
      idempotency_key: input.idempotency_key ?? null,
      decision_audit_id: null,
      decision_audit_hash: null,
      version: 1,
    };
    await this.appendRequired(
      r,
      "approval.requested",
      "REQUIRE_APPROVAL",
      r.requester,
      `request=${r.id}`,
    );
    await this.store.insert(r);
    this.notify("requested", r);
    return r;
  }

  // ---- reads (every read first applies due SLA timers, so a missed sweep can never leave a stale "pending") --------

  /** Tenant-scoped, system-level read for the resolver: applies due timers, then returns the request. */
  async peek(tenantId: string, id: string): Promise<ApprovalRequest> {
    return this.locked(tenantId, id, () => this.loadAdvanced(tenantId, id));
  }

  async get(principal: Principal, id: string): Promise<ApprovalRequest> {
    checkPrincipal(principal);
    return this.peek(principal.tenant_id, id);
  }

  /** Requests in the principal's tenant that they may act on (role match at the current level) or that they filed. */
  async list(
    principal: Principal,
    q: { status?: ApprovalStatus; limit?: number } = {},
  ): Promise<ApprovalRequest[]> {
    checkPrincipal(principal);
    const limit = Math.min(Math.max(q.limit ?? 50, 1), 200);
    const rows = await this.store.list(principal.tenant_id, {
      ...(q.status ? { status: q.status } : {}),
      limit: 1000,
    });
    const out: ApprovalRequest[] = [];
    for (const row of rows) {
      const cur = row.status === "pending" ? await this.peek(row.tenant_id, row.id) : row;
      if (q.status !== undefined && cur.status !== q.status) continue;
      if (cur.requester.id === principal.id || hasEligibleRole(cur, principal)) out.push(cur);
      if (out.length >= limit) break;
    }
    return out;
  }

  // ---- claim / release / decide -----------------------------------------------------------------------------------

  async claim(principal: Principal, id: string): Promise<ApprovalRequest> {
    checkPrincipal(principal);
    return this.locked(principal.tenant_id, id, async () => {
      const r = await this.loadAdvanced(principal.tenant_id, id);
      this.assertPending(r);
      this.authorize(r, principal);
      if (r.claimed_by === principal.id) return r;
      const next = this.bump(r, { claimed_by: principal.id });
      await this.appendRequired(
        next,
        "approval.claimed",
        "REQUIRE_APPROVAL",
        humanActor(principal),
        `request=${r.id}`,
      );
      await this.write(next, r.version);
      return next;
    });
  }

  async release(principal: Principal, id: string): Promise<ApprovalRequest> {
    checkPrincipal(principal);
    return this.locked(principal.tenant_id, id, async () => {
      const r = await this.loadAdvanced(principal.tenant_id, id);
      this.assertPending(r);
      if (r.claimed_by !== principal.id)
        throw new ApprovalError("CLAIMED_BY_OTHER", "only the claimant can release a claim");
      const next = this.bump(r, { claimed_by: null });
      await this.appendRequired(
        next,
        "approval.released",
        "REQUIRE_APPROVAL",
        humanActor(principal),
        `request=${r.id}`,
      );
      await this.write(next, r.version);
      return next;
    });
  }

  approve(principal: Principal, id: string, comment?: string): Promise<ApprovalRequest> {
    return this.decide(principal, id, "approved", comment);
  }

  deny(principal: Principal, id: string, comment?: string): Promise<ApprovalRequest> {
    return this.decide(principal, id, "denied", comment);
  }

  private async decide(
    principal: Principal,
    id: string,
    status: "approved" | "denied",
    comment: string | undefined,
  ): Promise<ApprovalRequest> {
    checkPrincipal(principal);
    if (comment !== undefined && (typeof comment !== "string" || comment.length > MAX_COMMENT))
      throw invalid("comment too long");
    return this.locked(principal.tenant_id, id, async () => {
      const r = await this.loadAdvanced(principal.tenant_id, id);
      if (isTerminal(r.status)) {
        // Idempotent replay by the same decider with the same verdict; anything else can never flip a decision.
        if (r.status === status && r.decided_by === principal.id) return r;
        throw new ApprovalError("ALREADY_DECIDED", `request already ${r.status}`);
      }
      this.authorize(r, principal);
      const now = this.clock();
      const next = this.bump(r, {
        status,
        decided_by: principal.id,
        decided_at_ms: now,
        decision_level: r.level,
        comment: comment ?? null,
        claimed_by: principal.id,
        reason: `${status} by ${principal.id} at level ${r.level}`,
      });
      const action = status === "approved" ? "approval.approved" : "approval.denied";
      if (status === "approved") {
        // ALLOW direction: no state change without a durable audit event.
        const ev = await this.appendRequired(
          next,
          action,
          "ALLOW",
          humanActor(principal),
          next.reason ?? "",
        );
        next.decision_audit_id = ev.id;
        next.decision_audit_hash = ev.hash;
      } else {
        await this.appendBestEffort(next, action, "DENY", humanActor(principal), next.reason ?? "");
      }
      await this.write(next, r.version);
      this.emitTerminal(next);
      return next;
    });
  }

  // ---- SLA ------------------------------------------------------------------------------------------------------

  /** Applies every due timer. Safe to call at any time; also run by `startSweeper`. Returns requests touched. */
  async sweep(limit = 500): Promise<number> {
    if (this.sweeping) return 0;
    this.sweeping = true;
    try {
      const due = await this.store.listDue(this.clock(), limit);
      let n = 0;
      for (const d of due) {
        try {
          await this.peek(d.tenant_id, d.id);
          n++;
        } catch (err) {
          this.log.error("sweep failed for request", {
            request_id: d.id,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
      return n;
    } finally {
      this.sweeping = false;
    }
  }

  startSweeper(
    intervalMs: number,
    timers: Timers = { setInterval, clearInterval },
  ): { stop(): void } {
    const h = timers.setInterval(() => {
      void this.sweep().catch((e: unknown) =>
        this.log.error("sweep crashed", { error: String(e) }),
      );
    }, intervalMs);
    return { stop: () => timers.clearInterval(h) };
  }

  /** Terminal-transition hook for the resolver. Returns an unsubscribe function. */
  onTerminal(cb: (tenantId: string, id: string) => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  /** Resolves when all in-flight notifications have settled (shutdown / tests). Never rejects. */
  async flush(): Promise<void> {
    while (this.pendingNotifications.size > 0)
      await Promise.allSettled([...this.pendingNotifications]);
  }

  // ---- decision record --------------------------------------------------------------------------------------------

  async decisionRecord(r: ApprovalRequest): Promise<DecisionRecord> {
    if (!isTerminal(r.status) || r.decided_at_ms === null || r.decision_level === null)
      throw new ApprovalError("NOT_DECIDED", "request is still pending");
    const outcome: Outcome =
      r.status === "approved" ? "APPROVED" : r.status === "denied" ? "DENIED" : "EXPIRED";
    try {
      return await signRecord(
        {
          request_id: r.id,
          tenant_id: r.tenant_id,
          run_id: r.run_id,
          tool: r.tool,
          args_hash: r.args_hash,
          outcome,
          decision: outcome === "APPROVED" ? "ALLOW" : "DENY",
          decided_by: r.decided_by ?? SYSTEM.id,
          decided_at: new Date(r.decided_at_ms).toISOString(),
          level: r.decision_level,
          reason: r.reason ?? "",
          audit_event_id: r.decision_audit_id ?? "",
          audit_hash: r.decision_audit_hash ?? "",
          key_id: this.signer.keyId,
        },
        this.signer,
      );
    } catch (err) {
      throw new ApprovalError("SIGNING_FAILED", `could not sign decision: ${String(err)}`);
    }
  }

  // ---- internals --------------------------------------------------------------------------------------------------

  private async loadAdvanced(tenantId: string, id: string): Promise<ApprovalRequest> {
    let r = await this.store.get(tenantId, id);
    if (!r || r.tenant_id !== tenantId)
      throw new ApprovalError("NOT_FOUND", "approval request not found");
    while (r.status === "pending" && this.clock() >= r.deadline_ms) r = await this.advanceOne(r);
    return r;
  }

  /** One due-timer step: escalate to the next level, or expire (DENY) at the end of the chain. */
  private async advanceOne(r: ApprovalRequest): Promise<ApprovalRequest> {
    const nextLevel = r.chain[r.level]; // chain is 0-indexed; level is 1-based, so this is level+1
    if (nextLevel) {
      const next = this.bump(r, {
        level: nextLevel.level,
        deadline_ms: r.deadline_ms + nextLevel.sla_seconds * 1000,
        claimed_by: null,
      });
      // Escalation widens who may approve, so it requires a durable audit event.
      await this.appendRequired(
        next,
        "approval.escalated",
        "REQUIRE_APPROVAL",
        SYSTEM,
        `request=${r.id} sla elapsed at level ${r.level}; escalated to level ${nextLevel.level}`,
      );
      await this.write(next, r.version);
      this.notify("escalated", next);
      return next;
    }
    const next = this.bump(r, {
      status: "expired",
      decided_by: null,
      decided_at_ms: r.deadline_ms,
      decision_level: r.level,
      reason: `sla elapsed at final level ${r.level}: denied`,
    });
    const ev = await this.appendBestEffort(
      next,
      "approval.expired",
      "DENY",
      SYSTEM,
      next.reason ?? "",
    );
    next.decision_audit_id = ev?.id ?? "";
    next.decision_audit_hash = ev?.hash ?? "";
    await this.write(next, r.version);
    this.emitTerminal(next);
    return next;
  }

  private assertPending(r: ApprovalRequest): void {
    if (isTerminal(r.status))
      throw new ApprovalError("ALREADY_DECIDED", `request already ${r.status}`);
  }

  /** Role, no-self-approval, separation-of-duties and claim checks for a pending request. */
  private authorize(r: ApprovalRequest, p: Principal): void {
    if (p.id === r.requester.id)
      throw new ApprovalError("SELF_APPROVAL", "requester cannot act on their own request");
    if (r.conflicted.includes(p.id))
      throw new ApprovalError(
        "CONFLICT_OF_INTEREST",
        "principal is barred by separation of duties",
      );
    if (!hasEligibleRole(r, p))
      throw new ApprovalError("FORBIDDEN_ROLE", "principal lacks a role eligible at this level");
    if (r.claimed_by !== null && r.claimed_by !== p.id)
      throw new ApprovalError("CLAIMED_BY_OTHER", "request is claimed by another approver");
  }

  private bump(r: ApprovalRequest, patch: Partial<ApprovalRequest>): ApprovalRequest {
    return { ...structuredClone(r), ...patch, version: r.version + 1 };
  }

  private async write(next: ApprovalRequest, expectedVersion: number): Promise<void> {
    if (!(await this.store.compareAndSet(next, expectedVersion)))
      throw new ApprovalError("CONFLICT", "approval request was modified concurrently");
  }

  private event(
    r: ApprovalRequest,
    action: AuditAction,
    decision: UnsealedEvent["decision"],
    actor: Actor,
    reason: string,
  ): UnsealedEvent {
    return {
      schema_version: 1,
      id: this.idGen(),
      tenant_id: r.tenant_id,
      ts: new Date(this.clock()).toISOString(),
      trace_id: r.trace_id,
      actor,
      blueprint: { name: r.agent.name, version: r.agent.version },
      policy_version: r.policy_version,
      enforcement_point: "admin",
      action,
      decision,
      reason: `${reason} tool=${r.tool} args=${r.args_hash}`.slice(0, 1000),
      inputs_hash: hashJson({
        request_id: r.id,
        run_id: r.run_id,
        tool: r.tool,
        args_hash: r.args_hash,
        requester: r.requester.id,
        risk_level: r.risk_level,
      }),
      outputs_hash: hashJson({
        status: r.status,
        level: r.level,
        deadline_ms: r.deadline_ms,
        claimed_by: r.claimed_by,
        decided_by: r.decided_by,
        comment_sha256: r.comment === null ? null : sha256Hex(r.comment),
      }),
    };
  }

  private async appendRequired(
    r: ApprovalRequest,
    action: AuditAction,
    decision: UnsealedEvent["decision"],
    actor: Actor,
    reason: string,
  ) {
    try {
      return await this.audit.append(this.event(r, action, decision, actor, reason));
    } catch (err) {
      this.log.error("audit append failed; refusing transition", {
        action,
        request_id: r.id,
        error: String(err),
      });
      throw new ApprovalError("AUDIT_FAILED", "audit append failed");
    }
  }

  /** For DENY-direction transitions: the safe state is applied even if the audit log is unavailable (loudly logged). */
  private async appendBestEffort(
    r: ApprovalRequest,
    action: AuditAction,
    decision: UnsealedEvent["decision"],
    actor: Actor,
    reason: string,
  ) {
    try {
      const ev = await this.audit.append(this.event(r, action, decision, actor, reason));
      r.decision_audit_id = ev.id;
      r.decision_audit_hash = ev.hash;
      return ev;
    } catch (err) {
      this.log.error("audit append failed on DENY transition; applying DENY anyway", {
        action,
        request_id: r.id,
        error: String(err),
      });
      return undefined;
    }
  }

  private emitTerminal(r: ApprovalRequest): void {
    this.notify(r.status === "expired" ? "expired" : "decided", r);
    for (const cb of this.listeners) {
      try {
        cb(r.tenant_id, r.id);
      } catch (err) {
        this.log.error("terminal listener failed", { error: String(err) });
      }
    }
  }

  private notify(kind: NotificationKind, r: ApprovalRequest): void {
    if (!this.dispatcher) return;
    const eligible = eligibleRoles(r);
    const n: Notification = {
      kind,
      tenant_id: r.tenant_id,
      request_id: r.id,
      run_id: r.run_id,
      agent: r.agent.name,
      tool: r.tool,
      args_hash: r.args_hash,
      risk_level: r.risk_level,
      requester_id: r.requester.id,
      level: r.level,
      roles: eligible,
      deadline: new Date(r.deadline_ms).toISOString(),
      ...(r.status !== "pending"
        ? {
            outcome: (r.status === "approved"
              ? "APPROVED"
              : r.status === "denied"
                ? "DENIED"
                : "EXPIRED") as Outcome,
          }
        : {}),
      ...(r.decided_by !== null ? { decided_by: r.decided_by } : {}),
    };
    // Detached on purpose: a slow or failing channel can never delay or alter a transition.
    const p: Promise<unknown> = this.dispatcher.dispatch(n).catch((e: unknown) => {
      this.log.error("dispatcher crashed", { error: String(e) });
    });
    this.pendingNotifications.add(p);
    void p.finally(() => this.pendingNotifications.delete(p));
  }

  private async locked<T>(tenantId: string, id: string, fn: () => Promise<T>): Promise<T> {
    const key = `${tenantId}/${id}`;
    const prev = this.locks.get(key) ?? Promise.resolve();
    const run = prev.then(fn, fn);
    const tail = run.catch(() => undefined);
    this.locks.set(key, tail);
    try {
      return await run;
    } finally {
      if (this.locks.get(key) === tail) this.locks.delete(key);
    }
  }
}

export function eligibleRoles(r: ApprovalRequest): string[] {
  return [...new Set(r.chain.slice(0, r.level).flatMap((l) => l.roles))];
}

function hasEligibleRole(r: ApprovalRequest, p: Principal): boolean {
  const e = new Set(eligibleRoles(r));
  return p.roles.some((role) => e.has(role));
}

const humanActor = (p: Principal): Actor => ({ type: "human", id: p.id });

function checkPrincipal(p: Principal): void {
  if (
    typeof p !== "object" ||
    p === null ||
    typeof p.tenant_id !== "string" ||
    p.tenant_id === "" ||
    typeof p.id !== "string" ||
    p.id === "" ||
    !Array.isArray(p.roles) ||
    !p.roles.every((r) => typeof r === "string")
  )
    throw invalid("invalid principal");
}
