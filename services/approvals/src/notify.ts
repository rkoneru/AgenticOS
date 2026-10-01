import { silentLogger, type Logger, type RiskLevel } from "./types.js";

export type NotificationKind = "requested" | "escalated" | "decided" | "expired";

/** What leaves the platform. Deliberately excludes tool arguments (only their hash) and any credential. */
export interface Notification {
  kind: NotificationKind;
  tenant_id: string;
  request_id: string;
  run_id: string;
  agent: string;
  tool: string;
  args_hash: string;
  risk_level: RiskLevel;
  requester_id: string;
  level: number;
  /** Roles that may act at this level (cumulative). */
  roles: string[];
  deadline: string;
  /** For `decided` / `expired`. */
  outcome?: "APPROVED" | "DENIED" | "EXPIRED";
  decided_by?: string;
}

export interface Notifier {
  readonly channel: string;
  /** Must throw on failure. Returning normally means the channel accepted the message (or had no target: skipped). */
  notify(n: Notification): Promise<void>;
}

export interface DispatchResult {
  channel: string;
  ok: boolean;
  attempts: number;
  error?: string;
}

export interface DispatcherOptions {
  notifiers: Notifier[];
  maxAttempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  sleep?: (ms: number) => Promise<void>;
  logger?: Logger;
}

/**
 * Fan-out with per-channel retry and exponential backoff. `dispatch` NEVER rejects and has no effect on approval
 * state: a failed or slow notification can neither block a transition nor approve anything. Failures are logged.
 */
export class NotificationDispatcher {
  private readonly notifiers: Notifier[];
  private readonly maxAttempts: number;
  private readonly baseDelayMs: number;
  private readonly maxDelayMs: number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly log: Logger;

  constructor(opts: DispatcherOptions) {
    this.notifiers = opts.notifiers;
    this.maxAttempts = Math.max(1, opts.maxAttempts ?? 4);
    this.baseDelayMs = opts.baseDelayMs ?? 500;
    this.maxDelayMs = opts.maxDelayMs ?? 30_000;
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.log = opts.logger ?? silentLogger;
  }

  async dispatch(n: Notification): Promise<DispatchResult[]> {
    return Promise.all(this.notifiers.map((nt) => this.one(nt, n)));
  }

  private async one(nt: Notifier, n: Notification): Promise<DispatchResult> {
    let lastError = "";
    for (let attempt = 1; attempt <= this.maxAttempts; attempt++) {
      try {
        await nt.notify(n);
        return { channel: nt.channel, ok: true, attempts: attempt };
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
        this.log.warn("notification attempt failed", {
          channel: nt.channel,
          request_id: n.request_id,
          kind: n.kind,
          attempt,
          error: lastError,
        });
        if (attempt < this.maxAttempts) {
          try {
            await this.sleep(Math.min(this.maxDelayMs, this.baseDelayMs * 2 ** (attempt - 1)));
          } catch {
            // a broken sleeper must not break the dispatcher; retry immediately
          }
        }
      }
    }
    this.log.error("notification gave up", {
      channel: nt.channel,
      request_id: n.request_id,
      kind: n.kind,
      error: lastError,
    });
    return { channel: nt.channel, ok: false, attempts: this.maxAttempts, error: lastError };
  }
}

export const TITLES: Record<NotificationKind, string> = {
  requested: "Approval requested",
  escalated: "Approval escalated",
  decided: "Approval decided",
  expired: "Approval expired (denied)",
};

/** Strip control characters and cap length so attacker-influenced strings cannot forge layout or headers. */
export function clean(s: string, max = 200): string {
  // eslint-disable-next-line no-control-regex
  const t = s.replace(/[\u0000-\u001f\u007f]/g, " ");
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

export function summaryLines(n: Notification, consoleBaseUrl?: string): [string, string][] {
  const rows: [string, string][] = [
    ["Tool", clean(n.tool)],
    ["Agent", clean(n.agent)],
    ["Run", clean(n.run_id)],
    ["Risk", n.risk_level],
    ["Requester", clean(n.requester_id)],
    ["Level", String(n.level)],
    ["Approver roles", clean(n.roles.join(", "))],
    ["Deadline", n.deadline],
    ["Args hash", n.args_hash.slice(0, 16)],
  ];
  if (n.outcome) rows.push(["Outcome", n.outcome]);
  if (n.decided_by) rows.push(["Decided by", clean(n.decided_by)]);
  if (consoleBaseUrl)
    rows.push(["Link", `${consoleBaseUrl.replace(/\/+$/, "")}/approvals/${n.request_id}`]);
  return rows;
}
