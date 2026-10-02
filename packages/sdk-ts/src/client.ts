import { AxisAbortError, AxisApiError, AxisError, AxisWaitTimeoutError } from "./errors.js";
import { GeneratedApi } from "./generated/client.js";
import { DEFAULT_BASE_URL, OPERATIONS } from "./generated/operations.js";
import type {
  Approval,
  ApprovalPage,
  ApprovalStatus,
  BlueprintPage,
  BlueprintVersion,
  EvalRun,
  GateDecision,
  KillSwitch,
  PolicyDocument,
  PolicyPack,
  PolicyPackPage,
  ProcessState,
  Run,
  RunEvent,
  RunPage,
  Signal,
  ListRunsParams,
  ListBlueprintsParams,
  ListApprovalsParams,
  ListPolicyPacksParams,
  ListAuditEventsParams,
  AblDocument,
  AuditEvent,
} from "./generated/types.js";
import { paginate, type Page } from "./pagination.js";
import { HttpTransport, type RequestOptions, type TransportConfig } from "./transport.js";
import { defaultSleep } from "./transport.js";
import { readSse, SseParser } from "./sse.js";

export interface AxisOptions {
  /** API key (sent as X-Axis-Api-Key). Defaults to the AXIS_API_KEY environment variable. */
  apiKey?: string;
  /** Short-lived bearer token (alternative to apiKey). */
  token?: string;
  /** Defaults to AXIS_BASE_URL, then the spec's server URL. */
  baseUrl?: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
  maxRetries?: number;
  allowInsecure?: boolean;
  onResponse?: TransportConfig["onResponse"];
  validateRequest?: TransportConfig["validateRequest"];
  validateResponse?: TransportConfig["validateResponse"];
  sleep?: TransportConfig["sleep"];
  random?: TransportConfig["random"];
  retryBaseMs?: number;
  retryMaxMs?: number;
}

const TERMINAL: ReadonlySet<ProcessState> = new Set<ProcessState>(["terminated"]);
const TENANT_KEYS = /^(tenant|tenant_?id|tenantid|x-axis-tenant.*)$/i;

type Opts = RequestOptions;
export type BlueprintRef = { name: string; version: string } | string;

export function parseBlueprintRef(ref: BlueprintRef): { name: string; version: string } {
  if (typeof ref !== "string") return { name: ref.name, version: ref.version };
  const at = ref.lastIndexOf("@");
  if (at <= 0 || at === ref.length - 1)
    throw new TypeError(`blueprint must be "name@version", got "${ref}"`);
  return { name: ref.slice(0, at), version: ref.slice(at + 1) };
}

function pick<T extends object>(o: T): T {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as T;
}

export interface StreamOptions extends Opts {
  /** Resume after this sequence number. */
  afterSequence?: number;
  /** Consecutive failed (or empty) connections tolerated before giving up. Default 5. */
  maxReconnects?: number;
  /** Reconnect delay when the server sent no `retry:` field. Default 1000 ms (doubling, capped at 10 s). */
  reconnectDelayMs?: number;
}

export interface WaitOptions extends Opts {
  /** Give up after this many ms (default 300 000). */
  timeoutMs?: number;
  pollIntervalMs?: number;
}

export class Runs {
  constructor(private readonly ax: Axis) {}

  /** Start a run. Retried safely: an Idempotency-Key is generated once and reused across retries. */
  start(
    args: {
      blueprint: BlueprintRef;
      input?: Record<string, unknown> | undefined;
      idempotencyKey?: string | undefined;
    },
    options?: Opts,
  ): Promise<Run> {
    return this.ax.api.startRun(
      pick({
        body: pick({ blueprint: parseBlueprintRef(args.blueprint), input: args.input }),
        idempotencyKey: args.idempotencyKey,
      }),
      options,
    );
  }

  get(runId: string, options?: Opts): Promise<Run> {
    return this.ax.api.getRun({ runId }, options);
  }

  list(args: ListRunsParams = {}, options?: Opts): Promise<RunPage> {
    return this.ax.api.listRuns(pick(args), options);
  }

  iterate(
    args: { limit?: number; state?: ProcessState; blueprint?: string; maxItems?: number } = {},
    options?: Opts,
  ): AsyncGenerator<Run> {
    const { maxItems, ...rest } = args;
    return paginate((cursor) => this.list(pick({ ...rest, cursor }), options), maxItems);
  }

  signal(
    runId: string,
    args: {
      signal: Signal;
      pid?: string | undefined;
      reason?: string | undefined;
      idempotencyKey?: string | undefined;
    },
    options?: Opts,
  ) {
    const { idempotencyKey, ...body } = args;
    return this.ax.api.signalRun(pick({ runId, body: pick(body), idempotencyKey }), options);
  }

  /** TERM by default (graceful); `force` sends KILL. */
  cancel(
    runId: string,
    args: {
      reason?: string | undefined;
      force?: boolean | undefined;
      pid?: string | undefined;
    } = {},
    options?: Opts,
  ) {
    return this.signal(
      runId,
      pick({ signal: args.force ? "KILL" : "TERM", reason: args.reason, pid: args.pid }) as {
        signal: Signal;
      },
      options,
    );
  }

  events(
    runId: string,
    args: { afterSequence?: number | undefined; limit?: number | undefined } = {},
    options?: Opts,
  ) {
    return this.ax.api.listRunEvents(
      pick({ runId, after_sequence: args.afterSequence, limit: args.limit }),
      options,
    );
  }

  /** Every event in sequence order (non-streaming), following `next_cursor`. */
  async *allEvents(runId: string, options?: Opts): AsyncGenerator<RunEvent> {
    let after = 0;
    for (;;) {
      const page = await this.events(runId, { afterSequence: after }, options);
      for (const e of page.items) {
        after = Math.max(after, e.sequence);
        yield e;
      }
      if (page.items.length === 0 || !page.next_cursor) return;
    }
  }

  /** Poll until the run terminates. Throws AxisWaitTimeoutError when `timeoutMs` elapses first. */
  async wait(runId: string, options: WaitOptions = {}): Promise<Run> {
    const timeout = options.timeoutMs ?? 300_000;
    const poll = options.pollIntervalMs ?? 1000;
    const started = Date.now();
    const { timeoutMs: _t, pollIntervalMs: _p, ...reqOpts } = options;
    void _t;
    void _p;
    for (;;) {
      const run = await this.get(runId, reqOpts);
      if (TERMINAL.has(run.state)) return run;
      const remaining = timeout - (Date.now() - started);
      if (remaining <= 0)
        throw new AxisWaitTimeoutError(`run ${runId} still ${run.state} after ${timeout} ms`);
      await this.ax.sleep(Math.min(poll, remaining), options.signal);
    }
  }

  /**
   * Live typed events for a run over SSE. Reconnects with `Last-Event-ID` (and `after_sequence`) after a
   * dropped connection, skips events already delivered, honours the server's `retry:` hint, and ends when the
   * stream closes and the run is terminated.
   */
  async *stream(runId: string, options: StreamOptions = {}): AsyncGenerator<RunEvent> {
    const { afterSequence, maxReconnects = 5, reconnectDelayMs = 1000, ...reqOpts } = options;
    const parser = new SseParser();
    let last = afterSequence ?? 0;
    let failures = 0;
    for (;;) {
      if (options.signal?.aborted) throw new AxisAbortError("stream aborted by caller");
      let progressed = false;
      try {
        const res = await this.ax.transport.openStream(
          OPERATIONS.listRunEvents,
          { runId, after_sequence: last },
          {
            ...reqOpts,
            headers: { ...reqOpts.headers, "last-event-id": String(last) },
            timeoutMs: reqOpts.timeoutMs ?? 24 * 3600_000,
          },
        );
        if (!res.body) throw new AxisApiError("event stream had no body", { status: res.status });
        for await (const ev of readSse(res.body, parser)) {
          if (ev.event !== "message" && ev.event !== "run_event") continue;
          let parsed: RunEvent;
          try {
            parsed = JSON.parse(ev.data) as RunEvent;
          } catch (err) {
            throw new AxisApiError("event stream carried malformed JSON", { cause: err });
          }
          if (typeof parsed.sequence !== "number" || parsed.sequence <= last) continue;
          last = parsed.sequence;
          progressed = true;
          yield parsed;
        }
        if (progressed) failures = 0;
        else failures++;
        const run = await this.get(runId, reqOpts);
        if (TERMINAL.has(run.state)) return;
      } catch (err) {
        if (err instanceof AxisAbortError || options.signal?.aborted) throw err;
        if (
          err instanceof AxisApiError &&
          !(err.status === 408 || err.status === 429 || (err.status ?? 0) >= 500)
        )
          throw err;
        if (!(err instanceof AxisError)) throw err;
        failures = progressed ? 1 : failures + 1;
      }
      if (failures > maxReconnects)
        throw new AxisError(`event stream for run ${runId} failed ${failures} times in a row`);
      const wait =
        parser.retry ?? Math.min(reconnectDelayMs * 2 ** Math.max(0, failures - 1), 10_000);
      await this.ax.sleep(wait, options.signal);
    }
  }
}

export class Blueprints {
  constructor(private readonly ax: Axis) {}
  list(args: ListBlueprintsParams = {}, options?: Opts): Promise<BlueprintPage> {
    return this.ax.api.listBlueprints(pick(args), options);
  }
  iterate(
    args: { limit?: number; maxItems?: number } = {},
    options?: Opts,
  ): AsyncGenerator<BlueprintVersion> {
    const { maxItems, ...rest } = args;
    return paginate((cursor) => this.list(pick({ ...rest, cursor }), options), maxItems);
  }
  get(name: string, version: string, options?: Opts): Promise<BlueprintVersion> {
    return this.ax.api.getBlueprintVersion({ name, version }, options);
  }
  publish(
    abl: AblDocument,
    args: { idempotencyKey?: string | undefined } = {},
    options?: Opts,
  ): Promise<BlueprintVersion> {
    return this.ax.api.publishBlueprintVersion(
      pick({ body: { abl }, idempotencyKey: args.idempotencyKey }),
      options,
    );
  }
}

export class Approvals {
  constructor(private readonly ax: Axis) {}
  list(args: ListApprovalsParams = {}, options?: Opts): Promise<ApprovalPage> {
    return this.ax.api.listApprovals(pick(args), options);
  }
  iterate(
    args: { status?: ApprovalStatus; limit?: number; maxItems?: number } = {},
    options?: Opts,
  ): AsyncGenerator<Approval> {
    const { maxItems, ...rest } = args;
    return paginate((cursor) => this.list(pick({ ...rest, cursor }), options), maxItems);
  }
  decide(
    approvalId: string,
    decision: "approve" | "reject",
    args: { comment?: string | undefined; idempotencyKey?: string | undefined } = {},
    options?: Opts,
  ): Promise<Approval> {
    return this.ax.api.decideApproval(
      pick({
        approvalId,
        body: pick({ decision, comment: args.comment }),
        idempotencyKey: args.idempotencyKey,
      }),
      options,
    );
  }
  approve(approvalId: string, comment?: string | undefined, options?: Opts) {
    return this.decide(approvalId, "approve", pick({ comment }), options);
  }
  reject(approvalId: string, comment?: string | undefined, options?: Opts) {
    return this.decide(approvalId, "reject", pick({ comment }), options);
  }
}

export class Policies {
  constructor(private readonly ax: Axis) {}
  list(args: ListPolicyPacksParams = {}, options?: Opts): Promise<PolicyPackPage> {
    return this.ax.api.listPolicyPacks(pick(args), options);
  }
  iterate(
    args: { limit?: number; maxItems?: number } = {},
    options?: Opts,
  ): AsyncGenerator<PolicyPack> {
    const { maxItems, ...rest } = args;
    return paginate((cursor) => this.list(pick({ ...rest, cursor }), options), maxItems);
  }
  publish(policy: PolicyDocument, options?: Opts): Promise<PolicyPack> {
    return this.ax.api.publishPolicyPack({ body: { policy } }, options);
  }
  /** Evaluate a hypothetical request against a policy without executing anything. */
  test(
    policy: PolicyDocument,
    request: { enforcement_point: string; action?: string; context: Record<string, unknown> },
    options?: Opts,
  ): Promise<GateDecision> {
    return this.ax.api.testPolicy({ body: { policy, request } }, options);
  }
}

export class Audit {
  constructor(private readonly ax: Axis) {}
  events(args: ListAuditEventsParams = {}, options?: Opts): Promise<Page<AuditEvent>> {
    return this.ax.api.listAuditEvents(pick(args), options);
  }
  iterate(
    args: {
      limit?: number;
      trace_id?: string;
      decision?: GateDecision["decision"];
      from_seq?: number;
      maxItems?: number;
    } = {},
    options?: Opts,
  ): AsyncGenerator<AuditEvent> {
    const { maxItems, ...rest } = args;
    return paginate((cursor) => this.events(pick({ ...rest, cursor }), options), maxItems);
  }
  verify(args: { from_seq?: number; to_seq?: number } = {}, options?: Opts) {
    return this.ax.api.verifyAuditChain(
      args.from_seq !== undefined || args.to_seq !== undefined ? { body: pick(args) } : {},
      options,
    );
  }
}

export class KillSwitches {
  constructor(private readonly ax: Axis) {}
  list(options?: Opts) {
    return this.ax.api.listKillSwitches(options);
  }
  set(
    args: {
      scope: "tenant" | "agent" | "tool";
      engaged: boolean;
      target?: string | undefined;
      reason?: string | undefined;
    },
    options?: Opts,
  ): Promise<KillSwitch> {
    if (args.scope !== "tenant" && !args.target)
      throw new TypeError(`kill-switch scope "${args.scope}" needs a target`);
    return this.ax.api.setKillSwitch({ body: pick(args) }, options);
  }
  engage(
    scope: "tenant" | "agent" | "tool",
    target?: string | undefined,
    reason?: string | undefined,
    options?: Opts,
  ) {
    return this.set(pick({ scope, engaged: true, target, reason }), options);
  }
  release(
    scope: "tenant" | "agent" | "tool",
    target?: string | undefined,
    reason?: string | undefined,
    options?: Opts,
  ) {
    return this.set(pick({ scope, engaged: false, target, reason }), options);
  }
}

export class Usage {
  constructor(private readonly ax: Axis) {}
  get(
    args: {
      from: string;
      to: string;
      groupBy?: "meter" | "model" | "blueprint" | "day" | undefined;
    },
    options?: Opts,
  ) {
    return this.ax.api.getUsage(
      pick({ from: args.from, to: args.to, group_by: args.groupBy }),
      options,
    );
  }
}

export class Evals {
  constructor(private readonly ax: Axis) {}
  start(
    args: { suite: string; blueprint: BlueprintRef; idempotencyKey?: string | undefined },
    options?: Opts,
  ): Promise<EvalRun> {
    return this.ax.api.startEvalRun(
      pick({
        body: { suite: args.suite, blueprint: parseBlueprintRef(args.blueprint) },
        idempotencyKey: args.idempotencyKey,
      }),
      options,
    );
  }
}

/**
 * The AXIS client. The tenant is always derived from the credential by the server: there is deliberately no
 * tenant option, and passing one is an error.
 */
export class Axis {
  readonly transport: HttpTransport;
  /** One method per operationId (generated). */
  readonly api: GeneratedApi;
  readonly runs: Runs;
  readonly blueprints: Blueprints;
  readonly approvals: Approvals;
  readonly policies: Policies;
  readonly audit: Audit;
  readonly killSwitches: KillSwitches;
  readonly usage: Usage;
  readonly evals: Evals;
  readonly sleep: (ms: number, signal?: AbortSignal) => Promise<void>;

  constructor(options: AxisOptions = {}) {
    for (const k of Object.keys(options)) {
      if (TENANT_KEYS.test(k))
        throw new TypeError(
          "the tenant is derived from the credential; it cannot be passed to the client",
        );
    }
    const env = typeof process !== "undefined" ? process.env : {};
    const apiKey = options.apiKey ?? (options.token ? undefined : env["AXIS_API_KEY"]);
    if (!apiKey && !options.token)
      throw new TypeError("an API key is required (apiKey option or AXIS_API_KEY)");
    this.sleep = options.sleep ?? defaultSleep;
    this.transport = new HttpTransport({
      baseUrl: options.baseUrl ?? env["AXIS_BASE_URL"] ?? DEFAULT_BASE_URL,
      apiKey,
      token: options.token,
      fetch: options.fetch,
      timeoutMs: options.timeoutMs,
      maxRetries: options.maxRetries,
      retryBaseMs: options.retryBaseMs,
      retryMaxMs: options.retryMaxMs,
      allowInsecure: options.allowInsecure,
      onResponse: options.onResponse,
      validateRequest: options.validateRequest,
      validateResponse: options.validateResponse,
      sleep: this.sleep,
      random: options.random,
    });
    this.api = new GeneratedApi(this.transport);
    this.runs = new Runs(this);
    this.blueprints = new Blueprints(this);
    this.approvals = new Approvals(this);
    this.policies = new Policies(this);
    this.audit = new Audit(this);
    this.killSwitches = new KillSwitches(this);
    this.usage = new Usage(this);
    this.evals = new Evals(this);
  }

  get baseUrl(): string {
    return this.transport.baseUrl;
  }

  toString(): string {
    return `Axis(${this.baseUrl}, credential=[REDACTED])`;
  }

  toJSON(): { baseUrl: string } {
    return { baseUrl: this.baseUrl };
  }
}
