import {
  AxisAbortError,
  AxisApiError,
  AxisConnectionError,
  AxisError,
  AxisWaitTimeoutError,
} from "./errors.js";
import { redactText } from "./redact.js";
import { GeneratedApi } from "./generated/client.js";
import { DEFAULT_BASE_URL, OPERATIONS } from "./generated/operations.js";
import type {
  Approval,
  ApprovalPage,
  ApprovalStatus,
  BlueprintPage,
  BlueprintVersion,
  EvalGateResult,
  EvalRun,
  CreateEvalDatasetRequest,
  CreateEvalSuiteRequest,
  PutEvalSamplingConfigRequest,
  ListEvalReviewTasksParams,
  ListEvalRunsParams,
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
  DsseEnvelope,
  Identity,
  InstallPreview,
  MarketplaceInstall,
  MarketplaceListing,
  RegistryKey,
  RegistryNamespace,
  RegistrySignature,
  RegistryVersion,
  ResolvedBlueprint,
} from "./generated/types.js";
import { paginate, type Page } from "./pagination.js";
import { HttpTransport, type RequestOptions, type TransportConfig } from "./transport.js";
import { defaultSleep } from "./transport.js";
import { readSse, SseParser, type SseEvent } from "./sse.js";

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

/** A body read that fails mid-stream is a dropped connection, not a programming error. */
async function* guarded(src: AsyncGenerator<SseEvent>): AsyncGenerator<SseEvent> {
  try {
    yield* src;
  } catch (err) {
    if (err instanceof AxisError) throw err;
    throw new AxisConnectionError(
      `event stream interrupted: ${err instanceof Error ? redactText(err.message) : "unknown error"}`,
    );
  }
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

  /** AGIL explanation of a run (read-only, deterministic, derived from the audit trail). */
  explain(runId: string, options?: Opts) {
    return this.ax.api.explainRun({ runId }, options);
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
        for await (const ev of guarded(readSse(res.body, parser))) {
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
  get(approvalId: string, options?: Opts): Promise<Approval> {
    return this.ax.api.getApproval({ approvalId }, options);
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
  /** Make a published version (its `version_id`) the tenant's active version of its pack; the Risk Kernel enforces it from then on. */
  activate(versionId: string, options?: Opts): Promise<PolicyPack> {
    return this.ax.api.activatePolicyPack({ versionId }, options);
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
  /** AGIL explanation of one audited decision or approval step. */
  explainEvent(seq: number, options?: Opts) {
    return this.ax.api.explainAuditEvent({ seq }, options);
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

const EVAL_FINAL = new Set(["passed", "failed", "errored"]);

/** `"name@version"`, `"namespace/name@version"` or `{name, version, namespace?}` to the wire shape of an eval run's blueprint. */
export function parseEvalBlueprint(
  ref: BlueprintRef | { namespace: string; name: string; version: string },
): {
  name: string;
  version: string;
  namespace?: string;
} {
  if (typeof ref !== "string") {
    const o = ref as { namespace?: string; name: string; version: string };
    return o.namespace === undefined
      ? { name: o.name, version: o.version }
      : { namespace: o.namespace, name: o.name, version: o.version };
  }
  const slash = ref.indexOf("/");
  if (slash < 0) return parseBlueprintRef(ref);
  const inner = parseBlueprintRef(ref.slice(slash + 1));
  return { namespace: ref.slice(0, slash), ...inner };
}

/** Datasets: immutable numbered versions; a PHI dataset is redacted before it is stored. */
export class EvalDatasets {
  constructor(private readonly ax: Axis) {}
  list(args: { name?: string | undefined } = {}, options?: Opts) {
    return this.ax.api.listEvalDatasets(pick(args), options);
  }
  create(
    body: CreateEvalDatasetRequest,
    args: { idempotencyKey?: string | undefined } = {},
    options?: Opts,
  ) {
    return this.ax.api.createEvalDataset(
      pick({ body, idempotencyKey: args.idempotencyKey }),
      options,
    );
  }
  /** `version` is an integer or `"latest"`. */
  get(name: string, version: number | "latest" = "latest", options?: Opts) {
    return this.ax.api.getEvalDatasetVersion({ name, version: String(version) }, options);
  }
}

/** Suites: immutable definitions (`name@major.minor.patch`) pinned to a dataset version. */
export class EvalSuites {
  constructor(private readonly ax: Axis) {}
  list(options?: Opts) {
    return this.ax.api.listEvalSuites(options);
  }
  create(
    body: CreateEvalSuiteRequest,
    args: { idempotencyKey?: string | undefined } = {},
    options?: Opts,
  ) {
    return this.ax.api.createEvalSuite(
      pick({ body, idempotencyKey: args.idempotencyKey }),
      options,
    );
  }
  get(ref: string, options?: Opts) {
    return this.ax.api.getEvalSuite({ suite: ref }, options);
  }
}

export class EvalBaselines {
  constructor(private readonly ax: Axis) {}
  list(blueprint: string, suite: string, options?: Opts) {
    return this.ax.api.listEvalBaselines({ blueprint, suite }, options);
  }
  /** Admin: make a finished, passed, intact run the baseline for its blueprint name and suite. */
  set(runId: string, args: { idempotencyKey?: string | undefined } = {}, options?: Opts) {
    return this.ax.api.setEvalBaseline(
      pick({ body: { run_id: runId }, idempotencyKey: args.idempotencyKey }),
      options,
    );
  }
}

/** Human review. The publisher of a blueprint and whoever started a run never see (or get) its tasks. */
export class EvalReview {
  constructor(private readonly ax: Axis) {}
  tasks(args: ListEvalReviewTasksParams = {}, options?: Opts) {
    return this.ax.api.listEvalReviewTasks(pick(args), options);
  }
  claim(taskId: string, options?: Opts) {
    return this.ax.api.claimEvalReviewTask({ taskId }, options);
  }
  grade(taskId: string, args: { score: number; comment: string }, options?: Opts) {
    return this.ax.api.gradeEvalReviewTask({ taskId, body: args }, options);
  }
  skip(taskId: string, reason: string, options?: Opts) {
    return this.ax.api.skipEvalReviewTask({ taskId, body: { reason } }, options);
  }
}

/** Online sampling of production runs. Results raise alerts and show history; they never gate or change a release. */
export class EvalSampling {
  constructor(private readonly ax: Axis) {}
  list(options?: Opts) {
    return this.ax.api.listEvalSamplingConfigs(options);
  }
  put(samplingId: string, body: PutEvalSamplingConfigRequest, options?: Opts) {
    return this.ax.api.putEvalSamplingConfig({ samplingId, body }, options);
  }
  summary(
    args: { blueprint?: string | undefined; suite?: string | undefined } = {},
    options?: Opts,
  ) {
    return this.ax.api.getEvalOnlineSummary(pick(args), options);
  }
}

/** Runners: only runs of a registered, un-revoked runner count toward a release gate. */
export class EvalRunners {
  constructor(private readonly ax: Axis) {}
  list(options?: Opts) {
    return this.ax.api.listEvalRunners(options);
  }
  register(runnerId: string, description?: string, options?: Opts) {
    return this.ax.api.registerEvalRunner(
      pick({ runnerId, body: description === undefined ? undefined : { description } }),
      options,
    );
  }
  revoke(runnerId: string, options?: Opts) {
    return this.ax.api.revokeEvalRunner({ runnerId }, options);
  }
}

export class Evals {
  readonly datasets: EvalDatasets;
  readonly suites: EvalSuites;
  readonly baselines: EvalBaselines;
  readonly review: EvalReview;
  readonly sampling: EvalSampling;
  readonly runners: EvalRunners;
  constructor(private readonly ax: Axis) {
    this.datasets = new EvalDatasets(ax);
    this.suites = new EvalSuites(ax);
    this.baselines = new EvalBaselines(ax);
    this.review = new EvalReview(ax);
    this.sampling = new EvalSampling(ax);
    this.runners = new EvalRunners(ax);
  }

  /** Queue a run of `suite` against a blueprint version; a registered runner executes it. The hub binds it to the version's content hash. */
  start(
    args: {
      suite: string;
      blueprint: BlueprintRef | { namespace: string; name: string; version: string };
      mode?: "ci" | "manual" | undefined;
      idempotencyKey?: string | undefined;
    },
    options?: Opts,
  ): Promise<EvalRun> {
    return this.ax.api.startEvalRun(
      pick({
        body: pick({
          suite: args.suite,
          mode: args.mode,
          blueprint: parseEvalBlueprint(args.blueprint),
        }),
        idempotencyKey: args.idempotencyKey,
      }),
      options,
    );
  }

  get(evalRunId: string, options?: Opts) {
    return this.ax.api.getEvalRun({ evalRunId }, options);
  }

  list(args: ListEvalRunsParams = {}, options?: Opts) {
    return this.ax.api.listEvalRuns(pick(args), options);
  }

  /** Every run, following the cursor (bounded by `maxItems`, default 1000). */
  async *iterate(
    args: Omit<ListEvalRunsParams, "cursor"> & { maxItems?: number } = {},
    options?: Opts,
  ): AsyncGenerator<EvalRun> {
    const { maxItems = 1000, ...q } = args;
    let cursor: string | undefined;
    let n = 0;
    for (;;) {
      const page = await this.list(pick({ ...q, cursor }), options);
      for (const r of page.items) {
        if (n++ >= maxItems) return;
        yield r;
      }
      if (!page.next_cursor) return;
      cursor = page.next_cursor;
    }
  }

  /** Poll until the run is passed, failed or errored. Throws AxisWaitTimeoutError when `timeoutMs` elapses first. */
  async wait(evalRunId: string, options: WaitOptions = {}) {
    const timeout = options.timeoutMs ?? 300_000;
    const poll = options.pollIntervalMs ?? 1000;
    const started = Date.now();
    const { timeoutMs: _t, pollIntervalMs: _p, ...reqOpts } = options;
    void _t;
    void _p;
    for (;;) {
      const run = await this.get(evalRunId, reqOpts);
      if (EVAL_FINAL.has(run.status)) return run;
      const remaining = timeout - (Date.now() - started);
      if (remaining <= 0)
        throw new AxisWaitTimeoutError(
          `eval run ${evalRunId} still ${run.status} after ${timeout} ms`,
        );
      await this.ax.sleep(Math.min(poll, remaining), options.signal);
    }
  }

  /** Comparison of a finished run with its blueprint's baseline; `undefined` when there is no baseline. */
  async comparison(evalRunId: string, options?: Opts) {
    return (await this.ax.api.getEvalRunComparison({ evalRunId }, options)).comparison;
  }

  /**
   * Ask the release gate. Fail-closed: `allowed` is true only when every required suite has a fresh, intact, passing run of this exact
   * content hash by a registered runner with no regression against the baseline; `reasons` explains every block.
   */
  gate(
    args: {
      blueprint: {
        name: string;
        version: string;
        content_hash: string;
        namespace?: string | undefined;
      };
      suites?: { ref: string; threshold?: number | undefined }[] | undefined;
    },
    options?: Opts,
  ): Promise<EvalGateResult> {
    return this.ax.api.gateEvalRelease(
      { body: pick({ blueprint: pick(args.blueprint), suites: args.suites?.map((x) => pick(x)) }) },
      options,
    );
  }
}

export interface SignedBundle {
  abl: AblDocument;
  signature: RegistrySignature;
  provenance: DsseEnvelope;
}

/**
 * Signed blueprint registry. Publishing needs a signed bundle (detached Ed25519 signature + DSSE provenance) produced by publisher
 * tooling that holds the private key and runs the ABL compiler (`axis registry sign`); the SDK transports it and never sees a key.
 */
export class Registry {
  constructor(private readonly ax: Axis) {}
  namespaces(options?: Opts) {
    return this.ax.api.listRegistryNamespaces(options);
  }
  claim(
    namespace: string,
    args: { idempotencyKey?: string | undefined } = {},
    options?: Opts,
  ): Promise<RegistryNamespace> {
    return this.ax.api.claimRegistryNamespace(
      pick({ body: { namespace }, idempotencyKey: args.idempotencyKey }),
      options,
    );
  }
  keys(namespace: string, options?: Opts) {
    return this.ax.api.listRegistryKeys({ namespace }, options);
  }
  addKey(
    namespace: string,
    publicKey: string,
    args: { idempotencyKey?: string | undefined } = {},
    options?: Opts,
  ): Promise<RegistryKey> {
    return this.ax.api.addRegistryKey(
      pick({ namespace, body: { public_key: publicKey }, idempotencyKey: args.idempotencyKey }),
      options,
    );
  }
  publish(
    namespace: string,
    bundle: SignedBundle,
    args: { idempotencyKey?: string | undefined } = {},
    options?: Opts,
  ): Promise<RegistryVersion> {
    return this.ax.api.publishRegistryBlueprint(
      pick({ namespace, body: bundle, idempotencyKey: args.idempotencyKey }),
      options,
    );
  }
  versions(namespace: string, name: string, options?: Opts) {
    return this.ax.api.listRegistryVersions({ namespace, name }, options);
  }
  yank(namespace: string, name: string, version: string, reason: string, options?: Opts) {
    return this.ax.api.yankRegistryVersion({ namespace, name, version, body: { reason } }, options);
  }
  /** `namespace/name@range` -> the highest non-yanked version, verified by the server on every call (hash, signature, provenance). */
  resolve(ref: string, options?: Opts): Promise<ResolvedBlueprint> {
    return this.ax.api.resolveRegistryBlueprint({ ref }, options);
  }
}

export interface InstallConsent {
  /** Called with the permission diff. Return true to consent; the install is sent only then and echoes the digest of THIS diff. */
  consent: (preview: InstallPreview) => boolean | Promise<boolean>;
  idempotencyKey?: string | undefined;
}

export class Marketplace {
  constructor(private readonly ax: Axis) {}
  listings(args: { q?: string | undefined; category?: string | undefined } = {}, options?: Opts) {
    return this.ax.api.listMarketplaceListings(pick(args), options);
  }
  listing(namespace: string, name: string, options?: Opts): Promise<MarketplaceListing> {
    return this.ax.api.getMarketplaceListing({ namespace, name }, options);
  }
  /** The permission diff against the tenant baseline, the findings and the consent digest (admin). */
  preview(namespace: string, name: string, range = "*", options?: Opts): Promise<InstallPreview> {
    return this.ax.api.previewMarketplaceInstall({ body: { namespace, name, range } }, options);
  }
  install(
    args: {
      namespace: string;
      name: string;
      version: string;
      contentHash: string;
      consentDigest: string;
      idempotencyKey?: string | undefined;
    },
    options?: Opts,
  ): Promise<MarketplaceInstall> {
    return this.ax.api.installMarketplaceListing(
      pick({
        body: {
          namespace: args.namespace,
          name: args.name,
          version: args.version,
          content_hash: args.contentHash,
          consent_digest: args.consentDigest,
        },
        idempotencyKey: args.idempotencyKey,
      }),
      options,
    );
  }
  /** Preview, ask `consent`, then install exactly what was previewed (version, hash and digest come from the preview, never the caller). */
  async installWithConsent(
    namespace: string,
    name: string,
    range: string,
    c: InstallConsent,
    options?: Opts,
  ): Promise<MarketplaceInstall> {
    const p = await this.preview(namespace, name, range, options);
    if (!(await c.consent(p)))
      throw new AxisError("install cancelled: the permission diff was not consented to");
    return this.install(
      pick({
        namespace: p.namespace,
        name: p.name,
        version: p.version,
        contentHash: p.content_hash,
        consentDigest: p.consent_digest,
        idempotencyKey: c.idempotencyKey,
      }),
      options,
    );
  }
  installs(options?: Opts) {
    return this.ax.api.listMarketplaceInstalls(options);
  }
  uninstall(namespace: string, name: string, options?: Opts) {
    return this.ax.api.uninstallMarketplaceListing({ namespace, name }, options);
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
  readonly registry: Registry;
  readonly marketplace: Marketplace;
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
    this.registry = new Registry(this);
    this.marketplace = new Marketplace(this);
  }

  /** Who this credential belongs to: tenant, member, role, credential kind and (for API keys) scopes. */
  me(options?: Opts): Promise<Identity> {
    return this.api.getMe(options);
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
