import { HubError, type EvalHub, type EvalRunDoc, type HubPrincipal } from "@axis/eval-hub";
import {
  PortConflict,
  PortForbidden,
  PortInvalid,
  PortNotFound,
  PortUnavailable,
  type EvalRunDetailDto,
  type EvalRunDto,
  type EvalsPort,
  type Principal,
} from "../ports.js";

/** Translates the hub's refusals. An integrity or validation failure carries the failing checks to the caller. */
export function fromHubError(e: unknown): never {
  if (!(e instanceof HubError)) throw e;
  switch (e.code) {
    case "not_found":
      throw new PortNotFound(e.message);
    case "forbidden":
    case "unauthenticated":
      throw new PortForbidden(e.message);
    case "conflict":
      throw new PortConflict(e.message);
    case "invalid":
    case "integrity_failed":
      throw new PortInvalid(
        e.message,
        (e.checks.length > 0 ? e.checks : [""]).map((c) => ({
          path: `/${c}`,
          message: e.message,
          keyword: e.code,
        })),
      );
    default:
      throw new PortUnavailable(e.message);
  }
}

/** The tenant and the role come from the authenticated gateway principal and nothing else. */
export const hubPrincipal = (p: Principal): HubPrincipal => ({
  kind: "tenant",
  tenantId: p.tenantId,
  subject: p.memberId,
  role: p.role,
});

/** The public EvalRun: what a client needs, without the hub's internal hashes. */
export function runDto(r: EvalRunDoc): EvalRunDto {
  return {
    id: r.id,
    suite: r.suite_ref,
    status: r.status,
    score: r.scores?.overall ?? null,
    threshold: r.pass_threshold,
    blueprint: r.blueprint,
    mode: r.mode,
    ...(r.scores ? { scores: r.scores } : {}),
    sample_size: r.sample_size,
    pending_human: r.pending_human,
    cost: r.cost,
    runner_id: r.runner_id,
    requested_by: r.requested_by,
    ...(r.provenance ? { provenance: r.provenance } : {}),
    created_at: r.created_at,
    started_at: r.started_at,
    finished_at: r.finished_at,
    failure_reason: r.failure_reason,
    record_hash: r.record_hash,
  };
}

const wrap = async <T>(f: () => Promise<T>): Promise<T> => {
  try {
    return await f();
  } catch (e) {
    return fromHubError(e);
  }
};

export class EvalsAdapter implements EvalsPort {
  constructor(private readonly hub: EvalHub) {}

  start(p: Principal, q: Parameters<EvalsPort["start"]>[1]): Promise<EvalRunDto> {
    return wrap(async () =>
      runDto(
        await this.hub.runs.request(hubPrincipal(p), {
          suite_ref: q.suite,
          blueprint: q.blueprint,
          ...(q.mode ? { mode: q.mode } : {}),
        }),
      ),
    );
  }
  listRuns(p: Principal, q: Parameters<EvalsPort["listRuns"]>[1]) {
    return wrap(async () => {
      const r = await this.hub.runs.list(hubPrincipal(p), {
        limit: q.limit,
        ...(q.cursor ? { cursor: q.cursor } : {}),
        ...(q.suite ? { suite_ref: q.suite } : {}),
        ...(q.blueprint ? { blueprint_name: q.blueprint } : {}),
        ...(q.content_hash ? { content_hash: q.content_hash } : {}),
        ...(q.status ? { status: q.status } : {}),
      });
      return { items: r.items.map(runDto), ...(r.next_cursor ? { next: r.next_cursor } : {}) };
    });
  }
  getRun(p: Principal, id: string): Promise<EvalRunDetailDto> {
    return wrap(async () => {
      const r = await this.hub.runs.get(hubPrincipal(p), id);
      return { ...runDto(r), case_results: r.case_results };
    });
  }
  comparison(p: Principal, id: string) {
    return wrap(async () => {
      const c = await this.hub.baselines.compareRun(hubPrincipal(p), id);
      return c === null ? undefined : (c as unknown as Record<string, unknown>);
    });
  }
  gate(p: Principal, body: { blueprint: unknown; suites?: unknown }) {
    return wrap(
      async () =>
        (await this.hub.gate.check(hubPrincipal(p), {
          blueprint: body.blueprint,
          suites: body.suites,
        })) as unknown as Record<string, unknown>,
    );
  }
  listDatasets(p: Principal, name?: string) {
    return wrap(
      async () =>
        (await this.hub.datasets.list(hubPrincipal(p), name)) as unknown as Record<
          string,
          unknown
        >[],
    );
  }
  createDataset(p: Principal, body: Record<string, unknown>) {
    return wrap(async () => {
      const d = await this.hub.datasets.create(hubPrincipal(p), {
        name: body["name"],
        description: body["description"],
        phi: body["phi"],
        cases: body["cases"],
      });
      const { cases: _cases, ...rest } = d;
      void _cases;
      return rest as unknown as Record<string, unknown>;
    });
  }
  getDataset(p: Principal, name: string, version: string) {
    return wrap(
      async () =>
        (await this.hub.datasets.get(hubPrincipal(p), `${name}@${version}`)) as unknown as Record<
          string,
          unknown
        >,
    );
  }
  listSuites(p: Principal) {
    return wrap(
      async () =>
        (await this.hub.suites.list(hubPrincipal(p))) as unknown as Record<string, unknown>[],
    );
  }
  createSuite(p: Principal, body: Record<string, unknown>) {
    return wrap(
      async () =>
        (await this.hub.suites.create(hubPrincipal(p), body as never)) as unknown as Record<
          string,
          unknown
        >,
    );
  }
  getSuite(p: Principal, ref: string) {
    return wrap(
      async () =>
        (await this.hub.suites.get(hubPrincipal(p), ref)) as unknown as Record<string, unknown>,
    );
  }
  listBaselines(p: Principal, blueprint: string, suite: string) {
    return wrap(
      async () =>
        (await this.hub.baselines.list(hubPrincipal(p), {
          blueprint_name: blueprint,
          suite_ref: suite,
        })) as unknown as Record<string, unknown>[],
    );
  }
  setBaseline(p: Principal, runId: string) {
    return wrap(
      async () =>
        (await this.hub.baselines.set(hubPrincipal(p), { run_id: runId })) as unknown as Record<
          string,
          unknown
        >,
    );
  }
  listTasks(p: Principal, q: { state?: string; run_id?: string }) {
    return wrap(
      async () =>
        (await this.hub.reviews.list(hubPrincipal(p), q)) as unknown as Record<string, unknown>[],
    );
  }
  claimTask(p: Principal, id: string) {
    return wrap(
      async () =>
        (await this.hub.reviews.claim(hubPrincipal(p), id)) as unknown as Record<string, unknown>,
    );
  }
  gradeTask(p: Principal, id: string, body: { score: number; comment: string }) {
    return wrap(
      async () =>
        (await this.hub.reviews.grade(hubPrincipal(p), id, body)) as unknown as Record<
          string,
          unknown
        >,
    );
  }
  skipTask(p: Principal, id: string, reason: string) {
    return wrap(
      async () =>
        (await this.hub.reviews.skip(hubPrincipal(p), id, reason)) as unknown as Record<
          string,
          unknown
        >,
    );
  }
  listSampling(p: Principal) {
    return wrap(
      async () =>
        (await this.hub.online.list(hubPrincipal(p))) as unknown as Record<string, unknown>[],
    );
  }
  putSampling(p: Principal, id: string, body: Record<string, unknown>) {
    return wrap(
      async () =>
        (await this.hub.online.put(hubPrincipal(p), id, {
          blueprint_name: body["blueprint"],
          suite_ref: body["suite"],
          rate: body["rate"],
          max_per_hour: body["max_per_hour"],
          ...(body["redaction"] !== undefined ? { redaction: body["redaction"] } : {}),
          ...(body["enabled"] !== undefined ? { enabled: body["enabled"] } : {}),
          ...(body["alert_threshold"] !== undefined
            ? { alert_threshold: body["alert_threshold"] }
            : {}),
        })) as unknown as Record<string, unknown>,
    );
  }
  onlineSummary(p: Principal, q: { blueprint?: string; suite?: string }) {
    return wrap(
      async () =>
        (await this.hub.online.summary(hubPrincipal(p), {
          ...(q.blueprint ? { blueprint_name: q.blueprint } : {}),
          ...(q.suite ? { suite_ref: q.suite } : {}),
        })) as unknown as Record<string, unknown>[],
    );
  }
  listRunners(p: Principal) {
    return wrap(
      async () =>
        (await this.hub.runs.listRunners(hubPrincipal(p))) as unknown as Record<string, unknown>[],
    );
  }
  registerRunner(p: Principal, id: string, description?: string) {
    return wrap(
      async () =>
        (await this.hub.runs.registerRunner(hubPrincipal(p), id, description)) as unknown as Record<
          string,
          unknown
        >,
    );
  }
  revokeRunner(p: Principal, id: string) {
    return wrap(
      async () =>
        (await this.hub.runs.revokeRunner(hubPrincipal(p), id)) as unknown as Record<
          string,
          unknown
        >,
    );
  }
}

/** Fail-closed stand-in for a gateway that was wired without an Eval Hub: every operation is a 503, never an empty success. */
export class UnavailableEvals implements EvalsPort {
  private fail(): never {
    throw new PortUnavailable("the Eval Hub is not configured on this gateway");
  }
  start = () => this.fail();
  listRuns = () => this.fail();
  getRun = () => this.fail();
  comparison = () => this.fail();
  gate = () => this.fail();
  listDatasets = () => this.fail();
  createDataset = () => this.fail();
  getDataset = () => this.fail();
  listSuites = () => this.fail();
  createSuite = () => this.fail();
  getSuite = () => this.fail();
  listBaselines = () => this.fail();
  setBaseline = () => this.fail();
  listTasks = () => this.fail();
  claimTask = () => this.fail();
  gradeTask = () => this.fail();
  skipTask = () => this.fail();
  listSampling = () => this.fail();
  putSampling = () => this.fail();
  onlineSummary = () => this.fail();
  listRunners = () => this.fail();
  registerRunner = () => this.fail();
  revokeRunner = () => this.fail();
}
