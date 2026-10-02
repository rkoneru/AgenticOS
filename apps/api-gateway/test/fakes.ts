import { randomUUID } from "node:crypto";
import {
  PortConflict,
  PortNotFound,
  PortUnavailable,
  type KillSwitchDto,
  type Page,
  type RunDto,
  type RunEventDto,
  type RunsPort,
  type StartRun,
} from "../src/index.js";
import type { KernelKillApplier, KillRequest } from "../src/index.js";

export const PID = "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV";

interface RunRec {
  tenantId: string;
  run: RunDto;
  events: RunEventDto[];
  manifest: unknown;
  waiters: (() => void)[];
  done: boolean;
}

/**
 * A scripted run service with the semantics the gateway relies on (it is NOT the Python server; the real one is exercised in
 * `runtime/tests/test_runserver.py`): tenant-scoped everything, a foreign run id is `undefined`/404, signals change state.
 */
export class FakeRuns implements RunsPort {
  readonly runs = new Map<string, RunRec>();
  starts: StartRun[] = [];
  failStart = false;
  streamsOpened = 0;

  async start(r: StartRun): Promise<RunDto> {
    if (this.failStart) throw new PortUnavailable("down");
    this.starts.push(r);
    const run: RunDto = {
      id: r.runId,
      init_pid: PID,
      blueprint: r.blueprint,
      state: "running",
      exit_reason: null,
      trace_id: r.traceId,
      created_at: new Date().toISOString(),
      finished_at: null,
    };
    this.runs.set(r.runId, {
      tenantId: r.tenantId,
      run,
      manifest: r.manifest,
      waiters: [],
      done: false,
      events: [
        { sequence: 1, type: "run_started", pid: PID, at: run.created_at, data: { blueprint: r.blueprint.name } },
        { sequence: 2, type: "process_spawned", pid: PID, at: run.created_at, data: { agent: r.blueprint.name } },
      ],
    });
    return { ...run };
  }

  private own(tenantId: string, id: string): RunRec | undefined {
    const r = this.runs.get(id);
    return r && r.tenantId === tenantId ? r : undefined;
  }

  async get(tenantId: string, id: string): Promise<RunDto | undefined> {
    const r = this.own(tenantId, id);
    return r && { ...r.run };
  }

  async list(tenantId: string, q: { limit: number; after?: string; state?: string; blueprint?: string }): Promise<Page<RunDto>> {
    const all = [...this.runs.values()]
      .filter((r) => r.tenantId === tenantId && (!q.state || r.run.state === q.state) && (!q.blueprint || r.run.blueprint.name === q.blueprint))
      .map((r) => ({ key: `${r.run.created_at}|${r.run.id}`, run: r.run }))
      .sort((a, b) => (a.key < b.key ? -1 : 1))
      .filter((x) => q.after === undefined || x.key > q.after);
    const slice = all.slice(0, q.limit);
    return { items: slice.map((x) => ({ ...x.run })), next: all.length > q.limit ? (slice[slice.length - 1] as { key: string }).key : undefined };
  }

  async signal(tenantId: string, id: string, s: { pid?: string; signal: string; reason?: string }): Promise<{ pid: string; state: string }> {
    const r = this.own(tenantId, id);
    if (!r || (s.pid !== undefined && s.pid !== PID)) throw new PortNotFound();
    if (r.run.state === "terminated") throw new PortConflict("the process has terminated");
    if (s.signal === "PAUSE") r.run.state = "suspended";
    else if (s.signal === "RESUME") r.run.state = "running";
    else if (s.signal === "TERM" || s.signal === "KILL") {
      r.run.state = "terminated";
      r.run.exit_reason = "killed";
      r.run.finished_at = new Date().toISOString();
      this.append(id, { type: "process_transition", data: { to: "terminated", exit_reason: "killed" } });
      r.done = true;
    }
    return { pid: PID, state: r.run.state };
  }

  append(id: string, e: { type: string; data?: Record<string, unknown> }): void {
    const r = this.runs.get(id);
    if (!r) throw new Error("no run");
    r.events.push({ sequence: r.events.length + 1, type: e.type, pid: PID, at: new Date().toISOString(), ...(e.data ? { data: e.data } : {}) });
    for (const w of r.waiters.splice(0)) w();
  }

  finish(id: string): void {
    const r = this.runs.get(id);
    if (r) {
      r.done = true;
      r.run.state = "terminated";
      r.run.exit_reason = "completed";
      for (const w of r.waiters.splice(0)) w();
    }
  }

  async events(tenantId: string, id: string, q: { afterSequence: number; limit: number }): Promise<RunEventDto[] | undefined> {
    const r = this.own(tenantId, id);
    return r && r.events.filter((e) => e.sequence > q.afterSequence).slice(0, q.limit).map((e) => ({ ...e }));
  }

  async *stream(tenantId: string, id: string, after: number, signal: AbortSignal): AsyncIterable<RunEventDto> {
    const r = this.own(tenantId, id);
    if (!r) throw new PortNotFound();
    this.streamsOpened++;
    let seen = after;
    while (!signal.aborted) {
      for (const e of r.events.filter((x) => x.sequence > seen)) {
        seen = e.sequence;
        yield { ...e };
      }
      if (r.done) return;
      await new Promise<void>((resolve) => {
        r.waiters.push(resolve);
        signal.addEventListener("abort", () => resolve(), { once: true });
      });
    }
  }
}

export class FakeKernel implements KernelKillApplier {
  calls: KillRequest[] = [];
  down = false;
  async apply(r: KillRequest): Promise<{ auditEventId: string }> {
    if (this.down) throw new PortUnavailable("kernel down");
    this.calls.push(r);
    return { auditEventId: randomUUID() };
  }
}

export type { KillSwitchDto };
