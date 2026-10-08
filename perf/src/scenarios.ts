/** Scenarios against the real stack. Each returns a function the open-model generator calls once per arrival. */
import type { Outcome } from "./openload.js";
import { evaluate, gateClient, gateRequest, http, type StackInfo, type Tenant } from "./stack.js";

export type Scenario = (i: number) => Promise<Outcome>;

const httpOutcome = (status: number, okStatuses: number[]): Outcome =>
  okStatuses.includes(status) ? { ok: true } : { ok: false, label: `http_${status}` };

/** GET /me: API-key authentication + tenant resolution on every request. */
export const me =
  (info: StackInfo, t: Tenant): Scenario =>
  async () =>
    httpOutcome((await http(info, t, "GET", "/me")).status, [200]);

export const auditList =
  (info: StackInfo, t: Tenant): Scenario =>
  async () =>
    httpOutcome((await http(info, t, "GET", "/audit/events?limit=50")).status, [200]);

export const auditVerify =
  (info: StackInfo, t: Tenant): Scenario =>
  async () =>
    httpOutcome((await http(info, t, "POST", "/audit/verify", {})).status, [200]);

export const registryResolve =
  (info: StackInfo, t: Tenant, ref: string): Scenario =>
  async () =>
    httpOutcome(
      (await http(info, t, "GET", `/registry/resolve?ref=${encodeURIComponent(ref)}`)).status,
      [200],
    );

/** POST /runs only: the 202 acknowledgement ("run start latency"). The run then proceeds in the background. */
export const runStartAck =
  (info: StackInfo, t: Tenant): Scenario =>
  async (i) =>
    httpOutcome(
      (
        await http(info, t, "POST", "/runs", {
          blueprint: { name: "claims-agent", version: "1.0.0" },
          input: { prompt: `hello ${i}` },
        })
      ).status,
      [200, 201, 202],
    );

/** POST /runs and wait until the run is terminated: start-to-finish for a one-model-call run (gated by the kernel, audited). */
export const runComplete =
  (info: StackInfo, t: Tenant): Scenario =>
  async (i) => {
    const r = await http(info, t, "POST", "/runs", {
      blueprint: { name: "claims-agent", version: "1.0.0" },
      input: { prompt: `hello ${i}` },
    });
    if (![200, 201, 202].includes(r.status)) return { ok: false, label: `http_${r.status}` };
    const id = (r.json() as { id: string }).id;
    for (let n = 0; n < 600; n++) {
      const g = await http(info, t, "GET", `/runs/${id}`);
      if (g.status !== 200) return { ok: false, label: `http_${g.status}` };
      const run = g.json() as { state: string; exit_reason?: string };
      if (run.state === "terminated")
        return run.exit_reason && !["completed", "success", "ok"].includes(run.exit_reason)
          ? { ok: false, label: `exit_${run.exit_reason}` }
          : { ok: true };
      await new Promise((res) => setTimeout(res, 25));
    }
    return { ok: false, label: "run_not_terminated" };
  };

/** gRPC GateService.Evaluate for an ALLOWed read tool call: policy + gates + a hash-chained audit row in Postgres. */
export function gate(info: StackInfo, t: Tenant): { scenario: Scenario; close: () => void } {
  const c = gateClient(info.kernel_target);
  return {
    scenario: async () => {
      const res = await evaluate(c, t.kernelToken, gateRequest(t.tenantId));
      return res.decision === "DECISION_ALLOW"
        ? { ok: true }
        : { ok: false, label: `decision_${res.decision}` };
    },
    close: () => c.close(),
  };
}

export interface FanOutResult {
  subscribers: number;
  connected: number;
  completed: number;
  eventsPerSubscriberMin: number;
  eventsPerSubscriberMax: number;
  /** ms from the approval decision to the end of each subscriber's stream, percentiles */
  deliveryMs: { p50: number; p95: number; p99: number; max: number };
  failed: number;
}

async function readSse(
  url: string,
  key: string,
  onOpen: () => void,
): Promise<{ events: number; endedAt: number }> {
  const r = await fetch(url, {
    headers: { authorization: `Bearer ${key}`, accept: "text/event-stream" },
  });
  if (r.status !== 200 || !r.body) throw new Error(`sse ${r.status}`);
  onOpen();
  let events = 0;
  const dec = new TextDecoder();
  let buf = "";
  for await (const chunk of r.body as unknown as AsyncIterable<Uint8Array>) {
    buf += dec.decode(chunk, { stream: true });
    let k: number;
    while ((k = buf.indexOf("\n\n")) >= 0) {
      if (/^data:/m.test(buf.slice(0, k))) events++;
      buf = buf.slice(k + 2);
    }
  }
  return { events, endedAt: performance.now() };
}

/**
 * SSE fan-out: ``n`` subscribers on ONE run's event stream. The run waits for a human approval; once all are connected the approval is
 * granted and we measure how long each stream takes to end (the run terminates and the server closes the stream) and how many events
 * each subscriber received (they must all receive the same number).
 */
export async function sseFanOut(info: StackInfo, t: Tenant, n: number): Promise<FanOutResult> {
  const run = await http(info, t, "POST", "/runs", {
    blueprint: { name: "claims-agent", version: "1.0.0" },
    input: { prompt: `review claim ${Math.floor(Math.random() * 1e6)}` },
  });
  const runId = (run.json() as { id: string }).id;
  let approvalId = "";
  for (let k = 0; k < 400 && !approvalId; k++) {
    const l = await http(info, t, "GET", "/approvals?status=pending");
    approvalId =
      (l.json() as { items: { id: string; run_id: string }[] }).items.find(
        (a) => a.run_id === runId,
      )?.id ?? "";
    if (!approvalId) await new Promise((r) => setTimeout(r, 50));
  }
  if (!approvalId) throw new Error("no pending approval for the fan-out run");
  let connected = 0;
  const streams = Array.from({ length: n }, () =>
    readSse(`${info.gateway}/runs/${runId}/events`, t.apiKey, () => connected++).catch(
      () => undefined,
    ),
  );
  for (let k = 0; k < 400 && connected < n; k++) await new Promise((r) => setTimeout(r, 25));
  const decidedAt = performance.now();
  const d = await http(info, t, "POST", `/approvals/${approvalId}/decision`, {
    decision: "approve",
  });
  if (d.status !== 200) throw new Error(`approve: ${d.status} ${d.text}`);
  const done = await Promise.race([
    Promise.all(streams),
    new Promise<undefined>((r) => setTimeout(() => r(undefined), 60_000)),
  ]);
  const ok = (done ?? []).filter((x): x is { events: number; endedAt: number } => x !== undefined);
  const ms = ok.map((x) => x.endedAt - decidedAt).sort((a, b) => a - b);
  const pick = (p: number): number => ms[Math.min(ms.length - 1, Math.floor(ms.length * p))] ?? 0;
  const counts = ok.map((x) => x.events);
  return {
    subscribers: n,
    connected,
    completed: ok.length,
    eventsPerSubscriberMin: Math.min(...counts),
    eventsPerSubscriberMax: Math.max(...counts),
    deliveryMs: {
      p50: round(pick(0.5)),
      p95: round(pick(0.95)),
      p99: round(pick(0.99)),
      max: round(ms[ms.length - 1] ?? 0),
    },
    failed: n - ok.length,
  };
}

const round = (x: number): number => Math.round(x * 10) / 10;
