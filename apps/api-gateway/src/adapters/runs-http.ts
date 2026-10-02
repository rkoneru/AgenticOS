import {
  PortConflict,
  PortInvalid,
  PortNotFound,
  PortUnavailable,
  type Page,
  type RunDto,
  type RunEventDto,
  type RunsPort,
  type StartRun,
} from "../ports.js";

/**
 * Client of the dev run service (`runtime/src/axis_runtime/runserver.py`). One bearer per tenant (`tokenFor`); the run service derives
 * the tenant from it, so this client cannot name another tenant. Answers are checked for shape before they are relayed.
 */
export class HttpRunsPort implements RunsPort {
  constructor(
    private readonly baseUrl: string,
    private readonly tokenFor: (tenantId: string) => string | undefined,
    private readonly timeoutMs = 15_000,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  private async call(
    tenantId: string,
    method: string,
    path: string,
    body?: unknown,
    signal?: AbortSignal,
  ): Promise<Response> {
    const token = this.tokenFor(tenantId);
    if (!token) throw new PortUnavailable("no run-service credential for this tenant");
    const ac = signal ? undefined : AbortSignal.timeout(this.timeoutMs);
    try {
      return await this.fetchImpl(this.baseUrl.replace(/\/$/, "") + path, {
        method,
        headers: {
          authorization: `Bearer ${token}`,
          ...(body !== undefined ? { "content-type": "application/json" } : {}),
        },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
        signal: signal ?? (ac as AbortSignal),
      });
    } catch {
      throw new PortUnavailable("the run service is unavailable; retry");
    }
  }

  private async json(res: Response): Promise<Record<string, unknown>> {
    if (res.status === 404) throw new PortNotFound();
    if (res.status === 409) throw new PortConflict((await safeDetail(res)) ?? "conflict");
    if (res.status === 422 || res.status === 400)
      throw new PortInvalid((await safeDetail(res)) ?? "invalid");
    if (res.status >= 300)
      throw new PortUnavailable("the run service could not complete the request; retry");
    try {
      const j = (await res.json()) as unknown;
      if (typeof j !== "object" || j === null) throw new Error("shape");
      return j as Record<string, unknown>;
    } catch {
      throw new PortUnavailable("the run service answered with an invalid response");
    }
  }

  async start(r: StartRun): Promise<RunDto> {
    const res = await this.call(r.tenantId, "POST", "/v1/runs", {
      run_id: r.runId,
      trace_id: r.traceId,
      blueprint: r.blueprint,
      manifest: r.manifest,
      input: r.input,
      principal: { id: r.principal.memberId, role: r.principal.role },
    });
    return (await this.json(res)) as unknown as RunDto;
  }

  async get(tenantId: string, runId: string): Promise<RunDto | undefined> {
    const res = await this.call(tenantId, "GET", `/v1/runs/${encodeURIComponent(runId)}`);
    if (res.status === 404) return undefined;
    return (await this.json(res)) as unknown as RunDto;
  }

  async list(
    tenantId: string,
    q: { limit: number; after?: string; state?: string; blueprint?: string },
  ): Promise<Page<RunDto>> {
    const p = new URLSearchParams({ limit: String(q.limit) });
    if (q.after) p.set("cursor", q.after);
    if (q.state) p.set("state", q.state);
    if (q.blueprint) p.set("blueprint", q.blueprint);
    const j = (await this.json(await this.call(tenantId, "GET", `/v1/runs?${p}`))) as {
      items?: RunDto[];
      next_cursor?: string | null;
    };
    if (!Array.isArray(j.items))
      throw new PortUnavailable("the run service answered with an invalid response");
    return { items: j.items, next: j.next_cursor ?? undefined };
  }

  async signal(
    tenantId: string,
    runId: string,
    s: { pid?: string; signal: string; reason?: string },
  ): Promise<{ pid: string; state: string }> {
    const j = await this.json(
      await this.call(tenantId, "POST", `/v1/runs/${encodeURIComponent(runId)}/signals`, s),
    );
    return { pid: String(j["pid"]), state: String(j["state"]) };
  }

  async events(
    tenantId: string,
    runId: string,
    q: { afterSequence: number; limit: number },
  ): Promise<RunEventDto[] | undefined> {
    const res = await this.call(
      tenantId,
      "GET",
      `/v1/runs/${encodeURIComponent(runId)}/events?after_sequence=${q.afterSequence}&limit=${q.limit}`,
    );
    if (res.status === 404) return undefined;
    const j = (await this.json(res)) as { items?: RunEventDto[] };
    if (!Array.isArray(j.items))
      throw new PortUnavailable("the run service answered with an invalid response");
    return j.items;
  }

  async *stream(
    tenantId: string,
    runId: string,
    afterSequence: number,
    signal: AbortSignal,
  ): AsyncIterable<RunEventDto> {
    const res = await this.call(
      tenantId,
      "GET",
      `/v1/runs/${encodeURIComponent(runId)}/events/stream?after_sequence=${afterSequence}`,
      undefined,
      signal,
    );
    if (res.status === 404) throw new PortNotFound();
    if (res.status !== 200 || !res.body)
      throw new PortUnavailable("the run service could not open the stream");
    const dec = new TextDecoder();
    let buf = "";
    for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
      buf += dec.decode(chunk, { stream: true });
      let i: number;
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const frame = buf.slice(0, i);
        buf = buf.slice(i + 2);
        const data = frame
          .split("\n")
          .filter((l) => l.startsWith("data: "))
          .map((l) => l.slice(6))
          .join("\n");
        const evt = frame
          .split("\n")
          .find((l) => l.startsWith("event: "))
          ?.slice(7);
        if (evt === "end") return;
        if (data && (evt === undefined || evt === "run_event"))
          yield JSON.parse(data) as RunEventDto;
      }
    }
  }
}

async function safeDetail(res: Response): Promise<string | undefined> {
  try {
    const j = (await res.json()) as { detail?: unknown };
    return typeof j.detail === "string" ? j.detail.slice(0, 200) : undefined;
  } catch {
    return undefined;
  }
}
