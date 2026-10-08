import http from "node:http";
import {
  BadRequest,
  RateLimiter,
  readJson,
  refuseProduction,
  sendJson,
  staticTokenAuthenticator,
} from "@axis/registry";
import { HubError } from "./errors.js";
import type { EvalHub } from "./hub.js";
import type { EvalRunDoc, HubPrincipal, HubRole } from "./types.js";

/**
 * DEV / E2E ONLY. Loopback HTTP/JSON over the hub (docs/spec/eval-hub.md, wire examples in contract/wire-v1.json). The tenant and the
 * role come from the BEARER TOKEN; a `tenant_id` in a body or query that differs is rejected with 403. Refuses NODE_ENV=production.
 *
 *  POST /v1/evals/datasets                      {name, description?, phi?, cases[]}                  -> next immutable version
 *  GET  /v1/evals/datasets[?name=]              GET /v1/evals/datasets/{name}/versions/{n|latest}
 *  POST /v1/evals/suites                        GET /v1/evals/suites[/{ref}]
 *  PUT  /v1/evals/runners/{id}   POST /v1/evals/runners/{id}/revoke   GET /v1/evals/runners
 *  POST /v1/evals/runs          (tenant: queue a run; runner: start a run)
 *  GET  /v1/evals/runs[?status&suite_ref&blueprint_name&content_hash&mode&limit&cursor]   GET /v1/evals/runs/{id}
 *  POST /v1/evals/runs/{id}/claim|results|fail      (runner)
 *  GET  /v1/evals/runs/{id}/comparison              GET /v1/evals/runs/{id}/attestation
 *  POST /v1/evals/baselines {run_id}                GET /v1/evals/baselines?blueprint_name&suite_ref
 *  POST /v1/evals/gate {blueprint, suites}
 *  GET  /v1/evals/reviews/tasks[?state&run_id&all]  GET .../tasks/{id}   POST .../tasks/{id}/claim|grade|skip   POST /v1/evals/reviews/sweep
 *  PUT  /v1/evals/sampling/{id}   POST /v1/evals/sampling/{id}/disable   GET /v1/evals/sampling
 *  POST /v1/evals/online/results (runner)           GET /v1/evals/online/summary[?blueprint_name&suite_ref]
 */
export type DevAuth =
  | { kind: "tenant"; tenantId: string; subject: string; role: HubRole }
  | { kind: "runner"; tenantId: string; runnerId: string };

export interface HubDevServerDeps {
  hub: EvalHub;
  tokens: Record<string, DevAuth>;
  rateLimit?: { max: number; windowMs: number };
  now?: () => number;
}

/** A run without its per-case rows (lists); the detail endpoint returns everything. */
export const runSummary = (r: EvalRunDoc): Omit<EvalRunDoc, "case_results"> & { case_count: number } => {
  const { case_results, ...rest } = r;
  return { ...rest, case_count: case_results.length };
};

function sendError(res: http.ServerResponse, err: unknown): void {
  if (err instanceof BadRequest)
    return sendJson(res, 400, { error: { code: "invalid", message: err.message } });
  if (err instanceof HubError)
    return sendJson(res, err.status, {
      error: {
        code: err.code,
        message: err.message,
        ...(err.checks.length ? { checks: err.checks } : {}),
      },
    });
  sendJson(res, 500, { error: { code: "internal" } });
}

const seg = (u: URL): string[] => u.pathname.split("/").filter(Boolean).map(decodeURIComponent);
const q = (u: URL, k: string): string | undefined => u.searchParams.get(k) ?? undefined;

export function createHubDevServer(deps: HubDevServerDeps): http.Server {
  refuseProduction("eval-hub");
  const auth = staticTokenAuthenticator(deps.tokens);
  const limiter = new RateLimiter(deps.rateLimit?.max ?? 600, deps.rateLimit?.windowMs ?? 60_000, deps.now);
  const h = deps.hub;

  const handle = async (
    method: string,
    url: URL,
    p: HubPrincipal,
    body: Record<string, unknown>,
  ): Promise<[number, unknown]> => {
    const s = seg(url);
    if (s[0] !== "v1" || s[1] !== "evals") throw new HubError("not_found", "no such route");
    const r = s.slice(2);
    const m = method;
    if (url.searchParams.has("tenant_id") && url.searchParams.get("tenant_id") !== p.tenantId)
      throw new HubError("forbidden", "forbidden");
    if (body["tenant_id"] !== undefined && body["tenant_id"] !== p.tenantId)
      throw new HubError("forbidden", "forbidden");

    switch (r[0]) {
      case "datasets": {
        if (r.length === 1 && m === "POST") {
          const d = await h.datasets.create(p, {
            name: body["name"],
            description: body["description"],
            phi: body["phi"],
            cases: body["cases"],
          });
          const { cases: _c, ...rest } = d;
          void _c;
          return [201, rest];
        }
        if (r.length === 1 && m === "GET") return [200, { items: await h.datasets.list(p, q(url, "name")) }];
        if (r.length === 4 && r[2] === "versions" && m === "GET")
          return [200, await h.datasets.get(p, `${r[1]}@${r[3]}`)];
        break;
      }
      case "suites": {
        if (r.length === 1 && m === "POST")
          return [201, await h.suites.create(p, body as unknown as Parameters<typeof h.suites.create>[1])];
        if (r.length === 1 && m === "GET") return [200, { items: await h.suites.list(p) }];
        if (r.length === 2 && m === "GET") return [200, await h.suites.get(p, r[1] as string)];
        break;
      }
      case "runners": {
        if (r.length === 1 && m === "GET") return [200, { items: await h.runs.listRunners(p) }];
        if (r.length === 2 && m === "PUT")
          return [200, await h.runs.registerRunner(p, r[1] as string, body["description"])];
        if (r.length === 3 && r[2] === "revoke" && m === "POST")
          return [200, await h.runs.revokeRunner(p, r[1] as string)];
        break;
      }
      case "runs": {
        if (r.length === 1 && m === "POST") {
          if (p.kind === "runner") return [201, await h.runs.startAsRunner(p, body as never)];
          return [202, await h.runs.request(p, body as never)];
        }
        if (r.length === 1 && m === "GET") {
          const limit = q(url, "limit");
          const page = await h.runs.list(p, {
            ...(q(url, "status") ? { status: q(url, "status") as string } : {}),
            ...(q(url, "suite_ref") ? { suite_ref: q(url, "suite_ref") as string } : {}),
            ...(q(url, "blueprint_name") ? { blueprint_name: q(url, "blueprint_name") as string } : {}),
            ...(q(url, "content_hash") ? { content_hash: q(url, "content_hash") as string } : {}),
            ...(q(url, "mode") ? { mode: q(url, "mode") as string } : {}),
            ...(limit ? { limit: Number(limit) } : {}),
            ...(q(url, "cursor") ? { cursor: q(url, "cursor") as string } : {}),
          });
          return [200, { items: page.items.map(runSummary), next_cursor: page.next_cursor }];
        }
        const id = r[1] as string;
        if (r.length === 2 && m === "GET") return [200, await h.runs.get(p, id)];
        if (r.length === 3 && m === "POST" && r[2] === "claim") return [200, await h.runs.claim(p, id)];
        if (r.length === 3 && m === "POST" && r[2] === "results")
          return [200, await h.runs.submitResults(p, id, body as never)];
        if (r.length === 3 && m === "POST" && r[2] === "fail")
          return [200, await h.runs.fail(p, id, body["reason"])];
        if (r.length === 3 && m === "GET" && r[2] === "comparison")
          return [200, { comparison: await h.baselines.compareRun(p, id) }];
        if (r.length === 3 && m === "GET" && r[2] === "attestation")
          return [200, await h.runs.attestation(p, id)];
        break;
      }
      case "baselines": {
        if (r.length === 1 && m === "POST") return [201, await h.baselines.set(p, { run_id: body["run_id"] })];
        if (r.length === 1 && m === "GET")
          return [
            200,
            {
              items: await h.baselines.list(p, {
                blueprint_name: q(url, "blueprint_name"),
                suite_ref: q(url, "suite_ref"),
              }),
            },
          ];
        break;
      }
      case "gate": {
        if (r.length === 1 && m === "POST") return [200, await h.gate.check(p, body as never)];
        break;
      }
      case "reviews": {
        if (r[1] === "sweep" && r.length === 2 && m === "POST") return [200, { marked: await h.reviews.sweep(p)}];
        if (r[1] === "tasks") {
          if (r.length === 2 && m === "GET")
            return [
              200,
              {
                items: await h.reviews.list(p, {
                  ...(q(url, "state") ? { state: q(url, "state") as string } : {}),
                  ...(q(url, "run_id") ? { run_id: q(url, "run_id") as string } : {}),
                  all: url.searchParams.get("all") === "true",
                }),
              },
            ];
          const id = r[2] as string;
          if (r.length === 3 && m === "GET") return [200, await h.reviews.get(p, id)];
          if (r.length === 4 && m === "POST" && r[3] === "claim") return [200, await h.reviews.claim(p, id)];
          if (r.length === 4 && m === "POST" && r[3] === "grade")
            return [200, await h.reviews.grade(p, id, { score: body["score"], comment: body["comment"] })];
          if (r.length === 4 && m === "POST" && r[3] === "skip")
            return [200, await h.reviews.skip(p, id, body["reason"])];
        }
        break;
      }
      case "sampling": {
        if (r.length === 1 && m === "GET") return [200, { items: await h.online.list(p) }];
        if (r.length === 2 && m === "PUT") return [200, await h.online.put(p, r[1] as string, body)];
        if (r.length === 3 && r[2] === "disable" && m === "POST")
          return [200, await h.online.disable(p, r[1] as string)];
        break;
      }
      case "online": {
        if (r[1] === "results" && r.length === 2 && m === "POST") return [201, await h.online.ingest(p, body)];
        if (r[1] === "summary" && r.length === 2 && m === "GET")
          return [
            200,
            {
              items: await h.online.summary(p, {
                blueprint_name: q(url, "blueprint_name"),
                suite_ref: q(url, "suite_ref"),
              }),
            },
          ];
        break;
      }
    }
    throw new HubError("not_found", "no such route");
  };

  return http.createServer((rq, res) => {
    void (async () => {
      try {
        const a = auth(rq.headers.authorization);
        if (!a) return sendJson(res, 401, { error: { code: "unauthenticated" } });
        const who = a.kind === "tenant" ? a.subject : a.runnerId;
        const wait = limiter.check(`${a.tenantId}:${who}`);
        if (wait > 0)
          return sendJson(res, 429, { error: { code: "rate_limited" } }, { "retry-after": String(Math.ceil(wait / 1000)) });
        const p: HubPrincipal = a.kind === "tenant" ? { ...a } : { ...a };
        const hasBody = rq.method === "POST" || rq.method === "PUT";
        const body = hasBody ? await readJson(rq) : {};
        const [status, json] = await handle(rq.method ?? "GET", new URL(rq.url ?? "/", "http://localhost"), p, body);
        sendJson(res, status, json);
      } catch (err) {
        sendError(res, err);
      }
    })();
  });
}
