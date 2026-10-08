import http from "node:http";
import {
  BadRequest,
  MAX_BODY,
  RateLimiter,
  listenLoopback,
  refuseProduction,
  sendJson,
  staticTokenAuthenticator,
} from "@axis/registry";
import type { ComplianceActor } from "./authz.js";
import { ComplianceError } from "./errors.js";
import type { Compliance } from "./hub.js";
import type { AssessmentInput, AssessmentState, LifecycleStage, RiskLevel } from "./types.js";

export { listenLoopback };

/** The tenant, the subject and the role all come from the BEARER TOKEN. A `tenant_id` anywhere else must match or the call is refused. */
export type DevAuth = ComplianceActor;

export interface ComplianceDevServerDeps {
  compliance: Compliance;
  tokens: Record<string, DevAuth>;
  authenticate?: (authorization: string | undefined) => DevAuth | undefined;
  rateLimit?: { max: number; windowMs: number };
  now?: () => number;
}

function sendError(res: http.ServerResponse, err: unknown): void {
  if (err instanceof BadRequest)
    return sendJson(res, 400, { error: { code: "invalid", message: err.message } });
  if (err instanceof ComplianceError)
    return sendJson(res, err.status, {
      error: {
        code: err.code,
        message: err.message,
        ...(err.checks.length ? { checks: err.checks } : {}),
      },
    });
  sendJson(res, 500, { error: { code: "internal" } });
}

function readJson(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let tooBig = false;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) tooBig = true;
      else chunks.push(c);
    });
    req.on("end", () => {
      if (tooBig) return reject(new BadRequest("body too large"));
      try {
        const v: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
        if (typeof v !== "object" || v === null || Array.isArray(v))
          return reject(new BadRequest("body must be a JSON object"));
        resolve(v as Record<string, unknown>);
      } catch {
        reject(new BadRequest("body is not valid JSON"));
      }
    });
    req.on("error", reject);
  });
}

const seg = (u: URL): string[] => u.pathname.split("/").filter(Boolean).map(decodeURIComponent);
const q = (u: URL, k: string): string | undefined => u.searchParams.get(k) ?? undefined;
const int = (v: unknown, what: string): number => {
  if (typeof v === "string" && /^\d+$/.test(v)) return Number(v);
  if (typeof v === "number" && Number.isInteger(v) && v >= 0) return v;
  throw new BadRequest(`${what} must be a non-negative integer`);
};

/**
 * DEV / E2E ONLY. Loopback HTTP/JSON over the compliance service. Refuses NODE_ENV=production.
 *
 *  POST /v1/compliance/systems               GET /v1/compliance/systems[?risk_level&lifecycle_stage]
 *  GET  /v1/compliance/systems/{id}[?version]   PUT /v1/compliance/systems/{id} {expected_version, ...}
 *  POST /v1/compliance/impact-assessments    GET  .../impact-assessments[?system_id&state&overdue]
 *  GET  /v1/compliance/impact-assessments/{id}[?version]    PUT .../{id} {expected_version, ...}
 *  POST /v1/compliance/impact-assessments/{id}/submit|withdraw {expected_version}
 *  POST /v1/compliance/impact-assessments/{id}/review {expected_version, decision, comment}
 *  POST /v1/compliance/documents {blueprint:{name,version}}   GET .../documents[?blueprint_name&blueprint_version]   GET .../documents/{id}
 */
export function createComplianceDevServer(deps: ComplianceDevServerDeps): http.Server {
  refuseProduction("compliance");
  const auth = deps.authenticate ?? staticTokenAuthenticator(deps.tokens);
  const limiter = new RateLimiter(
    deps.rateLimit?.max ?? 600,
    deps.rateLimit?.windowMs ?? 60_000,
    deps.now,
  );
  const c = deps.compliance;

  const handle = async (
    method: string,
    url: URL,
    p: DevAuth,
    body: Record<string, unknown>,
  ): Promise<[number, unknown]> => {
    const s = seg(url);
    if (s[0] !== "v1" || s[1] !== "compliance")
      throw new ComplianceError("not_found", "no such route");
    if (url.searchParams.has("tenant_id") && url.searchParams.get("tenant_id") !== p.tenantId)
      throw new ComplianceError("forbidden", "forbidden");
    if (body["tenant_id"] !== undefined && body["tenant_id"] !== p.tenantId)
      throw new ComplianceError("forbidden", "forbidden");
    const r = s.slice(2);
    const version = (): number | undefined => {
      const v = q(url, "version");
      return v === undefined ? undefined : int(v, "version");
    };
    const expected = (): number => int(body["expected_version"], "expected_version");
    const { expected_version: _e, tenant_id: _t, ...fields } = body;
    void _e;
    void _t;

    switch (r[0]) {
      case "systems": {
        if (r.length === 1 && method === "POST")
          return [201, await c.systems.create(p, fields as never)];
        if (r.length === 1 && method === "GET") {
          const rl = q(url, "risk_level") as RiskLevel | undefined;
          const ls = q(url, "lifecycle_stage") as LifecycleStage | undefined;
          return [
            200,
            {
              items: await c.systems.list(p, {
                ...(rl ? { risk_level: rl } : {}),
                ...(ls ? { lifecycle_stage: ls } : {}),
              }),
            },
          ];
        }
        if (r.length === 2 && method === "GET") {
          const v = version();
          return [200, await c.systems.get(p, r[1] as string, v)];
        }
        if (r.length === 2 && method === "PUT")
          return [200, await c.systems.update(p, r[1] as string, expected(), fields as never)];
        break;
      }
      case "impact-assessments": {
        if (r.length === 1 && method === "POST")
          return [201, await c.assessments.create(p, fields as unknown as AssessmentInput)];
        if (r.length === 1 && method === "GET") {
          const od = q(url, "overdue");
          const st = q(url, "state") as AssessmentState | undefined;
          const sid = q(url, "system_id");
          return [
            200,
            {
              items: await c.assessments.list(p, {
                ...(sid ? { system_id: sid } : {}),
                ...(st ? { state: st } : {}),
                ...(od !== undefined ? { overdue: od === "true" } : {}),
              }),
            },
          ];
        }
        if (r.length === 2 && method === "GET")
          return [200, await c.assessments.get(p, r[1] as string, version())];
        if (r.length === 2 && method === "PUT")
          return [200, await c.assessments.revise(p, r[1] as string, expected(), fields as never)];
        if (r.length === 3 && r[2] === "submit" && method === "POST")
          return [200, await c.assessments.submit(p, r[1] as string, expected())];
        if (r.length === 3 && r[2] === "withdraw" && method === "POST")
          return [200, await c.assessments.withdraw(p, r[1] as string, expected())];
        if (r.length === 3 && r[2] === "review" && method === "POST")
          return [
            200,
            await c.assessments.review(
              p,
              r[1] as string,
              expected(),
              body["decision"] as "approve",
              typeof body["comment"] === "string" ? body["comment"] : "",
            ),
          ];
        break;
      }
      case "documents": {
        if (r.length === 1 && method === "POST") {
          const out = await c.documents.generate(p, body["blueprint"] as never);
          return [out.created ? 201 : 200, out];
        }
        if (r.length === 1 && method === "GET") {
          const bn = q(url, "blueprint_name");
          const bv = q(url, "blueprint_version");
          return [
            200,
            {
              items: await c.documents.list(p, {
                ...(bn ? { blueprint_name: bn } : {}),
                ...(bv ? { blueprint_version: bv } : {}),
              }),
            },
          ];
        }
        if (r.length === 2 && method === "GET")
          return [200, await c.documents.get(p, r[1] as string)];
        break;
      }
      default:
    }
    throw new ComplianceError("not_found", "no such route");
  };

  return http.createServer((req, res) => {
    void (async () => {
      try {
        const p = auth(req.headers.authorization);
        if (!p) return sendJson(res, 401, { error: { code: "unauthenticated" } });
        const wait = limiter.check(`${p.tenantId}:${p.subject}`);
        if (wait > 0)
          return sendJson(
            res,
            429,
            { error: { code: "rate_limited" } },
            { "retry-after": String(Math.ceil(wait / 1000)) },
          );
        const url = new URL(req.url ?? "/", "http://localhost");
        const body = req.method === "GET" ? {} : await readJson(req);
        const [status, json] = await handle(req.method ?? "GET", url, p, body);
        sendJson(res, status, json);
      } catch (e) {
        sendError(res, e);
      }
    })();
  });
}
