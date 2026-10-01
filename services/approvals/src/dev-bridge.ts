import http from "node:http";
import type { AddressInfo } from "node:net";
import type { ApprovalResolver } from "./resolver.js";
import type { ApprovalService } from "./service.js";
import { ApprovalError, type ErrorCode, type Principal } from "./types.js";

/**
 * DEV / E2E ONLY. A loopback HTTP/JSON bridge so the Python runtime (and a test acting as the approver) can reach the in-process
 * approvals service without a new gRPC/OpenAPI surface (the contracts are frozen; docs/NEEDS.md #62, #50).
 *
 * It is NOT an approver API: the approver `principal` is taken from the request body (the bridge trusts its caller), there is no
 * SSO/MFA, and the transport is plaintext on 127.0.0.1. The tenant is never taken from the body: it comes from the bearer
 * credential, so a credential for tenant A can neither read, resolve nor decide tenant B's requests (they look "not found").
 *
 * Routes (all POST, JSON in/out, `Authorization: Bearer <token>`):
 *   /v1/approvals/resolve  {request_id, wait_ms?}       -> 200 {record} | 202 {status:"pending"} after wait_ms
 *   /v1/approvals/get      {request_id}                 -> {request}
 *   /v1/approvals/list     {principal, status?}         -> {requests}
 *   /v1/approvals/claim|approve|deny {request_id, principal:{id,roles}, comment?} -> {request}
 */
export type BridgeAuthenticator = (
  authorization: string | undefined,
) => Promise<string | undefined>;

export interface BridgeDeps {
  service: ApprovalService;
  resolver: ApprovalResolver;
  /** Returns the tenant id the bearer credential belongs to, or undefined. */
  authenticate: BridgeAuthenticator;
  /** Upper bound on `wait_ms` for resolve. Default 30 000. */
  maxWaitMs?: number;
}

const MAX_BODY = 64 * 1024;
const STATUS: Partial<Record<ErrorCode, number>> = {
  INVALID: 400,
  NOT_FOUND: 404,
  FORBIDDEN_ROLE: 403,
  SELF_APPROVAL: 403,
  CONFLICT_OF_INTEREST: 403,
  CLAIMED_BY_OTHER: 403,
  ALREADY_DECIDED: 409,
  CONFLICT: 409,
  NOT_DECIDED: 409,
};

class BadRequest extends Error {}

function readJson(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let size = 0;
    let tooBig = false;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY)
        tooBig = true; // keep draining (never buffering) so the 400 can still be delivered
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

const str = (v: unknown, what: string): string => {
  if (typeof v !== "string" || v === "") throw new BadRequest(`${what} required`);
  return v;
};

function principalOf(tenantId: string, v: unknown): Principal {
  if (typeof v !== "object" || v === null) throw new BadRequest("principal required");
  const p = v as Record<string, unknown>;
  const roles = p["roles"];
  if (!Array.isArray(roles) || !roles.every((r) => typeof r === "string"))
    throw new BadRequest("principal.roles must be a list of strings");
  return { tenant_id: tenantId, id: str(p["id"], "principal.id"), roles: roles as string[] };
}

export function createDevBridge(deps: BridgeDeps): http.Server {
  const maxWait = deps.maxWaitMs ?? 30_000;

  const handle = async (
    route: string,
    tenantId: string,
    body: Record<string, unknown>,
  ): Promise<{ status: number; json: unknown }> => {
    const { service, resolver } = deps;
    switch (route) {
      case "resolve": {
        const id = str(body["request_id"], "request_id");
        const w = body["wait_ms"];
        const wait = Math.min(typeof w === "number" && w > 0 ? w : 0, maxWait);
        const ac = new AbortController();
        const timer = setTimeout(() => ac.abort(), wait);
        try {
          return { status: 200, json: { record: await resolver.resolve(tenantId, id, ac.signal) } };
        } catch (err) {
          if (ac.signal.aborted) return { status: 202, json: { status: "pending" } };
          throw err;
        } finally {
          clearTimeout(timer);
        }
      }
      case "get":
        return {
          status: 200,
          json: { request: await service.peek(tenantId, str(body["request_id"], "request_id")) },
        };
      case "list": {
        const status = body["status"];
        const q = typeof status === "string" ? { status: status as "pending" } : {};
        return {
          status: 200,
          json: { requests: await service.list(principalOf(tenantId, body["principal"]), q) },
        };
      }
      case "claim":
      case "approve":
      case "deny": {
        const p = principalOf(tenantId, body["principal"]);
        const id = str(body["request_id"], "request_id");
        const c = body["comment"];
        const comment = typeof c === "string" ? c : undefined;
        const request =
          route === "claim"
            ? await service.claim(p, id)
            : route === "approve"
              ? await service.approve(p, id, comment)
              : await service.deny(p, id, comment);
        return { status: 200, json: { request } };
      }
      default:
        return { status: 404, json: { error: { code: "NOT_FOUND", message: "no such route" } } };
    }
  };

  return http.createServer((req, res) => {
    const send = (status: number, json: unknown): void => {
      const text = JSON.stringify(json);
      res.writeHead(status, {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(text),
      });
      res.end(text);
    };
    void (async () => {
      const m = /^\/v1\/approvals\/([a-z]+)$/.exec(req.url ?? "");
      if (req.method !== "POST" || !m) return send(404, { error: { code: "NOT_FOUND" } });
      const tenantId = await deps.authenticate(req.headers.authorization).catch(() => undefined);
      if (!tenantId) return send(401, { error: { code: "UNAUTHENTICATED" } });
      try {
        const out = await handle(m[1] as string, tenantId, await readJson(req));
        send(out.status, out.json);
      } catch (err) {
        if (err instanceof BadRequest)
          return send(400, { error: { code: "INVALID", message: err.message } });
        if (err instanceof ApprovalError)
          return send(STATUS[err.code] ?? 500, { error: { code: err.code, message: err.message } });
        send(500, { error: { code: "INTERNAL" } }); // fail closed: callers treat anything but 200 as DENY
      }
    })().catch(
      /* v8 ignore next 3 -- last resort: the socket died while answering */
      () => {
        if (!res.headersSent) send(500, { error: { code: "INTERNAL" } });
      },
    );
  });
}

/** Binds to the loopback interface only. Returns the chosen port. */
export function listenLoopback(server: http.Server, port = 0): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve((server.address() as AddressInfo).port));
  });
}

/** Static bearer-token table -> tenant id (dev/test only; production authenticates callers with mTLS / short-lived tokens). */
export function staticTenantAuthenticator(tokens: Record<string, string>): BridgeAuthenticator {
  return (authorization) => {
    const token =
      typeof authorization === "string" && authorization.startsWith("Bearer ")
        ? authorization.slice(7)
        : undefined;
    return Promise.resolve(
      token !== undefined && Object.prototype.hasOwnProperty.call(tokens, token)
        ? tokens[token]
        : undefined,
    );
  };
}
