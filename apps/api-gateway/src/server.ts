import { once } from "node:events";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { randomBytes, randomUUID } from "node:crypto";
import {
  isStream,
  type Ctx,
  type GatewayDeps,
  type GatewayOptions,
  type HandlerResult,
  type Route,
} from "./context.js";
import { CursorCodec, MemoryIdempotencyStore, TokenBuckets, fingerprint } from "./limits.js";
import {
  PortConflict,
  PortForbidden,
  PortInvalid,
  PortNotFound,
  PortUnavailable,
  type Principal,
  type RunEventDto,
} from "./ports.js";
import {
  ApiError,
  badRequest,
  conflict,
  forbidden,
  internal,
  methodNotAllowed,
  notFound,
  policyDenied,
  rateLimited,
  timeout,
  toProblem,
  tooLarge,
  unauthenticated,
  unavailable,
  unsupportedMedia,
  validation,
  type Problem,
  type ValidationIssue,
} from "./problem.js";
import { ROUTES } from "./routes.js";
import { ApiSpec, compileTemplate, type OperationSpec } from "./spec.js";

const REQUEST_ID = /^[A-Za-z0-9._-]{8,64}$/;
const TRACEPARENT = /^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$/;
const TENANT_HEADER = /^x-(axis-)?tenant(-id)?$/i;
const TENANT_KEY = /^tenant[_-]?id$/i;
const ALLOW_HEADERS =
  "authorization, content-type, idempotency-key, x-axis-api-key, x-request-id, last-event-id, traceparent";
const EXPOSE_HEADERS =
  "x-request-id, retry-after, ratelimit-limit, ratelimit-remaining, idempotent-replayed, www-authenticate";

const DEFAULTS = {
  maxBodyBytes: 1 << 20,
  requestTimeoutMs: 30_000,
  rate: { burst: 60, perSecond: 30 },
  unauthRate: { burst: 20, perSecond: 1 },
  maxSseStreamsPerTenant: 16,
  sseHeartbeatMs: 15_000,
  sseRecheckMs: 30_000,
  sseMaxMs: 15 * 60_000,
  idempotencyTtlMs: 24 * 3_600_000,
  maxVerifyEvents: 50_000,
};

interface Compiled {
  op: OperationSpec;
  route: Route;
  re: RegExp;
  names: string[];
}

export interface Gateway {
  server: http.Server;
  /** The operations this gateway serves (for drift tests). */
  operations: readonly OperationSpec[];
  listen(port?: number, host?: string): Promise<number>;
  close(): Promise<void>;
}

/**
 * The `/v1` gateway. Pipeline per request: request/trace ids -> CORS/security headers -> route -> (tenant headers refused) ->
 * credential -> per-tenant rate limit -> authorization (control-plane OPA pack) -> parameter and body validation against the OpenAPI
 * -> idempotency -> audit of the mutation (fail-closed) -> handler -> response validation -> problem+json on any failure.
 * The tenant is `principal.tenantId` and nothing else: no handler can read a tenant from the request.
 */
export function createGateway(deps: GatewayDeps, options: GatewayOptions = {}): Gateway {
  const o = { ...DEFAULTS, ...options };
  const spec = deps.spec ?? new ApiSpec();
  const now = o.now ?? Date.now;
  const log = o.log ?? (() => undefined);
  const limiter = deps.limiter ?? new TokenBuckets(o.rate, now);
  const unauth = deps.unauthLimiter ?? new TokenBuckets(o.unauthRate, now);
  const cursors = deps.cursors ?? new CursorCodec();
  const idem = deps.idempotency ?? new MemoryIdempotencyStore(now);
  const origins = new Set(o.allowedOrigins ?? []);

  // The route table and the spec must agree exactly: a missing or extra route fails at start-up.
  const compiled: Compiled[] = spec.operations.map((op) => {
    const route = ROUTES[op.id];
    if (!route) throw new Error(`OpenAPI operation ${op.id} has no route in the gateway`);
    return { op, route, ...compileTemplate(op.template) };
  });
  for (const id of Object.keys(ROUTES))
    if (!spec.operations.some((op) => op.id === id))
      throw new Error(`route ${id} is not in the OpenAPI document`);

  const streams = new Map<string, number>();

  function baseHeaders(
    res: http.ServerResponse,
    requestId: string,
    origin: string | undefined,
  ): void {
    res.setHeader("x-request-id", requestId);
    res.setHeader("x-content-type-options", "nosniff");
    res.setHeader("cache-control", "no-store");
    res.setHeader("referrer-policy", "no-referrer");
    res.setHeader("content-security-policy", "default-src 'none'; frame-ancestors 'none'");
    res.setHeader("cross-origin-resource-policy", "same-site");
    res.setHeader("x-frame-options", "DENY");
    if (o.behindTls)
      res.setHeader("strict-transport-security", "max-age=63072000; includeSubDomains");
    res.setHeader("vary", "Origin");
    if (origin !== undefined && origins.has(origin)) {
      res.setHeader("access-control-allow-origin", origin);
      res.setHeader("access-control-expose-headers", EXPOSE_HEADERS);
    }
  }

  function send(
    res: http.ServerResponse,
    status: number,
    body: unknown,
    contentType: string,
    extra: Record<string, string> = {},
  ): void {
    if (res.headersSent) return;
    const payload = body === undefined ? undefined : JSON.stringify(body);
    res.writeHead(status, {
      "content-type": contentType,
      ...(payload !== undefined ? { "content-length": String(Buffer.byteLength(payload)) } : {}),
      ...extra,
    });
    res.end(payload);
  }

  const sendProblem = (res: http.ServerResponse, err: ApiError, traceId: string): Problem => {
    const p = toProblem(err, traceId);
    send(res, err.status, p, "application/problem+json", err.headers);
    return p;
  };

  function readBody(req: http.IncomingMessage): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const declared = Number(req.headers["content-length"]);
      if (Number.isFinite(declared) && declared > o.maxBodyBytes) {
        req.resume();
        return reject(tooLarge(o.maxBodyBytes));
      }
      const chunks: Buffer[] = [];
      let size = 0;
      let over = false;
      req.on("data", (c: Buffer) => {
        size += c.length;
        if (size > o.maxBodyBytes) over = true;
        else chunks.push(c);
      });
      req.on("end", () =>
        over ? reject(tooLarge(o.maxBodyBytes)) : resolve(Buffer.concat(chunks)),
      );
      req.on("error", reject);
      req.on("aborted", () => reject(badRequest("request aborted")));
    });
  }

  function credentials(req: http.IncomingMessage): { bearer?: string; apiKey?: string } {
    const h = req.headers;
    const auth = h.authorization;
    const key = h["x-axis-api-key"];
    if (auth !== undefined && key !== undefined)
      throw badRequest("send one credential: Authorization or X-Axis-Api-Key");
    if (Array.isArray(key))
      throw badRequest("send one credential: Authorization or X-Axis-Api-Key");
    if (auth !== undefined) {
      const m = /^Bearer ([\x21-\x7e]{1,4096})$/.exec(auth);
      if (!m) throw unauthenticated("Authorization must be 'Bearer <token>'");
      return { bearer: m[1] as string };
    }
    if (key !== undefined) {
      if (!/^[\x21-\x7e]{1,4096}$/.test(key)) throw unauthenticated("invalid API key");
      return { apiKey: key };
    }
    throw unauthenticated();
  }

  async function authenticate(
    req: http.IncomingMessage,
    remote: string,
  ): Promise<{ principal: Principal; creds: { bearer?: string; apiKey?: string } }> {
    // A remote that keeps failing is refused before any credential lookup (brute-force and lookup-cost amplification).
    if (unauth.take(remote, 0).remaining < 1) throw rateLimited(1);
    let creds: { bearer?: string; apiKey?: string };
    try {
      creds = credentials(req);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) unauth.take(remote, 1);
      throw e;
    }
    let principal: Principal | undefined;
    try {
      principal = await deps.auth.authenticate(creds);
    } catch {
      throw unavailable("authentication is unavailable; retry");
    }
    if (!principal) {
      unauth.take(remote, 1);
      throw unauthenticated("invalid or expired credential");
    }
    return { principal, creds };
  }

  const query = (url: URL): Record<string, string> => {
    const out: Record<string, string> = {};
    for (const k of new Set(url.searchParams.keys())) {
      const all = url.searchParams.getAll(k);
      if (all.length > 1)
        throw validation(`query parameter ${k} given more than once`, [
          { path: `/${k}`, message: "repeated" },
        ]);
      out[k] = all[0] as string;
    }
    return out;
  };

  function mapError(e: unknown): ApiError {
    if (e instanceof ApiError) return e;
    if (e instanceof PortNotFound) return notFound();
    if (e instanceof PortConflict) return conflict(e.message);
    if (e instanceof PortForbidden) return forbidden(e.message);
    if (e instanceof PortInvalid) return validation(e.message, e.issues);
    if (e instanceof PortUnavailable) return unavailable(e.message);
    return internal();
  }

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const t0 = now();
    const hdrReqId = req.headers["x-request-id"];
    const requestId =
      typeof hdrReqId === "string" && REQUEST_ID.test(hdrReqId) ? hdrReqId : randomUUID();
    const tp =
      typeof req.headers.traceparent === "string"
        ? TRACEPARENT.exec(req.headers.traceparent)
        : null;
    const traceId =
      tp && tp[1] !== "0".repeat(32) ? (tp[1] as string) : randomBytes(16).toString("hex");
    const originHdr = req.headers.origin;
    const origin = typeof originHdr === "string" ? originHdr : undefined;
    baseHeaders(res, requestId, origin);
    res.setHeader("traceparent", `00-${traceId}-${randomBytes(8).toString("hex")}-01`);
    const method = (req.method ?? "GET").toUpperCase();
    const remote = req.socket.remoteAddress ?? "unknown";
    let status = 500;
    let opId = "-";
    let tenant = "-";
    try {
      let url: URL;
      try {
        url = new URL(req.url ?? "/", "http://gateway.invalid");
      } catch {
        throw badRequest("malformed request target");
      }
      if (url.pathname === "/healthz" && method === "GET") {
        status = 200;
        return send(res, 200, { status: "ok", api_version: spec.version }, "application/json");
      }
      if (method === "OPTIONS") {
        // Preflight: answered before authentication, only ever for an allow-listed origin.
        status = 204;
        const ok =
          origin !== undefined &&
          origins.has(origin) &&
          req.headers["access-control-request-method"] !== undefined;
        res.writeHead(204, {
          ...(ok
            ? {
                "access-control-allow-methods": "GET, POST, PUT, OPTIONS",
                "access-control-allow-headers": ALLOW_HEADERS,
                "access-control-max-age": "600",
              }
            : {}),
        });
        return void res.end();
      }
      const base = "/v1";
      if (url.pathname !== base && !url.pathname.startsWith(`${base}/`))
        throw notFound("no such resource");
      const path = url.pathname.slice(base.length) || "/";
      if (path.includes("//") || path.length > 512) throw notFound("no such resource");

      let match: Compiled | undefined;
      const allowed: string[] = [];
      let rawParams: string[] = [];
      for (const c of compiled) {
        const m = c.re.exec(path);
        if (!m) continue;
        allowed.push(c.op.method.toUpperCase());
        if (c.op.method.toUpperCase() === method) {
          match = c;
          rawParams = m.slice(1);
        }
      }
      if (!match)
        throw allowed.length > 0
          ? methodNotAllowed([...new Set(allowed)])
          : notFound("no such resource");
      opId = match.op.id;

      for (const h of Object.keys(req.headers))
        if (TENANT_HEADER.test(h))
          throw badRequest(
            "the tenant comes from your credential; remove the tenant header",
            "tenant_override",
          );

      const { principal, creds } = await authenticate(req, remote);
      tenant = principal.tenantId;

      const cost = o.costs?.[match.op.id] ?? 1;
      const rl = limiter.take(principal.tenantId, cost);
      res.setHeader("ratelimit-limit", String(rl.limit));
      res.setHeader("ratelimit-remaining", String(rl.remaining));
      if (!rl.ok) throw rateLimited(rl.retryAfterSec);

      // Authorization: fail-closed, before anything about the target is looked at.
      let decision;
      if (match.route.action === null) {
        // Identity-only operations (GET /me): a valid credential is all they need, and they never change state.
        decision = { allowed: true, reason: "identity", policyVersion: "n/a" };
      } else {
        try {
          decision = await deps.authz.decide(principal, match.route.action);
        } catch {
          decision = { allowed: false, reason: "policy evaluation error", policyVersion: "none" };
        }
      }
      if (!decision.allowed) {
        if (match.route.mutation)
          await deps.audit
            .record({
              tenantId: principal.tenantId,
              actor: { type: "human", id: principal.memberId },
              action: `api.${match.op.id}`,
              decision: "DENY",
              policyVersion: decision.policyVersion,
              reason: `op=${match.op.id} reason=${decision.reason}`.slice(0, 500),
              inputs: { op: match.op.id, request_id: requestId },
              outputs: { status: 403 },
              traceId,
            })
            .catch(() => undefined);
        const failure = /^(no policy|policy evaluation|malformed policy|unknown role)/.test(
          decision.reason,
        );
        throw failure
          ? policyDenied()
          : forbidden("your role or API key does not allow this operation");
      }

      // Parameters (path ids, query) against the OpenAPI schemas; unknown query parameters are refused.
      const pathVals: Record<string, string> = {};
      match.names.forEach((n, i) => {
        try {
          pathVals[n] = decodeURIComponent(rawParams[i] as string);
        } catch {
          throw badRequest("malformed path");
        }
      });
      const pv = spec.validateParams(match.op, "path", pathVals);
      if (pv.issues.length > 0) throw validation("invalid path parameter", pv.issues);
      const qv = spec.validateParams(match.op, "query", query(url));
      for (const k of Object.keys(qv.value))
        if (TENANT_KEY.test(k) || k.toLowerCase() === "tenant")
          throw validation("the tenant comes from your credential", [
            { path: `/${k}`, message: "not accepted" },
          ]);
      if (qv.issues.length > 0) throw validation("invalid query parameters", qv.issues);

      const idemHeader = req.headers["idempotency-key"];
      let idemKey: string | undefined;
      if (idemHeader !== undefined) {
        if (!match.op.idempotent) idemKey = undefined;
        else {
          if (Array.isArray(idemHeader)) throw validation("Idempotency-Key given more than once");
          const hv = spec.validateParams(match.op, "header", { "Idempotency-Key": idemHeader });
          if (hv.issues.length > 0) throw validation("invalid Idempotency-Key", hv.issues);
          idemKey = idemHeader;
        }
      }

      // Body.
      let body: unknown;
      if (match.op.bodyPtr) {
        const raw = await readBody(req);
        if (raw.length === 0) {
          if (match.op.bodyRequired)
            throw validation("a JSON body is required", [{ path: "/", message: "body required" }]);
        } else {
          const ct = (req.headers["content-type"] ?? "").split(";")[0]?.trim().toLowerCase();
          if (ct !== "application/json") throw unsupportedMedia();
          try {
            body = JSON.parse(raw.toString("utf8"));
          } catch {
            throw badRequest("the body is not valid JSON", "invalid_json");
          }
          if (typeof body === "object" && body !== null && !Array.isArray(body))
            for (const k of Object.keys(body))
              if (TENANT_KEY.test(k))
                throw validation("the tenant comes from your credential", [
                  { path: `/${k}`, message: "not accepted" },
                ]);
          const issues = spec.validateBody(match.op, body);
          if (issues.length > 0)
            throw validation("the request body does not match the API schema", issues);
        }
      } else {
        req.resume();
      }

      // Idempotency (only POSTs that declare the header, only when the client sent a key).
      const idemScope = `${principal.tenantId}\u0000${principal.memberId}`;
      let reserved = false;
      if (idemKey !== undefined) {
        const fp = fingerprint(method, match.op.template, pathVals, body);
        const b = await idem.begin(idemScope, idemKey, fp, o.idempotencyTtlMs);
        if (b.kind === "mismatch")
          throw validation("this Idempotency-Key was already used with a different request", [
            { path: "/", message: "idempotency key reuse" },
          ]);
        if (b.kind === "in_progress")
          throw conflict("a request with this Idempotency-Key is still being processed");
        if (b.kind === "replay") {
          status = b.response.status;
          return send(
            res,
            b.response.status,
            b.response.body,
            b.response.status >= 400 ? "application/problem+json" : "application/json",
            {
              ...b.response.headers,
              "idempotent-replayed": "true",
            },
          );
        }
        reserved = true;
      }

      try {
        if (match.route.mutation) {
          try {
            await deps.audit.record({
              tenantId: principal.tenantId,
              actor: { type: "human", id: principal.memberId },
              action: `api.${match.op.id}`,
              decision: "ALLOW",
              policyVersion: decision.policyVersion,
              reason: `op=${match.op.id} credential=${principal.credential}`,
              inputs: {
                op: match.op.id,
                params: pathVals,
                request_id: requestId,
                ...(body !== undefined ? { body } : {}),
              },
              outputs: { phase: "authorized" },
              traceId,
            });
          } catch {
            throw unavailable("the audit log is unavailable; the operation was not performed");
          }
        }
        const ac = new AbortController();
        res.on("close", () => ac.abort());
        const lastEvt = req.headers["last-event-id"];
        const ctx: Ctx = {
          principal,
          tenantId: principal.tenantId,
          operationId: match.op.id,
          params: pv.value,
          query: qv.value,
          body,
          traceId,
          requestId,
          deps,
          opts: o,
          cursors,
          wantsStream: String(req.headers.accept ?? "").includes("text/event-stream"),
          lastEventId:
            typeof lastEvt === "string" && /^\d{1,15}$/.test(lastEvt) ? Number(lastEvt) : undefined,
          signal: ac.signal,
        };
        let timer: NodeJS.Timeout | undefined;
        const result: HandlerResult = await Promise.race([
          match.route.handler(ctx),
          new Promise<never>((_, rej) => {
            timer = setTimeout(() => rej(timeout()), o.requestTimeoutMs);
          }),
        ]).finally(() => clearTimeout(timer));

        if (isStream(result)) {
          status = 200;
          await streamEvents(res, ctx, result, creds, ac);
          if (reserved) await idem.abort(idemScope, idemKey as string);
          return;
        }
        status = result.status;
        if (o.validateResponses) {
          const media = result.status >= 400 ? "application/problem+json" : "application/json";
          if (result.body !== undefined) {
            const issues = spec.validateResponse(match.op, result.status, media, result.body);
            if (issues && issues.length > 0) {
              log("error", "response violates the OpenAPI contract", {
                op: match.op.id,
                status: result.status,
                issues,
                request_id: requestId,
              });
              throw internal();
            }
          }
        }
        const extra = { ...(result.headers ?? {}) };
        if (reserved) {
          if (result.status >= 500 || result.status === 429)
            await idem.abort(idemScope, idemKey as string);
          else
            await idem.complete(idemScope, idemKey as string, {
              status: result.status,
              body: result.body,
              headers: extra,
            });
          reserved = false;
        }
        send(res, result.status, result.body, "application/json", extra);
      } catch (e) {
        if (reserved) {
          const err = mapError(e);
          // Deterministic client errors are remembered (a retry gets the same answer); anything else is retryable.
          if (err.status >= 400 && err.status < 500 && err.status !== 429 && err.status !== 408)
            await idem.complete(idemScope, idemKey as string, {
              status: err.status,
              body: toProblem(err, traceId),
              headers: err.headers,
            });
          else await idem.abort(idemScope, idemKey as string);
        }
        throw e;
      }
    } catch (e) {
      const err = mapError(e);
      if (!(e instanceof ApiError))
        log("error", "unhandled error", {
          op: opId,
          request_id: requestId,
          error: e instanceof Error ? e.message : String(e),
        });
      status = err.status;
      if (err.status === 413) res.setHeader("connection", "close");
      sendProblem(res, err, traceId);
    } finally {
      log("info", "request", {
        op: opId,
        method,
        status,
        tenant,
        request_id: requestId,
        trace_id: traceId,
        ms: now() - t0,
      });
    }
  }

  async function streamEvents(
    res: http.ServerResponse,
    ctx: Ctx,
    result: { stream: AsyncIterable<RunEventDto>; headers?: Record<string, string> },
    creds: { bearer?: string; apiKey?: string },
    ac: AbortController,
  ): Promise<void> {
    const t = ctx.tenantId;
    const open = streams.get(t) ?? 0;
    if (open >= o.maxSseStreamsPerTenant) throw rateLimited(5);
    streams.set(t, open + 1);
    const stop = (): void => ac.abort();
    res.on("close", stop);
    res.writeHead(200, {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-store, no-transform",
      "x-accel-buffering": "no",
      connection: "keep-alive",
      ...(result.headers ?? {}),
    });
    res.write("retry: 3000\n\n");
    const hb = setInterval(() => res.write(": keep-alive\n\n"), o.sseHeartbeatMs);
    // Credentials are re-checked while the stream is open: a revoked key or session ends it within one interval.
    const recheck = setInterval(() => {
      deps.auth
        .authenticate(creds)
        .then((p) => {
          if (!p || p.tenantId !== ctx.tenantId || p.memberId !== ctx.principal.memberId) stop();
        })
        .catch(stop);
    }, o.sseRecheckMs);
    const max = setTimeout(stop, o.sseMaxMs);
    let reason = "completed";
    try {
      const it = result.stream[Symbol.asyncIterator]();
      const aborted = new Promise<"abort">((r) =>
        ac.signal.addEventListener("abort", () => r("abort"), { once: true }),
      );
      while (!ac.signal.aborted) {
        const n = await Promise.race([it.next(), aborted]);
        if (n === "abort" || n.done) {
          if (n === "abort") void it.return?.();
          break;
        }
        const ev = n.value;
        if (!res.write(`id: ${ev.sequence}\nevent: run_event\ndata: ${JSON.stringify(ev)}\n\n`)) {
          await Promise.race([once(res, "drain"), aborted]);
        }
      }
      if (ac.signal.aborted) reason = "closed";
    } catch {
      reason = "error";
    } finally {
      clearInterval(hb);
      clearInterval(recheck);
      clearTimeout(max);
      streams.set(t, Math.max(0, (streams.get(t) ?? 1) - 1));
      if (streams.get(t) === 0) streams.delete(t);
      if (!res.writableEnded) res.end(`event: end\ndata: ${JSON.stringify({ reason })}\n\n`);
    }
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((e: unknown) => {
      log("error", "gateway failure", { error: e instanceof Error ? e.message : String(e) });
      if (!res.headersSent) send(res, 500, toProblem(internal(), "-"), "application/problem+json");
      else res.destroy();
    });
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 5_000;
  server.maxRequestsPerSocket = 1000;

  return {
    server,
    operations: spec.operations,
    listen: (port = 0, host = "127.0.0.1") =>
      new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => resolve((server.address() as AddressInfo).port));
      }),
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

export type { ValidationIssue };
