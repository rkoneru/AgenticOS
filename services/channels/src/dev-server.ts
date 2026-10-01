import http from "node:http";
import type { AddressInfo } from "node:net";
import { formatSse, issueWebSession, originAllowed, verifyWebSession } from "./adapters/web.js";
import { isReject } from "./adapters/base.js";
import { safeEqual } from "./crypto.js";
import type { ChannelGateway, SendRequest } from "./gateway.js";
import type { IdentityService } from "./identity.js";
import type { InboxQueue } from "./inbox.js";
import { parseTranscriptEvent } from "./transcript-events.js";
import type { ConversationStore } from "./store.js";
import {
  CHANNELS,
  ChannelError,
  type ChannelErrorCode,
  type ChannelId,
  type RawRequest,
  type RoutingTable,
} from "./types.js";
import type { WebHub } from "./adapters/web.js";

/**
 * DEV / E2E ONLY (docs/NEEDS.md, channels rows). One loopback-capable HTTP surface for the provider webhooks and for the runtime's
 * outbound `ChannelSender`. NOT a production edge: plaintext HTTP, static service tokens, no TLS termination, no WAF, no per-IP limits.
 *  - provider webhooks (`/v1/channels/<channel>/inbound`) are authenticated by the PROVIDER's signature, never a bearer token;
 *  - service routes (`/v1/channels/send`, `/identity/link-code`, `/conversations/...`) take a bearer token that fixes the TENANT; a
 *    `tenant_id` in a body that differs from the token's is refused, never honoured.
 */
export interface ServiceAuth {
  tenantId: string;
}
export type ServiceAuthenticator = (authorization: string | undefined) => ServiceAuth | undefined;

/** Constant-time token lookup: every configured token is compared; there is no early exit on a match. */
export function staticTokenAuthenticator(
  tokens: Record<string, ServiceAuth>,
): ServiceAuthenticator {
  return (authorization) => {
    if (authorization === undefined || !authorization.startsWith("Bearer ")) return undefined;
    const presented = authorization.slice(7);
    let found: ServiceAuth | undefined;
    for (const [tok, auth] of Object.entries(tokens)) if (safeEqual(tok, presented)) found = auth;
    return found;
  };
}

export interface DevServerDeps {
  gateway: ChannelGateway;
  routes: RoutingTable;
  store: ConversationStore;
  identity: IdentityService;
  hub: WebHub;
  /** The inbound-message to agent-run bridge (docs/adr/0017). Without it the inbox route is 404. */
  inbox?: InboxQueue;
  authenticate: ServiceAuthenticator;
  now?: () => number;
  maxBodyBytes?: number;
}

const HTTP: Record<ChannelErrorCode, number> = {
  INVALID: 400,
  TOO_LARGE: 413,
  TOO_LONG: 413,
  RATE_LIMITED: 429,
  UNKNOWN_ROUTE: 404,
  TRANSPORT: 502,
  NOT_FOUND: 404,
  FORBIDDEN: 403,
  AUDIT_FAILED: 503,
  CONFLICT: 409,
};

const json = (
  res: http.ServerResponse,
  status: number,
  body: unknown,
  extra: Record<string, string> = {},
): void => {
  res.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
    ...extra,
  });
  res.end(JSON.stringify(body));
};

function readBody(req: http.IncomingMessage, max: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let tooBig = false;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > max) tooBig = true;
      else chunks.push(c);
    });
    req.on("end", () =>
      tooBig
        ? reject(new ChannelError("TOO_LARGE", "body too large"))
        : resolve(Buffer.concat(chunks)),
    );
    req.on("error", reject);
  });
}

const str = (v: unknown, what: string, max = 20_000): string => {
  if (typeof v !== "string" || v === "" || v.length > max)
    throw new ChannelError("INVALID", `${what} must be a non-empty string`);
  return v;
};
const optStr = (v: unknown, what: string, max = 512): string | undefined =>
  v === undefined || v === null ? undefined : str(v, what, max);

function parseSend(b: Record<string, unknown>): SendRequest {
  const channel = str(b["channel"], "channel", 32);
  if (!CHANNELS.includes(channel as ChannelId))
    throw new ChannelError("INVALID", "unknown channel");
  const out: SendRequest = {
    channel: channel as ChannelId,
    text: str(b["text"] ?? b["body"], "text", 100_000),
  };
  const set = <K extends keyof SendRequest>(k: K, v: SendRequest[K] | undefined): void => {
    if (v !== undefined) out[k] = v;
  };
  set("conversation_id", optStr(b["conversation_id"], "conversation_id"));
  set("to", optStr(b["to"], "to"));
  set("subject", optStr(b["subject"], "subject", 200));
  set("from", optStr(b["from"], "from"));
  set("run_id", optStr(b["run_id"], "run_id"));
  set("trace_id", optStr(b["trace_id"], "trace_id", 32));
  set("idempotency_key", optStr(b["idempotency_key"], "idempotency_key"));
  return out;
}

export function createDevServer(deps: DevServerDeps): http.Server {
  const now = deps.now ?? Date.now;
  const maxBody = deps.maxBodyBytes ?? 512 * 1024;

  const rawOf = (req: http.IncomingMessage, body: Buffer, url: URL): RawRequest => {
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers[k] = v;
    return {
      method: req.method ?? "GET",
      url: url.pathname + url.search,
      headers,
      query: Object.fromEntries(url.searchParams),
      body,
    };
  };
  const cors = (
    route: { settings: Record<string, unknown> } | undefined,
    origin: string | undefined,
  ): Record<string, string> =>
    route && origin && originAllowed(route as never, origin)
      ? {
          "access-control-allow-origin": origin,
          vary: "origin",
          "access-control-allow-headers": "authorization, content-type, last-event-id",
        }
      : {};

  const handle = async (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const method = req.method ?? "GET";
    const path = url.pathname;
    const origin = typeof req.headers["origin"] === "string" ? req.headers["origin"] : undefined;

    if (method === "OPTIONS" && path.startsWith("/v1/channels/web/")) {
      res.writeHead(204, {
        "access-control-allow-methods": "GET, POST",
        "access-control-allow-headers": "authorization, content-type, last-event-id",
        ...(origin ? { "access-control-allow-origin": origin } : {}),
      });
      return void res.end();
    }

    const inbound = /^\/v1\/channels\/([a-z]+)\/inbound$/.exec(path);
    if (inbound && CHANNELS.includes(inbound[1] as ChannelId)) {
      const body = method === "POST" ? await readBody(req, maxBody) : Buffer.alloc(0);
      const r = await deps.gateway.handleInbound(inbound[1] as ChannelId, rawOf(req, body, url));
      const route = r.rejected?.route;
      res.writeHead(r.reply.status, {
        ...(r.reply.headers ?? {}),
        ...(inbound[1] === "web" ? cors(route ?? undefined, origin) : {}),
      });
      res.end(r.reply.body);
      return;
    }

    if (path === "/v1/channels/web/session" && method === "POST") {
      const body = JSON.parse((await readBody(req, 4096)).toString("utf8") || "{}") as Record<
        string,
        unknown
      >;
      const route = deps.routes.lookup("web", str(body["site"], "site", 128));
      if (!route?.enabled || !originAllowed(route, origin))
        return json(res, 403, { error: "forbidden" });
      const token = issueWebSession(route, { nowMs: now() });
      return json(res, 200, { token, expires_in: 3600 }, cors(route, origin));
    }

    if (path === "/v1/channels/web/events" && method === "GET") {
      const auth = req.headers["authorization"];
      const v =
        typeof auth === "string" && auth.startsWith("Bearer ")
          ? verifyWebSession(auth.slice(7), { routes: deps.routes, nowMs: now() })
          : undefined;
      if (!v || isReject(v) || !originAllowed(v.route, origin))
        return json(res, 401, { error: "unauthorized" });
      res.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-store",
        connection: "keep-alive",
        ...cors(v.route, origin),
      });
      res.write(": connected\n\n");
      const last = Number(req.headers["last-event-id"] ?? 0) || 0;
      const off = deps.hub.subscribe(
        v.route.tenant_id,
        v.session.sid,
        (e) => res.write(formatSse(e)),
        last,
      );
      const timer = setTimeout(() => res.end(), Math.max(0, v.session.exp * 1000 - now()));
      timer.unref();
      req.on("close", () => {
        clearTimeout(timer);
        off();
      });
      return;
    }

    // ---- service routes: bearer token fixes the tenant -------------------------------------------------------------------------
    const svc = deps.authenticate(
      typeof req.headers["authorization"] === "string" ? req.headers["authorization"] : undefined,
    );
    const isSvc =
      path === "/v1/channels/send" ||
      path === "/v1/channels/identity/link-code" ||
      path === "/v1/channels/inbox/next" ||
      path === "/v1/channels/transcript-events" ||
      /^\/v1\/channels\/conversations\/[^/]+\/messages$/.test(path);
    if (!isSvc) return json(res, 404, { error: "not found" });
    if (!svc) return json(res, 401, { error: "unauthorized" });

    const isLog = path.startsWith("/v1/channels/conversations/");
    if (method === "GET" && !isLog) return json(res, 405, { error: "method not allowed" });
    if (method === "GET") {
      const id = decodeURIComponent(path.split("/")[4]!);
      const msgs = await deps.store.messages(svc.tenantId, id, 200);
      return json(res, 200, { messages: msgs });
    }
    if (method !== "POST") return json(res, 405, { error: "method not allowed" });
    const b = JSON.parse((await readBody(req, maxBody)).toString("utf8") || "{}") as Record<
      string,
      unknown
    >;
    if (typeof b !== "object" || b === null || Array.isArray(b))
      throw new ChannelError("INVALID", "body must be a JSON object");
    if (b["tenant_id"] !== undefined && b["tenant_id"] !== svc.tenantId)
      return json(res, 403, { error: "tenant_id does not match the credential" });

    if (path === "/v1/channels/send")
      return json(res, 200, await deps.gateway.send(svc.tenantId, parseSend(b)));
    if (path === "/v1/channels/transcript-events")
      return json(
        res,
        200,
        await deps.gateway.recordTranscriptEvent(svc.tenantId, parseTranscriptEvent(b)),
      );
    if (path === "/v1/channels/inbox/next") {
      if (!deps.inbox) return json(res, 404, { error: "not found" });
      const wait =
        typeof b["wait_ms"] === "number" ? Math.min(Math.max(b["wait_ms"], 0), 30_000) : 0;
      return json(res, 200, { item: (await deps.inbox.take(svc.tenantId, wait)) ?? null });
    }
    const channel = str(b["channel"], "channel", 32) as ChannelId;
    if (!CHANNELS.includes(channel)) throw new ChannelError("INVALID", "unknown channel");
    return json(
      res,
      200,
      await deps.identity.issueLinkCode(
        svc.tenantId,
        channel,
        str(b["external_id"], "external_id", 512),
      ),
    );
  };

  return http.createServer((req, res) => {
    handle(req, res).catch((err: unknown) => {
      if (res.headersSent) return void res.end();
      if (err instanceof ChannelError)
        return json(res, HTTP[err.code], { error: err.code, message: err.message });
      if (err instanceof SyntaxError)
        return json(res, 400, { error: "INVALID", message: "body is not valid JSON" });
      json(res, 500, { error: "internal" });
    });
  });
}

/** Binds 127.0.0.1 only. */
export function listenLoopback(server: http.Server, port = 0): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve((server.address() as AddressInfo).port));
  });
}
