import http from "node:http";
import type { AddressInfo } from "node:net";
import {
  MemoryError,
  type Acl,
  type Json,
  type Metadata,
  type Principal,
  type Scope,
} from "./types.js";
import type { PgMemoryService } from "./store.js";

/**
 * DEV / E2E ONLY (docs/NEEDS.md, memory rows). A loopback HTTP/JSON surface so the Python runtime can reach the memory service
 * without a new gRPC/OpenAPI contract (contracts are frozen). NOT a production API:
 *  - plaintext HTTP on 127.0.0.1, static bearer tokens, no rate limiting;
 *  - the tenant ALWAYS comes from the bearer token (a `tenant_id` in the body that differs is rejected, never honoured);
 *  - the ACL `principal` comes from the request body: the caller is the trusted runtime, which has already authenticated the
 *    agent/user. A credential holder can therefore read as any principal of ITS OWN tenant, never of another tenant;
 *  - admin-only routes (ingest, set-acl, delete-document, forget, purge) require a token marked `admin`.
 *
 * Routes (POST, JSON, `Authorization: Bearer <token>`), wire format in docs/spec/memory.md and contract/wire-v1.json:
 *   agent: write, search, recall      admin: ingest, set-acl, delete-document, forget, purge
 */
export interface DevAuth {
  tenantId: string;
  admin: boolean;
}
export type DevAuthenticator = (authorization: string | undefined) => Promise<DevAuth | undefined>;

export interface DevServerDeps {
  service: PgMemoryService;
  authenticate: DevAuthenticator;
}

const MAX_BODY = 1_500_000;
const ADMIN_ROUTES = new Set(["ingest", "set-acl", "delete-document", "forget", "purge"]);
const AGENT_ROUTES = new Set(["write", "search", "recall"]);

class BadRequest extends Error {}
class Forbidden extends Error {}

function readJson(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let size = 0;
    let tooBig = false;
    const chunks: Buffer[] = [];
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

const opt = <T>(v: unknown, check: (x: unknown) => x is T, what: string): T | undefined => {
  if (v === undefined || v === null) return undefined;
  if (!check(v)) throw new BadRequest(`${what} has the wrong type`);
  return v;
};
const isStr = (x: unknown): x is string => typeof x === "string";
const isNum = (x: unknown): x is number => typeof x === "number";
const isBool = (x: unknown): x is boolean => typeof x === "boolean";
const isObj = (x: unknown): x is Record<string, Json> =>
  typeof x === "object" && x !== null && !Array.isArray(x);
const isStrList = (x: unknown): x is string[] => Array.isArray(x) && x.every(isStr);
const req = <T>(v: unknown, check: (x: unknown) => x is T, what: string): T => {
  const out = opt(v, check, what);
  if (out === undefined) throw new BadRequest(`${what} required`);
  return out;
};

function principalOf(v: unknown): Principal {
  const p = req(v, isObj, "principal");
  return {
    id: req(p["id"], isStr, "principal.id"),
    groups: opt(p["groups"], isStrList, "principal.groups") ?? [],
  };
}

/** Optional fields are only set when present (exactOptionalPropertyTypes). */
function compact<T extends object>(o: { [K in keyof T]: T[K] | undefined }): T {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as T;
}

export function createDevServer(deps: DevServerDeps): http.Server {
  const { service } = deps;

  const handle = async (
    route: string,
    tenantId: string,
    b: Record<string, unknown>,
  ): Promise<unknown> => {
    switch (route) {
      case "write": {
        const r = await service.write(
          tenantId,
          compact({
            scope: req(b["scope"], isStr, "scope") as "run",
            ownerRef: opt(b["owner_ref"], isStr, "owner_ref"),
            content: req(b["content"], isStr, "content"),
            metadata: opt(b["metadata"], isObj, "metadata") as Metadata | undefined,
            acl: opt(b["acl"], isObj, "acl") as Acl | undefined,
            subject: opt(b["subject"], isStr, "subject"),
            ttlSeconds: opt(b["ttl_seconds"], isNum, "ttl_seconds"),
            phi: opt(b["phi"], isBool, "phi"),
            redact: opt(b["redact"], isStrList, "redact"),
            principal: principalOf(b["principal"]),
          }),
        );
        return { id: r.id, deduped: r.deduped, phi: r.phi, expires_at: r.expiresAt };
      }
      case "ingest": {
        const r = await service.ingestDocument(
          tenantId,
          compact({
            kb: req(b["kb"], isStr, "kb"),
            content: req(b["content"], isStr, "content"),
            acl: req(b["acl"], isObj, "acl") as Acl,
            source: opt(b["source"], isStr, "source"),
            title: opt(b["title"], isStr, "title"),
            metadata: opt(b["metadata"], isObj, "metadata") as Metadata | undefined,
            subject: opt(b["subject"], isStr, "subject"),
            ttlSeconds: opt(b["ttl_seconds"], isNum, "ttl_seconds"),
            phi: opt(b["phi"], isBool, "phi"),
            redact: opt(b["redact"], isStrList, "redact"),
            principal: principalOf(b["principal"]),
          }),
        );
        return { document_id: r.documentId, chunks: r.chunks, deduped: r.deduped, phi: r.phi };
      }
      case "search": {
        const hits = await service.search(
          tenantId,
          principalOf(b["principal"]),
          compact({
            query: req(b["query"], isStr, "query"),
            limit: opt(b["limit"], isNum, "limit"),
            scopes: opt(b["scopes"], isStrList, "scopes") as Scope[] | undefined,
            ownerRef: opt(b["owner_ref"], isStr, "owner_ref"),
            kbs: opt(b["kbs"], isStrList, "kbs"),
            metadata: opt(b["metadata"], isObj, "metadata") as Metadata | undefined,
            minScore: opt(b["min_score"], isNum, "min_score"),
          }),
        );
        return {
          hits: hits.map((h) => ({
            id: h.id,
            document_id: h.documentId,
            scope: h.scope,
            owner_ref: h.ownerRef,
            kb: h.kb,
            content: h.content,
            metadata: h.metadata,
            score: h.score,
          })),
        };
      }
      case "recall": {
        const entries = await service.recall(
          tenantId,
          principalOf(b["principal"]),
          compact({
            scope: req(b["scope"], isStr, "scope") as Scope,
            ownerRef: opt(b["owner_ref"], isStr, "owner_ref"),
            limit: opt(b["limit"], isNum, "limit"),
          }),
        );
        return {
          entries: entries.map((e) => ({
            id: e.id,
            scope: e.scope,
            owner_ref: e.ownerRef,
            content: e.content,
            metadata: e.metadata,
            created_at: e.createdAt,
          })),
        };
      }
      case "set-acl":
        await service.setDocumentAcl(
          tenantId,
          req(b["document_id"], isStr, "document_id"),
          req(b["acl"], isObj, "acl") as Acl,
        );
        return { ok: true };
      case "delete-document":
        await service.deleteDocument(tenantId, req(b["document_id"], isStr, "document_id"));
        return { ok: true };
      case "forget":
        return await service.forgetSubject(tenantId, req(b["subject"], isStr, "subject"));
      default:
        return await service.purgeExpired(tenantId); // "purge"
    }
  };

  return http.createServer((rq, res) => {
    const send = (status: number, json: unknown): void => {
      const text = JSON.stringify(json);
      res.writeHead(status, {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(text),
      });
      res.end(text);
    };
    void (async () => {
      const m = /^\/v1\/memory\/([a-z-]+)$/.exec(rq.url ?? "");
      const route = m?.[1];
      if (
        rq.method !== "POST" ||
        route === undefined ||
        !(ADMIN_ROUTES.has(route) || AGENT_ROUTES.has(route))
      )
        return send(404, { error: { code: "NOT_FOUND" } });
      const auth = await deps.authenticate(rq.headers.authorization).catch(() => undefined);
      if (!auth) return send(401, { error: { code: "UNAUTHENTICATED" } });
      try {
        if (ADMIN_ROUTES.has(route) && !auth.admin) throw new Forbidden();
        const body = await readJson(rq);
        if (body["tenant_id"] !== undefined && body["tenant_id"] !== auth.tenantId)
          throw new Forbidden();
        send(200, await handle(route, auth.tenantId, body));
      } catch (err) {
        if (err instanceof BadRequest)
          return send(400, { error: { code: "INVALID", message: err.message } });
        if (err instanceof Forbidden) return send(403, { error: { code: "FORBIDDEN" } });
        if (err instanceof MemoryError) {
          const status = err.code === "INVALID" ? 400 : err.code === "NOT_FOUND" ? 404 : 502;
          return send(status, { error: { code: err.code, message: err.message } });
        }
        send(500, { error: { code: "INTERNAL" } }); // never echo internals; callers treat non-200 as failure
      }
    })();
  });
}

/** Binds to the loopback interface only. Returns the chosen port. */
export function listenLoopback(server: http.Server, port = 0): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve((server.address() as AddressInfo).port));
  });
}

/** Static bearer-token table (dev/test only). */
export function staticTokenAuthenticator(tokens: Record<string, DevAuth>): DevAuthenticator {
  return (authorization) => {
    const token =
      typeof authorization === "string" && authorization.startsWith("Bearer ")
        ? authorization.slice(7)
        : undefined;
    return Promise.resolve(
      token !== undefined && Object.hasOwn(tokens, token) ? tokens[token] : undefined,
    );
  };
}
