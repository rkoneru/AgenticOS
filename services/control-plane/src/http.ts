import http from "node:http";
import type { AddressInfo } from "node:net";
import { timingSafeEqual } from "node:crypto";
import type { AdminService } from "./admin.js";
import { randomToken } from "./crypto.js";
import type { ApiKeyService } from "./apikeys.js";
import type { Principal } from "./authz.js";
import type { DirectoryService } from "./directory.js";
import { CpError, forbidden, invalid, unauthenticated } from "./errors.js";
import type { IdentityProvider } from "./idp.js";
import type { ModelKeyService } from "./modelkeys.js";
import type { Provisioner } from "./provisioning.js";
import { isRole } from "./roles.js";
import { ScimHandler, scimError } from "./scim.js";
import type { SessionService } from "./sessions.js";
import type { SsoService } from "./sso.js";
import type { ControlPlaneStore } from "./types.js";

export interface HttpDeps {
  admin: AdminService;
  sessions: SessionService;
  apiKeys: ApiKeyService;
  sso: SsoService;
  directories: DirectoryService;
  scim: ScimHandler;
  idp: IdentityProvider;
  provisioner: Provisioner;
  modelKeys: ModelKeyService;
  store: ControlPlaneStore;
  /** Platform operator credential for tenant provisioning. Undefined disables the route. */
  platformToken?: string;
  /** DEV ONLY: enables `POST /dev/session` (issues a session for a named member) with this credential. */
  devToken?: string;
  /** DEV ONLY runtime bridge: bearer -> tenant id. Undefined disables `/internal/v1/model-keys/reveal`. */
  runtimeAuth?: (authorization: string | undefined) => string | undefined;
  /** Send `Secure` cookies (always true outside localhost tests). */
  secureCookies?: boolean;
}

const MAX_BODY = 256 * 1024;
export const COOKIE_ACCESS = "__Host-axis_at";
export const COOKIE_REFRESH = "__Host-axis_rt";
export const COOKIE_CSRF = "__Host-axis_csrf";
export const COOKIE_LOGIN = "__Host-axis_login";

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly code: string,
  ) {
    super(message);
  }
}

function equalToken(a: string | undefined, b: string | undefined): boolean {
  if (!a || !b) return false;
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    let big = false;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) big = true;
      else chunks.push(c);
    });
    req.on("end", () =>
      big
        ? reject(new HttpError(413, "request body too large", "too_large"))
        : resolve(Buffer.concat(chunks).toString("utf8")),
    );
    req.on("error", reject);
  });
}

function parseJson(raw: string): unknown {
  if (raw.length === 0) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    throw new HttpError(400, "body is not valid JSON", "bad_json");
  }
}

const cookies = (h: string | undefined): Record<string, string> =>
  Object.fromEntries(
    (h ?? "")
      .split(";")
      .map((c) => c.trim().split("="))
      .filter((p) => p.length >= 2)
      .map(([k, ...v]) => [k as string, v.join("=")]),
  );

const obj = (b: unknown): Record<string, unknown> => {
  if (typeof b !== "object" || b === null || Array.isArray(b))
    throw invalid("body must be a JSON object");
  const o = b as Record<string, unknown>;
  // The tenant is derived from the credential ONLY (OpenAPI convention). A body that names one is a client bug or an attack.
  for (const k of Object.keys(o))
    if (/^tenant[_-]?id$/i.test(k))
      throw invalid("tenant_id is not accepted: the tenant comes from your credential");
  return o;
};
const s = (v: unknown, name: string): string => {
  if (typeof v !== "string") throw invalid(`${name} must be a string`);
  return v;
};

/** The control plane HTTP surface: /admin/v1 (tenant admin), /scim/v2, /auth/*, /hooks/idp, /platform/v1, and dev-only bridges. */
export function createControlPlaneServer(d: HttpDeps): http.Server {
  const secure = d.secureCookies ?? true;
  const flags = (maxAge: number, sameSite: "Strict" | "Lax", httpOnly = true): string =>
    `Path=/; Max-Age=${maxAge}; SameSite=${sameSite}${httpOnly ? "; HttpOnly" : ""}${secure ? "; Secure" : ""}`;

  function problem(res: http.ServerResponse, status: number, code: string, detail: string): void {
    res.writeHead(status, {
      "content-type": "application/problem+json",
      "cache-control": "no-store",
    });
    res.end(JSON.stringify({ type: "about:blank", title: code, status, code, detail }));
  }
  function json(
    res: http.ServerResponse,
    status: number,
    body: unknown,
    extra: Record<string, string | string[]> = {},
  ): void {
    res.writeHead(status, {
      "content-type": "application/json",
      "cache-control": "no-store",
      ...extra,
    });
    res.end(body === undefined ? undefined : JSON.stringify(body));
  }

  async function authenticate(req: http.IncomingMessage): Promise<Principal> {
    const auth = req.headers.authorization;
    const m = /^Bearer (\S+)$/.exec(auth ?? "");
    if (m) {
      const tok = m[1] as string;
      const p = tok.startsWith("axk_")
        ? await d.apiKeys.verify(tok)
        : await d.sessions.authenticate(tok);
      if (!p) throw unauthenticated();
      return p;
    }
    const c = cookies(req.headers.cookie);
    const at = c[COOKIE_ACCESS];
    if (at) {
      const unsafe = !["GET", "HEAD", "OPTIONS"].includes(req.method ?? "GET");
      if (unsafe && !equalToken(c[COOKIE_CSRF], req.headers["x-axis-csrf"] as string | undefined))
        throw forbidden("CSRF token missing or wrong");
      const p = await d.sessions.authenticate(at);
      if (p) return p;
    }
    throw unauthenticated();
  }

  function sessionCookies(
    sess: {
      accessToken: string;
      refreshToken: string;
      accessExpiresAt: Date;
      sessionExpiresAt: Date;
    },
    csrf: string,
  ): string[] {
    const accessAge = Math.max(0, Math.floor((sess.accessExpiresAt.getTime() - Date.now()) / 1000));
    const refreshAge = Math.max(
      0,
      Math.floor((sess.sessionExpiresAt.getTime() - Date.now()) / 1000),
    );
    return [
      `${COOKIE_ACCESS}=${sess.accessToken}; ${flags(accessAge, "Strict")}`,
      `${COOKIE_REFRESH}=${sess.refreshToken}; ${flags(refreshAge, "Strict")}`,
      `${COOKIE_CSRF}=${csrf}; ${flags(refreshAge, "Strict", false)}`,
    ];
  }

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://x");
    const method = (req.method ?? "GET").toUpperCase();
    const path = url.pathname;

    // ---------------- SCIM
    if (path.startsWith("/scim/v2/") || path === "/scim/v2") {
      const ctx = await d.directories.authenticate(req.headers.authorization);
      if (!ctx) {
        const r = scimError(401, "authentication required");
        res.writeHead(401, {
          "content-type": "application/scim+json",
          "www-authenticate": 'Bearer realm="scim"',
        });
        res.end(JSON.stringify(r.body));
        return;
      }
      let body: unknown;
      try {
        body = parseJson(await readBody(req));
      } catch (e) {
        const st = e instanceof HttpError ? e.status : 400;
        res.writeHead(st, { "content-type": "application/scim+json" });
        res.end(JSON.stringify(scimError(st, (e as Error).message, "invalidSyntax").body));
        return;
      }
      const r = await d.scim.handle(ctx, {
        method,
        path: path.slice("/scim/v2".length),
        query: url.searchParams,
        body,
      });
      res.writeHead(r.status, {
        "content-type": "application/scim+json",
        "cache-control": "no-store",
      });
      res.end(r.body === undefined ? undefined : JSON.stringify(r.body));
      return;
    }

    // ---------------- SSO
    if (path === "/auth/sso/start" && method === "GET") {
      const org = url.searchParams.get("org") ?? "";
      const st = await d.sso.begin(org, url.searchParams.get("return_to") ?? undefined);
      res.writeHead(302, {
        location: st.redirectUrl,
        "set-cookie": `${COOKIE_LOGIN}=${st.cookie}; ${flags(st.cookieMaxAgeSec, "Lax")}`,
        "cache-control": "no-store",
      });
      res.end();
      return;
    }
    if (path === "/auth/sso/callback" && method === "GET") {
      const r = await d.sso.callback(
        {
          ...(url.searchParams.get("code") ? { code: url.searchParams.get("code") as string } : {}),
          ...(url.searchParams.get("state")
            ? { state: url.searchParams.get("state") as string }
            : {}),
          ...(url.searchParams.get("error") ? { error: "idp_error" } : {}),
        },
        cookies(req.headers.cookie)[COOKIE_LOGIN],
      );
      const csrf = randomToken(24);
      res.writeHead(302, {
        location: r.returnTo,
        "set-cookie": [...sessionCookies(r.session, csrf), `${COOKIE_LOGIN}=; ${flags(0, "Lax")}`],
        "cache-control": "no-store",
      });
      res.end();
      return;
    }
    if (path === "/auth/refresh" && method === "POST") {
      const c = cookies(req.headers.cookie);
      const body = parseJson(await readBody(req));
      const fromBody =
        typeof body === "object" && body !== null
          ? (body as Record<string, unknown>)["refresh_token"]
          : undefined;
      if (typeof fromBody !== "string") {
        if (!equalToken(c[COOKIE_CSRF], req.headers["x-axis-csrf"] as string | undefined))
          throw forbidden("CSRF token missing or wrong");
      }
      const tok = typeof fromBody === "string" ? fromBody : c[COOKIE_REFRESH];
      if (!tok) throw unauthenticated();
      const sess = await d.sessions.refresh(tok);
      const csrf = c[COOKIE_CSRF] ?? randomToken(24);
      json(
        res,
        200,
        {
          access_token: sess.accessToken,
          refresh_token: sess.refreshToken,
          expires_at: sess.accessExpiresAt.toISOString(),
        },
        { "set-cookie": sessionCookies(sess, csrf) },
      );
      return;
    }
    if (path === "/auth/logout" && method === "POST") {
      const p = await authenticate(req);
      if (p.sessionId) await d.sessions.revoke(p.tenantId, p.sessionId);
      json(res, 204, undefined, {
        "set-cookie": [
          `${COOKIE_ACCESS}=; ${flags(0, "Strict")}`,
          `${COOKIE_REFRESH}=; ${flags(0, "Strict")}`,
          `${COOKIE_CSRF}=; ${flags(0, "Strict", false)}`,
        ],
      });
      return;
    }

    // ---------------- IdP directory-sync events
    if (path === "/hooks/idp" && method === "POST") {
      const ctx = await d.directories.authenticate(req.headers.authorization);
      if (!ctx) throw unauthenticated();
      const raw = await readBody(req);
      let ev;
      try {
        ev = d.idp.parseDirectoryEvent(raw, req.headers["x-idp-signature"] as string | undefined);
      } catch {
        throw unauthenticated("bad signature");
      }
      await d.directories.applyEvent(ctx, ev);
      json(res, 204, undefined);
      return;
    }

    // ---------------- platform provisioning
    if (path === "/platform/v1/tenants" && method === "POST") {
      const m = /^Bearer (\S+)$/.exec(req.headers.authorization ?? "");
      if (!d.platformToken || !equalToken(m?.[1], d.platformToken)) throw unauthenticated();
      const b = obj(parseJson(await readBody(req)));
      const out = await d.provisioner.signup({
        slug: s(b["slug"], "slug"),
        name: s(b["name"], "name"),
        ownerEmail: s(b["owner_email"], "owner_email"),
        ...(typeof b["owner_name"] === "string" ? { ownerName: b["owner_name"] } : {}),
        region: s(b["region"], "region"),
        ...(typeof b["phi_mode"] === "boolean" ? { phiMode: b["phi_mode"] } : {}),
      });
      json(res, 201, {
        tenant_id: out.tenantId,
        owner_member_id: out.ownerMemberId,
        policy_version: out.policyVersion,
      });
      return;
    }

    // ---------------- dev session (NOT production): a named member gets a session. The tenant IS in the body here, by design:
    // this route exists only when a dev token is configured and is the one place a credential names its own tenant.
    if (path === "/dev/session" && method === "POST") {
      const m = /^Bearer (\S+)$/.exec(req.headers.authorization ?? "");
      if (!d.devToken || !equalToken(m?.[1], d.devToken)) throw unauthenticated();
      const b = parseJson(await readBody(req)) as Record<string, unknown> | undefined;
      const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      const member =
        typeof b?.["tenant_id"] === "string" &&
        typeof b["member_id"] === "string" &&
        uuid.test(b["tenant_id"]) &&
        uuid.test(b["member_id"])
          ? await d.store.getMember(b["tenant_id"], b["member_id"])
          : undefined;
      if (!member) throw new HttpError(404, "member not found", "not_found");
      const sess = await d.sessions.issue(member, "dev");
      json(res, 201, {
        access_token: sess.accessToken,
        refresh_token: sess.refreshToken,
        expires_at: sess.accessExpiresAt.toISOString(),
      });
      return;
    }

    // ---------------- runtime bridge (dev; non-production)
    if (path === "/internal/v1/model-keys/reveal" && method === "POST") {
      const tenant = d.runtimeAuth?.(req.headers.authorization);
      if (!tenant) throw unauthenticated();
      const b = obj(parseJson(await readBody(req)));
      const v = await d.modelKeys.revealForRuntime(
        tenant,
        s(b["provider"], "provider"),
        typeof b["label"] === "string" ? b["label"] : "default",
      );
      if (v === undefined) throw new HttpError(404, "secret not found", "not_found");
      json(res, 200, { value: v });
      return;
    }

    // The tenant's budget configuration for the runtime (TKI ledger limits). Same bearer as the key bridge: the tenant is the one
    // the token was issued for. Read-only, no secrets. DEV bridge (NEEDS #186 covers production transport).
    if (path === "/internal/v1/budget-config" && method === "GET") {
      const tenant = d.runtimeAuth?.(req.headers.authorization);
      if (!tenant) throw unauthenticated();
      json(res, 200, await d.admin.budgetConfig(tenant));
      return;
    }

    // ---------------- /admin/v1
    if (path.startsWith("/admin/v1/")) {
      const p = await authenticate(req);
      const segs = path.slice("/admin/v1/".length).split("/").filter(Boolean);
      const body =
        method === "GET" || method === "DELETE" ? undefined : parseJson(await readBody(req));
      const out = await admin(p, method, segs, url.searchParams, body);
      if (out === undefined) json(res, 204, undefined);
      else json(res, out.status ?? 200, out.body);
      return;
    }
    throw new HttpError(404, "not found", "not_found");
  }

  async function admin(
    p: Principal,
    m: string,
    seg: string[],
    q: URLSearchParams,
    rawBody: unknown,
  ): Promise<{ status?: number; body: unknown } | undefined> {
    const a = d.admin;
    const [r0, r1, r2] = seg;
    const lim = q.get("limit") ? Number(q.get("limit")) : undefined;
    const after = q.get("cursor") ?? undefined;
    const body = (): Record<string, unknown> => obj(rawBody);
    const ok = <T>(x: T): { body: T } => ({ body: x });
    const created = <T>(x: T): { status: number; body: T } => ({ status: 201, body: x });
    const notFound = (): never => {
      throw new HttpError(404, "not found", "not_found");
    };

    switch (r0) {
      case "tenant":
        if (m === "GET" && !r1) return ok(await a.tenant(p));
        return notFound();
      case "members":
        if (!r1) {
          if (m === "GET") return ok(await a.listMembers(p, lim, after));
          if (m === "POST") {
            const b = body();
            const role = s(b["role"], "role");
            if (!isRole(role)) throw invalid("unknown role");
            return created(await a.inviteMember(p, { email: s(b["email"], "email"), role }));
          }
        } else if (!r2) {
          if (m === "GET") return ok(await a.getMember(p, r1));
          if (m === "PATCH") {
            const role = s(body()["role"], "role");
            if (!isRole(role)) throw invalid("unknown role");
            return ok(await a.updateMemberRole(p, r1, role));
          }
          if (m === "DELETE") return void (await a.removeMember(p, r1));
        } else if (r2 === "revoke-sessions" && m === "POST")
          return ok(await a.revokeMemberSessions(p, r1));
        return notFound();
      case "api-keys":
        if (!r1) {
          if (m === "GET") return ok(await a.listApiKeys(p, lim, after));
          if (m === "POST") {
            const b = body();
            const out = await a.createApiKey(p, {
              name: s(b["name"], "name"),
              scopes: Array.isArray(b["scopes"]) ? (b["scopes"] as string[]) : [],
              ...(typeof b["environment"] === "string"
                ? { environment: b["environment"] as "dev" }
                : {}),
              ...(typeof b["expires_in_days"] === "number"
                ? { expiresInDays: b["expires_in_days"] }
                : {}),
            });
            return created({ ...out.key, secret: out.secret });
          }
        } else if (r2 === "rotate" && m === "POST") {
          const out = await a.rotateApiKey(p, r1);
          return created({ ...out.key, secret: out.secret });
        } else if (!r2 && m === "DELETE") return ok(await a.revokeApiKey(p, r1));
        return notFound();
      case "model-keys":
        if (!r1 && m === "GET") return ok({ items: await a.listModelKeys(p) });
        if (r1 && r2 && m === "PUT")
          return ok(await a.putModelKey(p, r1, r2, s(body()["value"], "value")));
        if (r1 && r2 && m === "DELETE") return void (await a.deleteModelKey(p, r1, r2));
        return notFound();
      case "policies":
        if (!r1 && m === "GET") return ok({ items: await a.listPolicies(p) });
        if (!r1 && m === "POST") return created(await a.publishPolicy(p, obj(rawBody)["policy"]));
        if (r1 && r2 === "activate" && m === "POST") return ok(await a.activatePolicy(p, r1));
        if (r1 && !r2 && m === "DELETE") return void (await a.deactivatePolicy(p, r1));
        return notFound();
      case "budgets":
        if (!r1 && m === "GET") return ok({ items: await a.listBudgets(p) });
        if (!r1 && m === "PUT") {
          const b = body();
          return ok(
            await a.putBudget(p, {
              scope: b["scope"] as "tenant",
              ...(typeof b["target"] === "string" ? { target: b["target"] } : {}),
              metric: b["metric"] as "tokens",
              period: b["period"] as "day",
              ...(typeof b["soft"] === "number" ? { soft: b["soft"] } : {}),
              ...(typeof b["hard"] === "number" ? { hard: b["hard"] } : {}),
            }),
          );
        }
        if (r1 && m === "DELETE") return void (await a.deleteBudget(p, r1));
        return notFound();
      case "settings":
        if (m === "GET") return ok(await a.getSettings(p));
        if (m === "PATCH") {
          const b = body();
          return ok(
            await a.updateRetention(p, {
              ...(typeof b["retention_audit_days"] === "number"
                ? { auditDays: b["retention_audit_days"] }
                : {}),
              ...(typeof b["retention_transcript_days"] === "number"
                ? { transcriptDays: b["retention_transcript_days"] }
                : {}),
              ...(typeof b["retention_memory_days"] === "number"
                ? { memoryDays: b["retention_memory_days"] }
                : {}),
            }),
          );
        }
        return notFound();
      case "directories":
        if (!r1) {
          if (m === "GET") return ok({ items: await a.listDirectories(p) });
          if (m === "POST") {
            const b = body();
            const role = typeof b["default_role"] === "string" ? b["default_role"] : "viewer";
            if (!isRole(role)) throw invalid("unknown role");
            return created(await a.createDirectory(p, s(b["name"], "name"), role));
          }
        } else if (r2 === "rotate-token" && m === "POST")
          return ok(await a.rotateDirectoryToken(p, r1));
        else if (r2 === "role-mappings" && m === "PUT") {
          const b = body();
          const role = b["role"] === null ? undefined : s(b["role"], "role");
          if (role !== undefined && !isRole(role)) throw invalid("unknown role");
          await a.setGroupRole(p, r1, s(b["group"], "group"), role);
          return undefined;
        } else if (!r2 && m === "DELETE") return void (await a.revokeDirectory(p, r1));
        return notFound();
      case "sso":
        if (r1 === "connection" && m === "PUT") {
          const b = body();
          const ct = s(b["connection_type"], "connection_type");
          if (ct !== "saml" && ct !== "oidc") throw invalid("unknown connection type");
          const jr = typeof b["jit_default_role"] === "string" ? b["jit_default_role"] : undefined;
          if (jr !== undefined && !isRole(jr)) throw invalid("unknown role");
          return ok(
            await a.setSsoConnection(p, {
              idpOrgId: s(b["idp_org_id"], "idp_org_id"),
              ...(typeof b["idp_connection_id"] === "string"
                ? { idpConnectionId: b["idp_connection_id"] }
                : {}),
              connectionType: ct,
              ...(typeof b["jit_enabled"] === "boolean" ? { jitEnabled: b["jit_enabled"] } : {}),
              ...(jr ? { jitDefaultRole: jr as "viewer" } : {}),
            }),
          );
        }
        if (r1 === "portal-link" && m === "POST") {
          const b = body();
          const intent = s(b["intent"], "intent");
          if (intent !== "sso" && intent !== "dsync") throw invalid("unknown intent");
          return ok(await a.adminPortalLink(p, intent, s(b["return_url"], "return_url")));
        }
        return notFound();
      case "domains":
        if (!r1 && m === "GET") return ok({ items: await a.listDomains(p) });
        if (!r1 && m === "POST")
          return created(await a.beginDomain(p, s(body()["domain"], "domain")));
        if (r1 && r2 === "verify" && m === "POST") return ok(await a.verifyDomain(p, r1));
        return notFound();
      case "audit":
        if (r1 === "events" && m === "GET")
          return ok({
            items: await a.listAudit(p, {
              ...(q.get("from_seq") ? { fromSeq: Number(q.get("from_seq")) } : {}),
              ...(lim ? { limit: lim } : {}),
            }),
          });
        return notFound();
      default:
        return notFound();
    }
  }

  return http.createServer((req, res) => {
    handle(req, res).catch((err: unknown) => {
      if (res.headersSent) return res.end();
      if (err instanceof HttpError) return problem(res, err.status, err.code, err.message);
      if (err instanceof CpError) return problem(res, err.status, err.code, err.message);
      // Never echo internals: unexpected errors are an opaque 500 (details belong in server logs, which must not contain secrets).
      return problem(res, 500, "internal", "internal error");
    });
  });
}

export function listenLoopback(server: http.Server, port = 0): Promise<number> {
  return new Promise((resolve) =>
    server.listen(port, "127.0.0.1", () => resolve((server.address() as AddressInfo).port)),
  );
}
