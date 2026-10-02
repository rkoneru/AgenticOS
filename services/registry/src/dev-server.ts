import http from "node:http";
import {
  BadRequest,
  RateLimiter,
  optDate,
  optStr,
  readJson,
  refuseProduction,
  sendError,
  sendJson,
  staticTokenAuthenticator,
  str,
} from "./http-kit.js";
import { RegistryError } from "./errors.js";
import type { PublishInput, RegistryService, ResolvedBlueprint } from "./service.js";
import type { TenantPrincipal, VersionRecord } from "./types.js";

/**
 * DEV / E2E ONLY. Loopback HTTP/JSON over the registry service. NOT a production API (the OpenAPI contract is frozen; this is an
 * internal surface, docs/spec/registry.md). The tenant and role come from the BEARER TOKEN; a `tenant_id` in a body or query that
 * differs is rejected with 403, never honoured. Refuses to start when NODE_ENV=production.
 *
 *  POST /v1/registry/namespaces                                   {namespace}
 *  GET  /v1/registry/namespaces
 *  GET  /v1/registry/namespaces/{ns}/keys
 *  POST /v1/registry/namespaces/{ns}/keys                         {public_key, valid_from?}
 *  POST /v1/registry/namespaces/{ns}/keys/{kid}/rotate            {new_public_key, effective_at?}
 *  POST /v1/registry/namespaces/{ns}/keys/{kid}/revoke            {reason, effective_at?}
 *  POST /v1/registry/namespaces/{ns}/blueprints                   {abl, signature:{key_id,signed_at,sig}, provenance}
 *  GET  /v1/registry/blueprints/{ns}/{name}/versions
 *  GET  /v1/registry/blueprints/{ns}/{name}/versions/{version}
 *  GET  /v1/registry/resolve?ref=ns/name@range
 *  POST /v1/registry/blueprints/{ns}/{name}/versions/{version}/yank|deprecate   {reason}
 */
export interface DevTenantAuth {
  tenantId: string;
  subject: string;
  role: TenantPrincipal["role"];
}

export interface RegistryDevServerDeps {
  registry: RegistryService;
  tokens: Record<string, DevTenantAuth>;
  /** Requests per window per subject (default 120 / 60 s). */
  rateLimit?: { max: number; windowMs: number };
  now?: () => number;
}

const recordJson = (r: VersionRecord, state?: { state: string; reason: string | null }) => ({
  namespace: r.namespace,
  name: r.name,
  version: r.version,
  content_hash: r.contentHash,
  risk_level: r.riskLevel,
  signature: { key_id: r.signature.keyId, signed_at: r.signature.signedAt, sig: r.signature.sig },
  published_at: r.publishedAt.toISOString(),
  published_by: r.publishedBy,
  ...(state ? { state: state.state, state_reason: state.reason } : {}),
});

const resolvedJson = (r: ResolvedBlueprint) => ({
  ...recordJson(r.record, { state: r.state, reason: r.statusReason }),
  abl: r.abl,
  provenance: r.record.provenance,
  verification: {
    key_id: r.verification.keyId,
    builder: r.verification.builder,
    source_ref: r.verification.sourceRef,
    compiler_version: r.verification.compilerVersion,
  },
});

export function createRegistryDevServer(deps: RegistryDevServerDeps): http.Server {
  refuseProduction("registry");
  const auth = staticTokenAuthenticator(deps.tokens);
  const limiter = new RateLimiter(
    deps.rateLimit?.max ?? 120,
    deps.rateLimit?.windowMs ?? 60_000,
    deps.now,
  );
  const reg = deps.registry;

  const handle = async (
    rq: http.IncomingMessage,
    url: URL,
    p: TenantPrincipal,
  ): Promise<[number, unknown]> => {
    const seg = url.pathname.split("/").filter(Boolean).map(decodeURIComponent);
    if (seg[0] !== "v1" || seg[1] !== "registry")
      throw new RegistryError("not_found", "no such route");
    const q = url.searchParams;
    if (q.has("tenant_id") && q.get("tenant_id") !== p.tenantId)
      throw new RegistryError("forbidden", "forbidden");
    const body = rq.method === "POST" ? await readJson(rq) : {};
    if (body["tenant_id"] !== undefined && body["tenant_id"] !== p.tenantId)
      throw new RegistryError("forbidden", "forbidden");
    const route = seg.slice(2);
    const m = rq.method;

    if (route[0] === "namespaces") {
      if (route.length === 1 && m === "POST") {
        const n = await reg.claimNamespace(p, str(body["namespace"], "namespace"));
        return [201, { namespace: n.namespace, created_at: n.createdAt.toISOString() }];
      }
      if (route.length === 1 && m === "GET")
        return [
          200,
          {
            items: (await reg.listNamespaces(p)).map((n) => ({
              namespace: n.namespace,
              public: n.public,
            })),
          },
        ];
      const ns = route[1] as string;
      if (route[2] === "keys") {
        if (route.length === 3 && m === "GET")
          return [200, { items: (await reg.listKeys(p, ns)).map(keyJson) }];
        if (route.length === 3 && m === "POST") {
          const vf = optDate(body["valid_from"], "valid_from");
          const k = await reg.addKey(p, ns, {
            publicKey: str(body["public_key"], "public_key"),
            ...(vf ? { validFrom: vf } : {}),
          });
          return [201, keyJson(k)];
        }
        const kid = route[3] as string;
        if (route.length === 5 && m === "POST" && route[4] === "rotate") {
          const at = optDate(body["effective_at"], "effective_at");
          const r = await reg.rotateKey(p, ns, kid, {
            newPublicKey: str(body["new_public_key"], "new_public_key"),
            ...(at ? { effectiveAt: at } : {}),
          });
          return [200, { old_key: keyJson(r.oldKey), new_key: keyJson(r.newKey) }];
        }
        if (route.length === 5 && m === "POST" && route[4] === "revoke") {
          const reason = str(body["reason"], "reason");
          if (reason !== "retired" && reason !== "compromised")
            throw new BadRequest("reason must be retired or compromised");
          const at = optDate(body["effective_at"], "effective_at");
          return [
            200,
            keyJson(
              await reg.revokeKey(p, ns, kid, { reason, ...(at ? { effectiveAt: at } : {}) }),
            ),
          ];
        }
      }
      if (route[2] === "blueprints" && route.length === 3 && m === "POST") {
        const sig = body["signature"] as Record<string, unknown> | undefined;
        if (typeof sig !== "object" || sig === null) throw new BadRequest("signature is required");
        const input: PublishInput = {
          abl: body["abl"],
          signature: {
            keyId: str(sig["key_id"], "signature.key_id"),
            signedAt: str(sig["signed_at"], "signature.signed_at"),
            sig: str(sig["sig"], "signature.sig"),
          },
          provenance: body["provenance"] as PublishInput["provenance"],
        };
        return [201, recordJson(await reg.publish(p, ns, input))];
      }
    }
    if (route[0] === "blueprints" && route.length >= 4 && route[3] === "versions") {
      const [, ns, name] = route as [string, string, string];
      const v: TenantViewer = { tenantId: p.tenantId };
      if (route.length === 4 && m === "GET")
        return [
          200,
          {
            items: (await reg.listVersions(v, ns, name)).map((r) => recordJson(r.record, r.status)),
          },
        ];
      const version = route[4] as string;
      if (route.length === 5 && m === "GET")
        return [200, resolvedJson(await reg.getVersion(v, ns, name, version))];
      if (route.length === 6 && m === "POST" && (route[5] === "yank" || route[5] === "deprecate")) {
        const reason = str(body["reason"], "reason");
        await (route[5] === "yank"
          ? reg.yank(p, ns, name, version, reason)
          : reg.deprecate(p, ns, name, version, reason));
        return [200, { ok: true }];
      }
    }
    if (route[0] === "resolve" && route.length === 1 && m === "GET")
      return [
        200,
        resolvedJson(
          await reg.resolve({ tenantId: p.tenantId }, str(q.get("ref") ?? undefined, "ref")),
        ),
      ];
    throw new RegistryError("not_found", "no such route");
  };

  return http.createServer((rq, res) => {
    void (async () => {
      try {
        const a = auth(rq.headers.authorization);
        if (!a) return sendJson(res, 401, { error: { code: "unauthenticated" } });
        const wait = limiter.check(a.subject);
        if (wait > 0)
          return sendJson(
            res,
            429,
            { error: { code: "rate_limited" } },
            { "retry-after": String(Math.ceil(wait / 1000)) },
          );
        const p: TenantPrincipal = {
          kind: "tenant",
          tenantId: a.tenantId,
          subject: a.subject,
          role: a.role,
        };
        const [status, json] = await handle(rq, new URL(rq.url ?? "/", "http://localhost"), p);
        sendJson(res, status, json);
      } catch (err) {
        sendError(res, err);
      }
    })();
  });
}

type TenantViewer = { tenantId: string };

const keyJson = (k: import("./types.js").PublisherKey) => ({
  key_id: k.keyId,
  public_key: k.publicKey,
  valid_from: k.validFrom.toISOString(),
  valid_until: k.validUntil?.toISOString() ?? null,
  revoked_at: k.revokedAt?.toISOString() ?? null,
  revoke_reason: k.revokeReason,
});

export { optStr };
