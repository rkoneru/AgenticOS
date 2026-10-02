import http from "node:http";
import {
  BadRequest,
  RateLimiter,
  RegistryError,
  readJson,
  refuseProduction,
  sendError,
  sendJson,
  staticTokenAuthenticator,
  str,
} from "@axis/registry";
import type { Marketplace } from "./service.js";
import { parseReviewId } from "./reviews.js";
import type { StaffPrincipal, TenantPrincipal } from "./types.js";

/**
 * DEV / E2E ONLY. Loopback HTTP/JSON over the marketplace services (internal surface; the OpenAPI contract is frozen). The bearer token
 * fixes who the caller is: a tenant member (tenant + role), or platform staff (reviewer | moderator). A `tenant_id` in a body or query that
 * differs from the token's tenant is a 403. The public catalog needs NO token. Refuses to start when NODE_ENV=production.
 *
 *  public   GET  /v1/catalog[?q=&category=]            GET /v1/catalog/{ns}/{name}
 *  tenant   GET|POST /v1/publisher  (POST = start)     POST /v1/publisher/evidence
 *           POST /v1/publisher/listings                POST|GET /v1/publisher/reviews
 *           GET|PUT /v1/tenant/baseline
 *           POST /v1/installs/preview {namespace,name,range}      GET /v1/installs
 *           POST /v1/installs {namespace,name,version,content_hash,consent_digest}
 *           POST /v1/installs/{ns}/{name}/update {version,consent_digest?}     POST /v1/installs/{ns}/{name}/uninstall
 *           POST /v1/installs/flush-metering
 *  reviewer GET  /v1/review/publishers                 GET /v1/review/publishers/{tenant}/evidence
 *           POST /v1/review/publishers/{tenant}/decision {decision, reason}
 *           GET  /v1/review/queue[?state=]             GET /v1/review/reviews/{id}
 *           POST /v1/review/reviews/{id}/decision {decision, note, acknowledged_findings?}
 *  moderator POST /v1/moderation/takedowns {namespace,name,version?,reason}     POST /v1/moderation/publishers/{tenant}/suspend {reason}
 */
export type DevAuth =
  | ({ kind: "tenant" } & Omit<TenantPrincipal, "kind">)
  | { kind: "reviewer" | "moderator"; subject: string; tenantId?: string };

export interface MarketplaceDevDeps {
  marketplace: Marketplace;
  tokens: Record<string, DevAuth>;
  rateLimit?: { max: number; windowMs: number };
  /** Stricter limit for expensive actions (review submissions, installs, verification). */
  sensitiveRateLimit?: { max: number; windowMs: number };
  now?: () => number;
}

const SENSITIVE = /^(POST \/v1\/(installs|publisher\/(reviews|listings|evidence)))/;

export function createMarketplaceDevServer(deps: MarketplaceDevDeps): http.Server {
  refuseProduction("marketplace");
  const auth = staticTokenAuthenticator(deps.tokens);
  const limiter = new RateLimiter(
    deps.rateLimit?.max ?? 240,
    deps.rateLimit?.windowMs ?? 60_000,
    deps.now,
  );
  const strict = new RateLimiter(
    deps.sensitiveRateLimit?.max ?? 30,
    deps.sensitiveRateLimit?.windowMs ?? 60_000,
    deps.now,
  );
  const mp = deps.marketplace;
  const wrong = (): never => {
    throw new RegistryError("forbidden", "wrong credential type for this route");
  };

  const handle = async (
    rq: http.IncomingMessage,
    url: URL,
    a: DevAuth | undefined,
  ): Promise<[number, unknown]> => {
    const seg = url.pathname.split("/").filter(Boolean).map(decodeURIComponent);
    const m = rq.method;
    const q = url.searchParams;
    if (seg[0] !== "v1") throw new RegistryError("not_found", "no such route");
    // ---- public
    if (seg[1] === "catalog" && m === "GET") {
      if (seg.length === 2)
        return [
          200,
          {
            items: await mp.listings.catalog({
              ...(q.get("q") ? { text: q.get("q") as string } : {}),
              ...(q.get("category") ? { category: q.get("category") as string } : {}),
            }),
          },
        ];
      if (seg.length === 4)
        return [200, await mp.listings.entry(seg[2] as string, seg[3] as string)];
    }
    if (!a) throw new RegistryError("unauthenticated", "authentication required");
    const body = m === "POST" || m === "PUT" ? await readJson(rq) : {};
    if (a.kind === "tenant") {
      if (
        (q.has("tenant_id") && q.get("tenant_id") !== a.tenantId) ||
        (body["tenant_id"] !== undefined && body["tenant_id"] !== a.tenantId)
      )
        throw new RegistryError("forbidden", "forbidden");
    }
    const route = seg.slice(1);
    const tp = (): TenantPrincipal =>
      a.kind === "tenant"
        ? { kind: "tenant", tenantId: a.tenantId, subject: a.subject, role: a.role }
        : wrong();
    const staff = (k: StaffPrincipal["kind"]): StaffPrincipal =>
      a.kind === k
        ? { kind: k, subject: a.subject, ...(a.tenantId ? { tenantId: a.tenantId } : {}) }
        : wrong();

    if (route[0] === "publisher") {
      const p = tp();
      if (route.length === 1 && m === "GET")
        return [200, { publisher: (await mp.publishers.get(p)) ?? null }];
      if (route.length === 1 && m === "POST") {
        const r = await mp.publishers.start(p, {
          legalName: str(body["legal_name"], "legal_name"),
          domain: str(body["domain"], "domain"),
          contactEmail: str(body["contact_email"], "contact_email"),
        });
        return [201, r];
      }
      if (route[1] === "evidence" && m === "POST")
        return [200, { items: await mp.publishers.submitEvidence(p) }];
      if (route[1] === "evidence" && m === "GET")
        return [200, { items: await mp.publishers.evidence(p) }];
      if (route[1] === "listings" && m === "POST") {
        const cats = body["categories"];
        return [
          201,
          await mp.listings.create(p, {
            namespace: str(body["namespace"], "namespace"),
            name: str(body["name"], "name"),
            title: str(body["title"], "title"),
            summary: str(body["summary"], "summary"),
            ...(Array.isArray(cats) ? { categories: cats as string[] } : {}),
          }),
        ];
      }
      if (route[1] === "reviews" && m === "POST")
        return [
          201,
          await mp.reviews.submit(p, {
            namespace: str(body["namespace"], "namespace"),
            name: str(body["name"], "name"),
            version: str(body["version"], "version"),
          }),
        ];
      if (route[1] === "reviews" && m === "GET") return [200, { items: await mp.reviews.mine(p) }];
    }
    if (route[0] === "tenant" && route[1] === "baseline") {
      const p = tp();
      if (m === "GET") return [200, await mp.installs.baseline(p)];
      if (m === "PUT") return [200, await mp.installs.setBaseline(p, body["granted"] as never)];
    }
    if (route[0] === "installs") {
      const p = tp();
      if (route.length === 1 && m === "GET") return [200, { items: await mp.installs.list(p) }];
      if (route[1] === "preview" && m === "POST")
        return [
          200,
          await mp.installs.preview(
            p,
            str(body["namespace"], "namespace"),
            str(body["name"], "name"),
            str(body["range"], "range"),
          ),
        ];
      if (route[1] === "flush-metering" && m === "POST")
        return [200, { flushed: await mp.installs.flushMetering(p) }];
      if (route.length === 1 && m === "POST")
        return [
          201,
          await mp.installs.install(p, {
            namespace: str(body["namespace"], "namespace"),
            name: str(body["name"], "name"),
            version: str(body["version"], "version"),
            contentHash: str(body["content_hash"], "content_hash"),
            consentDigest: str(body["consent_digest"], "consent_digest"),
          }),
        ];
      if (route.length === 4 && route[3] === "update" && m === "POST")
        return [
          200,
          await mp.installs.update(p, route[1] as string, route[2] as string, {
            version: str(body["version"], "version"),
            ...(typeof body["consent_digest"] === "string"
              ? { consentDigest: body["consent_digest"] }
              : {}),
            ...(body["allow_downgrade"] === true ? { allowDowngrade: true } : {}),
          }),
        ];
      if (route.length === 4 && route[3] === "uninstall" && m === "POST") {
        await mp.installs.uninstall(p, route[1] as string, route[2] as string);
        return [200, { ok: true }];
      }
      if (route.length === 3 && m === "GET")
        return [200, await mp.installs.get(p, route[1] as string, route[2] as string)];
    }
    if (route[0] === "review") {
      const r = staff("reviewer");
      if (route[1] === "publishers" && route.length === 2 && m === "GET")
        return [200, { items: await mp.publishers.queue(r) }];
      if (route[1] === "publishers" && route[3] === "evidence" && m === "GET")
        return [200, { items: await mp.publishers.evidenceFor(r, route[2] as string) }];
      if (route[1] === "publishers" && route[3] === "decision" && m === "POST")
        return [
          200,
          await mp.publishers.decide(r, route[2] as string, {
            decision: str(body["decision"], "decision") as "approve",
            reason: str(body["reason"], "reason"),
          }),
        ];
      if (route[1] === "queue" && m === "GET")
        return [
          200,
          { items: await mp.reviews.queue(r, (q.get("state") ?? "in_review") as "in_review") },
        ];
      if (route[1] === "reviews" && route.length === 3 && m === "GET")
        return [200, await mp.reviews.get(r, route[2] as string)];
      if (route[1] === "reviews" && route[3] === "decision" && m === "POST") {
        parseReviewId(route[2] as string);
        const ack = body["acknowledged_findings"];
        return [
          200,
          await mp.reviews.decide(r, route[2] as string, {
            decision: str(body["decision"], "decision") as "approve",
            note: str(body["note"], "note"),
            ...(Array.isArray(ack) ? { acknowledged: ack as string[] } : {}),
          }),
        ];
      }
    }
    if (route[0] === "moderation") {
      const mod = staff("moderator");
      if (route[1] === "takedowns" && m === "POST")
        return [
          200,
          await mp.listings.takedown(mod, {
            namespace: str(body["namespace"], "namespace"),
            name: str(body["name"], "name"),
            ...(typeof body["version"] === "string" ? { version: body["version"] } : {}),
            reason: str(body["reason"], "reason"),
          }),
        ];
      if (route[1] === "publishers" && route[3] === "suspend" && m === "POST") {
        await mp.publishers.suspend(mod, route[2] as string, str(body["reason"], "reason"));
        return [200, { ok: true }];
      }
    }
    throw new RegistryError("not_found", "no such route");
  };

  return http.createServer((rq, res) => {
    void (async () => {
      try {
        const url = new URL(rq.url ?? "/", "http://localhost");
        const a = auth(rq.headers.authorization);
        const who = a ? `${a.kind}:${a.subject}` : `anon:${rq.socket.remoteAddress ?? ""}`;
        let wait = limiter.check(who);
        if (wait === 0 && a && SENSITIVE.test(`${rq.method} ${url.pathname}`))
          wait = strict.check(who);
        if (wait > 0)
          return sendJson(
            res,
            429,
            { error: { code: "rate_limited" } },
            { "retry-after": String(Math.ceil(wait / 1000)) },
          );
        const [status, json] = await handle(rq, url, a);
        sendJson(res, status, json);
      } catch (err) {
        if (err instanceof SyntaxError || err instanceof BadRequest) return sendError(res, err);
        sendError(res, err);
      }
    })();
  });
}
