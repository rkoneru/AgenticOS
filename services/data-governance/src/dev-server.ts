import http from "node:http";
import type { AddressInfo } from "node:net";
import type { DsarEngine, OpenInput, RejectReason } from "./dsar.js";
import type { HoldRegistry } from "./registry.js";
import type { RetentionEngine } from "./retention.js";
import type { DsarRequest, Hold } from "./store.js";
import { GovernanceError, isDataClass, type Principal } from "./types.js";

/**
 * DEV / INTERNAL admin surface (`/admin/v1`), not the public API (docs/spec/data-governance.md section 9; NEEDS 3208). Loopback HTTP,
 * bearer tokens mapped to a Principal (tenant and roles come from the credential, never from the body), no rate limiting. Responses never
 * contain sealed identifiers, and the bodies of a DSAR export are returned only by the export route.
 *
 *   POST /admin/v1/dsar                    {kind, identifiers[], destination_region?}   GET /admin/v1/dsar[?status=]   GET /admin/v1/dsar/:id
 *   POST /admin/v1/dsar/:id/{verify|extend|reject|export|erase|restrict}                POST /admin/v1/dsar/sweep
 *   POST /admin/v1/holds {scope, reason, classes?, case_ref?, groups?}   GET /admin/v1/holds   POST /admin/v1/holds/:id/release
 *   GET /admin/v1/retention   PUT /admin/v1/retention/:class {days}   POST /admin/v1/retention/run {dry_run?, classes?}
 */
export type Authenticator = (authorization: string | undefined) => Promise<Principal | undefined>;
export interface AdminDeps {
  dsar: DsarEngine;
  holds: HoldRegistry;
  retention: RetentionEngine;
  authenticate: Authenticator;
}

const MAX_BODY = 256_000;
class Bad extends Error {}

function readJson(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size <= MAX_BODY) chunks.push(c);
    });
    req.on("end", () => {
      if (size > MAX_BODY) return reject(new Bad("body too large"));
      try {
        const v: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
        if (typeof v !== "object" || v === null || Array.isArray(v))
          return reject(new Bad("body must be a JSON object"));
        resolve(v as Record<string, unknown>);
      } catch {
        reject(new Bad("body must be JSON"));
      }
    });
    req.on("error", () => reject(new Bad("read error")));
  });
}

export const dsarView = (r: DsarRequest): Record<string, unknown> => ({
  id: r.id,
  kind: r.kind,
  subject_ref: r.subjectRef,
  status: r.status,
  received_at: r.receivedAt.toISOString(),
  due_at: (r.extendedUntil ?? r.dueAt).toISOString(),
  extended: r.extendedUntil !== null,
  verified_at: r.verifiedAt?.toISOString() ?? null,
  verified_method: r.verifiedMethod,
  destination_region: r.destinationRegion,
  result: r.result,
});
export const holdView = (h: Hold): Record<string, unknown> => ({
  id: h.id,
  kind: h.kind,
  scope: h.scope,
  case_ref: h.caseRef,
  classes: h.dataClasses,
  reason: h.reason,
  placed_by: h.placedBy,
  placed_at: h.placedAt.toISOString(),
  released_at: h.releasedAt?.toISOString() ?? null,
});

const STATUS: Record<GovernanceError["code"], number> = {
  forbidden: 403,
  not_found: 404,
  invalid: 400,
  conflict: 409,
  not_verified: 409,
  residency: 403,
  held: 409,
  residual_data: 500,
  restricted: 403,
  unavailable: 503,
};

export function createAdminServer(d: AdminDeps): http.Server {
  return http.createServer((rq, rs) => {
    const send = (status: number, body: unknown): void => {
      rs.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
      rs.end(JSON.stringify(body));
    };
    void (async () => {
      try {
        const url = new URL(rq.url ?? "/", "http://localhost");
        const parts = url.pathname.split("/").filter(Boolean);
        if (parts[0] !== "admin" || parts[1] !== "v1")
          return send(404, { error: { code: "not_found" } });
        const p = await d.authenticate(rq.headers.authorization);
        if (!p) return send(401, { error: { code: "unauthenticated" } });
        const body = rq.method === "GET" ? {} : await readJson(rq);
        const m = rq.method ?? "GET";
        const [, , res, id, act] = parts;

        if (res === "dsar") {
          if (!id && m === "POST") {
            const input: OpenInput = {
              kind: body["kind"] as OpenInput["kind"],
              identifiers: body["identifiers"] as OpenInput["identifiers"],
              ...(typeof body["destination_region"] === "string"
                ? { destinationRegion: body["destination_region"] }
                : {}),
            };
            if (
              !["export", "erase", "restrict"].includes(input.kind) ||
              !Array.isArray(input.identifiers)
            )
              throw new Bad("kind and identifiers[] are required");
            return send(201, dsarView(await d.dsar.open(p, input)));
          }
          if (!id && m === "GET") {
            const st = url.searchParams.get("status");
            return send(200, {
              items: (await d.dsar.list(p, st ? [st as DsarRequest["status"]] : undefined)).map(
                dsarView,
              ),
            });
          }
          if (id === "sweep" && m === "POST") return send(200, { items: await d.dsar.sweepSla(p) });
          if (id && !act && m === "GET") return send(200, dsarView(await d.dsar.get(p, id)));
          if (id && act && m === "POST") {
            switch (act) {
              case "verify":
                return send(200, dsarView(await d.dsar.verify(p, id, body["evidence"])));
              case "extend":
                return send(
                  200,
                  dsarView(await d.dsar.extend(p, id, String(body["reason"] ?? ""))),
                );
              case "reject":
                return send(
                  200,
                  dsarView(await d.dsar.reject(p, id, body["reason"] as RejectReason)),
                );
              case "export":
                return send(200, await d.dsar.export(p, id));
              case "erase": {
                const o = await d.dsar.erase(p, id);
                return send(200, {
                  status: o.status,
                  request: dsarView(o.request),
                  providers: o.providers,
                });
              }
              case "restrict":
                return send(
                  200,
                  dsarView(await d.dsar.applyRestriction(p, id, String(body["reason"] ?? ""))),
                );
            }
          }
        } else if (res === "holds") {
          if (!id && m === "POST") {
            const kind = body["restriction"] === true ? "restriction" : "hold";
            const groups = body["groups"] as never;
            const h =
              kind === "restriction"
                ? await d.holds.restrict(
                    p,
                    (groups as never[])[0] ?? [],
                    String(body["reason"] ?? ""),
                  )
                : await d.holds.placeHold(p, {
                    scope: body["scope"] as never,
                    reason: String(body["reason"] ?? ""),
                    dataClasses: body["classes"] as never,
                    caseRef: body["case_ref"] as never,
                    groups,
                  });
            return send(201, holdView(h));
          }
          if (!id && m === "GET")
            return send(200, {
              items: (await d.holds.list(p, url.searchParams.get("all") !== "1")).map(holdView),
            });
          if (id && act === "release" && m === "POST")
            return send(200, holdView(await d.holds.release(p, id)));
        } else if (res === "retention") {
          if (!id && m === "GET")
            return send(200, { items: (await d.retention.resolve(p.tenantId)) ?? [] });
          if (id === "run" && m === "POST") {
            const classes = Array.isArray(body["classes"])
              ? (body["classes"] as unknown[]).filter(isDataClass)
              : undefined;
            return send(
              200,
              await d.retention.run(p, {
                dryRun: body["dry_run"] !== false,
                ...(classes ? { classes } : {}),
              }),
            );
          }
          if (id && m === "PUT") {
            if (!isDataClass(id)) throw new Bad("unknown data class");
            await d.retention.setPolicy(p, id, Number(body["days"]));
            return send(200, { data_class: id, days: Number(body["days"]) });
          }
        }
        send(404, { error: { code: "not_found" } });
      } catch (err) {
        if (err instanceof Bad)
          return send(400, { error: { code: "invalid", message: err.message } });
        if (err instanceof GovernanceError)
          return send(STATUS[err.code], { error: { code: err.code, message: err.message } });
        send(500, { error: { code: "internal" } });
      }
    })();
  });
}

export function listenLoopback(server: http.Server, port = 0): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve((server.address() as AddressInfo).port));
  });
}

export function staticTokenAuthenticator(tokens: Record<string, Principal>): Authenticator {
  return (authorization) => {
    const t =
      typeof authorization === "string" && authorization.startsWith("Bearer ")
        ? authorization.slice(7)
        : undefined;
    return Promise.resolve(t !== undefined && Object.hasOwn(tokens, t) ? tokens[t] : undefined);
  };
}
