import { createHash, timingSafeEqual } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { AdjustmentApi } from "./adjustments.js";
import { mapRunEvents, modelClassifier, type RunEventLite } from "./emitters.js";
import { BillingError } from "./errors.js";
import type { InvoiceStore } from "./invoices.js";
import type { UsageLedger } from "./ledger.js";
import { invoiceToJson } from "./invoices.js";
import type { Granularity } from "./periods.js";
import { isMeter, PERIOD_RE, type Meter } from "./types.js";

/**
 * DEV / E2E ONLY (docs/NEEDS.md, billing rows). A loopback HTTP/JSON surface so the Python runtime can emit usage and a tenant can
 * read its statement without a new OpenAPI contract (contracts are frozen). NOT a production API:
 *  - plaintext HTTP on 127.0.0.1, static bearer tokens, no rate limiting; refuses to start when NODE_ENV=production;
 *  - the tenant ALWAYS comes from the bearer token; a `tenant_id` in a body or query that differs is rejected (403), never honoured;
 *  - scopes: `read` (statement, periods, rollup, entries: READ-ONLY), `ingest` (run events: the trusted runtime), `admin`
 *    (adjustments with a mandatory reason; audited). A tenant statement token holds `read` only.
 *
 *  GET  /v1/usage/periods                       sealed periods
 *  GET  /v1/usage/statement?period=YYYY-MM      totals, seal and latest invoice of a period
 *  GET  /v1/usage/rollup?granularity=hour|day|month&from=ISO&to=ISO[&meter=]
 *  GET  /v1/usage/entries?period=YYYY-MM[&meter=]   (at most 500 rows)
 *  POST /v1/usage/run-events      {run_id, events:[...]}            -> {records, inserted, duplicates, conflicts, skipped}
 *  POST /v1/usage/adjustments     {idempotency_key, meter, quantity, event_time, reason, dimensions?, corrects_key?}
 */
export type Scope = "read" | "ingest" | "admin";
export interface DevAuth {
  tenantId: string;
  scopes: readonly Scope[];
  /** Who this credential is (recorded as the actor of an adjustment). */
  subject: string;
}
export type DevAuthenticator = (authorization: string | undefined) => Promise<DevAuth | undefined>;

export interface DevServerDeps {
  ledger: UsageLedger;
  invoices: InvoiceStore;
  adjustments: AdjustmentApi;
  authenticate: DevAuthenticator;
  classifyRules?: readonly { prefix: string; class: string }[];
  now?: () => Date;
}

const MAX_BODY = 4_000_000;
const MAX_EVENTS = 20_000;
const MAX_ENTRIES = 500;

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

const str = (v: unknown, what: string): string => {
  if (typeof v !== "string" || v === "") throw new BadRequest(`${what} must be a non-empty string`);
  return v;
};
const bigint = (v: unknown, what: string): bigint => {
  if (typeof v === "string" && /^-?\d{1,16}$/.test(v)) return BigInt(v);
  throw new BadRequest(`${what} must be an integer string`);
};
const date = (v: unknown, what: string): Date => {
  const d = new Date(str(v, what));
  if (Number.isNaN(d.getTime())) throw new BadRequest(`${what} must be an ISO timestamp`);
  return d;
};
const period = (v: unknown): string => {
  const p = str(v, "period");
  if (!PERIOD_RE.test(p)) throw new BadRequest("period must be YYYY-MM");
  return p;
};
const meterOf = (v: string | null): Meter | undefined => {
  if (v === null) return undefined;
  if (!isMeter(v)) throw new BadRequest("unknown meter");
  return v;
};

const entryJson = (e: Awaited<ReturnType<UsageLedger["entries"]>>[number]) => ({
  id: e.id,
  idempotency_key: e.idempotencyKey,
  entry_type: e.entryType,
  meter: e.meter,
  quantity: e.quantity.toString(),
  event_time: e.eventTime.toISOString(),
  period: e.periodId,
  original_period: e.originalPeriodId,
  dimensions: e.dimensions,
  source: e.source,
  reason: e.reason,
  actor: e.actor,
});

export function createDevServer(deps: DevServerDeps): http.Server {
  if (process.env["NODE_ENV"] === "production")
    throw new Error("the billing dev server must not run with NODE_ENV=production");
  const { ledger } = deps;
  const classify = modelClassifier(deps.classifyRules ?? []);

  const get = async (path: string, q: URLSearchParams, auth: DevAuth): Promise<unknown> => {
    const t = auth.tenantId;
    if (q.has("tenant_id") && q.get("tenant_id") !== t) throw new Forbidden();
    switch (path) {
      case "periods":
        return {
          periods: (await ledger.seals(t)).map((s) => ({
            period: s.periodId,
            seq: s.seq,
            seal_hash: s.sealHash,
            event_count: s.eventCount,
            totals: s.totals,
            closed_at: s.closedAt.toISOString(),
          })),
        };
      case "statement": {
        const p = period(q.get("period"));
        const seal = (await ledger.seals(t)).find((s) => s.periodId === p);
        const invoices = await deps.invoices.list(t, p);
        const latest = invoices[invoices.length - 1];
        return {
          period: p,
          sealed: seal !== undefined,
          seal_hash: seal?.sealHash ?? null,
          totals: (await ledger.totals(t, p)).map((r) => ({
            meter: r.meter,
            dimension: r.dimension,
            quantity: r.quantity.toString(),
          })),
          invoice: latest
            ? { revision: latest.revision, hash: latest.hash, ...invoiceToJson(latest.invoice) }
            : null,
        };
      }
      case "rollup": {
        const g = q.get("granularity") ?? "day";
        if (g !== "hour" && g !== "day" && g !== "month")
          throw new BadRequest("granularity must be hour, day or month");
        const m = meterOf(q.get("meter"));
        const rows = await ledger.rollup(t, {
          granularity: g as Granularity,
          from: date(q.get("from"), "from"),
          to: date(q.get("to"), "to"),
          ...(m ? { meter: m } : {}),
        });
        return {
          rows: rows.map((r) => ({
            bucket: r.bucket,
            meter: r.meter,
            quantity: r.quantity.toString(),
          })),
        };
      }
      default: {
        const m = meterOf(q.get("meter"));
        const entries = await ledger.entries(t, {
          periodId: period(q.get("period")),
          ...(m ? { meter: m } : {}),
        });
        return {
          entries: entries.slice(0, MAX_ENTRIES).map(entryJson),
          truncated: entries.length > MAX_ENTRIES,
        };
      }
    }
  };

  const post = async (
    path: string,
    b: Record<string, unknown>,
    auth: DevAuth,
  ): Promise<unknown> => {
    const t = auth.tenantId;
    if (b["tenant_id"] !== undefined && b["tenant_id"] !== t) throw new Forbidden();
    if (path === "run-events") {
      if (!auth.scopes.includes("ingest")) throw new Forbidden();
      const events = b["events"];
      if (!Array.isArray(events) || events.length === 0 || events.length > MAX_EVENTS)
        throw new BadRequest("events must be a non-empty array");
      const runId = str(b["run_id"], "run_id");
      const lite = events.map((e: unknown): RunEventLite => {
        const o = (typeof e === "object" && e !== null ? e : {}) as Record<string, unknown>;
        const data = o["data"];
        if (
          o["run_id"] !== runId ||
          typeof o["seq"] !== "number" ||
          typeof o["type"] !== "string" ||
          typeof o["ts"] !== "string" ||
          typeof data !== "object" ||
          data === null
        )
          throw new BadRequest("malformed event");
        return {
          run_id: runId,
          seq: o["seq"],
          ts: o["ts"],
          type: o["type"],
          pid: typeof o["pid"] === "string" ? o["pid"] : null,
          data: data as Record<string, unknown>,
        };
      });
      const mapped = mapRunEvents(lite, { tenantId: t, classifyModel: classify });
      let inserted = 0;
      let duplicates = 0;
      let conflicts = 0;
      for (const rec of mapped.records) {
        const r = await ledger.append(rec);
        if (r.status === "inserted") inserted++;
        else if (r.status === "duplicate") duplicates++;
        else conflicts++;
      }
      return {
        records: mapped.records.length,
        inserted,
        duplicates,
        conflicts,
        skipped: mapped.skipped,
      };
    }
    if (!auth.scopes.includes("admin")) throw new Forbidden();
    const r = await deps.adjustments.adjust({
      tenantId: t,
      idempotencyKey: str(b["idempotency_key"], "idempotency_key"),
      meter: meterOf(str(b["meter"], "meter")) as Meter,
      quantity: bigint(b["quantity"], "quantity"),
      eventTime: date(b["event_time"], "event_time"),
      reason: str(b["reason"], "reason"),
      actor: auth.subject,
      ...(typeof b["corrects_key"] === "string" ? { correctsKey: b["corrects_key"] } : {}),
      ...(typeof b["dimensions"] === "object" && b["dimensions"] !== null
        ? { dimensions: b["dimensions"] as Record<string, string> }
        : {}),
    });
    return r.status === "conflict"
      ? { status: "conflict" }
      : { status: r.status, entry: entryJson(r.entry) };
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
      const url = new URL(rq.url ?? "/", "http://localhost");
      const m = /^\/v1\/usage\/([a-z-]+)$/.exec(url.pathname);
      const path = m?.[1];
      const isGet =
        rq.method === "GET" &&
        path !== undefined &&
        ["periods", "statement", "rollup", "entries"].includes(path);
      const isPost = rq.method === "POST" && (path === "run-events" || path === "adjustments");
      if (path === undefined || !(isGet || isPost))
        return send(404, { error: { code: "NOT_FOUND" } });
      const auth = await deps.authenticate(rq.headers.authorization).catch(() => undefined);
      if (!auth) return send(401, { error: { code: "UNAUTHENTICATED" } });
      try {
        if (isGet) {
          if (!auth.scopes.includes("read")) throw new Forbidden();
          return send(200, await get(path, url.searchParams, auth));
        }
        send(200, await post(path, await readJson(rq), auth));
      } catch (err) {
        if (err instanceof BadRequest)
          return send(400, { error: { code: "INVALID", message: err.message } });
        if (err instanceof Forbidden) return send(403, { error: { code: "FORBIDDEN" } });
        if (err instanceof BillingError) {
          const status =
            err.code === "INVALID" || err.code === "TENANT_MISMATCH"
              ? err.code === "INVALID"
                ? 400
                : 403
              : err.code === "NOT_FOUND"
                ? 404
                : 502;
          return send(status, { error: { code: err.code, message: err.message } });
        }
        send(500, { error: { code: "INTERNAL" } }); // never echo internals
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

const digest = (s: string): Buffer => createHash("sha256").update(s, "utf8").digest();

/** Static bearer-token table (dev/test only); compares in constant time over every entry. */
export function staticTokenAuthenticator(tokens: Record<string, DevAuth>): DevAuthenticator {
  const entries = Object.entries(tokens).map(([tok, auth]) => ({ h: digest(tok), auth }));
  return (authorization) => {
    const token =
      typeof authorization === "string" && authorization.startsWith("Bearer ")
        ? authorization.slice(7)
        : undefined;
    if (token === undefined) return Promise.resolve(undefined);
    const h = digest(token);
    let found: DevAuth | undefined;
    for (const e of entries) if (timingSafeEqual(e.h, h)) found = e.auth;
    return Promise.resolve(found);
  };
}
