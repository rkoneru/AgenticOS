import { createHash, timingSafeEqual } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { RegistryError } from "./errors.js";

/** Small shared helpers for the DEV HTTP surfaces of the registry and the marketplace (loopback, static bearer tokens, NOT production). */

export class BadRequest extends Error {}

export const MAX_BODY = 4_000_000;

export function readJson(req: http.IncomingMessage): Promise<Record<string, unknown>> {
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

export const str = (v: unknown, what: string): string => {
  if (typeof v !== "string" || v === "") throw new BadRequest(`${what} must be a non-empty string`);
  return v;
};
export const optStr = (v: unknown, what: string): string | undefined =>
  v === undefined ? undefined : str(v, what);
export const date = (v: unknown, what: string): Date => {
  const d = new Date(str(v, what));
  if (Number.isNaN(d.getTime())) throw new BadRequest(`${what} must be an ISO timestamp`);
  return d;
};
export const optDate = (v: unknown, what: string): Date | undefined =>
  v === undefined ? undefined : date(v, what);

export function sendJson(
  res: http.ServerResponse,
  status: number,
  json: unknown,
  extra: Record<string, string> = {},
): void {
  const text = JSON.stringify(json);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(text),
    ...extra,
  });
  res.end(text);
}

/** Maps any thrown value to a response. Unknown errors never leak their message. */
export function sendError(res: http.ServerResponse, err: unknown): void {
  if (err instanceof BadRequest)
    return sendJson(res, 400, { error: { code: "invalid", message: err.message } });
  if (err instanceof RegistryError)
    return sendJson(res, err.status, {
      error: {
        code: err.code,
        message: err.message,
        ...(err.checks.length ? { checks: err.checks } : {}),
      },
    });
  sendJson(res, 500, { error: { code: "internal" } });
}

/** Sliding-window limiter keyed by credential subject. `now` is injectable so tests need no sleeping. */
export class RateLimiter {
  private hits = new Map<string, number[]>();
  constructor(
    private readonly max: number,
    private readonly windowMs: number,
    private readonly now: () => number = Date.now,
  ) {}
  /** Returns 0 when allowed, else the milliseconds until the next hit would be allowed. */
  check(key: string): number {
    const t = this.now();
    const live = (this.hits.get(key) ?? []).filter((x) => t - x < this.windowMs);
    if (live.length >= this.max) {
      this.hits.set(key, live);
      return this.windowMs - (t - (live[0] as number));
    }
    live.push(t);
    this.hits.set(key, live);
    return 0;
  }
}

const digest = (s: string): Buffer => createHash("sha256").update(s, "utf8").digest();

/** Static bearer-token table (dev/test only): constant-time compare against every entry. */
export function staticTokenAuthenticator<A>(
  tokens: Record<string, A>,
): (authorization: string | undefined) => A | undefined {
  const entries = Object.entries(tokens).map(([tok, auth]) => ({ h: digest(tok), auth }));
  return (authorization) => {
    const token =
      typeof authorization === "string" && authorization.startsWith("Bearer ")
        ? authorization.slice(7)
        : undefined;
    if (token === undefined) return undefined;
    const h = digest(token);
    let found: A | undefined;
    for (const e of entries) if (timingSafeEqual(e.h, h)) found = e.auth;
    return found;
  };
}

/** Binds to the loopback interface only. Returns the chosen port. */
export function listenLoopback(server: http.Server, port = 0): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve((server.address() as AddressInfo).port));
  });
}

export function refuseProduction(name: string): void {
  if (process.env["NODE_ENV"] === "production")
    throw new Error(`the ${name} dev server must not run with NODE_ENV=production`);
}
