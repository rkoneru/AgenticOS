/** Pure helpers for the same-origin backend-for-frontend route (`app/api/axis/[...path]`). */

import { CSRF_COOKIE, CSRF_HEADER } from "./api";

const ALLOWED_PREFIXES: ReadonlyArray<readonly string[]> = [
  ["v1"],
  ["admin", "v1"],
  ["auth", "me"],
  ["auth", "refresh"],
  ["auth", "logout"],
];

const SEGMENT = /^[A-Za-z0-9._~:@!$&'()*+,;=%-]+$/;

/** Map `/api/axis/<segments>` onto an upstream URL, or `undefined` when the path is not allowed. */
export function resolveUpstream(
  segments: readonly string[],
  search: string,
  base: string,
): string | undefined {
  if (segments.length === 0) return undefined;
  const decoded: string[] = [];
  for (const raw of segments) {
    if (!SEGMENT.test(raw)) return undefined;
    let d: string;
    try {
      d = decodeURIComponent(raw);
    } catch {
      return undefined;
    }
    if (d === "." || d === ".." || d.includes("/") || d.includes("\\") || d.includes("\0"))
      return undefined;
    decoded.push(d);
  }
  const ok = ALLOWED_PREFIXES.some((p) => p.every((s, i) => decoded[i] === s));
  if (!ok) return undefined;
  const root = base.replace(/\/+$/, "");
  return `${root}/${segments.join("/")}${search}`;
}

/** `/v1/*` is the API gateway; `/admin/v1/*` and `/auth/*` are the control plane (login, session refresh, tenant admin). */
export function upstreamKind(segments: readonly string[]): "gateway" | "control" {
  return segments[0] === "v1" ? "gateway" : "control";
}

/** The session access token from a Cookie header: the gateway authenticates a bearer token, never a cookie. */
export function bearerFromCookie(
  cookieHeader: string | null,
  cookieName: string,
): string | undefined {
  for (const part of (cookieHeader ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === cookieName) {
      const v = part.slice(i + 1).trim();
      return /^[\x21-\x7e]{1,4096}$/.test(v) ? v : undefined;
    }
  }
  return undefined;
}

/**
 * The `X-Forwarded-For` the BFF relays to the gateway, so that failed sign-ins are throttled per CLIENT and not for the whole console
 * (every request reaches the gateway from this server's address). Only when the console itself sits behind a proxy it trusts
 * (`AXIS_TRUST_PROXY=1`, and the gateway lists this server in `GW_TRUSTED_PROXIES`); otherwise a client could name its own address.
 * Only IP-literal entries survive.
 */
export function forwardedForHeader(value: string | null, trustProxy: boolean): string | undefined {
  if (!trustProxy || !value) return undefined;
  const hops = value
    .split(",")
    .map((h) => h.trim())
    .filter((h) => /^[0-9A-Fa-f:.]{2,45}$/.test(h));
  return hops.length > 0 ? hops.join(", ") : undefined;
}

const SAFE = new Set(["GET", "HEAD", "OPTIONS"]);

export type CsrfVerdict = { ok: true } | { ok: false; reason: string };

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * CSRF for cookie-authenticated unsafe methods: the request must be same-origin (Origin, else
 * Sec-Fetch-Site) AND carry the double-submit token in a header equal to the readable cookie.
 */
export function checkCsrf(input: {
  method: string;
  origin: string | null;
  host: string | null;
  secFetchSite: string | null;
  cookieToken: string | undefined;
  headerToken: string | null;
  /** Requests authenticated by an API key header have no ambient credentials to forge. */
  hasApiKey?: boolean;
}): CsrfVerdict {
  if (SAFE.has(input.method.toUpperCase())) return { ok: true };
  if (input.hasApiKey) return { ok: true };
  if (input.origin) {
    let h: string;
    try {
      h = new URL(input.origin).host;
    } catch {
      return { ok: false, reason: "bad origin" };
    }
    if (!input.host || h !== input.host) return { ok: false, reason: "cross-origin" };
  } else if (input.secFetchSite && input.secFetchSite !== "same-origin") {
    return { ok: false, reason: "cross-site" };
  }
  if (!input.cookieToken || !input.headerToken) return { ok: false, reason: "missing csrf token" };
  if (!timingSafeEqual(input.cookieToken, input.headerToken))
    return { ok: false, reason: "csrf token mismatch" };
  return { ok: true };
}

/** Request headers the BFF forwards upstream (allow-list; everything else is dropped). */
export const FORWARD_REQUEST_HEADERS = [
  "accept",
  "content-type",
  "cookie",
  "idempotency-key",
  "x-axis-api-key",
  "authorization",
  CSRF_HEADER,
  "last-event-id",
] as const;

export const RESPONSE_HEADER_DROP = new Set([
  "content-encoding",
  "content-length",
  "transfer-encoding",
  "connection",
  "keep-alive",
]);

export { CSRF_COOKIE };
