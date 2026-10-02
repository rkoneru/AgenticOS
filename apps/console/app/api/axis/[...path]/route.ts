import { NextResponse, type NextRequest } from "next/server";
import { CSRF_COOKIE } from "@/lib/api";
import {
  FORWARD_REQUEST_HEADERS,
  RESPONSE_HEADER_DROP,
  bearerFromCookie,
  checkCsrf,
  forwardedForHeader,
  resolveUpstream,
  upstreamKind,
} from "@/lib/bff";

/**
 * Same-origin backend-for-frontend. The browser never talks to the control plane directly:
 * this route (1) allow-lists the upstream path, (2) enforces CSRF for unsafe methods, (3) forwards the
 * session cookie, and (4) streams the response (so SSE works). The control plane is still the authority.
 */
export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// `/v1` goes to the API gateway; `/admin/v1` and `/auth` to the control plane (default: the same server, as the mock API is).
const GATEWAY = process.env["AXIS_API_URL"] ?? "http://127.0.0.1:4010";
const CONTROL = process.env["AXIS_CONTROL_PLANE_URL"] ?? GATEWAY;
// The real gateway authenticates `Authorization: Bearer`, not cookies: the BFF (which can read the HttpOnly session cookie) converts.
const GATEWAY_BEARER = process.env["AXIS_GATEWAY_BEARER"] === "1";
const SESSION_COOKIE = process.env["AXIS_SESSION_COOKIE"] ?? "__Host-axis_at";
// Behind a trusted reverse proxy the client's address is relayed to the gateway (its `GW_TRUSTED_PROXIES` must list this server).
const TRUST_PROXY = process.env["AXIS_TRUST_PROXY"] === "1";

async function handle(
  req: NextRequest,
  ctx: { params: Promise<{ path: string[] }> },
): Promise<Response> {
  const { path } = await ctx.params;
  const kind = upstreamKind(path);
  const url = resolveUpstream(path, req.nextUrl.search, kind === "gateway" ? GATEWAY : CONTROL);
  if (!url) return problem(404, "not_found", "Not found");

  const csrf = checkCsrf({
    method: req.method,
    origin: req.headers.get("origin"),
    host: req.headers.get("host"),
    secFetchSite: req.headers.get("sec-fetch-site"),
    cookieToken: req.cookies.get(CSRF_COOKIE)?.value,
    headerToken: req.headers.get("x-axis-csrf"),
    hasApiKey: req.headers.has("x-axis-api-key"),
  });
  if (!csrf.ok) return problem(403, "forbidden", `CSRF check failed: ${csrf.reason}`);

  const headers = new Headers();
  for (const h of FORWARD_REQUEST_HEADERS) {
    const v = req.headers.get(h);
    if (v) headers.set(h, v);
  }
  const xff = forwardedForHeader(req.headers.get("x-forwarded-for"), TRUST_PROXY);
  if (xff) headers.set("x-forwarded-for", xff);
  if (GATEWAY_BEARER && kind === "gateway") {
    // The credential the gateway sees is the session's own; whatever the browser put in Authorization is discarded.
    headers.delete("authorization");
    headers.delete("cookie");
    headers.delete("x-axis-api-key");
    const t = bearerFromCookie(req.headers.get("cookie"), SESSION_COOKIE);
    if (t) headers.set("authorization", `Bearer ${t}`);
  }
  const hasBody = req.method !== "GET" && req.method !== "HEAD";
  let upstream: Response;
  try {
    upstream = await fetch(url, {
      method: req.method,
      headers,
      redirect: "manual",
      cache: "no-store",
      signal: req.signal,
      ...(hasBody ? { body: await req.arrayBuffer() } : {}),
    });
  } catch {
    return problem(502, "internal", "The control plane is unreachable");
  }
  const out = new Headers();
  upstream.headers.forEach((v, k) => {
    if (!RESPONSE_HEADER_DROP.has(k.toLowerCase()) && k.toLowerCase() !== "set-cookie")
      out.set(k, v);
  });
  for (const c of upstream.headers.getSetCookie()) out.append("set-cookie", c);
  out.set("cache-control", "no-store");
  return new Response(upstream.body, { status: upstream.status, headers: out });
}

function problem(status: number, code: string, title: string): Response {
  return NextResponse.json(
    { type: `https://axis.example/problems/${code}`, title, status, code },
    { status, headers: { "content-type": "application/problem+json" } },
  );
}

export { handle as GET, handle as POST, handle as PUT, handle as PATCH, handle as DELETE };
