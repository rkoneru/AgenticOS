import { NextResponse, type NextRequest } from "next/server";
import { buildCsp, isPublicPath, newNonce, securityHeaders } from "@/lib/security";

const SESSION_COOKIE = process.env["AXIS_SESSION_COOKIE"] ?? "__Host-axis_at";

export function proxy(req: NextRequest): NextResponse {
  const { pathname, search } = req.nextUrl;
  const dev = process.env.NODE_ENV !== "production";
  const nonce = newNonce();
  const insecureHttp = process.env["AXIS_INSECURE_HTTP"] === "1";
  const csp = buildCsp(nonce, { dev, insecureHttp });
  const sec = securityHeaders(csp, { https: !dev && !insecureHttp });

  // Optimistic gate only: the control plane validates the session on every API call.
  const isApi = pathname.startsWith("/api/");
  if (!isApi && !isPublicPath(pathname) && !req.cookies.get(SESSION_COOKIE)) {
    const url = req.nextUrl.clone();
    url.pathname = "/login";
    url.search = `?return_to=${encodeURIComponent(pathname + search)}`;
    const res = NextResponse.redirect(url);
    for (const [k, v] of Object.entries(sec)) res.headers.set(k, v);
    return res;
  }

  const requestHeaders = new Headers(req.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("content-security-policy", csp);
  const res = NextResponse.next({ request: { headers: requestHeaders } });
  for (const [k, v] of Object.entries(sec)) res.headers.set(k, v);
  if (!isApi) res.headers.set("cache-control", "no-store");
  return res;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
