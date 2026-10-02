import { type NextRequest } from "next/server";
import { RESPONSE_HEADER_DROP } from "@/lib/bff";

/**
 * The SSO redirect flow (`/auth/sso/start`, `/auth/sso/callback`) must run on the console origin so the control plane's cookies are set for
 * it. A route handler (not a build-time rewrite) so the control plane's address is read at RUN time. Only these two GETs are proxied,
 * redirects are passed through untouched, and nothing else of the control plane is reachable from here.
 */
export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const CONTROL =
  process.env["AXIS_CONTROL_PLANE_URL"] ?? process.env["AXIS_API_URL"] ?? "http://127.0.0.1:4010";
const ALLOWED = new Set(["start", "callback"]);

export async function GET(
  req: NextRequest,
  ctx: { params: Promise<{ path: string[] }> },
): Promise<Response> {
  const { path } = await ctx.params;
  if (path.length !== 1 || !ALLOWED.has(path[0] as string))
    return new Response("not found", { status: 404 });
  const headers = new Headers();
  const cookie = req.headers.get("cookie");
  if (cookie) headers.set("cookie", cookie);
  let upstream: Response;
  try {
    upstream = await fetch(
      `${CONTROL.replace(/\/+$/, "")}/auth/sso/${path[0]}${req.nextUrl.search}`,
      {
        method: "GET",
        headers,
        redirect: "manual",
        cache: "no-store",
      },
    );
  } catch {
    return new Response("the control plane is unreachable", { status: 502 });
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
