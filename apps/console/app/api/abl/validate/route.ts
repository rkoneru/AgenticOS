import { NextResponse, type NextRequest } from "next/server";
import * as engine from "@axis/abl";
import { CSRF_COOKIE } from "@/lib/api";
import { checkCsrf } from "@/lib/bff";
import { checkAbl } from "@/lib/abl-diagnostics";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** Live ABL validation with the real compiler/linter. Pure computation: no tenant data is read or written. */
export async function POST(req: NextRequest): Promise<Response> {
  if (!req.cookies.get(process.env["AXIS_SESSION_COOKIE"] ?? "__Host-axis_at")) {
    return NextResponse.json(
      { title: "Sign in required", status: 401, code: "unauthenticated" },
      { status: 401 },
    );
  }
  const csrf = checkCsrf({
    method: "POST",
    origin: req.headers.get("origin"),
    host: req.headers.get("host"),
    secFetchSite: req.headers.get("sec-fetch-site"),
    cookieToken: req.cookies.get(CSRF_COOKIE)?.value,
    headerToken: req.headers.get("x-axis-csrf"),
  });
  if (!csrf.ok)
    return NextResponse.json({ title: "CSRF check failed", status: 403 }, { status: 403 });
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ title: "Body must be JSON", status: 400 }, { status: 400 });
  }
  const text = (body as { text?: unknown } | null)?.text;
  if (typeof text !== "string")
    return NextResponse.json({ title: "text must be a string", status: 422 }, { status: 422 });
  const { doc, ...rest } = checkAbl(text, engine as unknown as Parameters<typeof checkAbl>[1]);
  return NextResponse.json({ ...rest, doc });
}
