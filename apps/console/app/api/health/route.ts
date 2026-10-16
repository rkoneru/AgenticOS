import { NextResponse } from "next/server";

/** Liveness/readiness probe target for the console's Helm Deployment (Phase 10). No auth, no backend calls: it only proves the
 * Next.js server process itself is up and serving requests. */
export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function GET(): NextResponse {
  return NextResponse.json({ status: "ok" });
}
