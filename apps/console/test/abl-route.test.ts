import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import { POST } from "@/app/api/abl/validate/route";

const ORIGIN = "https://console.example";
function req(
  body: BodyInit | null,
  extra: Record<string, string> = {},
  duplex = false,
): NextRequest {
  return new NextRequest(`${ORIGIN}/api/abl/validate`, {
    method: "POST",
    headers: {
      host: "console.example",
      origin: ORIGIN,
      cookie: "__Host-axis_at=session; __Host-axis_csrf=tok",
      "x-axis-csrf": "tok",
      "content-type": "application/json",
      ...extra,
    },
    body,
    ...(duplex ? { duplex: "half" } : {}),
  } as ConstructorParameters<typeof NextRequest>[1]);
}

describe("POST /api/abl/validate", () => {
  it("validates small documents", async () => {
    const r = await POST(req(JSON.stringify({ text: "apiVersion: nope" })));
    expect(r.status).toBe(200);
    expect((await r.json()).ok).toBe(false);
  });
  it("refuses a body over the cap however it is framed (the cookie is only checked for presence)", async () => {
    const big = JSON.stringify({ text: "a".repeat(1024 * 1024 + 10) });
    expect((await POST(req(big))).status).toBe(413);
    // chunked: no Content-Length to look at
    const chunked = new ReadableStream<Uint8Array>({
      start(c) {
        const piece = new TextEncoder().encode("a".repeat(64 * 1024));
        for (let i = 0; i < 20; i++) c.enqueue(piece);
        c.close();
      },
    });
    const r = await POST(req(chunked as unknown as BodyInit, {}, true));
    expect(r.status).toBe(413);
  });
  it("keeps its other refusals", async () => {
    expect((await POST(req("{ nope"))).status).toBe(400);
    expect((await POST(req(JSON.stringify({ text: 5 })))).status).toBe(422);
    expect((await POST(req("{}", { cookie: "x=1" }))).status).toBe(401);
    expect((await POST(req("{}", { origin: "https://evil.example" }))).status).toBe(403);
  });
});
