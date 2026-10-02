import { describe, expect, it, vi } from "vitest";
import {
  ApiError,
  createApi,
  readCookie,
  withQuery,
  newIdempotencyKey,
  CSRF_HEADER,
} from "@/lib/api";

function mockFetch(handler: (url: string, init: RequestInit) => Response | Promise<Response>) {
  return vi.fn(async (u: RequestInfo | URL, init?: RequestInit) =>
    handler(String(u), init ?? {}),
  ) as unknown as typeof fetch & ReturnType<typeof vi.fn>;
}
const ok = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

describe("helpers", () => {
  it("reads cookies", () => {
    expect(readCookie("b", "a=1; b=x%20y; c=3")).toBe("x y");
    expect(readCookie("z", "a=1")).toBeUndefined();
    expect(readCookie("a", "")).toBeUndefined();
    expect(readCookie("q")).toBeUndefined(); // no document in node
  });
  it("builds queries and skips empty values", () => {
    expect(withQuery("/x", { a: 1, b: "", c: undefined, d: null, e: "z w" })).toBe("/x?a=1&e=z+w");
    expect(withQuery("/x")).toBe("/x");
    expect(withQuery("/x", {})).toBe("/x");
  });
  it("makes idempotency keys of valid length", () => {
    const k = newIdempotencyKey();
    expect(k.length).toBeGreaterThanOrEqual(8);
    expect(k.length).toBeLessThanOrEqual(128);
  });
});

describe("ApiError", () => {
  it("maps status to default codes and detects not-available", () => {
    expect(new ApiError(401, undefined, "x").code).toBe("unauthenticated");
    expect(new ApiError(403, undefined, "x").code).toBe("forbidden");
    expect(new ApiError(404, undefined, "x").notAvailable).toBe(true);
    expect(new ApiError(409, undefined, "x").code).toBe("conflict");
    expect(new ApiError(422, undefined, "x").code).toBe("validation_failed");
    expect(new ApiError(429, undefined, "x").code).toBe("rate_limited");
    expect(new ApiError(500, undefined, "x").code).toBe("internal");
    expect(new ApiError(500, undefined, "x").notAvailable).toBe(false);
    const e = new ApiError(
      422,
      {
        title: "bad",
        status: 422,
        code: "validation_failed",
        detail: "d",
        trace_id: "t",
        errors: [{ path: "/a", message: "m" }],
      },
      "f",
    );
    expect([e.message, e.detail, e.traceId, e.errors.length]).toEqual(["bad", "d", "t", 1]);
  });
});

describe("client", () => {
  it("GET sends no csrf and no idempotency key", async () => {
    const f = mockFetch(() => ok({ items: [] }));
    const api = createApi({ fetchImpl: f, csrf: () => "tok" });
    await api.listRuns({ state: "running", limit: 5 });
    const [url, init] = f.mock.calls[0]!;
    expect(url).toBe("/api/axis/v1/runs?state=running&limit=5");
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h[CSRF_HEADER]).toBeUndefined();
    expect(h["idempotency-key"]).toBeUndefined();
    expect((init as RequestInit).credentials).toBe("same-origin");
  });

  it("POST sends csrf token, idempotency key and JSON body", async () => {
    const f = mockFetch(() => ok({ id: "r" }, 202));
    const api = createApi({ fetchImpl: f, csrf: () => "tok", idempotencyKey: () => "idem-12345" });
    await api.startRun({ name: "a", version: "1.0.0" }, { q: 1 });
    const [url, init] = f.mock.calls[0]!;
    const i = init as RequestInit;
    const h = i.headers as Record<string, string>;
    expect(url).toBe("/api/axis/v1/runs");
    expect(h[CSRF_HEADER]).toBe("tok");
    expect(h["idempotency-key"]).toBe("idem-12345");
    expect(JSON.parse(i.body as string)).toEqual({
      blueprint: { name: "a", version: "1.0.0" },
      input: { q: 1 },
    });
  });

  it("omits the csrf header when there is no token and escapes path segments", async () => {
    const f = mockFetch(() => ok({}));
    const api = createApi({ fetchImpl: f, csrf: () => undefined });
    await api.getBlueprintVersion("a/b", "1.0.0 x");
    await api.deleteModelKey("p", "l");
    expect(f.mock.calls[0]![0]).toBe("/api/axis/v1/blueprints/a%2Fb/versions/1.0.0%20x");
    expect(
      ((f.mock.calls[1]![1] as RequestInit).headers as Record<string, string>)[CSRF_HEADER],
    ).toBeUndefined();
  });

  it("returns undefined for 204", async () => {
    const api = createApi({
      fetchImpl: mockFetch(() => new Response(null, { status: 204 })),
      csrf: () => "t",
    });
    await expect(api.removeMember("m1")).resolves.toBeUndefined();
  });

  it("raises ApiError with problem body and signals 401", async () => {
    const onUnauthenticated = vi.fn();
    const f = mockFetch(() => ok({ title: "Nope", status: 401, code: "unauthenticated" }, 401));
    const api = createApi({ fetchImpl: f, onUnauthenticated });
    await expect(api.listRuns()).rejects.toMatchObject({ status: 401, message: "Nope" });
    expect(onUnauthenticated).toHaveBeenCalled();
  });

  it("tolerates non-JSON error bodies", async () => {
    const api = createApi({ fetchImpl: mockFetch(() => new Response("<html>", { status: 502 })) });
    await expect(api.listRuns()).rejects.toMatchObject({
      status: 502,
      message: "Request failed (502)",
    });
  });

  it("exercises every operation against the expected method and path", async () => {
    const f = mockFetch((url) =>
      url.endsWith("/v1/me")
        ? ok({ tenant: { id: "t" }, member: { id: "m", role: "owner" } })
        : ok({ items: [] }),
    );
    const api = createApi({ fetchImpl: f, csrf: () => "t", idempotencyKey: () => "idem-12345" });
    const pol = { a: 1 };
    const bp = { name: "a", version: "1" };
    await Promise.all([
      api.session(),
      api.logout(),
      api.listBlueprints(),
      api.publishBlueprint({}),
      api.getRun("r"),
      api.signalRun("r", "PAUSE", "why"),
      api.signalRun("r", "KILL"),
      api.listRunEvents("r", { after_sequence: 3 }),
      api.listApprovals({ status: "pending" }),
      api.decideApproval("a", "approve", "ok"),
      api.decideApproval("a", "reject"),
      api.listPolicyPacks(),
      api.publishPolicyPack(pol),
      api.testPolicy(pol, { enforcement_point: "tool_call", context: {} }),
      api.activatePolicy("v1"),
      api.listAuditEvents({ trace_id: "x" }),
      api.verifyAudit({ from_seq: 1 }),
      api.verifyAudit(),
      api.listKillSwitches(),
      api.setKillSwitch({ scope: "tenant", engaged: true }),
      api.getUsage({ from: "a", to: "b" }),
      api.listEvalRuns(),
      api.startEvalRun("s", bp),
      api.explainRun("r"),
      api.explainApproval("a"),
      api.explainAuditEvent("7"),
      api.tenant(),
      api.listMembers(),
      api.inviteMember("e@x", "viewer"),
      api.updateMemberRole("m", "admin"),
      api.listApiKeys(),
      api.createApiKey({ name: "n", scopes: [] }),
      api.rotateApiKey("k"),
      api.revokeApiKey("k"),
      api.listModelKeys(),
      api.putModelKey("p", "l", "v"),
      api.listBudgets(),
      api.putBudgets([]),
      api.deleteBudget("b"),
      api.getSso(),
      api.putSso({}),
      api.listDirectories(),
      api.listListings({ q: "x" }),
      api.getListing("ns", "l"),
      api.previewInstall("ns", "l", "^1"),
      api.installListing({
        namespace: "ns",
        name: "l",
        version: "1.0.0",
        content_hash: "a".repeat(64),
        consent_digest: "d",
      } as never),
      api.listInstalls(),
      api.listRegistryNamespaces(),
      api.listRegistryVersions("ns", "l"),
      api.resolveRegistry("ns/l@^1"),
      api.getApproval("a"),
    ]);
    const calls = f.mock.calls.map(
      (c) => `${(c[1] as RequestInit).method} ${String(c[0]).split("?")[0]}`,
    );
    expect(calls).toContain("POST /api/axis/v1/policies:test");
    expect(calls).toContain("POST /api/axis/v1/policies/v1/activate");
    expect(calls).toContain("PUT /api/axis/admin/v1/model-keys/p/l");
    expect(calls).toContain("GET /api/axis/v1/me");
    expect(calls).toContain("POST /api/axis/v1/approvals/a/decision");
    expect(calls).toContain("POST /api/axis/v1/marketplace/installs");
    expect(calls.length).toBe(52);
  });

  it("opens an event stream with the SSE accept header", async () => {
    const stream = new ReadableStream<Uint8Array>();
    const f = mockFetch(
      () => new Response(stream, { status: 200, headers: { "content-type": "text/event-stream" } }),
    );
    const api = createApi({ fetchImpl: f });
    const ac = new AbortController();
    const s = await api.streamRunEvents("r1", 4, ac.signal);
    expect(s).toBeDefined();
    const [url, init] = f.mock.calls[0]!;
    expect(url).toBe("/api/axis/v1/runs/r1/events?after_sequence=4");
    expect(((init as RequestInit).headers as Record<string, string>)["accept"]).toBe(
      "text/event-stream",
    );
    expect((init as RequestInit).signal).toBe(ac.signal);
  });

  it("rejects an event stream without a body", async () => {
    const api = createApi({ fetchImpl: mockFetch(() => new Response(null, { status: 200 })) });
    await expect(api.streamRunEvents("r", 0, new AbortController().signal)).rejects.toMatchObject({
      status: 502,
    });
  });
});
