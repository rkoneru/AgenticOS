import { inspect } from "node:util";
import { describe, expect, it } from "vitest";
import {
  ApprovalRequiredError,
  AuthenticationError,
  AxisApiError,
  AxisError,
  BudgetExceededError,
  ConflictError,
  errorFromProblem,
  InternalServerError,
  NotFoundError,
  parseRetryAfter,
  PermissionError,
  PolicyDeniedError,
  RateLimitError,
  redactText,
  Secret,
  ValidationError,
  Axis,
} from "../src/index.js";

const KEY = "axk_live_SUPERSECRET0123456789";

describe("secret redaction", () => {
  it("Secret never reveals through string, JSON, inspect or template", () => {
    const s = new Secret(KEY);
    for (const out of [
      String(s),
      JSON.stringify({ s }),
      inspect(s),
      `${s}`,
      inspect({ nested: { s } }, { depth: 5 }),
    ]) {
      expect(out).not.toContain("SUPERSECRET");
    }
    expect(s.reveal()).toBe(KEY);
  });
  it("redactText removes known secrets, bearer tokens and api-key headers", () => {
    const t = redactText(`boom ${KEY} Bearer abc.def-ghi x-axis-api-key: zzz999`, [KEY]);
    expect(t).not.toMatch(/SUPERSECRET|abc\.def|zzz999/);
    expect(redactText("short", ["ab"])).toBe("short");
  });
  it("the client, its transport and errors never expose the API key", async () => {
    const ax = new Axis({
      apiKey: KEY,
      baseUrl: "https://api.x.test/v1",
      maxRetries: 0,
      fetch: () => Promise.reject(new Error(`fail with ${KEY}`)),
    });
    for (const out of [
      String(ax),
      JSON.stringify(ax),
      inspect(ax, { depth: 6, showHidden: true }),
      String(ax.transport),
      JSON.stringify(ax.transport),
      inspect(ax.transport, { depth: 6, showHidden: true }),
    ]) {
      expect(out).not.toContain("SUPERSECRET");
    }
    const err = await ax.runs.get("3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f").then(
      () => new Error("unexpected success"),
      (e: unknown) => e as Error,
    );
    expect(err).toBeInstanceOf(AxisError);
    expect(String(err.message) + inspect(err, { depth: 6 })).not.toContain("SUPERSECRET");
  });
  it("AxisError scrubs credential-shaped text in messages", () => {
    expect(new AxisError("auth failed: Bearer top.secret.token").message).not.toContain(
      "top.secret",
    );
  });
});

describe("error mapping (RFC 9457)", () => {
  const p = (code: string, extra = {}) => ({
    type: `https://axis.example/problems/${code}`,
    title: "T",
    status: 400,
    code,
    ...extra,
  });
  const ids = { requestId: "r1", traceId: "t1" };
  it.each([
    [403, "policy_denied", PolicyDeniedError],
    [403, "approval_required", ApprovalRequiredError],
    [429, "rate_limited", RateLimitError],
    [402, "budget_exceeded", BudgetExceededError],
    [422, "validation_failed", ValidationError],
    [401, "unauthenticated", AuthenticationError],
    [403, "forbidden", PermissionError],
    [404, "not_found", NotFoundError],
    [409, "conflict", ConflictError],
    [500, "internal", InternalServerError],
  ] as const)("%i %s", (status, code, cls) => {
    const e = errorFromProblem(status, p(code), ids);
    expect(e).toBeInstanceOf(cls);
    expect(e).toBeInstanceOf(AxisApiError);
    expect(e.code).toBe(code);
    expect(e.requestId).toBe("r1");
    expect(e.traceId).toBe("t1");
    expect(e.status).toBe(status);
  });
  it("falls back to the status when the problem has no known code", () => {
    expect(errorFromProblem(401, undefined, {})).toBeInstanceOf(AuthenticationError);
    expect(errorFromProblem(403, undefined, {})).toBeInstanceOf(PermissionError);
    expect(errorFromProblem(404, undefined, {})).toBeInstanceOf(NotFoundError);
    expect(errorFromProblem(409, undefined, {})).toBeInstanceOf(ConflictError);
    expect(errorFromProblem(422, undefined, {})).toBeInstanceOf(ValidationError);
    expect(errorFromProblem(429, undefined, {})).toBeInstanceOf(RateLimitError);
    expect(errorFromProblem(503, undefined, {})).toBeInstanceOf(InternalServerError);
    expect(errorFromProblem(418, undefined, {}).constructor).toBe(AxisApiError);
  });
  it("derives the slug from the problem type URI", () => {
    const e = errorFromProblem(
      403,
      { type: "https://axis.example/problems/policy_denied", title: "x", status: 403 },
      {},
    );
    expect(e).toBeInstanceOf(PolicyDeniedError);
    expect(
      errorFromProblem(400, { type: "about:blank", title: "x", status: 400 }, {}).code,
    ).toBeUndefined();
  });
  it("exposes validation errors, approval id, retry-after and trace id from the body", () => {
    const v = errorFromProblem(
      422,
      { ...p("validation_failed"), errors: [{ path: "/abl", message: "bad" }] },
      {},
    ) as ValidationError;
    expect(v.errors).toEqual([{ path: "/abl", message: "bad" }]);
    expect(
      errorFromProblem(422, p("validation_failed"), {}) instanceof ValidationError &&
        (errorFromProblem(422, p("validation_failed"), {}) as ValidationError).errors,
    ).toEqual([]);
    const a = errorFromProblem(
      403,
      p("approval_required", { approval_id: "ap-1" }),
      {},
    ) as ApprovalRequiredError;
    expect(a.approvalId).toBe("ap-1");
    expect(
      (errorFromProblem(403, p("approval_required"), {}) as ApprovalRequiredError).approvalId,
    ).toBeUndefined();
    const r = errorFromProblem(429, p("rate_limited", { trace_id: "tb" }), {
      retryAfterSeconds: 7,
    }) as RateLimitError;
    expect(r.retryAfterSeconds).toBe(7);
    expect(r.traceId).toBe("tb");
    expect(r.message).toContain("HTTP 429");
  });
  it("parses Retry-After seconds and dates", () => {
    expect(parseRetryAfter(null)).toBeUndefined();
    expect(parseRetryAfter("5")).toBe(5);
    expect(parseRetryAfter("garbage")).toBeUndefined();
    expect(parseRetryAfter(new Date(10_000).toUTCString(), 4000)).toBe(6);
    expect(parseRetryAfter(new Date(1000).toUTCString(), 4000)).toBe(0);
  });
});
