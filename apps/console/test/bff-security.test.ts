import { describe, expect, it } from "vitest";
import { bearerFromCookie, checkCsrf, resolveUpstream, upstreamKind } from "@/lib/bff";
import { buildCsp, isPublicPath, newNonce, safeReturnTo, securityHeaders } from "@/lib/security";
import { can, NAV, ROLES } from "@/lib/roles";
import { countdown } from "@/lib/sla";
import { parseFeatures } from "@/lib/features";

const B = "http://api:4010";

describe("resolveUpstream", () => {
  it("allows the API surface only", () => {
    expect(resolveUpstream(["v1", "runs"], "?a=1", B)).toBe("http://api:4010/v1/runs?a=1");
    expect(resolveUpstream(["v1", "policies:test"], "", B)).toBe(
      "http://api:4010/v1/policies:test",
    );
    expect(resolveUpstream(["admin", "v1", "members"], "", `${B}/`)).toBe(
      "http://api:4010/admin/v1/members",
    );
    expect(resolveUpstream(["auth", "me"], "", B)).toBeDefined();
    expect(resolveUpstream(["auth", "logout"], "", B)).toBeDefined();
  });
  it("rejects everything else", () => {
    for (const segs of [
      [],
      ["dev", "session"],
      ["internal", "v1", "x"],
      ["scim", "v2"],
      ["platform", "v1"],
      ["auth", "sso", "start"],
      ["v2", "runs"],
      ["admin", "x"],
    ]) {
      expect(resolveUpstream(segs, "", B), segs.join("/")).toBeUndefined();
    }
  });
  it("rejects traversal and smuggling in segments", () => {
    expect(resolveUpstream(["v1", ".."], "", B)).toBeUndefined();
    expect(resolveUpstream(["v1", "%2e%2e", "dev"], "", B)).toBeUndefined();
    expect(resolveUpstream(["v1", "a%2Fb"], "", B)).toBeUndefined();
    expect(resolveUpstream(["v1", "a%5Cb"], "", B)).toBeUndefined();
    expect(resolveUpstream(["v1", "a%00"], "", B)).toBeUndefined();
    expect(resolveUpstream(["v1", "%E0%A4%A"], "", B)).toBeUndefined();
    expect(resolveUpstream(["v1", "a b"], "", B)).toBeUndefined();
    expect(resolveUpstream(["v1", "a/b"], "", B)).toBeUndefined();
    expect(resolveUpstream(["v1", "."], "", B)).toBeUndefined();
  });
});

describe("checkCsrf", () => {
  const base = {
    method: "POST",
    origin: "https://c.example",
    host: "c.example",
    secFetchSite: "same-origin",
    cookieToken: "tok",
    headerToken: "tok",
  };
  it("passes safe methods and API keys without a token", () => {
    expect(
      checkCsrf({ ...base, method: "GET", cookieToken: undefined, headerToken: null }).ok,
    ).toBe(true);
    expect(
      checkCsrf({ ...base, cookieToken: undefined, headerToken: null, hasApiKey: true }).ok,
    ).toBe(true);
  });
  it("accepts same-origin with matching double-submit token", () => {
    expect(checkCsrf(base).ok).toBe(true);
    expect(checkCsrf({ ...base, origin: null }).ok).toBe(true);
  });
  it("rejects cross-origin, bad origin, cross-site and token problems", () => {
    expect(checkCsrf({ ...base, origin: "https://evil.example" })).toEqual({
      ok: false,
      reason: "cross-origin",
    });
    expect(checkCsrf({ ...base, origin: "not a url" })).toEqual({
      ok: false,
      reason: "bad origin",
    });
    expect(checkCsrf({ ...base, host: null })).toEqual({ ok: false, reason: "cross-origin" });
    expect(checkCsrf({ ...base, origin: null, secFetchSite: "cross-site" })).toEqual({
      ok: false,
      reason: "cross-site",
    });
    expect(checkCsrf({ ...base, headerToken: null })).toMatchObject({ ok: false });
    expect(checkCsrf({ ...base, cookieToken: undefined })).toMatchObject({ ok: false });
    expect(checkCsrf({ ...base, headerToken: "tok2" })).toEqual({
      ok: false,
      reason: "csrf token mismatch",
    });
    expect(checkCsrf({ ...base, headerToken: "xxx" })).toEqual({
      ok: false,
      reason: "csrf token mismatch",
    });
  });
});

describe("security", () => {
  it("builds a strict CSP with the nonce", () => {
    const csp = buildCsp("abc");
    expect(csp).toContain("script-src 'self' 'nonce-abc' 'strict-dynamic'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("connect-src 'self'");
    expect(csp).toContain("upgrade-insecure-requests");
    expect(csp).not.toContain("unsafe-eval");
    expect(csp).not.toContain("unsafe-inline");
  });
  it("omits upgrade-insecure-requests for explicit insecure-http test deployments", () => {
    expect(buildCsp("abc", { insecureHttp: true })).not.toContain("upgrade-insecure-requests");
  });
  it("relaxes only for dev", () => {
    const csp = buildCsp("abc", { dev: true });
    expect(csp).toContain("'unsafe-eval'");
    expect(csp).not.toContain("upgrade-insecure-requests");
  });
  it("sets headers", () => {
    const h = securityHeaders("x", { https: true });
    expect(h["x-frame-options"]).toBe("DENY");
    expect(h["strict-transport-security"]).toBeDefined();
    expect(securityHeaders("x")["strict-transport-security"]).toBeUndefined();
  });
  it("makes unique nonces", () => {
    expect(newNonce()).not.toBe(newNonce());
  });
  it("classifies public paths and sanitises return_to", () => {
    expect(isPublicPath("/login")).toBe(true);
    expect(isPublicPath("/auth/sso/start")).toBe(true);
    expect(isPublicPath("/_next/static/a.js")).toBe(true);
    expect(isPublicPath("/runs")).toBe(false);
    expect(isPublicPath("/loginx")).toBe(false);
    expect(safeReturnTo("/runs?x=1")).toBe("/runs?x=1");
    for (const bad of [
      "//evil.com",
      "/\\evil.com",
      "https://evil.com",
      "javascript:alert(1)",
      "",
      null,
      undefined,
      "/a\nb",
    ]) {
      expect(safeReturnTo(bad)).toBe("/");
    }
  });
});

describe("roles", () => {
  it("hides by role", () => {
    expect(can("viewer", "runs.start")).toBe(false);
    expect(can("builder", "runs.start")).toBe(true);
    expect(can("operator", "blueprints.write")).toBe(false);
    expect(can("admin", "policies.activate")).toBe(true);
    expect(can("builder", "policies.write")).toBe(false);
    expect(can("admin", "admin.sso")).toBe(false);
    expect(can("owner", "admin.sso")).toBe(true);
    expect(can("auditor", "audit.read")).toBe(true);
    expect(can("viewer", "audit.read")).toBe(false);
    expect(can(undefined, "audit.read")).toBe(false);
  });
  it("covers every capability and role", () => {
    for (const r of ROLES) {
      for (const cap of [
        "blueprints.write",
        "runs.start",
        "runs.signal",
        "approvals.decide",
        "policies.write",
        "policies.activate",
        "audit.read",
        "usage.read",
        "admin.members",
        "admin.keys",
        "admin.modelkeys",
        "admin.budgets",
        "admin.sso",
        "marketplace.install",
        "killswitch.set",
      ] as const) {
        expect(typeof can(r, cap)).toBe("boolean");
      }
      expect(NAV.filter((n) => n.show(r)).length).toBeGreaterThan(0);
    }
    expect(NAV.filter((n) => n.show("viewer")).map((n) => n.href)).not.toContain("/admin");
    expect(NAV.filter((n) => n.show("billing")).map((n) => n.href)).toContain("/usage");
  });
});

describe("countdown", () => {
  const now = Date.parse("2026-01-01T00:00:00Z");
  it("formats remaining and overdue", () => {
    expect(countdown("2026-01-01T02:05:00Z", now)).toMatchObject({
      label: "2h 5m left",
      state: "ok",
    });
    expect(countdown("2026-01-01T00:10:30Z", now)).toMatchObject({
      label: "10m 30s left",
      state: "urgent",
    });
    expect(countdown("2026-01-01T00:00:20Z", now)).toMatchObject({
      label: "20s left",
      state: "urgent",
    });
    expect(countdown("2025-12-31T23:00:00Z", now)).toMatchObject({
      label: "overdue by 1h 0m",
      state: "overdue",
    });
    expect(countdown("garbage", now).state).toBe("overdue");
  });
});

describe("features", () => {
  it("parses flags with defaults", () => {
    expect(parseFeatures({})).toEqual({ marketplace: true, evals: true, devLogin: false });
    expect(
      parseFeatures({ NEXT_PUBLIC_FEATURE_MARKETPLACE: "0", NEXT_PUBLIC_DEV_LOGIN: "true" }),
    ).toEqual({ marketplace: false, evals: true, devLogin: true });
  });
});

describe("gateway vs control-plane routing and the bearer conversion", () => {
  it("/v1 goes to the gateway, everything else allowed to the control plane", () => {
    expect(upstreamKind(["v1", "runs"])).toBe("gateway");
    expect(upstreamKind(["admin", "v1", "members"])).toBe("control");
    expect(upstreamKind(["auth", "refresh"])).toBe("control");
  });
  it("takes the access token from the session cookie only, and refuses odd values", () => {
    const c = "a=1; __Host-axis_at=tok.en-123; __Host-axis_csrf=c";
    expect(bearerFromCookie(c, "__Host-axis_at")).toBe("tok.en-123");
    expect(bearerFromCookie("x=1", "__Host-axis_at")).toBeUndefined();
    expect(bearerFromCookie(null, "__Host-axis_at")).toBeUndefined();
    expect(bearerFromCookie("__Host-axis_at=a b", "__Host-axis_at")).toBeUndefined();
    expect(
      bearerFromCookie(`__Host-axis_at=${"x".repeat(5000)}`, "__Host-axis_at"),
    ).toBeUndefined();
    // a look-alike cookie name is not the session cookie
    expect(bearerFromCookie("evil__Host-axis_at=zzz", "__Host-axis_at")).toBeUndefined();
  });
});

describe("CSP form-action and the IdP redirect", () => {
  it("is 'self' only unless an IdP origin is configured", () => {
    expect(buildCsp("n")).toContain("form-action 'self';");
    expect(buildCsp("n", { formActionOrigins: ["https://idp.example"] })).toContain(
      "form-action 'self' https://idp.example;",
    );
  });
});
