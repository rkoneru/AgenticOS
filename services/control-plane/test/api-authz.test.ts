import { describe, expect, it } from "vitest";
import {
  API_ACTIONS,
  ROLES,
  isRead,
  requiredScope,
  scopeAllows,
  type ApiAction,
  type Principal,
  type Role,
} from "../src/index.js";
import { sharedAuthorizer } from "./world.js";

const T = "11111111-1111-4111-8111-111111111111";
const me = (role: Role, over: Partial<Principal> = {}): Principal => ({
  tenantId: T,
  memberId: "22222222-2222-4222-8222-222222222222",
  role,
  credential: "session",
  ...over,
});

// owner and admin may READ governance state; writing and erasing personal data belongs to the privacy officer alone (ADR 0111).
const ALL = API_ACTIONS.filter((a) => a !== "api.governance.write" && a !== "api.governance.erase");
const MATRIX: Record<Role, ApiAction[]> = {
  owner: ALL,
  admin: ALL,
  builder: [
    "api.blueprints.read",
    "api.blueprints.publish",
    "api.runs.read",
    "api.runs.start",
    "api.runs.signal",
    "api.events.read",
    "api.policies.read",
    "api.policies.publish",
    "api.policies.test",
    "api.usage.read",
    "api.evals.run",
    "api.explanations.read",
    "api.registry.read",
    "api.registry.write",
    "api.marketplace.read",
    "api.evals.read",
    "api.evals.write",
    "api.evals.review",
    "api.compliance.read",
    "api.compliance.write",
  ],
  operator: [
    "api.blueprints.read",
    "api.runs.read",
    "api.runs.start",
    "api.runs.signal",
    "api.events.read",
    "api.approvals.read",
    "api.approvals.decide",
    "api.policies.read",
    "api.killswitch.read",
    "api.killswitch.write",
    "api.usage.read",
    "api.explanations.read",
    "api.registry.read",
    "api.marketplace.read",
    "api.evals.read",
    "api.evals.review",
    "api.compliance.read",
  ],
  auditor: [
    "api.blueprints.read",
    "api.runs.read",
    "api.events.read",
    "api.approvals.read",
    "api.policies.read",
    "api.audit.read",
    "api.audit.verify",
    "api.killswitch.read",
    "api.usage.read",
    "api.explanations.read",
    "api.registry.read",
    "api.marketplace.read",
    "api.evals.read",
    "api.compliance.read",
    "api.compliance.review",
    "api.governance.read",
  ],
  privacy_officer: [
    "api.governance.read",
    "api.governance.write",
    "api.governance.erase",
    "api.compliance.read",
  ],
  billing: ["api.usage.read"],
  viewer: [
    "api.blueprints.read",
    "api.runs.read",
    "api.events.read",
    "api.policies.read",
    "api.explanations.read",
    "api.registry.read",
    "api.marketplace.read",
    "api.evals.read",
    "api.compliance.read",
  ],
};

describe("api action namespace (ADR 0024)", () => {
  it("the OPA pack allows exactly the role matrix", async () => {
    const a = await sharedAuthorizer();
    for (const role of ROLES)
      for (const action of API_ACTIONS) {
        const d = await a.decide({ principal: me(role), action });
        expect(d.allowed, `${role} ${action}`).toBe(MATRIX[role].includes(action));
      }
  });

  it("an API key needs the resource scope; the pack is then asked and still decides by role", async () => {
    const a = await sharedAuthorizer();
    const key = (scopes: string[], role: Role = "owner") =>
      me(role, { credential: "api_key", scopes, apiKeyId: "k" });
    expect(
      (await a.decide({ principal: key(["runs:write"]), action: "api.runs.start" })).allowed,
    ).toBe(true);
    expect(
      (await a.decide({ principal: key(["runs:read"]), action: "api.runs.start" })).allowed,
    ).toBe(false);
    expect((await a.decide({ principal: key(["*"]), action: "api.audit.verify" })).allowed).toBe(
      true,
    );
    expect(
      (await a.decide({ principal: key(["runs:*"]), action: "api.runs.signal" })).allowed,
    ).toBe(true);
    expect(
      (await a.decide({ principal: key(["audit:read"]), action: "api.audit.verify" })).allowed,
    ).toBe(true);
    expect(
      (await a.decide({ principal: key(["usage:read"]), action: "api.audit.read" })).allowed,
    ).toBe(false);
    // a viewer's key with every scope still cannot do what a viewer cannot do
    expect(
      (await a.decide({ principal: key(["*"], "viewer"), action: "api.runs.start" })).allowed,
    ).toBe(false);
    // the cross-tenant ABAC rule applies to the api namespace
    const d = await a.decide({
      principal: me("owner"),
      action: "api.runs.read",
      resource: { tenantId: "other" },
    });
    expect(d.allowed).toBe(false);
  });

  it("eval actions: reads need evals:read, everything else evals:write; a reviewer key cannot administer", async () => {
    const a = await sharedAuthorizer();
    expect(requiredScope("api.evals.read")).toBe("evals:read");
    for (const v of ["run", "write", "admin", "review"])
      expect(requiredScope(`api.evals.${v}`)).toBe("evals:write");
    const key = (scopes: string[], role: Role) =>
      me(role, { credential: "api_key", scopes, apiKeyId: "k" });
    expect(
      (await a.decide({ principal: key(["evals:read"], "owner"), action: "api.evals.admin" }))
        .allowed,
    ).toBe(false);
    expect(
      (await a.decide({ principal: key(["evals:write"], "owner"), action: "api.evals.admin" }))
        .allowed,
    ).toBe(true);
    expect(
      (await a.decide({ principal: key(["evals:write"], "operator"), action: "api.evals.admin" }))
        .allowed,
    ).toBe(false);
    expect(
      (await a.decide({ principal: key(["evals:write"], "operator"), action: "api.evals.review" }))
        .allowed,
    ).toBe(true);
    expect(
      (await a.decide({ principal: key(["evals:write"], "viewer"), action: "api.evals.review" }))
        .allowed,
    ).toBe(false);
    expect((await a.decide({ principal: me("auditor"), action: "api.evals.review" })).allowed).toBe(
      false,
    );
  });

  it("compliance actions: reads need compliance:read, write and review need compliance:write; a builder key cannot review", async () => {
    const a = await sharedAuthorizer();
    expect(requiredScope("api.compliance.read")).toBe("compliance:read");
    for (const v of ["write", "review"])
      expect(requiredScope(`api.compliance.${v}`)).toBe("compliance:write");
    const key = (scopes: string[], role: Role) =>
      me(role, { credential: "api_key", scopes, apiKeyId: "k" });
    const can = async (scopes: string[], role: Role, action: ApiAction) =>
      (await a.decide({ principal: key(scopes, role), action })).allowed;
    expect(await can(["compliance:read"], "owner", "api.compliance.write")).toBe(false);
    expect(await can(["compliance:write"], "owner", "api.compliance.write")).toBe(true);
    expect(await can(["compliance:write"], "builder", "api.compliance.review")).toBe(false);
    expect(await can(["compliance:write"], "auditor", "api.compliance.review")).toBe(true);
    expect(await can(["compliance:write"], "auditor", "api.compliance.write")).toBe(false);
    expect(await can(["runs:write"], "owner", "api.compliance.read")).toBe(false);
    expect(await can(["compliance:read"], "billing", "api.compliance.read")).toBe(false);
  });

  it("scope names: api.<resource>.<verb> maps to <resource>:read|write", () => {
    expect(requiredScope("api.runs.start")).toBe("runs:write");
    expect(requiredScope("api.runs.read")).toBe("runs:read");
    expect(requiredScope("api.policies.test")).toBe("policies:read");
    expect(requiredScope("api.audit.verify")).toBe("audit:read");
    expect(requiredScope("api.killswitch.write")).toBe("killswitch:write");
    expect(requiredScope("apikeys.create")).toBe("apikeys:write");
    expect(scopeAllows(["runs:read"], "api.runs.start")).toBe(false);
    expect(isRead("api.policies.test")).toBe(true);
    expect(isRead("api.audit.verify")).toBe(true);
    expect(isRead("api.runs.start")).toBe(false);
  });
});
