import { describe, expect, it } from "vitest";
import {
  ACTIONS,
  Authorizer,
  ROLES,
  ROLE_RANK,
  scopeAllows,
  requiredScope,
  withinCeiling,
  type Action,
  type PolicyEngine,
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
const engine = (fn: (i: Record<string, unknown>) => unknown | Promise<unknown>): PolicyEngine => ({
  evaluate: async (i) => fn(i),
});

describe("Authorizer (OPA Wasm, fail-closed)", () => {
  it("allows exactly the RBAC matrix", async () => {
    const a = await sharedAuthorizer();
    const allowed: Record<Role, Action[]> = {
      owner: [...ACTIONS],
      admin: ACTIONS.filter((x) => !["tenant.close", "billing.write"].includes(x)),
      builder: [
        "tenant.read",
        "members.read",
        "apikeys.read",
        "apikeys.create",
        "apikeys.rotate",
        "apikeys.revoke",
        "modelkeys.read",
        "modelkeys.write",
        "modelkeys.delete",
        "policies.read",
        "policies.publish",
        "budgets.read",
        "settings.read",
      ],
      operator: [
        "tenant.read",
        "members.read",
        "apikeys.read",
        "policies.read",
        "budgets.read",
        "budgets.write",
        "settings.read",
      ],
      auditor: [
        "tenant.read",
        "members.read",
        "apikeys.read",
        "modelkeys.read",
        "policies.read",
        "budgets.read",
        "settings.read",
        "audit.read",
        "directories.read",
      ],
      billing: ["tenant.read", "billing.read", "billing.write", "budgets.read", "budgets.write"],
      viewer: ["tenant.read", "policies.read", "budgets.read"],
    };
    for (const role of ROLES) {
      for (const action of ACTIONS) {
        const d = await a.decide({
          principal: me(role),
          action,
          resource: { classification: "internal" },
        });
        expect(d.allowed, `${role} ${action}`).toBe(allowed[role].includes(action));
        expect(d.decision).toBe(d.allowed ? "ALLOW" : "DENY");
      }
    }
  });

  it("DENIES on missing policy, engine error, timeout, malformed and non-ALLOW results", async () => {
    const req = { principal: me("owner"), action: "tenant.read" as const };
    expect((await Authorizer.missing().decide(req)).allowed).toBe(false);
    const mk = (e: PolicyEngine, extra: { timeoutMs?: number; clock?: () => number } = {}) =>
      new Authorizer({ engine: e, policyVersion: "t@1", ...extra });
    expect(
      (
        await mk(
          engine(() => {
            throw new Error("boom");
          }),
        ).decide(req)
      ).reason,
    ).toMatch(/error/);
    expect((await mk({ evaluate: () => Promise.reject(new Error("x")) }).decide(req)).allowed).toBe(
      false,
    );
    expect((await mk(engine(() => undefined)).decide(req)).reason).toMatch(/malformed/);
    expect((await mk(engine(() => "ALLOW")).decide(req)).allowed).toBe(false);
    expect((await mk(engine(() => null)).decide(req)).allowed).toBe(false);
    expect(
      (await mk(engine(() => ({ decision: "ALLOW_WITH_REDACTION" }))).decide(req)).allowed,
    ).toBe(false);
    expect((await mk(engine(() => ({ decision: "REQUIRE_APPROVAL" }))).decide(req)).allowed).toBe(
      false,
    );
    expect((await mk(engine(() => ({ decision: "allow" }))).decide(req)).allowed).toBe(false);
    expect(
      (await mk(engine(() => ({ decision: "DENY", reason: "nope" }))).decide(req)).reason,
    ).toBe("nope");
    expect((await mk(engine(() => ({ decision: "DENY" }))).decide(req)).reason).toBe(
      "denied by policy",
    );
    const ok = await mk(engine(() => ({ decision: "ALLOW", winners: ["a", 1] }))).decide(req);
    expect(ok.allowed).toBe(true);
    expect(ok.winners).toEqual(["a"]);
    expect((await mk(engine(() => ({ decision: "ALLOW" }))).decide(req)).winners).toEqual([]);
    let t = 0;
    const slow = mk(
      engine(() => ({ decision: "ALLOW" })),
      { timeoutMs: 10, clock: () => (t += 100) },
    );
    expect((await slow.decide(req)).reason).toMatch(/time budget/);
  });

  it("DENIES unknown roles and never asks the engine when a hard invariant fails", async () => {
    let asked = 0;
    const a = new Authorizer({
      engine: engine(() => (asked++, { decision: "ALLOW" })),
      policyVersion: "t",
    });
    expect(
      (await a.decide({ principal: me("root" as Role), action: "tenant.read" })).reason,
    ).toMatch(/role/);
    expect(
      (
        await a.decide({
          principal: me("admin"),
          action: "tenant.read",
          resource: { tenantId: "99999999-9999-4999-8999-999999999999" },
        })
      ).allowed,
    ).toBe(false);
    expect(
      (
        await a.decide({
          principal: me("admin"),
          action: "members.update_role",
          targetRole: "owner",
        })
      ).allowed,
    ).toBe(false);
    expect(
      (
        await a.decide({
          principal: me("admin"),
          action: "members.update_role",
          targetRole: "viewer",
          currentTargetRole: "owner",
        })
      ).allowed,
    ).toBe(false);
    expect(
      (
        await a.decide({
          principal: me("owner", { credential: "api_key", scopes: ["members:read"] }),
          action: "members.invite",
        })
      ).allowed,
    ).toBe(false);
    expect(asked).toBe(0);
    expect(
      (
        await a.decide({
          principal: me("admin"),
          action: "members.update_role",
          targetRole: "admin",
          currentTargetRole: "viewer",
        })
      ).allowed,
    ).toBe(true);
    expect(asked).toBe(1);
  });

  it("passes ABAC attributes the policy keys on", async () => {
    const seen: Record<string, unknown>[] = [];
    const a = new Authorizer({
      engine: engine((i) => (seen.push(i), { decision: "ALLOW" })),
      policyVersion: "t",
    });
    await a.decide({
      principal: me("builder"),
      action: "apikeys.rotate",
      resource: {
        ownerMemberId: "someone-else",
        environment: "prod",
        classification: "restricted",
      },
    });
    const i = seen[0] as {
      args: Record<string, unknown>;
      data: Record<string, unknown>;
      tenant: { id: string };
      actor: Record<string, unknown>;
    };
    expect(i.args).toEqual({
      same_tenant: true,
      within_ceiling: true,
      owner_is_actor: false,
      environment: "prod",
    });
    expect(i.data["classification"]).toBe("restricted");
    expect(i.tenant.id).toBe(T);
    expect(i.actor["credential"]).toBe("session");
  });

  it("scopes and ceiling helpers", () => {
    expect(requiredScope("members.read")).toBe("members:read");
    expect(requiredScope("members.invite")).toBe("members:write");
    expect(scopeAllows(["*"], "x.y")).toBe(true);
    expect(scopeAllows(["members:*"], "members.invite")).toBe(true);
    expect(scopeAllows(["members:read"], "members.invite")).toBe(false);
    expect(scopeAllows(["members:read"], "members.read")).toBe(true);
    expect(scopeAllows(undefined, "members.read")).toBe(false);
    expect(scopeAllows([], "members.read")).toBe(false);
    expect(withinCeiling("admin", "admin")).toBe(true);
    expect(withinCeiling("admin", "owner")).toBe(false);
    expect(ROLE_RANK.owner).toBeGreaterThan(ROLE_RANK.admin);
  });

  it("fromPackFile refuses a pack that does not compile", async () => {
    const { writeFileSync, mkdtempSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const f = join(mkdtempSync(join(tmpdir(), "cp-")), "bad.yaml");
    writeFileSync(f, "apiVersion: nope\n");
    await expect(Authorizer.fromPackFile(f)).rejects.toThrow(/does not compile/);
  });
});
