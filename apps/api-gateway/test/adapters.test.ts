import { CpError } from "@axis/control-plane";
import { ApprovalError } from "@axis/approvals";
import { describe, expect, it } from "vitest";
import {
  ApprovalsAdapter,
  ControlPlaneAuthenticator,
  ControlPlanePolicies,
  PortConflict,
  PortForbidden,
  PortInvalid,
  PortNotFound,
  PortUnavailable,
  StorePolicyMetadata,
  fromCpError,
} from "../src/index.js";

const P = { tenantId: "t", memberId: "m", role: "owner", credential: "session" } as never;

describe("control-plane adapters", () => {
  it("authenticator routes by credential shape", async () => {
    const calls: string[] = [];
    const a = new ControlPlaneAuthenticator({
      apiKeys: { verify: async (k) => (calls.push(`key:${k}`), P) },
      sessions: { authenticate: async (t) => (calls.push(`sess:${t}`), P) },
    });
    await a.authenticate({ apiKey: "axk_x" });
    await a.authenticate({ bearer: "axk_y" });
    await a.authenticate({ bearer: "tok" });
    expect(await a.authenticate({})).toBeUndefined();
    expect(calls).toEqual(["key:axk_x", "key:axk_y", "sess:tok"]);
  });
  it("maps every control-plane error code", () => {
    const expectErr = (code: ConstructorParameters<typeof CpError>[0], cls: unknown) => {
      try {
        fromCpError(new CpError(code, "m"));
      } catch (e) {
        expect(e).toBeInstanceOf(cls);
        return;
      }
      throw new Error("no throw");
    };
    expectErr("not_found", PortNotFound);
    expectErr("conflict", PortConflict);
    expectErr("forbidden", PortForbidden);
    expectErr("invalid", PortInvalid);
    expectErr("unavailable", PortUnavailable);
    expect(() => fromCpError(new Error("x"))).toThrow("x");
  });
  it("policy list/publish translate errors; metadata reads only rules asked for", async () => {
    const pol = new ControlPlanePolicies({
      packs: {
        list: async () => [],
        publish: async () => Promise.reject(new CpError("conflict", "dup")),
      },
      tester: { evaluate: async () => ({ decision: "ALLOW", policy_version: "p@1" }) },
    });
    expect((await pol.list(P, { limit: 5 })).items).toEqual([]);
    await expect(pol.publish(P, {})).rejects.toBeInstanceOf(PortConflict);
    const md = new StorePolicyMetadata({
      listPackVersions: async () => [
        {
          packName: "p",
          source: {
            spec: {
              rules: [
                {
                  id: "a",
                  decision: "DENY",
                  description: "d",
                  approval: { roles: ["x"], slaSeconds: 5 },
                },
                { id: "b" },
              ],
            },
          },
        } as never,
      ],
    });
    expect(await md.describeRules("t", ["p/a"])).toEqual([
      { id: "p/a", decision: "DENY", description: "d", approval: { roles: ["x"], slaSeconds: 5 } },
    ]);
  });
  it("approvals adapter maps service errors", async () => {
    const mk = (code: ConstructorParameters<typeof ApprovalError>[0]) =>
      new ApprovalsAdapter({
        list: async () => [],
        approve: async () => Promise.reject(new ApprovalError(code, "m")),
        deny: async () => Promise.reject(new ApprovalError(code, "m")),
      });
    for (const [code, cls] of [
      ["NOT_FOUND", PortNotFound],
      ["SELF_APPROVAL", PortForbidden],
      ["CONFLICT_OF_INTEREST", PortForbidden],
      ["ALREADY_DECIDED", PortConflict],
      ["INVALID", PortInvalid],
      ["AUDIT_FAILED", PortUnavailable],
    ] as const) {
      await expect(mk(code).decide(P, "id", { decision: "approve" })).rejects.toBeInstanceOf(cls);
      await expect(mk(code).decide(P, "id", { decision: "reject" })).rejects.toBeInstanceOf(cls);
    }
    await expect(
      new ApprovalsAdapter({
        list: async () => Promise.reject(new ApprovalError("NOT_FOUND", "x")),
        approve: async () => ({}) as never,
        deny: async () => ({}) as never,
      }).list(P, { limit: 1 }),
    ).rejects.toBeInstanceOf(PortNotFound);
  });
});
