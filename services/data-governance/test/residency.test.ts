import { describe, expect, it } from "vitest";
import { ResidencyError, ResidencyPolicy, StaticRegionResolver } from "../src/residency.js";

const T_EU = "11111111-1111-4111-8111-111111111111";
const T_US = "22222222-2222-4222-8222-222222222222";
const T_MULTI = "33333333-3333-4333-8333-333333333333";
const policy = new ResidencyPolicy(
  new StaticRegionResolver({
    [T_EU]: { homeRegion: "eu-west-1" },
    [T_US]: { homeRegion: "us-east-1" },
    [T_MULTI]: { homeRegion: "eu-west-1", allowedRegions: ["EU-central-1", " "] },
  }),
);

describe("ResidencyPolicy", () => {
  it("allows the home region and refuses other regions (two regions, both directions)", async () => {
    await expect(policy.assertWrite(T_EU, "eu-west-1")).resolves.toBeUndefined();
    await expect(policy.assertWrite(T_US, "us-east-1")).resolves.toBeUndefined();
    await expect(policy.assertWrite(T_EU, "us-east-1")).rejects.toBeInstanceOf(ResidencyError);
    await expect(policy.assertWrite(T_US, "eu-west-1")).rejects.toBeInstanceOf(ResidencyError);
    await expect(policy.assertEgress(T_EU, "us-east-1")).rejects.toThrow(/egress/);
    await expect(policy.assertModelRegion(T_US, "eu-west-1")).rejects.toThrow(/model call/);
    await expect(policy.assertModelRegion(T_US, "us-east-1")).resolves.toBeUndefined();
  });
  it("matches regions case-insensitively and supports extra allowed regions", async () => {
    await expect(policy.assertWrite(T_EU, " EU-WEST-1 ")).resolves.toBeUndefined();
    await expect(policy.assertEgress(T_MULTI, "eu-central-1")).resolves.toBeUndefined();
    expect(await policy.allowedRegions(T_MULTI)).toEqual(["eu-central-1", "eu-west-1"]);
    await expect(policy.assertEgress(T_MULTI, "us-east-1")).rejects.toBeInstanceOf(ResidencyError);
  });
  it("is fail-closed: unknown tenant, empty/undefined region, empty home, resolver error", async () => {
    await expect(
      policy.assertWrite("44444444-4444-4444-8444-444444444444", "eu-west-1"),
    ).rejects.toBeInstanceOf(ResidencyError);
    await expect(policy.assertWrite(T_EU, undefined)).rejects.toBeInstanceOf(ResidencyError);
    await expect(policy.assertWrite(T_EU, "  ")).rejects.toBeInstanceOf(ResidencyError);
    expect(await policy.permits(T_EU, "")).toBe(false);
    const empty = new ResidencyPolicy(new StaticRegionResolver({ [T_EU]: { homeRegion: " " } }));
    await expect(empty.assertWrite(T_EU, "")).rejects.toBeInstanceOf(ResidencyError);
    expect(await empty.allowedRegions(T_EU)).toEqual([]);
    const broken = new ResidencyPolicy({
      resolve: async () => {
        throw new Error("cp down");
      },
    });
    await expect(broken.assertWrite(T_EU, "eu-west-1")).rejects.toBeInstanceOf(ResidencyError);
    expect(await broken.allowedRegions(T_EU)).toEqual([]);
  });
  it("forService binds a write guard to the instance region", async () => {
    const eu = policy.forService("eu-west-1");
    await expect(eu.assertWrite(T_EU)).resolves.toBeUndefined();
    await expect(eu.assertWrite(T_US)).rejects.toBeInstanceOf(ResidencyError);
    expect(new ResidencyError("x").code).toBe("region_mismatch");
  });
});
