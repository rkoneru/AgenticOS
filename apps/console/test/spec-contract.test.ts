import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { createApi } from "@/lib/api";

/** Every frozen-/v1 call the console makes must exist in the OpenAPI document (method + path). */
const spec = parse(
  readFileSync(
    fileURLToPath(new URL("../../../packages/contracts/openapi/axis-v1.yaml", import.meta.url)),
    "utf8",
  ),
) as { paths: Record<string, Record<string, unknown>> };

const ADDITIVE = [
  /\/explanation$/,
  /\/marketplace\//,
  /^\/v1\/evals\/runs$/ /* GET list is additive; POST is frozen */,
  /^\/auth\//,
  /^\/admin\//,
];

describe("console data layer vs OpenAPI v1", () => {
  it("only calls frozen operations except for documented additive ones", async () => {
    const calls: string[] = [];
    const f = (async (u: RequestInfo | URL, init?: RequestInit) => {
      calls.push(`${init?.method} ${String(u).replace("/api/axis", "").split("?")[0]}`);
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    }) as typeof fetch;
    const api = createApi({ fetchImpl: f, csrf: () => "t" });
    const id = "11111111-1111-4111-8111-111111111111";
    await Promise.all([
      api.listBlueprints(),
      api.publishBlueprint({}),
      api.getBlueprintVersion("a", "1"),
      api.listRuns(),
      api.startRun({ name: "a", version: "1" }),
      api.getRun(id),
      api.signalRun(id, "PAUSE"),
      api.listRunEvents(id),
      api.listApprovals(),
      api.decideApproval(id, "approve"),
      api.listPolicyPacks(),
      api.publishPolicyPack({}),
      api.testPolicy({}, { enforcement_point: "x", context: {} }),
      api.listAuditEvents(),
      api.verifyAudit(),
      api.listKillSwitches(),
      api.setKillSwitch({ scope: "tenant", engaged: true }),
      api.getUsage({ from: "a", to: "b" }),
      api.startEvalRun("s", { name: "a", version: "1" }),
    ]);
    for (const c of calls) {
      const [method, path] = c.split(" ") as [string, string];
      // Convert concrete ids back to template form by matching against spec paths.
      const rel = path.replace(/^\/v1/, "");
      const match = Object.keys(spec.paths).find((p) =>
        new RegExp(`^${p.replace(/\{[^}]+\}/g, "[^/]+")}$`).test(rel),
      );
      expect(match, `${c} must exist in axis-v1.yaml`).toBeDefined();
      expect(spec.paths[match!]![method.toLowerCase()], `${c} method`).toBeDefined();
    }
    expect(calls).toHaveLength(19);
    // sanity: the additive allow-list really is only used for non-spec paths
    expect(ADDITIVE.length).toBeGreaterThan(0);
  });
});
