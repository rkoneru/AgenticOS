import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { currentHashes, ROOT } from "../scripts/freeze.js";

describe("contracts freeze (ADR-0007)", () => {
  it("frozen files match FREEZE.json; changing one requires an ADR and `pnpm --filter @axis/contracts freeze`", () => {
    const manifest = JSON.parse(readFileSync(`${ROOT}packages/contracts/FREEZE.json`, "utf8"));
    expect(currentHashes()).toEqual(manifest.files);
  });
});
