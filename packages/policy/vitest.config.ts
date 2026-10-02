import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Several tests shell out to the real `opa` binary (incl. the 73-case control-plane pack).
    testTimeout: 60_000,
    hookTimeout: 60_000,
    coverage: {
      provider: "v8",
      include: ["src/**"],
      thresholds: { lines: 95, branches: 95, functions: 95, statements: 95 },
    },
  },
});
