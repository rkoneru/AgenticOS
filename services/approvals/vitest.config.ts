import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    testTimeout: 30_000, // the 40-seed property walks exceed the 5 s default when turbo runs every package in parallel
    coverage: {
      provider: "v8",
      include: ["src/**"],

      thresholds: { lines: 95, branches: 95, functions: 95, statements: 95 },
    },
  },
});
