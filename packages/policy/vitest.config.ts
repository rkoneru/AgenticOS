import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    testTimeout: 30_000,
    hookTimeout: 30_000,
    coverage: {
      provider: "v8",
      include: ["src/**"],
      thresholds: { lines: 95, branches: 95, functions: 95, statements: 95 },
    },
  },
});
