import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    testTimeout: 30_000,
    coverage: {
      provider: "v8",
      include: ["src/**"],
      thresholds: { lines: 85, branches: 85, functions: 85, statements: 85 },
    },
  },
});
