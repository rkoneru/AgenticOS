import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    testTimeout: 30_000,
    coverage: {
      provider: "v8",
      include: ["src/**"],
      exclude: ["src/build.ts"],
      thresholds: { lines: 85, branches: 80, functions: 85, statements: 85 },
    },
  },
});
