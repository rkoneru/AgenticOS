import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    testTimeout: 20_000,
    coverage: {
      provider: "v8",
      include: ["src/proxy.ts"],
      thresholds: { lines: 90, branches: 80, functions: 90, statements: 90 },
    },
  },
});
