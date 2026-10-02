import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    testTimeout: 30_000,
    globalSetup: ["./test/global-setup.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**"],
      exclude: ["src/cli.ts"],
      // tenancy/RLS is a core package: 95% gate.
      thresholds: { lines: 95, branches: 95, functions: 95, statements: 95 },
    },
  },
});
