import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globalSetup: ["./test/global-setup.ts"],
    fileParallelism: false,
    testTimeout: 30_000,
    coverage: {
      provider: "v8",
      include: ["src/**"],
      exclude: ["src/main.ts", "src/index.ts"],
      thresholds: {
        lines: 85,
        branches: 85,
        functions: 85,
        statements: 85,
        // Safety-critical modules: 95% lines/statements/functions (branches 90 where the remainder is defensive narrowing).
        "src/authz.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/tenancy.ts": { lines: 95, branches: 90, functions: 95, statements: 95 },
        "src/sessions.ts": { lines: 95, branches: 90, functions: 85, statements: 95 },
        "src/apikeys.ts": { lines: 95, branches: 90, functions: 85, statements: 95 },
        "src/scim.ts": { lines: 95, branches: 85, functions: 95, statements: 95 },
        "src/directory.ts": { lines: 95, branches: 85, functions: 95, statements: 95 },
      },
    },
  },
});
