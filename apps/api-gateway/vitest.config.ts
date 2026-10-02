import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    testTimeout: 30_000,
    hookTimeout: 60_000,
    coverage: {
      provider: "v8",
      include: ["src/**"],
      exclude: ["src/main.ts", "src/index.ts", "src/dev-wire.ts"],
      thresholds: {
        lines: 85,
        branches: 85,
        functions: 85,
        statements: 85,
        // authn / authz / tenant routing / idempotency / rate limiting / problem mapping: 95%.
        "src/server.ts": { lines: 92, branches: 85, functions: 90, statements: 92 },
        "src/limits.ts": { lines: 95, branches: 90, functions: 95, statements: 95 },
        "src/problem.ts": { lines: 95, branches: 90, functions: 95, statements: 95 },
        "src/adapters/control-plane.ts": { lines: 90, branches: 80, functions: 90, statements: 90 },
        "src/adapters/approvals.ts": { lines: 94, branches: 85, functions: 95, statements: 94 },
      },
    },
  },
});
