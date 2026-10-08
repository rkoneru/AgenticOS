import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globalSetup: ["./test/global-setup.ts"],
    fileParallelism: false,
    testTimeout: 30_000,
    coverage: {
      provider: "v8",
      include: ["src/**"],
      // main.ts is a process entry point (env parsing + listen).
      exclude: ["src/main.ts"],
      thresholds: {
        lines: 90,
        branches: 90,
        functions: 90,
        statements: 90,
        // Safety logic: the gate, scoring/threshold/regression/significance, integrity recompute, baselines, tenancy/authz, review queue.
        "src/gate.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/scoring.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/integrity.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/baselines.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/authz.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/reviews.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/runs.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
      },
    },
  },
});
