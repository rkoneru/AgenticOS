import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    testTimeout: 60_000,
    globalSetup: ["./test/global-setup.ts"],
    fileParallelism: false,
    coverage: {
      provider: "v8",
      include: ["src/**"],
      // main.ts is a process entry point (env parsing + listen); it is smoke-tested by spawning it, which v8 cannot attribute.
      exclude: ["src/main.ts"],
      thresholds: {
        lines: 85,
        branches: 80,
        functions: 85,
        statements: 85,
        // Decision logic: DSAR engine, retention decision, holds, residency, pseudonymisation (95%).
        "src/dsar.ts": { lines: 95, branches: 90, functions: 95, statements: 95 },
        "src/retention.ts": { lines: 95, branches: 90, functions: 95, statements: 95 },
        "src/holds.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/residency.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/keys.ts": { lines: 95, branches: 90, functions: 95, statements: 95 },
      },
    },
  },
});
