import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globalSetup: ["./test/global-setup.ts"],
    fileParallelism: false,
    testTimeout: 30_000,
    coverage: {
      provider: "v8",
      include: ["src/**"],
      exclude: ["src/main.ts"],
      thresholds: {
        lines: 85,
        branches: 85,
        functions: 85,
        statements: 85,
        // Core safety logic: review state machine, install consent, capability diff.
        "src/states.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/capabilities.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/installs.ts": { lines: 95, branches: 90, functions: 95, statements: 95 },
        "src/reviews.ts": { lines: 95, branches: 90, functions: 95, statements: 95 },
      },
    },
  },
});
