import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    testTimeout: 30_000,
    coverage: {
      provider: "v8",
      // The harness LIBRARY (histogram, arrival model, report) is what the numbers depend on: 95%. The scenario/CLI glue that talks to
      // a live stack (src/scenarios.ts, src/cli.ts, src/audit-bench.ts, src/stack.ts) is exercised by `make loadtest`, not unit tests.
      include: ["src/hdr.ts", "src/openload.ts", "src/report.ts"],
      thresholds: { lines: 95, branches: 90, functions: 95, statements: 95 },
    },
  },
});
