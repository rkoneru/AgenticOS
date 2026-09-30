import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globalSetup: ["./test/global-setup.ts"],
    // Files share one migrated database and some tests disable a table trigger as superuser: run files serially.
    fileParallelism: false,
    coverage: {
      provider: "v8",
      include: ["src/**"],
      // The audit service is a core package: 95% gate on lines and branches.
      thresholds: { lines: 95, branches: 95, functions: 95, statements: 95 },
    },
  },
});
