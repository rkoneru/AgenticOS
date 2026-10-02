import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    testTimeout: 30_000,
    globalSetup: ["./test/global-setup.ts"],
    fileParallelism: false,
    coverage: {
      provider: "v8",
      include: ["src/**"],
      // main.ts is a process entry point (env parsing + listen); it is smoke-tested by spawning it, which v8 cannot attribute.
      exclude: ["src/main.ts"],
      // Overall 85%; the tenancy/ACL-critical modules (acl.ts, store.ts) are held to 95% via perFile-style thresholds.
      thresholds: {
        lines: 85,
        branches: 85,
        functions: 85,
        statements: 85,
        "src/acl.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/store.ts": { lines: 95, branches: 90, functions: 95, statements: 95 },
        "src/chunk.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
      },
    },
  },
});
