import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globalSetup: ["./test/global-setup.ts"],
    fileParallelism: false,
    coverage: {
      provider: "v8",
      include: ["src/**"],
      // main.ts is a process entry point (env parsing + listen).
      exclude: ["src/main.ts"],
      thresholds: {
        lines: 85,
        branches: 85,
        functions: 85,
        statements: 85,
        // Security-critical modules: signature verification, tenant routing, identity linking, dedupe.
        "src/crypto.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/jwt.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/routing.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/replay.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/identity.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
      },
    },
  },
});
