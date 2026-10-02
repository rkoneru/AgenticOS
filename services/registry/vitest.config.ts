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
        lines: 85,
        branches: 85,
        functions: 85,
        statements: 85,
        // Core: signing, provenance, semver, verification (CLAUDE.md-style 95% on safety logic).
        "src/signing.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/provenance.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/semver.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/verify.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/service.ts": { lines: 90, branches: 85, functions: 90, statements: 90 },
      },
    },
  },
});
