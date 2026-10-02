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
        // Core: the ledger and its safety logic (CLAUDE.md: 95% on the billing ledger).
        "src/types.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/periods.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/seal.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/ledger.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/memory-ledger.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/pg-ledger.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
      },
    },
  },
});
