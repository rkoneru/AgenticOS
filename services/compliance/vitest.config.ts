import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globalSetup: ["./test/global-setup.ts"],
    fileParallelism: false,
    testTimeout: 30_000,
    coverage: {
      provider: "v8",
      include: ["src/**"],
      // main.ts and cli.ts are process entry points (argv/env parsing, listen); their logic lives in tested modules.
      exclude: ["src/main.ts", "src/cli.ts"],
      thresholds: {
        lines: 90,
        branches: 85,
        functions: 90,
        statements: 90,
        // Safety logic: the matrix checker, document assembly/sealing, the review state machine, tenancy/authz.
        "src/matrix/check.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/docgen/assemble.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/docgen/seal.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/docgen/verify.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/records/states.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/records/assessments.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/authz.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
        "src/docstore.ts": { lines: 95, branches: 95, functions: 95, statements: 95 },
      },
    },
  },
});
