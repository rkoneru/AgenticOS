import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      include: ["src/**"],
      // The generated layer is covered by the spec-coverage test; the ergonomic layer must hold 85%.
      thresholds: { lines: 85, branches: 85, functions: 85, statements: 85 },
    },
  },
});
