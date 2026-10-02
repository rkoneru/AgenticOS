import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      include: ["src/**"],
      thresholds: { lines: 95, branches: 90, functions: 90, statements: 95 },
    },
  },
});
