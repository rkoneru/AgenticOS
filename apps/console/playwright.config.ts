import { defineConfig, devices } from "@playwright/test";

const WEB = 3100;
const API = 4010;
const env = {
  AXIS_API_URL: `http://127.0.0.1:${API}`,
  AXIS_INSECURE_HTTP: "1",
  NEXT_TELEMETRY_DISABLED: "1",
  MOCK_API_PORT: String(API),
};

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 45_000,
  reporter: [["list"]],
  use: {
    baseURL: `http://localhost:${WEB}`,
    trace: "retain-on-failure",
    ...devices["Desktop Chrome"],
  },
  webServer: [
    {
      command: "pnpm exec tsx mock-api/main.ts",
      url: `http://127.0.0.1:${API}/__health`,
      env,
      reuseExistingServer: false,
      timeout: 30_000,
    },
    // `pnpm build` (with NEXT_PUBLIC_DEV_LOGIN=1) must have run first: `make console-e2e` does that.
    {
      command: `pnpm exec next start -p ${WEB}`,
      url: `http://localhost:${WEB}/login`,
      env,
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
});
