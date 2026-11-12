import { defineConfig, devices } from "@playwright/test";

const WEB = 3100;
const API = 4010;
const env = {
  AXIS_API_URL: `http://127.0.0.1:${API}`,
  AXIS_INSECURE_HTTP: "1",
  NEXT_TELEMETRY_DISABLED: "1",
  MOCK_API_PORT: String(API),
};

// next.config.ts sets `output: "standalone"` for the Phase 10 Docker image (apps/console/Dockerfile).
// `next start` does not serve a standalone build (Next prints a warning and the app misbehaves —
// e.g. client-side hydration that depends on a route handler can hang indefinitely); the Dockerfile
// itself already runs the real standalone entrypoint (`node apps/console/server.js`). Do the same
// here: copy the static assets next to the standalone server (as the Dockerfile's COPY step does)
// and run that server directly, matching production rather than a mode `next` doesn't support.
const STANDALONE_SERVER = `.next/standalone/apps/console/server.js`;
const START_STANDALONE =
  `rm -rf .next/standalone/apps/console/.next/static && ` +
  `cp -r .next/static .next/standalone/apps/console/.next/static && ` +
  `PORT=${WEB} HOSTNAME=127.0.0.1 node ${STANDALONE_SERVER}`;

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
      command: `sh -c "${START_STANDALONE}"`,
      url: `http://localhost:${WEB}/login`,
      env,
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
});
